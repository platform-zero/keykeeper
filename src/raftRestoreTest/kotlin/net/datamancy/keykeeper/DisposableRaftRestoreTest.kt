package net.datamancy.keykeeper

import kotlinx.serialization.json.*
import java.net.ServerSocket
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.util.Comparator
import java.util.UUID
import kotlin.test.*

/** Starts a fresh process with fresh storage: NEVER run against an existing Bao instance. */
class DisposableRaftRestoreTest {
    @Test fun `isolated real OpenBao Raft snapshot restores fake value and grants`() {
        require(System.getenv("KEYKEEPER_DISPOSABLE_RAFT_CONFIRM") == "YES-NEW-INSTANCE-ONLY")
        val binary = Path.of(System.getenv("KEYKEEPER_TEST_BAO_BINARY") ?: error("Missing local OpenBao binary"))
        require(Files.isRegularFile(binary) && Files.isExecutable(binary))
        val parent = Path.of("build", "raft-scratch").toAbsolutePath()
        Files.createDirectories(parent)
        val scratch = Files.createTempDirectory(parent, "keykeeper-")
        val apiPort = ServerSocket(0).use { it.localPort }
        val clusterPort = ServerSocket(0).use { it.localPort }
        val base = URI("http://127.0.0.1:$apiPort")
        val config = scratch.resolve("bao.hcl")
        Files.writeString(config, """
            ui = false
            disable_mlock = true
            api_addr = "http://127.0.0.1:$apiPort"
            cluster_addr = "http://127.0.0.1:$clusterPort"
            storage "raft" { path = "${scratch.resolve("raft")}" node_id = "disposable-test" }
            listener "tcp" { address = "127.0.0.1:$apiPort" cluster_address = "127.0.0.1:$clusterPort" tls_disable = true }
        """.trimIndent())
        val process = ProcessBuilder(binary.toString(), "server", "-config=${config}")
            .redirectErrorStream(true).redirectOutput(scratch.resolve("bao-process.log").toFile()).start()
        val client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build()
        fun call(method: String, path: String, token: String? = null, body: ByteArray? = null): HttpResponse<ByteArray> {
            val builder = HttpRequest.newBuilder(base.resolve(path)).timeout(Duration.ofSeconds(10))
            if (token != null) builder.header("X-Vault-Token", token)
            if (body != null) builder.header("Content-Type", if (path.endsWith("snapshot-force")) "application/octet-stream" else "application/json")
            return client.send(builder.method(method, if (body == null) HttpRequest.BodyPublishers.noBody()
                else HttpRequest.BodyPublishers.ofByteArray(body)).build(), HttpResponse.BodyHandlers.ofByteArray())
        }
        fun json(response: HttpResponse<ByteArray>) = Json.parseToJsonElement(response.body().toString(Charsets.UTF_8)).jsonObject
        fun waitForActive(token: String) {
            repeat(60) {
                val result = runCatching { call("GET", "/v1/sys/health", token) }.getOrNull()
                if (result?.statusCode() == 200) return
                Thread.sleep(500)
            }
            error("Disposable Bao did not become active")
        }
        try {
            var ready = false
            for (attempt in 1..40) {
                if (!process.isAlive) error("Disposable Bao stopped")
                if (runCatching { call("GET", "/v1/sys/health") }.isSuccess) { ready = true; break }
                Thread.sleep(250)
            }
            check(ready) { "Disposable Bao did not start" }
            val init = json(call("PUT", "/v1/sys/init", body = "{\"secret_shares\":1,\"secret_threshold\":1}".toByteArray()))
            val unseal = init.getValue("keys_base64").jsonArray.single().jsonPrimitive.content
            val token = init.getValue("root_token").jsonPrimitive.content
            fun unsealIfNeeded() {
                repeat(60) {
                    val health = runCatching { call("GET", "/v1/sys/health").statusCode() }.getOrNull()
                    if (health == 200) return
                    if (health == 503) {
                        val response = call("PUT", "/v1/sys/unseal", body = buildJsonObject { put("key", unseal) }.toString().toByteArray())
                        assertEquals(200, response.statusCode())
                    }
                    Thread.sleep(500)
                }
                error("Disposable Bao failed to unseal")
            }
            unsealIfNeeded()
            waitForActive(token)
            val mount = "keykeeper-test-${UUID.randomUUID().toString().take(8)}"
            assertEquals(204, call("POST", "/v1/sys/mounts/$mount", token,
                "{\"type\":\"kv\",\"options\":{\"version\":\"2\"}}".toByteArray()).statusCode())
            val store = OpenBaoStore(base, mount, token)
            val owner = Principal("disposable-issuer", "test-owner", PrincipalKind.HUMAN)
            val agent = Principal(owner.issuer, "test-agent", PrincipalKind.AGENT)
            val vault = Vault(store, LocalTestVerifier("fake-only-token-012345678901234", owner)) { }
            val item = vault.create(owner, "fake-value-${UUID.randomUUID()}")
            val saved = vault.read(owner, item.id)
            vault.share(owner, item.id, Grant(agent, setOf(Right.READ)))
            assertEquals(saved, vault.read(agent, item.id))
            val snapshot = call("GET", "/v1/sys/storage/raft/snapshot", token)
            assertEquals(200, snapshot.statusCode())
            assertTrue(snapshot.body().isNotEmpty())
            vault.revoke(owner, item.id, agent)
            vault.edit(owner, item.id, "fake-changed")
            assertFailsWith<Denied> { vault.read(agent, item.id) }
            // Force restore is safe ONLY because this process and its Raft directory were created here.
            val restored = call("POST", "/v1/sys/storage/raft/snapshot-force", token, snapshot.body())
            assertTrue(restored.statusCode() in setOf(200, 204))
            unsealIfNeeded()
            waitForActive(token)
            assertEquals(saved, vault.read(owner, item.id))
            assertEquals(saved, vault.read(agent, item.id))
        } finally {
            process.destroy()
            if (!process.waitFor(5, java.util.concurrent.TimeUnit.SECONDS)) process.destroyForcibly().waitFor()
            Files.walk(scratch).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) } }
        }
    }
}
