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
import java.util.concurrent.TimeUnit
import kotlin.test.*

/** Two separately initialized, locally launched Raft clusters. Never accepts an existing Bao URL. */
class DisposableRaftRestoreTest {
    private data class Keys(val unseal: String, val token: String)

    private class Node(private val binary: Path, private val directory: Path, name: String) : AutoCloseable {
        private fun port() = ServerSocket(0).use { it.localPort }
        private val apiPort = port()
        private val clusterPort = generateSequence { port() }.first { it != apiPort }
        val base = URI("http://127.0.0.1:$apiPort")
        private val config = directory.resolve("bao.hcl")
        private val client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build()
        private var process: Process? = null
        val alive: Boolean get() = process?.isAlive == true

        init {
            Files.createDirectory(directory)
            Files.writeString(config, """
                ui = false
                disable_mlock = true
                api_addr = "$base"
                cluster_addr = "http://127.0.0.1:$clusterPort"
                storage "raft" { path = "${directory.resolve("raft")}" node_id = "$name" }
                listener "tcp" { address = "127.0.0.1:$apiPort" cluster_address = "127.0.0.1:$clusterPort" tls_disable = true }
            """.trimIndent())
            start()
        }
        private fun start() {
            process = ProcessBuilder(binary.toString(), "server", "-config=$config")
                .redirectErrorStream(true).redirectOutput(directory.resolve("bao-process.log").toFile()).start()
        }
        fun restart() { stop(); start() }
        private fun stop() {
            process?.destroy()
            if (process?.waitFor(5, TimeUnit.SECONDS) == false) process?.destroyForcibly()?.waitFor()
        }
        override fun close() = stop()

        fun call(method: String, path: String, token: String? = null, body: ByteArray? = null,
                 timeoutSeconds: Long = 10): HttpResponse<ByteArray> {
            val builder = HttpRequest.newBuilder(base.resolve(path)).timeout(Duration.ofSeconds(timeoutSeconds))
            if (token != null) builder.header("X-Vault-Token", token)
            if (body != null) builder.header("Content-Type", if (path.endsWith("snapshot-force")) "application/octet-stream" else "application/json")
            return client.send(builder.method(method, if (body == null) HttpRequest.BodyPublishers.noBody()
                else HttpRequest.BodyPublishers.ofByteArray(body)).build(), HttpResponse.BodyHandlers.ofByteArray())
        }
        private fun health() = runCatching { call("GET", "/v1/sys/health").statusCode() }.getOrNull()
        fun initialize(): Keys {
            var fresh = false
            for (attempt in 1..120) {
                check(alive) { "Disposable Bao stopped" }
                val status = health()
                if (status == 501) { fresh = true; break }
                check(status == null || status == 503) { "Not a fresh node (health=$status)" }
                Thread.sleep(250)
            }
            check(fresh) { "Fresh Bao did not become uninitialized" }
            // Never retry init: a timed-out successful init would lose the one-time unseal key.
            val response = call("PUT", "/v1/sys/init", body = "{\"secret_shares\":1,\"secret_threshold\":1}".toByteArray(), timeoutSeconds = 60)
            assertEquals(200, response.statusCode())
            val init = Json.parseToJsonElement(response.body().toString(Charsets.UTF_8)).jsonObject
            val keys = Keys(init.getValue("keys_base64").jsonArray.single().jsonPrimitive.content,
                init.getValue("root_token").jsonPrimitive.content)
            awaitActive(keys.unseal)
            return keys
        }
        fun awaitActive(vararg unsealKeys: String) {
            for (attempt in 1..120) {
                check(alive) { "Disposable Bao stopped while recovering" }
                when (health()) {
                    200 -> return
                    503 -> for (key in unsealKeys) {
                        val result = runCatching { call("PUT", "/v1/sys/unseal", body = buildJsonObject { put("key", key) }.toString().toByteArray()) }.getOrNull()
                        if (result?.statusCode() == 200 &&
                            Json.parseToJsonElement(result.body().toString(Charsets.UTF_8)).jsonObject["sealed"]?.jsonPrimitive?.booleanOrNull == false) break
                    }
                }
                Thread.sleep(500)
            }
            error("Disposable Bao did not become active")
        }
    }

    @Test fun `restore snapshot to independently initialized fresh Raft target and verify fake value and agent rights`() {
        require(System.getenv("KEYKEEPER_DISPOSABLE_RAFT_CONFIRM") == "YES-NEW-INSTANCE-ONLY")
        val binary = Path.of(System.getenv("KEYKEEPER_TEST_BAO_BINARY") ?: error("Missing local OpenBao binary"))
        require(Files.isRegularFile(binary) && Files.isExecutable(binary))
        val parent = Path.of("build", "raft-scratch").toAbsolutePath()
        Files.createDirectories(parent)
        val scratch = Files.createTempDirectory(parent, "keykeeper-")
        var source: Node? = null
        var target: Node? = null
        try {
            source = Node(binary, scratch.resolve("source"), "source-${UUID.randomUUID()}")
            val sourceKeys = source.initialize()
            val mount = "keykeeper-test-${UUID.randomUUID().toString().take(8)}"
            assertEquals(204, source.call("POST", "/v1/sys/mounts/$mount", sourceKeys.token,
                "{\"type\":\"kv\",\"options\":{\"version\":\"2\"}}".toByteArray()).statusCode())
            val owner = Principal("disposable-issuer", "test-owner", PrincipalKind.HUMAN)
            val agent = Principal(owner.issuer, "test-agent", PrincipalKind.AGENT)
            fun vault(node: Node, token: String) = Vault(OpenBaoStore(node.base, mount, token),
                LocalTestVerifier("fake-only-token-012345678901234", owner)) { }
            val original = vault(source, sourceKeys.token)
            val fakeValue = "fake-value-${UUID.randomUUID()}"
            val item = (1..20).firstNotNullOfOrNull {
                try { original.create(owner, fakeValue) }
                catch (_: Conflict) { Thread.sleep(500); null }
            } ?: error("Disposable KV-v2 mount did not accept CAS create")
            original.share(owner, item.id, Grant(agent, setOf(Right.READ)))
            assertEquals(fakeValue, original.read(owner, item.id))
            assertEquals(fakeValue, original.read(agent, item.id))
            val snapshot = source.call("GET", "/v1/sys/storage/raft/snapshot", sourceKeys.token, timeoutSeconds = 60)
            assertEquals(200, snapshot.statusCode())
            assertTrue(snapshot.body().isNotEmpty())
            original.revoke(owner, item.id, agent)
            original.edit(owner, item.id, "fake-changed")
            assertFailsWith<Denied> { original.read(agent, item.id) }
            assertEquals("fake-changed", original.read(owner, item.id))

            // A DIFFERENT Raft directory, process, listener and separately generated unseal/root keys.
            target = Node(binary, scratch.resolve("target"), "target-${UUID.randomUUID()}")
            val targetKeys = target.initialize()
            assertNotEquals(source.base, target.base)
            assertNotEquals(sourceKeys.token, targetKeys.token)
            assertEquals(404, target.call("GET", "/v1/$mount/data/${item.id}", targetKeys.token).statusCode())
            val restored = target.call("POST", "/v1/sys/storage/raft/snapshot-force", targetKeys.token, snapshot.body(), timeoutSeconds = 60)
            assertTrue(restored.statusCode() in setOf(200, 204))
            // Reopen the target's OWN restored Raft directory; never restart/reuse source storage.
            target.restart()
            target.awaitActive(targetKeys.unseal, sourceKeys.unseal)
            val recovered = vault(target, sourceKeys.token)
            var ready = false
            var lastStatus: Int? = null
            for (attempt in 1..120) {
                check(target.alive) { "Disposable restore target stopped" }
                lastStatus = runCatching { target.call("GET", "/v1/$mount/data/${item.id}", sourceKeys.token).statusCode() }.getOrNull()
                if (lastStatus == 200 && runCatching {
                    recovered.read(owner, item.id) == fakeValue && recovered.read(agent, item.id) == fakeValue
                }.getOrDefault(false)) { ready = true; break }
                Thread.sleep(500)
            }
            assertTrue(ready, "target failed to restore fake value/grant (last HTTP status=$lastStatus)")
            assertEquals(fakeValue, recovered.read(owner, item.id))
            assertEquals(fakeValue, recovered.read(agent, item.id))
            recovered.revoke(owner, item.id, agent)
            assertFailsWith<Denied> { recovered.read(agent, item.id) }
            assertEquals(fakeValue, recovered.read(owner, item.id))
            // Source remains independent and retains the post-snapshot revoke/edit.
            assertFailsWith<Denied> { original.read(agent, item.id) }
            assertEquals("fake-changed", original.read(owner, item.id))
        } finally {
            target?.close()
            source?.close()
            Files.walk(scratch).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) } }
        }
    }
}
