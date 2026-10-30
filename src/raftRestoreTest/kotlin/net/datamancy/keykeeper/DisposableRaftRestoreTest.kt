package net.datamancy.keykeeper

import kotlinx.serialization.json.*
import java.net.ServerSocket
import java.net.InetSocketAddress
import java.net.URLDecoder
import com.sun.net.httpserver.HttpServer
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.RSAPublicKey
import java.security.MessageDigest
import java.util.Base64
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

    @Test fun `fake OIDC browser PKCE session and agent JWT use real disposable KV v2`() {
        require(System.getenv("KEYKEEPER_DISPOSABLE_RAFT_CONFIRM") == "YES-NEW-INSTANCE-ONLY")
        val binary = Path.of(System.getenv("KEYKEEPER_TEST_BAO_BINARY") ?: error("Missing local OpenBao binary"))
        require(Files.isRegularFile(binary) && Files.isExecutable(binary))
        val parent = Path.of("build", "raft-scratch").toAbsolutePath()
        Files.createDirectories(parent)
        val scratch = Files.createTempDirectory(parent, "keykeeper-oidc-")
        val idp = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        var bao: Node? = null
        try {
            bao = Node(binary, scratch.resolve("bao"), "oidc-${UUID.randomUUID()}")
            val keys = bao.initialize()
            val mount = "keykeeper-test-${UUID.randomUUID().toString().take(8)}"
            assertEquals(204, bao.call("POST", "/v1/sys/mounts/$mount", keys.token,
                "{\"type\":\"kv\",\"options\":{\"version\":\"2\"}}".toByteArray()).statusCode())
            val pair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
            fun b64(bytes: ByteArray) = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
            fun unsigned(n: java.math.BigInteger) = n.toByteArray().let { if (it[0] == 0.toByte()) it.drop(1).toByteArray() else it }
            val public = pair.public as RSAPublicKey
            val jwks = buildJsonObject { put("keys", JsonArray(listOf(buildJsonObject {
                put("kid", "disposable"); put("kty", "RSA"); put("alg", "RS256"); put("use", "sig")
                put("n", b64(unsigned(public.modulus))); put("e", b64(unsigned(public.publicExponent)))
            }))) }.toString()
            val issuer = "https://fake-idp.test/realms/disposable"
            val owner = Principal(issuer, "browser-owner", PrincipalKind.HUMAN)
            val agent = Principal(issuer, "device-agent", PrincipalKind.AGENT)
            val revoked = mutableSetOf<String>()
            fun signed(subject: Principal, client: String): String {
                val header = "{\"alg\":\"RS256\",\"kid\":\"disposable\",\"typ\":\"JWT\"}"
                val now = System.currentTimeMillis() / 1000
                val claims = buildJsonObject {
                    put("iss", issuer); put("aud", "vault-api"); put("sub", subject.subject); put("azp", client)
                    put("keykeeper_principal_type", subject.kind.name); put("jti", "fake-${UUID.randomUUID()}")
                    put("nbf", now - 5); put("iat", now - 5); put("exp", now + 300)
                }
                val data = b64(header.toByteArray()) + "." + b64(claims.toString().toByteArray())
                return data + "." + b64(Signature.getInstance("SHA256withRSA").apply {
                    initSign(pair.private); update(data.toByteArray())
                }.sign())
            }
            val browserToken = signed(owner, "browser")
            val agentToken = signed(agent, "device")
            val challenges = mutableMapOf<String, String>()
            idp.createContext("/protocol/openid-connect/token") { exchange ->
                val body = exchange.requestBody.readAllBytes().toString(Charsets.UTF_8)
                val params = body.split('&').associate { part ->
                    val fields = part.split('=', limit = 2)
                    fields[0] to URLDecoder.decode(fields[1], Charsets.UTF_8)
                }
                val challenge = b64(MessageDigest.getInstance("SHA-256").digest(params.getValue("code_verifier").toByteArray()))
                val valid = challenges.remove(params["code"]) == challenge && params["grant_type"] == "authorization_code"
                val payload = (if (valid) "{\"access_token\":\"$browserToken\",\"token_type\":\"Bearer\"}" else "{}").toByteArray()
                exchange.sendResponseHeaders(if (valid) 200 else 400, payload.size.toLong())
                exchange.responseBody.use { it.write(payload) }
            }
            idp.start()
            val verifier = OidcIdentityVerifier(issuer, "vault-api", mapOf("browser" to PrincipalKind.HUMAN, "device" to PrincipalKind.AGENT),
                JwksSource { jwks }, RevocationChecker { jti, _, _ -> jti in revoked })
            val vault = Vault(OpenBaoStore(bao.base, mount, keys.token), verifier) { }
            val fakeIdp = URI("http://127.0.0.1:${idp.address.port}")
            val oauth = object : OAuthCodeClient {
                override fun authorization(state: String, challenge: String, redirect: URI): URI =
                    URI("$fakeIdp/protocol/openid-connect/auth?state=$state&code_challenge=$challenge&code_challenge_method=S256")
                override fun exchange(code: String, verifier: String, redirect: URI): String {
                    val form = "grant_type=authorization_code&code=$code&code_verifier=$verifier"
                    val response = HttpClient.newHttpClient().send(HttpRequest.newBuilder(fakeIdp.resolve("/protocol/openid-connect/token"))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(form)).build(), HttpResponse.BodyHandlers.ofString())
                    if (response.statusCode() != 200) throw Denied()
                    return Json.parseToJsonElement(response.body()).jsonObject.getValue("access_token").jsonPrimitive.content
                }
            }
            fun recipient(p: Principal) = buildJsonObject {
                put("issuer", p.issuer); put("subject", p.subject); put("kind", p.kind.name)
            }
            VaultWeb(vault, browser = BrowserOidc(oauth, vault)).use { web ->
                web.start()
                val http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()
                val base = "http://127.0.0.1:${web.port}"
                fun request(path: String, cookie: String? = null, method: String = "GET", body: String? = null,
                            csrf: String? = null, bearer: String? = null): HttpResponse<String> {
                    val builder = HttpRequest.newBuilder(URI(base + path))
                    if (cookie != null) builder.header("Cookie", cookie)
                    if (csrf != null) { builder.header("Origin", base); builder.header("X-Keykeeper-CSRF", csrf) }
                    if (bearer != null) builder.header("Authorization", "Bearer $bearer")
                    if (body != null) builder.header("Content-Type", "application/json")
                    return http.send(builder.method(method, if (body == null) HttpRequest.BodyPublishers.noBody()
                        else HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString())
                }
                val login = request("/auth/login")
                assertEquals(303, login.statusCode())
                val stateCookie = login.headers().allValues("Set-Cookie").single().substringBefore(';')
                val auth = URI(login.headers().firstValue("Location").orElseThrow())
                val params = auth.rawQuery.split('&').associate {
                    val fields = it.split('=', limit = 2)
                    fields[0] to URLDecoder.decode(fields[1], Charsets.UTF_8)
                }
                val code = UUID.randomUUID().toString()
                challenges[code] = params.getValue("code_challenge")
                val callback = request("/auth/callback?state=${params.getValue("state")}&code=$code", stateCookie)
                assertEquals(303, callback.statusCode())
                val cookie = callback.headers().allValues("Set-Cookie").first { it.startsWith("kk_session=") }.substringBefore(';')
                val csrf = Json.parseToJsonElement(request("/auth/session", cookie).body()).jsonObject.getValue("csrf").jsonPrimitive.content
                val fake = "fake-only-${UUID.randomUUID()}"
                val created = request("/api/items", cookie, "POST", buildJsonObject { put("value", fake) }.toString(), csrf)
                assertEquals(200, created.statusCode())
                val id = Json.parseToJsonElement(created.body()).jsonObject.getValue("id").jsonPrimitive.content
                assertEquals(fake, Json.parseToJsonElement(request("/api/items/$id", cookie).body()).jsonObject.getValue("value").jsonPrimitive.content)
                assertEquals(403, request("/api/items/$id", bearer = agentToken).statusCode())
                val share = buildJsonObject {
                    put("recipient", recipient(agent)); put("rights", JsonArray(listOf(JsonPrimitive("READ"))))
                }
                assertEquals(200, request("/api/items/$id/share", cookie, "POST", share.toString(), csrf).statusCode())
                assertEquals(fake, Json.parseToJsonElement(request("/api/items/$id", bearer = agentToken).body()).jsonObject.getValue("value").jsonPrimitive.content)
                assertEquals(403, request("/api/items/$id/revoke", cookie, "POST", buildJsonObject { put("recipient", recipient(agent)) }.toString()).statusCode())
                assertEquals(200, request("/api/items/$id/revoke", cookie, "POST", buildJsonObject { put("recipient", recipient(agent)) }.toString(), csrf).statusCode())
                assertEquals(403, request("/api/items/$id", bearer = agentToken).statusCode())
                assertEquals(200, request("/auth/logout", cookie, "POST", csrf = csrf).statusCode())
                assertEquals(403, request("/api/items/$id", cookie).statusCode())
            }
        } finally {
            idp.stop(0)
            bao?.close()
            Files.walk(scratch).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) } }
        }
    }
}
