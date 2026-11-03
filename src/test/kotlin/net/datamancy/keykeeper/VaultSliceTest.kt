package net.datamancy.keykeeper

import com.sun.net.httpserver.HttpServer
import kotlinx.serialization.json.*
import java.net.InetSocketAddress
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.util.UUID
import kotlin.test.*

class VaultSliceTest {
    private val owner = Principal("test-issuer", "owner", PrincipalKind.HUMAN)
    private val agent = Principal("test-issuer", "agent", PrincipalKind.AGENT)
    private val human = Principal("test-issuer", "human", PrincipalKind.HUMAN)
    private val secret = "fake-secret-sentinel-123"

    private class MemoryStore : CredentialStore {
        val records = mutableMapOf<String, StoredCredential>()
        override fun keys() = records.keys.toList()
        override fun get(id: String) = records[id]
        override fun put(item: StoredCredential, expectedVersion: Int) {
            if ((records[item.metadata.id]?.version ?: 0) != expectedVersion) throw Conflict()
            records[item.metadata.id] = item.copy(version = expectedVersion + 1)
        }
    }

    @Test fun `human and agent use same grant edit share revoke with immediate access checks and safe audit`() {
        val store = MemoryStore()
        val events = mutableListOf<AuditEvent>()
        val vault = Vault(store, LocalTestVerifier("012345678901234567890123", owner), events::add)
        val item = vault.create(owner, secret)
        assertEquals(emptyList(), vault.list(agent))
        assertFailsWith<Denied> { vault.read(agent, item.id) }
        vault.share(owner, item.id, Grant(agent, setOf(Right.READ, Right.EDIT, Right.SHARE)))
        assertEquals(secret, vault.read(agent, item.id))
        vault.edit(agent, item.id, "changed")
        vault.share(agent, item.id, Grant(human, setOf(Right.READ)))
        assertEquals("changed", vault.read(human, item.id))
        assertFailsWith<Denied> { vault.edit(human, item.id, "not allowed") }
        assertFailsWith<Denied> { vault.share(human, item.id, Grant(owner, setOf(Right.READ))) }
        vault.revoke(agent, item.id, human)
        assertFailsWith<Denied> { vault.read(human, item.id) }
        vault.revoke(owner, item.id, agent)
        assertFailsWith<Denied> { vault.read(agent, item.id) }
        assertEquals(emptyList(), vault.list(agent))
        assertFailsWith<Denied> { vault.authenticate(secret) }
        assertTrue(events.any { it.action == "read" && it.outcome == "failed" })
        assertTrue(events.any { it.action == "authenticate" && it.outcome == "failed" })
        assertFalse(events.toString().contains(secret))
        assertFalse(events.toString().contains(owner.subject))
        assertTrue(events.all { it.actorHash == "-" || it.actorHash.matches(Regex("[0-9a-f]{64}")) })
    }

    @Test fun `web routes require verified bearer and never expose value in list or errors`() {
        val store = MemoryStore()
        val events = mutableListOf<AuditEvent>()
        val agentToken = "agent-token-01234567890123456789"
        val humanToken = "human-token-01234567890123456789"
        VaultWeb(Vault(store, LocalTestVerifier(mapOf("012345678901234567890123" to owner, agentToken to agent, humanToken to human)), events::add)).use { web ->
            web.start()
            val client = HttpClient.newHttpClient()
            fun call(method: String, path: String, token: String?, payload: String? = null): HttpResponse<String> {
                val req = HttpRequest.newBuilder(URI("http://127.0.0.1:${web.port}$path"))
                if (token != null) req.header("Authorization", "Bearer $token")
                if (payload != null) req.header("Content-Type", "application/json")
                return client.send(req.method(method, if (payload == null) HttpRequest.BodyPublishers.noBody()
                    else HttpRequest.BodyPublishers.ofString(payload)).build(), HttpResponse.BodyHandlers.ofString())
            }
            val token = "012345678901234567890123"
            assertEquals(403, call("GET", "/api/items", null).statusCode())
            assertEquals(403, call("GET", "/api/items", "wrong").statusCode())
            assertEquals(200, call("GET", "/", null).statusCode())
            val created = call("POST", "/api/items", token, buildJsonObject { put("value", secret) }.toString())
            assertEquals(200, created.statusCode())
            val id = Json.parseToJsonElement(created.body()).jsonObject.getValue("id").jsonPrimitive.content
            assertEquals("[]", call("GET", "/api/items", agentToken).body())
            assertEquals(403, call("GET", "/api/items/$id", agentToken).statusCode())
            val shareBody = buildJsonObject {
                put("recipient", agent.toJson()); put("rights", JsonArray(listOf(JsonPrimitive("READ"), JsonPrimitive("EDIT"), JsonPrimitive("SHARE"))))
            }.toString()
            assertEquals(200, call("POST", "/api/items/$id/share", token, shareBody).statusCode())
            assertEquals(secret, Json.parseToJsonElement(call("GET", "/api/items/$id", agentToken).body()).jsonObject.getValue("value").jsonPrimitive.content)
            val delegated = buildJsonObject {
                put("recipient", human.toJson()); put("rights", JsonArray(listOf(JsonPrimitive("READ"))))
            }.toString()
            assertEquals(200, call("POST", "/api/items/$id/share", agentToken, delegated).statusCode())
            assertEquals(secret, Json.parseToJsonElement(call("GET", "/api/items/$id", humanToken).body()).jsonObject.getValue("value").jsonPrimitive.content)
            assertEquals(403, call("PUT", "/api/items/$id", humanToken, "{\"value\":\"denied\"}").statusCode())
            assertEquals(200, call("POST", "/api/items/$id/revoke", agentToken,
                buildJsonObject { put("recipient", human.toJson()) }.toString()).statusCode())
            assertEquals(403, call("GET", "/api/items/$id", humanToken).statusCode())
            assertEquals(200, call("PUT", "/api/items/$id", agentToken, "{\"value\":\"agent-edited\"}").statusCode())
            val revokeBody = buildJsonObject { put("recipient", agent.toJson()) }.toString()
            assertEquals(200, call("POST", "/api/items/$id/revoke", token, revokeBody).statusCode())
            assertEquals(403, call("GET", "/api/items/$id", agentToken).statusCode())
            val list = call("GET", "/api/items", token)
            assertEquals(200, list.statusCode())
            assertFalse(list.body().contains(secret))
            assertEquals("agent-edited", Json.parseToJsonElement(call("GET", "/api/items/$id", token).body()).jsonObject.getValue("value").jsonPrimitive.content)
            assertEquals(200, call("PUT", "/api/items/$id", token, "{\"value\":\"updated\"}").statusCode())
            assertEquals("updated", Json.parseToJsonElement(call("GET", "/api/items/$id", token).body()).jsonObject.getValue("value").jsonPrimitive.content)
            val malformed = call("GET", "/api/items/$secret", token)
            assertEquals(404, malformed.statusCode())
            assertFalse(events.toString().contains(secret))
            assertFalse(malformed.body().contains(secret))
            assertEquals("no-store", list.headers().firstValue("Cache-Control").orElse(""))
        }
    }

    @Test fun `HTTP rejects malformed inputs and masks storage failures without exposing fake values`() {
        val store = object : CredentialStore {
            override fun keys(): List<String> = error("fake upstream $secret")
            override fun get(id: String): StoredCredential? = null
            override fun put(item: StoredCredential, expectedVersion: Int): Unit = throw Conflict()
        }
        VaultWeb(Vault(store, LocalTestVerifier("012345678901234567890123", owner)) {}).use { web ->
            web.start()
            val client = HttpClient.newHttpClient()
            fun call(method: String, path: String, value: String? = null): HttpResponse<String> {
                val builder = HttpRequest.newBuilder(URI("http://127.0.0.1:${web.port}$path"))
                    .header("Authorization", "Bearer 012345678901234567890123")
                if (value != null) builder.header("Content-Type", "application/json")
                return client.send(builder.method(method, if (value == null) HttpRequest.BodyPublishers.noBody()
                    else HttpRequest.BodyPublishers.ofString(value)).build(), HttpResponse.BodyHandlers.ofString())
            }
            assertEquals(404, call("GET", "/api/unknown").statusCode())
            assertEquals(400, call("GET", "/api/items?token=not-allowed").statusCode())
            assertEquals(400, call("POST", "/api/items", "{}").statusCode())
            assertEquals(400, call("POST", "/api/items", "{invalid").statusCode())
            assertEquals(409, call("POST", "/api/items", "{\"value\":\"$secret\"}").statusCode())
            val failed = call("GET", "/api/items")
            assertEquals(503, failed.statusCode())
            assertFalse(failed.body().contains(secret))
        }
    }

    @Test fun `OpenBao KV v2 wire format uses CAS and opaque record with sanitized upstream errors`() {
        val id = UUID.randomUUID().toString()
        var tokenSeen = false
        var casSeen = false
        var stored = false
        val mock = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        mock.createContext("/v1/test/") { x ->
            val path = x.requestURI.path
            tokenSeen = x.requestHeaders.getFirst("X-Vault-Token") == "fake-bao-token"
            val body = x.requestBody.readAllBytes().toString(Charsets.UTF_8)
            val output: String
            val code: Int
            when {
                x.requestMethod == "LIST" && path == "/v1/test/metadata/" -> {
                    code = 200; output = "{\"data\":{\"keys\":[\"$id\"]}}"
                }
                x.requestMethod == "POST" && path == "/v1/test/data/$id" -> {
                    val obj = Json.parseToJsonElement(body).jsonObject
                    casSeen = obj.getValue("options").jsonObject.getValue("cas").jsonPrimitive.int == 0 &&
                        obj.getValue("data").jsonObject.getValue("record").jsonObject.getValue("value").jsonPrimitive.content == secret
                    if (stored) { code = 400; output = "upstream echoed $secret fake-bao-token" }
                    else { stored = true; code = 200; output = "{}" }
                }
                x.requestMethod == "GET" && path == "/v1/test/data/$id" -> {
                    code = 200
                    output = buildJsonObject { put("data", buildJsonObject {
                        put("metadata", buildJsonObject { put("version", 1) })
                        put("data", buildJsonObject { put("record", buildJsonObject {
                            put("metadata", CredentialMetadata(id, owner).toJson()); put("value", secret)
                        }) })
                    }) }.toString()
                }
                else -> { code = 404; output = "{}" }
            }
            val bytes = output.toByteArray()
            x.sendResponseHeaders(code, bytes.size.toLong())
            x.responseBody.use { it.write(bytes) }
        }
        mock.start()
        try {
            val adapter = OpenBaoStore(URI("http://127.0.0.1:${mock.address.port}"), "test", "fake-bao-token")
            assertEquals(listOf(id), adapter.keys())
            assertEquals(null, adapter.get(UUID.randomUUID().toString()))
            val item = StoredCredential(CredentialMetadata(id, owner), secret, 0)
            adapter.put(item, 0)
            assertTrue(tokenSeen && casSeen)
            assertEquals(secret, adapter.get(id)?.value)
            assertEquals(1, adapter.get(id)?.version)
            val error = assertFailsWith<Conflict> { adapter.put(item, 0) }
            assertFalse(error.toString().contains(secret))
            assertFailsWith<IllegalArgumentException> { OpenBaoStore(URI("http://example.com"), "test", "token") }
            assertFailsWith<IllegalArgumentException> { OpenBaoStore(URI("https://bao:8200"), "test", "token") }
            OpenBaoStore(URI("https://bao:8200"), "test", "token", allowRemoteHttps = true)
            for (url in listOf("http://bao:8200", "https://user:pass@bao", "https://bao/path", "https://bao?query", "https://bao#fragment", "https:/missing")) {
                assertFailsWith<IllegalArgumentException> { OpenBaoStore(URI(url), "test", "token", allowRemoteHttps = true) }
            }
        } finally { mock.stop(0) }
    }
}
