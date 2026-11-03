package net.datamancy.keykeeper

import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import kotlinx.serialization.json.*
import kotlin.test.*

class CredentialLifecycleTest {
    private val owner = Principal("issuer", "owner", PrincipalKind.HUMAN)
    private val agent = Principal("issuer", "agent", PrincipalKind.AGENT)
    private class Store : CredentialStore {
        val records = mutableMapOf<String, StoredCredential>()
        var conflict = false
        override fun keys() = records.keys.toList()
        override fun get(id: String) = records[id]
        override fun put(item: StoredCredential, expectedVersion: Int) {
            if (conflict || (records[item.metadata.id]?.version ?: 0) != expectedVersion) throw Conflict()
            records[item.metadata.id] = item.copy(version = expectedVersion + 1)
        }
    }

    @Test fun `rotation atomically clears grants and retirement cannot be resurrected`() {
        val store = Store()
        val events = mutableListOf<AuditEvent>()
        val vault = Vault(store, LocalTestVerifier("synthetic-owner-token-123456789", owner), events::add)
        val item = vault.create(owner, "old-secret")
        assertFalse(item.toJson().containsKey("retired"))
        assertFalse(item.toJson().metadata().retired)
        assertEquals(1, vault.version(owner, item.id))
        assertFailsWith<Denied> { vault.version(agent, item.id) }
        assertFailsWith<IllegalArgumentException> { vault.edit(owner, item.id, "invalid", 0) }
        vault.edit(owner, item.id, "old-secret", 1)
        assertFailsWith<Conflict> { vault.edit(owner, item.id, "stale", 1) }
        vault.share(owner, item.id, Grant(agent, Right.entries.toSet()))
        assertFailsWith<Denied> { vault.rotate(agent, item.id, "unauthorized") }
        assertFailsWith<Denied> { vault.retire(agent, item.id) }
        assertFailsWith<IllegalArgumentException> { vault.rotate(owner, item.id, "") }
        assertTrue(vault.rotate(owner, item.id, "new-secret").grants.isEmpty())
        assertEquals("new-secret", vault.read(owner, item.id))
        assertFailsWith<Denied> { vault.read(agent, item.id) }
        val retired = vault.retire(owner, item.id)
        assertTrue(retired.retired)
        assertTrue(retired.toJson().metadata().retired)
        assertEquals("", store.records.getValue(item.id).value)
        assertTrue(vault.list(owner).isEmpty())
        assertFailsWith<Denied> { vault.read(owner, item.id) }
        assertFailsWith<Denied> { vault.version(owner, item.id) }
        assertFailsWith<Denied> { vault.edit(owner, item.id, "resurrect") }
        assertFailsWith<Denied> { vault.rotate(owner, item.id, "resurrect") }
        assertFailsWith<Denied> { vault.retire(owner, item.id) }
        assertFailsWith<Denied> { vault.share(owner, item.id, Grant(agent, setOf(Right.READ))) }
        assertFailsWith<Denied> { vault.revoke(owner, item.id, agent) }
        assertFalse(events.toString().contains("new-secret"))
        assertFalse(events.toString().contains("old-secret"))
    }

    @Test fun `rotation and retirement do not overwrite concurrent changes`() {
        val store = Store()
        val vault = Vault(store, LocalTestVerifier("synthetic-owner-token-123456789", owner), {})
        val item = vault.create(owner, "original")
        vault.share(owner, item.id, Grant(agent, setOf(Right.READ)))
        store.conflict = true
        assertFailsWith<Conflict> { vault.rotate(owner, item.id, "replacement") }
        assertFailsWith<Conflict> { vault.retire(owner, item.id) }
        assertEquals("original", vault.read(agent, item.id))
        assertFalse(store.records.getValue(item.id).metadata.retired)
    }

    @Test fun `registered rotate and retire endpoints enforce ownership and return tombstone metadata only`() {
        val store = Store()
        val ownerToken = "synthetic-owner-token-123456789"
        val agentToken = "synthetic-agent-token-123456789"
        val vault = Vault(store, LocalTestVerifier(mapOf(ownerToken to owner, agentToken to agent)), {})
        val item = vault.create(owner, "old")
        vault.share(owner, item.id, Grant(agent, Right.entries.toSet()))
        VaultWeb(vault).use { web ->
            web.start()
            val client = HttpClient.newHttpClient()
            fun call(action: String, token: String, body: String): HttpResponse<String> = client.send(
                HttpRequest.newBuilder(URI("${web.origin}/api/items/${item.id}/$action"))
                    .header("Authorization", "Bearer $token").header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString())
            assertEquals(403, call("rotate", agentToken, """{"value":"new"}""").statusCode())
            assertEquals(200, call("rotate", ownerToken, """{"value":"new"}""").statusCode())
            assertEquals(400, call("retire", ownerToken, """{"unexpected":true}""").statusCode())
            val response = call("retire", ownerToken, "{}")
            assertEquals(200, response.statusCode())
            assertTrue(Json.parseToJsonElement(response.body()).jsonObject.getValue("retired").jsonPrimitive.boolean)
            assertFalse(response.body().contains("value"))
            assertEquals(403, call("rotate", ownerToken, """{"value":"resurrect"}""").statusCode())
        }
    }
}
