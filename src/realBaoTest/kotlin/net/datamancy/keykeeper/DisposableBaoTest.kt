package net.datamancy.keykeeper

import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.util.UUID
import kotlin.test.*

/** Never part of `test`/`check`. Operator must provision an isolated disposable local KV-v2 mount. */
class DisposableBaoTest {
    @Test fun `real KV v2 CAS listing read share revoke and generated record cleanup`() {
        fun required(name: String) = System.getenv(name)?.takeIf { it.isNotBlank() } ?: error("Missing $name")
        require(required("KEYKEEPER_REAL_BAO_DISPOSABLE") == "YES")
        val base = URI(required("KEYKEEPER_REAL_BAO_URL"))
        val mount = required("KEYKEEPER_REAL_BAO_MOUNT")
        require(mount.startsWith("keykeeper-test-") && mount.matches(Regex("[a-zA-Z0-9_-]+")))
        val token = required("KEYKEEPER_REAL_BAO_TOKEN")
        // OpenBaoStore enforces loopback, including on the cleanup path below.
        val store = OpenBaoStore(base, mount, token)
        val id = UUID.randomUUID().toString()
        val owner = Principal("disposable-integration", "owner", PrincipalKind.HUMAN)
        val agent = Principal(owner.issuer, "agent", PrincipalKind.AGENT)
        val fakeValue = "fake-only-${UUID.randomUUID()}"
        var created = false
        try {
            val metadata = CredentialMetadata(id, owner)
            store.put(StoredCredential(metadata, fakeValue, 0), 0)
            created = true
            assertEquals(1, store.get(id)?.version)
            assertEquals(fakeValue, store.get(id)?.value)
            assertTrue(id in store.keys())
            assertFailsWith<Conflict> { store.put(StoredCredential(metadata, fakeValue, 0), 0) }
            val vault = Vault(store, LocalTestVerifier("disposable-test-token-0123456789", owner)) { }
            assertFailsWith<Denied> { vault.read(agent, id) }
            vault.share(owner, id, Grant(agent, setOf(Right.READ, Right.EDIT)))
            assertEquals(fakeValue, vault.read(agent, id))
            vault.edit(agent, id, "changed-fake-only")
            assertEquals("changed-fake-only", vault.read(owner, id))
            vault.revoke(owner, id, agent)
            assertFailsWith<Denied> { vault.read(agent, id) }
        } finally {
            if (created) {
                // Delete only the random ID created by this test, including all versions.
                val url = URI(base.toString().trimEnd('/') + "/v1/$mount/metadata/$id")
                val request = HttpRequest.newBuilder(url).header("X-Vault-Token", token).DELETE().build()
                val response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.discarding())
                check(response.statusCode() == 204 || response.statusCode() == 200) { "Disposable record cleanup failed" }
                assertNull(store.get(id))
            }
        }
    }
}
