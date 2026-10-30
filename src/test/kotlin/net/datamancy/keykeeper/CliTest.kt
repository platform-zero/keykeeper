package net.datamancy.keykeeper

import kotlinx.serialization.json.*
import java.io.StringReader
import kotlin.test.*

class CliTest {
    private val owner = Principal("fake-issuer", "person", PrincipalKind.HUMAN)
    private val bot = Principal("fake-issuer", "bot", PrincipalKind.AGENT)
    private val personToken = "test-person-token-0123456789012345"
    private val botToken = "test-agent-token-01234567890123456"

    private class Store : CredentialStore {
        val values = mutableMapOf<String, StoredCredential>()
        override fun keys() = values.keys.toList()
        override fun get(id: String) = values[id]
        override fun put(item: StoredCredential, expectedVersion: Int) {
            if ((values[item.metadata.id]?.version ?: 0) != expectedVersion) throw Conflict()
            values[item.metadata.id] = item.copy(version = expectedVersion + 1)
        }
    }

    @Test fun `CLI passes fake values by stdin and supports both kinds over real loopback HTTP`() {
        VaultWeb(Vault(Store(), LocalTestVerifier(mapOf(personToken to owner, botToken to bot))) {}).use { web ->
            web.start()
            fun command(token: String, vararg args: String, stdin: String = ""): String {
                val output = mutableListOf<String>()
                val variables = mapOf("KEYKEEPER_URL" to "http://127.0.0.1:${web.port}", "KEYKEEPER_TEST_TOKEN" to token)
                cli(args.toList(), variables::get, StringReader(stdin), output::add)
                assertEquals(1, output.size)
                return output.single()
            }
            val created = command(personToken, "create", stdin = "fake-cli-value")
            val id = Json.parseToJsonElement(created).jsonObject.getValue("id").jsonPrimitive.content
            assertEquals("fake-cli-value", command(personToken, "read", id))
            assertFalse(command(personToken, "list").contains("fake-cli-value"))
            assertEquals("[]", command(botToken, "list"))
            assertFailsWith<IllegalArgumentException> { command(botToken, "read", id) }
            command(personToken, "share", id, "fake-issuer", "bot", "AGENT", "READ,EDIT,SHARE")
            assertEquals("fake-cli-value", command(botToken, "read", id))
            command(botToken, "edit", id, stdin = "changed-cli-value")
            assertEquals("changed-cli-value", command(personToken, "read", id))
            command(personToken, "revoke", id, "fake-issuer", "bot", "AGENT")
            assertFailsWith<IllegalArgumentException> { command(botToken, "read", id) }
            assertFailsWith<IllegalArgumentException> { command(personToken, "read", "../../bad") }
            assertFailsWith<IllegalArgumentException> { command(personToken, "share", id, "fake-issuer", "bot", "AGENT", "BAD") }
            assertFailsWith<IllegalStateException> { command(personToken, "unknown") }
            assertFailsWith<IllegalArgumentException> { command(personToken, "create", "extra") }
            assertFailsWith<IllegalArgumentException> { cli(listOf("list"), { if (it == "KEYKEEPER_URL") "http://example.com" else personToken }) }
            assertFailsWith<IllegalStateException> { cli(listOf("list"), { if (it == "KEYKEEPER_TEST_TOKEN") personToken else null }, tokenVariable = "KEYKEEPER_ACCESS_TOKEN") }
            assertEquals("[]", command(botToken, "list"))
            assertFailsWith<IllegalStateException> { cli(listOf("list"), { null }) }
        }
    }
}
