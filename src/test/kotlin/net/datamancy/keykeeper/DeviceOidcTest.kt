package net.datamancy.keykeeper

import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.io.StringReader
import kotlin.test.*

class DeviceOidcTest {
    @Test fun `disabled device grant fails closed without accepting or printing tokens`() {
        val idp = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        idp.createContext("/protocol/openid-connect/auth/device") { exchange ->
            exchange.requestBody.close()
            val bytes = "{\"error\":\"unauthorized_client\"}".toByteArray()
            exchange.sendResponseHeaders(400, bytes.size.toLong())
            exchange.responseBody.use { it.write(bytes) }
        }
        idp.start()
        try {
            val prompts = mutableListOf<String>()
            assertFailsWith<Denied> { DeviceOidc(URI("http://127.0.0.1:${idp.address.port}"), "agent", true).login(prompts::add) }
            assertTrue(prompts.isEmpty())
        } finally { idp.stop(0) }
    }
    @Test fun `device flow uses disposable fake IdP, returns token in memory and CLI needs no token argument or environment`() {
        val fakeToken = "signed-fake-agent-token-012345678901234"
        var polls = 0
        val idp = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        idp.createContext("/protocol/openid-connect/") { exchange ->
            val form = exchange.requestBody.readAllBytes().toString(Charsets.UTF_8)
            val text = when (exchange.requestURI.path.substringAfterLast('/')) {
                "device" -> "{\"device_code\":\"fake-device\",\"user_code\":\"ONLY-FAKE\",\"verification_uri\":\"http://127.0.0.1:${idp.address.port}/activate\",\"expires_in\":10,\"interval\":1}"
                "token" -> {
                    assertTrue(form.contains("device_code=fake-device"))
                    polls++
                    if (polls == 1) "{\"error\":\"authorization_pending\"}" else "{\"access_token\":\"$fakeToken\",\"token_type\":\"Bearer\"}"
                }
                else -> "{}"
            }
            val bytes = text.toByteArray()
            exchange.sendResponseHeaders(if (polls == 1 && exchange.requestURI.path.endsWith("/token")) 400 else 200, bytes.size.toLong())
            exchange.responseBody.use { it.write(bytes) }
        }
        idp.start()
        try {
            val fakeBase = URI("http://127.0.0.1:${idp.address.port}")
            assertFailsWith<IllegalArgumentException> { DeviceOidc(fakeBase, "agent") }
            val prompts = mutableListOf<String>()
            val token = DeviceOidc(fakeBase, "agent", true).login(prompts::add)
            assertEquals(fakeToken, token)
            assertEquals(2, polls)
            assertTrue(prompts.single().contains("ONLY-FAKE"))
            assertFalse(prompts.single().contains(fakeToken))
            val store = object : CredentialStore {
                override fun keys() = emptyList<String>()
                override fun get(id: String): StoredCredential? = null
                override fun put(item: StoredCredential, expectedVersion: Int) = Unit
            }
            VaultWeb(Vault(store, LocalTestVerifier(fakeToken, Principal("fake-issuer", "agent", PrincipalKind.AGENT))) {}).use { web ->
                web.start()
                val outputs = mutableListOf<String>()
                cli(listOf("list"), { key -> if (key == "KEYKEEPER_URL") "http://127.0.0.1:${web.port}" else null },
                    StringReader(""), outputs::add, tokenVariable = "KEYKEEPER_ACCESS_TOKEN", tokenProvider = { token })
                assertEquals(listOf("[]"), outputs)
            }
        } finally { idp.stop(0) }
    }
}
