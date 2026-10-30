package net.datamancy.keykeeper

import java.net.URI
import java.io.ByteArrayInputStream
import java.nio.charset.StandardCharsets
import java.net.ServerSocket
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import kotlin.test.*

class KeycloakWiringTest {
    private val issuer = "https://id.example.test/realms/isolated"
    private val url = "$issuer/protocol/openid-connect/token/introspect"

    @Test fun `introspection response must be active and bound to signed subject and jti`() {
        assertTrue(introspectionActive("{\"active\":true,\"sub\":\"alice\",\"jti\":\"123\"}", "123", "alice"))
        assertTrue(introspectionActive("{\"active\":true,\"sub\":\"alice\"}", "123", "alice"))
        for (body in listOf("{}", "bad-json", "{\"active\":false,\"sub\":\"alice\"}",
            "{\"active\":true,\"sub\":\"eve\"}",
            "{\"active\":true,\"sub\":\"alice\",\"jti\":\"other\"}")) {
            assertFalse(introspectionActive(body, "123", "alice"))
        }
    }
    @Test fun `introspection URL cannot be caller-controlled or downgraded`() {
        PinnedKeycloakIntrospection(URI(issuer), URI(url), "confidential-test-client", "fake-secret")
        assertFailsWith<IllegalArgumentException> { PinnedKeycloakIntrospection(URI(issuer), URI("http://id.example.test/keys"), "client", "fake") }
        assertFailsWith<IllegalArgumentException> { PinnedKeycloakIntrospection(URI(issuer), URI("https://other.test/realms/isolated/protocol/openid-connect/token/introspect"), "client", "fake") }
        assertFailsWith<IllegalArgumentException> { PinnedKeycloakIntrospection(URI(issuer), URI(url), "bad:client", "fake") }
        assertFailsWith<IllegalArgumentException> { PinnedKeycloakIntrospection(URI(issuer), URI(url), "client", "") }
    }
    @Test fun `introspection sends original bearer to pinned URL and fails closed on inactive and oversized replies`() {
        var status = 200
        var body = "{\"active\":true,\"sub\":\"alice\",\"jti\":\"id1\"}"
        val checker = PinnedKeycloakIntrospection(URI(issuer), URI(url), "client", "fake-only", { request ->
            assertEquals(URI(url), request.uri())
            assertEquals("POST", request.method())
            assertEquals("Basic Y2xpZW50OmZha2Utb25seQ==", request.headers().firstValue("Authorization").orElse(""))
            val publisher = request.bodyPublisher().orElseThrow()
            val chunks = mutableListOf<ByteArray>()
            publisher.subscribe(object : java.util.concurrent.Flow.Subscriber<java.nio.ByteBuffer> {
                override fun onSubscribe(s: java.util.concurrent.Flow.Subscription) { s.request(Long.MAX_VALUE) }
                override fun onNext(b: java.nio.ByteBuffer) { val bytes = ByteArray(b.remaining()); b.get(bytes); chunks += bytes }
                override fun onError(t: Throwable) { throw AssertionError(t) }
                override fun onComplete() = Unit
            })
            assertTrue(chunks.flatMap { it.asIterable() }.toByteArray().toString(StandardCharsets.UTF_8).contains("token=fake.bearer"))
            status to ByteArrayInputStream(body.toByteArray())
        })
        assertFalse(checker.isRevoked("id1", "fake.bearer", "alice"))
        body = "{\"active\":false}"
        assertTrue(checker.isRevoked("id1", "fake.bearer", "alice"))
        status = 503
        assertTrue(checker.isRevoked("id1", "fake.bearer", "alice"))
        status = 200
        body = "x".repeat(65_537)
        assertTrue(checker.isRevoked("id1", "fake.bearer", "alice"))
    }
    @Test fun `OIDC server configuration never accepts fake test token even when present`() {
        val port = ServerSocket(0).use { it.localPort }
        val config = mapOf("KEYKEEPER_OIDC_ISSUER" to issuer, "KEYKEEPER_OIDC_AUDIENCE" to "vault-api",
            "KEYKEEPER_OIDC_HUMAN_CLIENT" to "browser", "KEYKEEPER_OIDC_AGENT_CLIENT" to "service",
            "KEYKEEPER_OIDC_INTROSPECTION_CLIENT" to "introspect", "KEYKEEPER_OIDC_INTROSPECTION_SECRET" to "fake-only",
            "KEYKEEPER_BAO_URL" to "http://127.0.0.1:1", "KEYKEEPER_BAO_MOUNT" to "fake-test",
            "KEYKEEPER_BAO_TOKEN" to "fake-only", "KEYKEEPER_PORT" to "$port",
            "KEYKEEPER_TEST_TOKEN" to "012345678901234567890123")
        serveOidc(config::get) {}.use { web ->
            val req = HttpRequest.newBuilder(URI("http://127.0.0.1:${web.port}/api/items"))
                .header("Authorization", "Bearer ${config.getValue("KEYKEEPER_TEST_TOKEN")}").build()
            assertEquals(403, HttpClient.newHttpClient().send(req, HttpResponse.BodyHandlers.ofString()).statusCode())
        }
        assertFailsWith<IllegalArgumentException> {
            serveOidc((config + ("KEYKEEPER_OIDC_AGENT_CLIENT" to "browser"))::get) {}
        }
        assertFailsWith<IllegalStateException> {
            serveOidc((config - "KEYKEEPER_OIDC_INTROSPECTION_SECRET")::get) {}
        }
    }
}
