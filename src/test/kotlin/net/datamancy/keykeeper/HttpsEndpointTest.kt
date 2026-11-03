package net.datamancy.keykeeper

import java.net.URI
import java.net.ServerSocket
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyStore
import java.security.cert.CertificateFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import kotlinx.serialization.json.*
import kotlin.test.*

/** Public, disposable test key. No native IdP/backend, production certificate or secrets. */
class HttpsEndpointTest {
    private val cert = Path.of("src/test/resources/tls-unit/certificate.pem")
    private val key = Path.of("src/test/resources/tls-unit/private-key.pem")
    private class Memory : CredentialStore {
        private val records = mutableMapOf<String, StoredCredential>()
        override fun keys() = records.keys.toList()
        override fun get(id: String) = records[id]
        override fun put(item: StoredCredential, expectedVersion: Int) {
            if ((records[item.metadata.id]?.version ?: 0) != expectedVersion) throw Conflict()
            records[item.metadata.id] = item.copy(version = expectedVersion + 1)
        }
    }
    private fun client(): HttpClient {
        val store = KeyStore.getInstance("PKCS12").apply {
            load(null, null)
            setCertificateEntry("unit", Files.newInputStream(cert).use { CertificateFactory.getInstance("X.509").generateCertificate(it) })
        }
        val trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(store) }
        return HttpClient.newBuilder().sslContext(SSLContext.getInstance("TLS").apply { init(null, trust.trustManagers, null) })
            .followRedirects(HttpClient.Redirect.NEVER).build()
    }
    @Test fun `explicit TLS provides host-bound secure cookies exact origin and no plaintext fallback`() {
        val port = ServerSocket(0).use { it.localPort }
        val base = "https://localhost:$port"
        val token = "unit-only-token-not-a-production-credential"
        val vault = Vault(Memory(), LocalTestVerifier(token, Principal("unit", "owner", PrincipalKind.HUMAN))) {}
        val oauth = object : OAuthCodeClient {
            override fun authorization(state: String, challenge: String, redirect: URI): URI {
                assertEquals("$base/auth/callback", redirect.toString())
                return URI("https://idp.invalid/?state=$state")
            }
            override fun exchange(code: String, verifier: String, redirect: URI): String {
                assertEquals("unit-code", code)
                return token
            }
        }
        VaultWeb(vault, port, BrowserOidc(oauth, vault), HttpsEndpoint.load(URI(base), cert, key)).use { web ->
            web.start()
            assertEquals(base, web.origin)
            val http = client()
            fun request(path: String, cookie: String? = null, origin: String? = null, csrf: String? = null, post: Boolean = false): HttpResponse<String> {
                val builder = HttpRequest.newBuilder(URI(base + path))
                if (cookie != null) builder.header("Cookie", cookie)
                if (origin != null) builder.header("Origin", origin)
                if (csrf != null) builder.header("X-Keykeeper-CSRF", csrf)
                if (post) builder.POST(HttpRequest.BodyPublishers.noBody())
                return http.send(builder.build(), HttpResponse.BodyHandlers.ofString())
            }
            assertEquals(200, request("/").statusCode())
            assertEquals(200, request("/vault.css").statusCode())
            assertTrue(request("/vault.css").headers().firstValue("Content-Type").orElseThrow().startsWith("text/css"))
            probeHttps(mapOf("KEYKEEPER_PUBLIC_ORIGIN" to base)::get, http)
            assertEquals(403, http.send(HttpRequest.newBuilder(URI("https://127.0.0.1:$port/")).build(), HttpResponse.BodyHandlers.discarding()).statusCode())
            assertFails { probeHttps(mapOf("KEYKEEPER_PUBLIC_ORIGIN" to "https://127.0.0.1:$port")::get, http) }
            assertFails { HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI(base)).build(), HttpResponse.BodyHandlers.discarding()) }
            assertFails { http.send(HttpRequest.newBuilder(URI("http://127.0.0.1:$port/")).timeout(java.time.Duration.ofSeconds(2)).build(), HttpResponse.BodyHandlers.discarding()) }
            val login = request("/auth/login")
            val cookie = login.headers().firstValue("Set-Cookie").orElseThrow()
            assertTrue(cookie.startsWith("__Host-kk_state=")); assertTrue(cookie.contains("; Secure")); assertTrue(cookie.contains("Path=/;"))
            val state = URI(login.headers().firstValue("Location").orElseThrow()).rawQuery.substringAfter("state=")
            val callback = request("/auth/callback?state=$state&code=unit-code", cookie.substringBefore(';'))
            assertEquals(303, callback.statusCode())
            val session = callback.headers().allValues("Set-Cookie").single { it.startsWith("__Host-kk_session=") }
            assertTrue(session.contains("; Secure")); assertTrue(session.contains("HttpOnly")); assertFalse(session.contains(token))
            val sessionCookie = session.substringBefore(';')
            val csrf = Json.parseToJsonElement(request("/auth/session", sessionCookie).body()).jsonObject.getValue("csrf").jsonPrimitive.content
            assertEquals(403, request("/auth/logout", sessionCookie, "http://localhost:$port", csrf, true).statusCode())
            val logout = request("/auth/logout", sessionCookie, base, csrf, true)
            assertEquals(200, logout.statusCode()); assertTrue(logout.headers().firstValue("Set-Cookie").orElseThrow().contains("; Secure"))
            assertEquals(403, request("/auth/session", sessionCookie).statusCode())
        }
    }
    @Test fun `malformed origins key material symlinks and mismatched ports fail closed`() {
        for (origin in listOf("http://localhost:8443", "https://localhost", "https://localhost:8443/", "https://u@localhost:8443", "https://localhost:8443?x", "https://localhost:8443#x", "https://LOCALHOST:8443")) {
            assertFailsWith<IllegalArgumentException> { HttpsEndpoint(URI(origin), SSLContext.getDefault()) }
        }
        val dir = Files.createTempDirectory("keykeeper-tls-unit")
        try {
            val bad = dir.resolve("bad"); Files.writeString(bad, "not a key")
            assertFails { HttpsEndpoint.load(URI("https://localhost:8443"), cert, bad) }
            assertFails { HttpsEndpoint.load(URI("https://localhost:8443"), bad, key) }
            Files.writeString(bad, "")
            assertFails { HttpsEndpoint.load(URI("https://localhost:8443"), cert, bad) }
            val link = dir.resolve("link"); Files.createSymbolicLink(link, key.toAbsolutePath())
            assertFails { HttpsEndpoint.load(URI("https://localhost:8443"), cert, link) }
            val otherKey = java.security.KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair().private.encoded
            Files.writeString(bad, "-----BEGIN PRIVATE KEY-----\n" + java.util.Base64.getEncoder().encodeToString(otherKey) + "\n-----END PRIVATE KEY-----\n")
            assertFails { HttpsEndpoint.load(URI("https://localhost:8443"), cert, bad) }
            val vault = Vault(Memory(), LocalTestVerifier("unit-only-token-at-least-24-bytes", Principal("unit", "owner", PrincipalKind.HUMAN))) {}
            assertFails { VaultWeb(vault, 1234, https = HttpsEndpoint.load(URI("https://localhost:8443"), cert, key)) }
            assertFails { probeHttps(mapOf("KEYKEEPER_PUBLIC_ORIGIN" to "http://localhost:8443")::get) }
            assertFails { serveLocalTest(mapOf("KEYKEEPER_PUBLIC_ORIGIN" to "https://localhost:8443")::get) {} }
        } finally { Files.walk(dir).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
}
