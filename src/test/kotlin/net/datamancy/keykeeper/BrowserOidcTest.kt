package net.datamancy.keykeeper

import com.sun.net.httpserver.HttpServer
import kotlinx.serialization.json.*
import java.net.InetSocketAddress
import java.net.URI
import java.net.URLDecoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.RSAPublicKey
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.Base64
import java.util.UUID
import kotlin.test.*

class BrowserOidcTest {
    private val issuer = "https://fake-issuer.test/realms/disposable"
    private val now = 1_900_000_000L
    private val clock = Clock.fixed(Instant.ofEpochSecond(now), ZoneOffset.UTC)
    private val pair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
    private fun b64(bytes: ByteArray) = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    private fun b64(text: String) = b64(text.toByteArray())
    private fun signed(): String {
        val header = "{\"alg\":\"RS256\",\"kid\":\"fake\",\"typ\":\"JWT\"}"
        val claims = buildJsonObject {
            put("iss", issuer); put("aud", "vault-api"); put("sub", "human-1"); put("azp", "browser")
            put("keykeeper_principal_type", "HUMAN"); put("jti", "fake-jti"); put("nbf", now - 10)
            put("iat", now - 10); put("exp", now + 300)
        }
        val input = b64(header) + "." + b64(claims.toString())
        return input + "." + b64(Signature.getInstance("SHA256withRSA").apply { initSign(pair.private); update(input.toByteArray()) }.sign())
    }
    private fun jwks(): String {
        val key = pair.public as RSAPublicKey
        fun unsigned(n: java.math.BigInteger) = n.toByteArray().let { if (it[0] == 0.toByte()) it.drop(1).toByteArray() else it }
        return buildJsonObject { put("keys", JsonArray(listOf(buildJsonObject {
            put("kty", "RSA"); put("kid", "fake"); put("alg", "RS256"); put("use", "sig")
            put("n", b64(unsigned(key.modulus))); put("e", b64(unsigned(key.publicExponent)))
        }))) }.toString()
    }
    private class Memory : CredentialStore {
        val items = mutableMapOf<String, StoredCredential>()
        override fun keys() = items.keys.toList()
        override fun get(id: String) = items[id]
        override fun put(item: StoredCredential, expectedVersion: Int) {
            if ((items[item.metadata.id]?.version ?: 0) != expectedVersion) throw Conflict()
            items[item.metadata.id] = item.copy(version = expectedVersion + 1)
        }
    }
    private fun query(uri: URI): Map<String, String> = uri.rawQuery.split('&').associate {
        val parts = it.split('=', limit = 2)
        URLDecoder.decode(parts[0], Charsets.UTF_8) to URLDecoder.decode(parts[1], Charsets.UTF_8)
    }

    @Test fun `fake IdP issues locally signed JWT after S256 exchange, browser session needs CSRF and logout`() {
        val jwt = signed()
        val expected = mutableMapOf<String, String>()
        var exchanges = 0
        val idp = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        idp.createContext("/protocol/openid-connect/token") { exchange ->
            exchanges++
            val params = exchange.requestBody.readAllBytes().toString(Charsets.UTF_8).split('&').associate {
                val p = it.split('=', limit = 2); p[0] to URLDecoder.decode(p[1], Charsets.UTF_8)
            }
            val challenge = b64(MessageDigest.getInstance("SHA-256").digest(params.getValue("code_verifier").toByteArray()))
            val valid = expected.remove(params["code"]) == challenge && params["grant_type"] == "authorization_code"
            val body = if (valid) "{\"access_token\":\"$jwt\",\"token_type\":\"Bearer\"}" else "{}"
            val bytes = body.toByteArray()
            exchange.sendResponseHeaders(if (valid) 200 else 400, bytes.size.toLong())
            exchange.responseBody.use { it.write(bytes) }
        }
        idp.start()
        try {
            val fakeBase = URI("http://127.0.0.1:${idp.address.port}")
            assertFailsWith<IllegalArgumentException> { PinnedKeycloakCodeClient(fakeBase, "browser") }
            val oauth = PinnedKeycloakCodeClient(fakeBase, "browser", true)
            val verifier = OidcIdentityVerifier(issuer, "vault-api", mapOf("browser" to PrincipalKind.HUMAN),
                JwksSource { jwks() }, RevocationChecker { _, _, _ -> false }, clock)
            val vault = Vault(Memory(), verifier) { }
            val browser = BrowserOidc(oauth, vault, clock)
            VaultWeb(vault, browser = browser).use { web ->
                web.start()
                val client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()
                val base = "http://127.0.0.1:${web.port}"
                fun request(path: String, cookie: String? = null, method: String = "GET", body: String? = null,
                            csrf: String? = null, origin: String? = null): HttpResponse<String> {
                    val builder = HttpRequest.newBuilder(URI(base + path))
                    if (cookie != null) builder.header("Cookie", cookie)
                    if (csrf != null) builder.header("X-Keykeeper-CSRF", csrf)
                    if (origin != null) builder.header("Origin", origin)
                    if (body != null) builder.header("Content-Type", "application/json")
                    return client.send(builder.method(method, if (body == null) HttpRequest.BodyPublishers.noBody()
                        else HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString())
                }
                val login = request("/auth/login")
                assertEquals(303, login.statusCode())
                val stateCookie = login.headers().allValues("Set-Cookie").single().substringBefore(';')
                val authorize = URI(login.headers().firstValue("Location").orElseThrow())
                val params = query(authorize)
                assertEquals("S256", params["code_challenge_method"])
                assertEquals("code", params["response_type"])
                assertEquals("$base/auth/callback", params["redirect_uri"])
                val code = UUID.randomUUID().toString()
                expected[code] = params.getValue("code_challenge")
                val callback = "/auth/callback?state=${params.getValue("state")}&iss=${java.net.URLEncoder.encode(fakeBase.toString(), Charsets.UTF_8)}&code=$code"
                assertEquals(403, request(callback, "kk_state=wrong").statusCode())
                // Failed state consumes the one-time attempt: start again.
                val second = request("/auth/login")
                val secondCookie = second.headers().allValues("Set-Cookie").single().substringBefore(';')
                val secondState = query(URI(second.headers().firstValue("Location").orElseThrow()))
                expected[code] = secondState.getValue("code_challenge")
                val validCallback = "/auth/callback?state=${secondState.getValue("state")}&iss=${java.net.URLEncoder.encode(fakeBase.toString(), Charsets.UTF_8)}&code=$code"
                val success = request(validCallback, secondCookie)
                assertEquals(303, success.statusCode())
                val sessionCookie = success.headers().allValues("Set-Cookie").first { it.startsWith("kk_session=") }.substringBefore(';')
                assertFalse(sessionCookie.contains(jwt))
                assertEquals(403, request(validCallback, secondCookie).statusCode())
                assertEquals(1, exchanges)
                val session = request("/auth/session", sessionCookie)
                assertEquals(200, session.statusCode())
                val csrf = Json.parseToJsonElement(session.body()).jsonObject.getValue("csrf").jsonPrimitive.content
                assertEquals(403, request("/api/items", sessionCookie, "POST", "{\"value\":\"fake-only\"}").statusCode())
                assertEquals(403, request("/api/items", sessionCookie, "POST", "{\"value\":\"fake-only\"}", csrf, "http://attacker.test").statusCode())
                val created = request("/api/items", sessionCookie, "POST", "{\"value\":\"fake-only\"}", csrf, base)
                assertEquals(200, created.statusCode())
                val id = Json.parseToJsonElement(created.body()).jsonObject.getValue("id").jsonPrimitive.content
                assertEquals("fake-only", Json.parseToJsonElement(request("/api/items/$id", sessionCookie).body()).jsonObject.getValue("value").jsonPrimitive.content)
                assertEquals(403, request("/auth/logout", sessionCookie, "POST", csrf = "bad", origin = base).statusCode())
                assertEquals(200, request("/auth/logout", sessionCookie, "POST", csrf = csrf, origin = base).statusCode())
                assertEquals(403, request("/api/items/$id", sessionCookie).statusCode())
                assertEquals(403, request("/auth/session", sessionCookie).statusCode())
            }
        } finally { idp.stop(0) }
    }

    @Test fun `pinned callback issuer mismatch fails closed and consumes state`() {
        val oauth = object : OAuthCodeClient {
            override val expectedIssuer = issuer
            override fun authorization(state: String, challenge: String, redirect: URI) = URI("https://fake-issuer.test/?state=$state")
            override fun exchange(code: String, verifier: String, redirect: URI): String = error("must not exchange wrong issuer")
        }
        val vault = Vault(Memory(), LocalTestVerifier("disposable-test-token-0123456789", Principal(issuer, "human", PrincipalKind.HUMAN))) { }
        val browser = BrowserOidc(oauth, vault, clock)
        val redirect = URI("http://127.0.0.1:8765/auth/callback")
        val (url, cookie) = browser.begin(redirect)
        val state = query(url).getValue("state")
        assertFailsWith<Denied> { browser.finish(state, cookie, "code", redirect, "https://other.test") }
        assertFailsWith<Denied> { browser.finish(state, cookie, "code", redirect, issuer) }
    }
    @Test fun `pending state and session expire and cannot be replayed`() {
        val oauth = object : OAuthCodeClient {
            override fun authorization(state: String, challenge: String, redirect: URI) = URI("https://fake-issuer.test/?state=$state")
            override fun exchange(code: String, verifier: String, redirect: URI) = signed()
        }
        val verifier = OidcIdentityVerifier(issuer, "vault-api", mapOf("browser" to PrincipalKind.HUMAN),
            JwksSource { jwks() }, RevocationChecker { _, _, _ -> false }, clock)
        class MovingClock(var seconds: Long) : Clock() {
            override fun getZone() = ZoneOffset.UTC
            override fun withZone(zone: java.time.ZoneId): Clock = this
            override fun instant() = Instant.ofEpochSecond(seconds)
        }
        val moving = MovingClock(now)
        val browser = BrowserOidc(oauth, Vault(Memory(), verifier) {}, moving)
        val redirect = URI("http://127.0.0.1:8765/auth/callback")
        val (url, cookie) = browser.begin(redirect)
        val state = query(url).getValue("state")
        val session = browser.finish(state, cookie, "code", redirect)
        assertNotNull(browser.session(session))
        assertFailsWith<Denied> { browser.finish(state, cookie, "code", redirect) }
        val (laterUrl, laterCookie) = browser.begin(redirect)
        moving.seconds += 901
        assertNull(browser.session(session))
        assertFailsWith<Denied> { browser.finish(query(laterUrl).getValue("state"), laterCookie, "code", redirect) }
        browser.logout(session)
        assertNull(browser.session(session))
    }
}
