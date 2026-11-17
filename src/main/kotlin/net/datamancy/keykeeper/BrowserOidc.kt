package net.datamancy.keykeeper

import kotlinx.serialization.json.*
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Clock
import java.time.Duration
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap

data class OAuthGrant(val accessToken: String, val refreshToken: String? = null)

interface OAuthCodeClient {
    val expectedIssuer: String? get() = null
    val requiresUpstreamLogout: Boolean get() = false
    fun authorization(state: String, challenge: String, redirect: URI): URI
    fun exchange(code: String, verifier: String, redirect: URI): String
    fun exchangeGrant(code: String, verifier: String, redirect: URI): OAuthGrant = OAuthGrant(exchange(code, verifier, redirect))
    fun revoke(refreshToken: String) { throw Denied() }
}

/** Fixed HTTPS Keycloak realm endpoints. Only authorization code + S256 PKCE, no client secret in browser. */
class PinnedKeycloakCodeClient internal constructor(issuer: URI, private val clientId: String, private val allowLocalFake: Boolean) : OAuthCodeClient {
    constructor(issuer: URI, clientId: String) : this(issuer, clientId, false)
    override val expectedIssuer = issuer.toString()
    override val requiresUpstreamLogout: Boolean get() = !allowLocalFake
    init {
        require(issuer.host != null && issuer.rawUserInfo == null && issuer.rawQuery == null && issuer.rawFragment == null && clientId.isNotBlank())
        require(issuer.scheme == "https" || (allowLocalFake && issuer.scheme == "http" && issuer.host == "127.0.0.1"))
    }
    private val auth = issuer.resolve(issuer.toString().trimEnd('/') + "/protocol/openid-connect/auth")
    private val token = issuer.resolve(issuer.toString().trimEnd('/') + "/protocol/openid-connect/token")
    private val logout = issuer.resolve(issuer.toString().trimEnd('/') + "/protocol/openid-connect/logout")
    private val http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).followRedirects(HttpClient.Redirect.NEVER).build()
    override fun authorization(state: String, challenge: String, redirect: URI): URI = URI(auth.toString() + "?" + form(mapOf(
        "response_type" to "code", "client_id" to clientId, "redirect_uri" to redirect.toString(),
        "scope" to "openid", "state" to state, "code_challenge" to challenge, "code_challenge_method" to "S256")))
    override fun exchange(code: String, verifier: String, redirect: URI): String = exchangeGrant(code, verifier, redirect).accessToken
    override fun exchangeGrant(code: String, verifier: String, redirect: URI): OAuthGrant {
        val request = HttpRequest.newBuilder(token).timeout(Duration.ofSeconds(5)).header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(form(mapOf("grant_type" to "authorization_code", "client_id" to clientId,
                "code" to code, "redirect_uri" to redirect.toString(), "code_verifier" to verifier)))).build()
        val response = http.send(request, HttpResponse.BodyHandlers.ofInputStream())
        return response.body().use { stream ->
            if (response.statusCode() != 200) throw Denied()
            val bytes = stream.readNBytes(65_537)
            if (bytes.size > 65_536) throw Denied()
            val obj = Json.parseToJsonElement(bytes.toString(Charsets.UTF_8)).jsonObject
            if (obj["token_type"]?.jsonPrimitive?.content != "Bearer") throw Denied()
            val access = obj.getValue("access_token").jsonPrimitive.content.takeIf { it.isNotBlank() } ?: throw Denied()
            val refresh = obj["refresh_token"]?.jsonPrimitive?.content?.takeIf { it.isNotBlank() }
            if (requiresUpstreamLogout && refresh == null) throw Denied()
            OAuthGrant(access, refresh)
        }
    }
    override fun revoke(refreshToken: String) {
        require(refreshToken.isNotBlank() && refreshToken.length <= 16_384)
        val request = HttpRequest.newBuilder(logout).timeout(Duration.ofSeconds(5))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(form(mapOf("client_id" to clientId, "refresh_token" to refreshToken)))).build()
        val response = http.send(request, HttpResponse.BodyHandlers.ofInputStream())
        response.body().use { stream ->
            if (stream.readNBytes(65_537).size > 65_536 || response.statusCode() !in setOf(200, 204)) throw Denied()
        }
    }
}

internal fun form(params: Map<String, String>): String = params.entries.joinToString("&") {
    URLEncoder.encode(it.key, Charsets.UTF_8) + "=" + URLEncoder.encode(it.value, Charsets.UTF_8)
}

/** Process-local, short-lived server-side token sessions. Never sends access tokens to browser JS/cookies. */
class BrowserOidc(private val oauth: OAuthCodeClient, private val vault: Vault, private val clock: Clock = Clock.systemUTC(),
    private val revocationProof: ((String) -> Boolean)? = null) {
    private data class Pending(val verifier: String, val browser: String, val created: Long)
    private data class Entry(val token: String, val refresh: String?, val csrf: String, val created: Long)
    data class Session(val token: String, val csrf: String)
    private val random = SecureRandom()
    private val pending = ConcurrentHashMap<String, Pending>()
    private val sessions = ConcurrentHashMap<String, Entry>()
    private fun nonce(): String = ByteArray(32).also(random::nextBytes).let { Base64.getUrlEncoder().withoutPadding().encodeToString(it) }
    private fun now() = clock.instant().epochSecond
    private fun valid(created: Long, lifetime: Long = 900) = now() >= created && now() - created < lifetime
    fun begin(redirect: URI): Pair<URI, String> {
        pending.entries.removeIf { !valid(it.value.created, 300) }
        require(pending.size < 1000)
        val state = nonce(); val browser = nonce(); val verifier = nonce()
        pending[state] = Pending(verifier, browser, now())
        val challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray()))
        return oauth.authorization(state, challenge, redirect) to browser
    }
    fun finish(state: String, browser: String?, code: String, redirect: URI, issuer: String? = null): String {
        val attempt = pending.remove(state) ?: throw Denied() // one time, including failed exchange
        if (oauth.expectedIssuer != null && issuer != oauth.expectedIssuer) throw Denied()
        if (!valid(attempt.created, 300) || browser == null || !MessageDigest.isEqual(attempt.browser.toByteArray(), browser.toByteArray()) || code.isBlank()) throw Denied()
        val grant = oauth.exchangeGrant(code, attempt.verifier, redirect)
        vault.authenticate(grant.accessToken) // full JWT signature, issuer, client/kind, expiry and introspection
        sessions.entries.removeIf { !valid(it.value.created) }
        require(sessions.size < 1000)
        val sessionId = nonce()
        sessions[sessionId] = Entry(grant.accessToken, grant.refreshToken, nonce(), now())
        return sessionId
    }
    fun session(id: String?): Session? {
        val entry = id?.let(sessions::get) ?: return null
        if (!valid(entry.created)) { sessions.remove(id, entry); return null }
        return Session(entry.token, entry.csrf)
    }
    fun logout(id: String?) {
        val entry = if (id == null) null else sessions.remove(id)
        // Clear our local session even if upstream is unavailable; never claim upstream revocation
        // when Keycloak could still honor a stolen bearer. The web route fails closed on error.
        if (entry != null && oauth.requiresUpstreamLogout) {
            oauth.revoke(entry.refresh ?: throw Denied())
            if (revocationProof?.invoke(entry.token) != true) throw Denied()
        }
    }
}
