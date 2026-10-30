package net.datamancy.keykeeper

import kotlinx.serialization.json.*
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.io.InputStream
import java.time.Duration
import java.util.Base64

/** Every signed access token is introspected at a pinned Keycloak realm endpoint, without caching. */
class PinnedKeycloakIntrospection internal constructor(
    issuer: URI, endpoint: URI, clientId: String, clientSecret: String,
    private val transport: (HttpRequest) -> Pair<Int, InputStream>,
) : RevocationChecker {
    companion object {
        private val httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3))
            .followRedirects(HttpClient.Redirect.NEVER).build()
    }
    constructor(issuer: URI, endpoint: URI, clientId: String, clientSecret: String) :
        this(issuer, endpoint, clientId, clientSecret, { req ->
            val response = httpClient.send(req, HttpResponse.BodyHandlers.ofInputStream())
            response.statusCode() to response.body()
        })
    init {
        require(issuer.scheme == "https" && issuer.host != null && issuer.rawUserInfo == null && issuer.rawQuery == null && issuer.rawFragment == null)
        require(endpoint.scheme == "https" && endpoint.host == issuer.host && endpoint.port == issuer.port &&
            endpoint.rawUserInfo == null && endpoint.rawQuery == null && endpoint.rawFragment == null &&
            endpoint.path == issuer.path.trimEnd('/') + "/protocol/openid-connect/token/introspect")
        require(clientId.isNotBlank() && clientSecret.isNotBlank() && !clientId.contains(':'))
    }
    private val url = endpoint
    private val authorization = "Basic " + Base64.getEncoder().encodeToString("$clientId:$clientSecret".toByteArray())

    override fun isRevoked(jti: String, bearer: String, subject: String): Boolean {
        val form = "token=" + URLEncoder.encode(bearer, Charsets.UTF_8) + "&token_type_hint=access_token"
        val request = HttpRequest.newBuilder(url).timeout(Duration.ofSeconds(5))
            .header("Authorization", authorization).header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(form)).build()
        val (status, body) = transport(request)
        return body.use { stream ->
            if (status != 200) true
            else {
                val bytes = stream.readNBytes(65_537)
                bytes.size > 65_536 || !introspectionActive(bytes.toString(Charsets.UTF_8), jti, subject)
            }
        }
    }
}

/** Fail closed on missing, malformed or mismatched introspection response. */
internal fun introspectionActive(body: String, jti: String, subject: String): Boolean = try {
    val data = Json.parseToJsonElement(body).jsonObject
    data["active"]?.jsonPrimitive?.booleanOrNull == true &&
        data["sub"]?.jsonPrimitive?.content == subject &&
        (data["jti"] == null || data["jti"]?.jsonPrimitive?.content == jti)
} catch (_: Exception) { false }
