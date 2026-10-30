package net.datamancy.keykeeper

import kotlinx.serialization.json.*
import java.math.BigInteger
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.KeyFactory
import java.security.Signature
import java.security.interfaces.RSAPublicKey
import java.security.spec.RSAPublicKeySpec
import java.time.Clock
import java.time.Duration
import java.util.Base64

/** Pinned JWKS document source. Never derive a key URL from an unverified JWT. */
fun interface JwksSource { fun document(): String }
/** Must consult a trusted revocation source for every jti; throwing fails authentication closed. */
fun interface RevocationChecker { fun isRevoked(jti: String): Boolean }

/** HTTPS-only pinned Keycloak realm certs endpoint; no redirects, stale-key fallback or token-derived URLs. */
class PinnedHttpsJwksSource(issuer: URI, jwks: URI) : JwksSource {
    init {
        require(issuer.scheme == "https" && issuer.host != null && issuer.rawUserInfo == null && issuer.rawQuery == null && issuer.rawFragment == null)
        require(jwks.scheme == "https" && jwks.host == issuer.host && jwks.port == issuer.port &&
            jwks.rawUserInfo == null && jwks.rawQuery == null && jwks.rawFragment == null &&
            jwks.path == issuer.path.trimEnd('/') + "/protocol/openid-connect/certs")
    }
    private val client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3))
        .followRedirects(HttpClient.Redirect.NEVER).build()
    private val endpoint = jwks
    override fun document(): String {
        val response = client.send(HttpRequest.newBuilder(endpoint).timeout(Duration.ofSeconds(5)).GET().build(),
            HttpResponse.BodyHandlers.ofInputStream())
        return response.body().use { stream ->
            if (response.statusCode() != 200) throw IllegalStateException("JWKS unavailable")
            val bytes = stream.readNBytes(131_073)
            if (bytes.size > 131_072) throw IllegalStateException("JWKS too large")
            bytes.toString(Charsets.UTF_8)
        }
    }
}

/** Strict RS256 access-token verification. azp and admin-managed type must both match pinned client policy. */
class OidcIdentityVerifier(
    private val issuer: String,
    private val audience: String,
    private val clients: Map<String, PrincipalKind>,
    private val jwks: JwksSource,
    private val revocation: RevocationChecker,
    private val clock: Clock = Clock.systemUTC(),
) : IdentityVerifier {
    init {
        require(issuer.startsWith("https://") && URI(issuer).let { it.host != null && it.rawUserInfo == null && it.rawQuery == null && it.rawFragment == null })
        require(audience.isNotBlank() && clients.isNotEmpty() && clients.keys.all { it.isNotBlank() })
    }
    override fun verify(bearer: String): Principal? = try { validate(bearer) } catch (_: Exception) { null }

    private fun decode(input: String): ByteArray {
        require(input.isNotEmpty() && input.matches(Regex("[A-Za-z0-9_-]+")))
        return Base64.getUrlDecoder().decode(input)
    }
    private fun JsonObject.text(name: String): String = (getValue(name) as JsonPrimitive).also { require(it.isString) }.content
    private fun JsonObject.seconds(name: String): Long {
        val field = getValue(name) as JsonPrimitive
        require(!field.isString && field.content.matches(Regex("-?[0-9]+")))
        return field.content.toLong()
    }
    private fun validate(token: String): Principal {
        require(token.length <= 16_384)
        val parts = token.split('.')
        require(parts.size == 3 && parts.take(2).all { it.length <= 8192 })
        val header = Json.parseToJsonElement(decode(parts[0]).toString(Charsets.UTF_8)).jsonObject
        require(header.keys == setOf("alg", "kid", "typ") && header.text("alg") == "RS256" && header.text("typ") in setOf("JWT", "at+jwt"))
        val kid = header.text("kid")
        require(kid.isNotBlank() && kid.length <= 128)
        val document = jwks.document()
        require(document.length <= 131_072)
        val keys = Json.parseToJsonElement(document).jsonObject.getValue("keys").jsonArray.map { it.jsonObject }
        require(keys.size in 1..64 && keys.map { it.text("kid") }.distinct().size == keys.size)
        val key = keys.single { it.text("kid") == kid }
        require(key.text("kty") == "RSA" && key.text("alg") == "RS256" && key["use"]?.jsonPrimitive?.content == "sig")
        val modulus = BigInteger(1, decode(key.text("n")))
        val exponent = BigInteger(1, decode(key.text("e")))
        require(modulus.bitLength() in 2048..4096 && exponent == BigInteger.valueOf(65537))
        val publicKey = KeyFactory.getInstance("RSA").generatePublic(RSAPublicKeySpec(modulus, exponent)) as RSAPublicKey
        val signature = Signature.getInstance("SHA256withRSA")
        signature.initVerify(publicKey)
        signature.update("${parts[0]}.${parts[1]}".toByteArray(Charsets.US_ASCII))
        require(signature.verify(decode(parts[2])))

        val claims = Json.parseToJsonElement(decode(parts[1]).toString(Charsets.UTF_8)).jsonObject
        require(claims.text("iss") == issuer)
        val aud = claims.getValue("aud")
        require(if (aud is JsonArray) aud.any { it is JsonPrimitive && it.isString && it.content == audience }
            else aud is JsonPrimitive && aud.isString && aud.content == audience)
        val now = clock.instant().epochSecond
        val nbf = claims.seconds("nbf")
        val iat = claims.seconds("iat")
        val exp = claims.seconds("exp")
        require(nbf <= now && iat <= now && now < exp && exp > nbf && exp - iat in 1..3600)
        val subject = claims.text("sub")
        val jti = claims.text("jti")
        require(subject.isNotBlank() && jti.isNotBlank())
        val kind = clients[claims.text("azp")] ?: throw IllegalArgumentException()
        // `keykeeper_principal_type` must be an admin-only signed protocol mapper, never a user-editable attribute.
        require(claims.text("keykeeper_principal_type") == kind.name)
        require(!revocation.isRevoked(jti))
        return Principal(issuer, subject, kind)
    }
}
