package net.datamancy.keykeeper

import kotlinx.serialization.json.*
import java.net.URI
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.RSAPublicKey
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.Base64
import kotlin.test.*

class OidcIdentityVerifierTest {
    private val issuer = "https://id.example.test/realms/local"
    private val audience = "keykeeper-api"
    private val now = 1_900_000_000L
    private val pair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
    private val other = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
    private val revoked = mutableSetOf<String>()
    private var source: String = jwks()
    private val clients = mapOf("web-client" to PrincipalKind.HUMAN, "service-client" to PrincipalKind.AGENT)
    private fun encode(bytes: ByteArray) = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    private fun encode(text: String) = encode(text.toByteArray())
    private fun unsigned(n: java.math.BigInteger) = n.toByteArray().let { if (it[0] == 0.toByte()) it.drop(1).toByteArray() else it }
    private fun jwks(kid: String = "key-1", key: KeyPair = pair): String {
        val pub = key.public as RSAPublicKey
        return buildJsonObject { put("keys", JsonArray(listOf(buildJsonObject {
            put("kid", kid); put("kty", "RSA"); put("alg", "RS256"); put("use", "sig")
            put("n", encode(unsigned(pub.modulus))); put("e", encode(unsigned(pub.publicExponent)))
        }))) }.toString()
    }
    private fun verifier(checker: RevocationChecker = RevocationChecker { it in revoked }) = OidcIdentityVerifier(
        issuer, audience, clients, JwksSource { source }, checker, Clock.fixed(Instant.ofEpochSecond(now), ZoneOffset.UTC))
    private fun claims(client: String = "web-client", type: String = "HUMAN") = buildJsonObject {
        put("iss", issuer); put("aud", audience); put("sub", "test-subject"); put("azp", client)
        put("keykeeper_principal_type", type); put("jti", "one-time-test-id")
        put("nbf", now - 20); put("iat", now - 20); put("exp", now + 180)
    }
    private fun token(payload: JsonObject = claims(), kid: String = "key-1", key: KeyPair = pair,
                      header: JsonObject = buildJsonObject { put("alg", "RS256"); put("kid", kid); put("typ", "JWT") }): String {
        val input = encode(header.toString()) + "." + encode(payload.toString())
        val signature = Signature.getInstance("SHA256withRSA").apply { initSign(key.private); update(input.toByteArray()) }.sign()
        return input + "." + encode(signature)
    }
    private fun changed(name: String, value: JsonElement) = JsonObject(claims().toMutableMap().apply { put(name, value) })

    @Test fun `locally signed human and agent tokens require both pinned client and trusted type`() {
        val verifier = verifier()
        assertEquals(Principal(issuer, "test-subject", PrincipalKind.HUMAN), verifier.verify(token()))
        assertEquals(Principal(issuer, "test-subject", PrincipalKind.AGENT), verifier.verify(token(claims("service-client", "AGENT"))))
        assertNull(verifier.verify(token(claims("web-client", "AGENT"))))
        assertNull(verifier.verify(token(claims("service-client", "HUMAN"))))
        assertNull(verifier.verify(token(claims("other-client", "AGENT"))))
        assertNull(verifier.verify(token(changed("keykeeper_principal_type", JsonPrimitive("agent")))))
        assertNull(verifier.verify(token(changed("sub", JsonPrimitive("")))))
        assertNull(verifier.verify(token(changed("jti", JsonPrimitive("")))))
        assertNull(verifier.verify(token(changed("iss", JsonPrimitive("https://other.test")))))
        assertNull(verifier.verify(token(changed("aud", JsonPrimitive("wrong")))))
        assertNotNull(verifier.verify(token(changed("aud", JsonArray(listOf(JsonPrimitive("other"), JsonPrimitive(audience)))))))
        assertNull(verifier.verify(token(changed("aud", JsonArray(listOf(JsonPrimitive("other")))))))
        assertNull(verifier.verify(token(changed("aud", JsonPrimitive(17)))))
    }
    @Test fun `expiration not-before issued-at lifetime and revocation fail closed`() {
        val verifier = verifier()
        for ((field, value) in listOf("exp" to now, "nbf" to (now + 1), "iat" to (now + 1),
            "exp" to (now + 5000), "exp" to (now - 1), "iat" to (now + 6000))) {
            assertNull(verifier.verify(token(changed(field, JsonPrimitive(value)))), "$field=$value")
        }
        assertNull(verifier.verify(token(changed("exp", JsonPrimitive("9999999999")))))
        assertNull(verifier.verify(token(changed("nbf", JsonPrimitive(now + 300)))))
        revoked += "one-time-test-id"
        assertNull(verifier.verify(token()))
        assertNull(verifier(RevocationChecker { error("unavailable") }).verify(token()))
        revoked.clear()
        assertNotNull(verifier.verify(token()))
    }
    @Test fun `untrusted JWT header keys key substitution weak algorithms and malformed JWKS fail closed`() {
        val verifier = verifier()
        assertNull(verifier.verify("not-a-jwt"))
        assertNull(verifier.verify("a.b.c.d"))
        assertNull(verifier.verify(token(kid = "not-pinned")))
        assertNull(verifier.verify(token(key = other)))
        assertNull(verifier.verify(token(header = buildJsonObject {
            put("alg", "none"); put("kid", "key-1"); put("typ", "JWT")
        })))
        assertNull(verifier.verify(token(header = buildJsonObject {
            put("alg", "RS256"); put("kid", "key-1"); put("typ", "JWT"); put("jku", "https://attacker.test/keys")
        })))
        assertNull(verifier.verify(token().dropLast(1) + "!"))
        source = "{\"keys\": []}"
        assertNull(verifier.verify(token()))
        source = buildJsonObject { put("keys", JsonArray(listOf(Json.parseToJsonElement(jwks()).jsonObject.getValue("keys").jsonArray[0],
            Json.parseToJsonElement(jwks()).jsonObject.getValue("keys").jsonArray[0]))) }.toString()
        assertNull(verifier.verify(token()))
        source = jwks(key = other)
        assertNull(verifier.verify(token()))
        source = jwks(kid = "rotated")
        assertNotNull(verifier.verify(token(kid = "rotated")))
    }
    @Test fun `vault denies revoked signed bearer and audits without token contents`() {
        val events = mutableListOf<AuditEvent>()
        val store = object : CredentialStore {
            override fun keys() = emptyList<String>()
            override fun get(id: String): StoredCredential? = null
            override fun put(item: StoredCredential, expectedVersion: Int) = error("unused")
        }
        val vault = Vault(store, verifier(), events::add)
        val signed = token()
        assertEquals(Principal(issuer, "test-subject", PrincipalKind.HUMAN), vault.authenticate(signed))
        revoked += "one-time-test-id"
        assertFailsWith<Denied> { vault.authenticate(signed) }
        assertEquals("failed", events.single().outcome)
        assertFalse(events.toString().contains(signed))
    }
    @Test fun `pinned endpoint and verifier configuration reject unsafe values`() {
        val realm = URI(issuer)
        PinnedHttpsJwksSource(realm, URI("$issuer/protocol/openid-connect/certs"))
        assertFailsWith<IllegalArgumentException> { PinnedHttpsJwksSource(realm, URI("http://id.example.test/keys")) }
        assertFailsWith<IllegalArgumentException> { PinnedHttpsJwksSource(realm, URI("https://other.test/realms/local/protocol/openid-connect/certs")) }
        assertFailsWith<IllegalArgumentException> { PinnedHttpsJwksSource(realm, URI("$issuer/protocol/openid-connect/certs?x=1")) }
        assertFailsWith<IllegalArgumentException> { OidcIdentityVerifier("http://id.example.test", audience, clients, JwksSource { source }, RevocationChecker { false }) }
        assertFailsWith<IllegalArgumentException> { OidcIdentityVerifier(issuer, "", clients, JwksSource { source }, RevocationChecker { false }) }
    }
}
