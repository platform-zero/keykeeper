package net.datamancy.keykeeper

import kotlinx.serialization.json.*
import java.io.IOException
import java.security.MessageDigest
import java.util.UUID

/** Verification must happen server-side. Implementations must validate signature, issuer, audience and expiry. */
fun interface IdentityVerifier { fun verify(bearer: String): Principal? }

/** Development only: a single opaque token supplied by the operator, never claims supplied by the caller. */
class LocalTestVerifier(private val subjects: Map<String, Principal>) : IdentityVerifier {
    constructor(token: String, principal: Principal) : this(mapOf(token to principal))
    init { require(subjects.isNotEmpty() && subjects.keys.all { it.length >= 24 }) }
    override fun verify(bearer: String): Principal? = subjects.entries.firstOrNull {
        MessageDigest.isEqual(it.key.toByteArray(), bearer.toByteArray())
    }?.value
}

class Denied : RuntimeException()
class Missing : RuntimeException()
class Conflict : RuntimeException()

/** No value or token may be passed to an audit sink. */
data class AuditEvent(val action: String, val actorHash: String, val itemId: String, val outcome: String)
fun interface AuditSink { fun record(event: AuditEvent) }

internal fun Principal.toJson(): JsonObject = buildJsonObject {
    put("issuer", issuer); put("subject", subject); put("kind", kind.name)
}
internal fun JsonObject.principal(): Principal = Principal(getValue("issuer").jsonPrimitive.content, getValue("subject").jsonPrimitive.content,
    PrincipalKind.valueOf(getValue("kind").jsonPrimitive.content))
internal fun CredentialMetadata.toJson(): JsonObject = buildJsonObject {
    put("id", id); put("owner", owner.toJson())
    put("grants", JsonArray(grants.map { g -> buildJsonObject {
        put("recipient", g.recipient.toJson()); put("rights", JsonArray(g.rights.map { JsonPrimitive(it.name) }))
    } }))
}
internal fun JsonObject.metadata(): CredentialMetadata = CredentialMetadata(
    getValue("id").jsonPrimitive.content, getValue("owner").jsonObject.principal(),
    getValue("grants").jsonArray.map { grant ->
        val g = grant.jsonObject
        Grant(g.getValue("recipient").jsonObject.principal(), g.getValue("rights").jsonArray.map { Right.valueOf(it.jsonPrimitive.content) }.toSet())
    })

data class StoredCredential(val metadata: CredentialMetadata, val value: String, val version: Int)

/** Store is exclusively accessed by the service; versions provide compare-and-swap for grant updates. */
interface CredentialStore {
    fun keys(): List<String>
    fun get(id: String): StoredCredential?
    fun put(item: StoredCredential, expectedVersion: Int)
}

class Vault(private val store: CredentialStore, private val verifier: IdentityVerifier, private val audit: AuditSink) {
    fun authenticate(bearer: String): Principal {
        val principal = verifier.verify(bearer)
        if (principal == null) {
            audit.record(AuditEvent("authenticate", "-", "-", "failed"))
            throw Denied()
        }
        return principal
    }

    private fun <T> audited(action: String, actor: Principal, id: String, block: () -> T): T {
        val digest = MessageDigest.getInstance("SHA-256").digest("${actor.issuer}\u0000${actor.subject}\u0000${actor.kind}".toByteArray())
            .joinToString("") { "%02x".format(it) }
        try {
            val result = block()
            audit.record(AuditEvent(action, digest, safeAuditId(id), "ok"))
            return result
        } catch (e: Exception) {
            audit.record(AuditEvent(action, digest, safeAuditId(id), "failed"))
            throw e
        }
    }

    private fun safeAuditId(id: String): String = if (runCatching { UUID.fromString(id).toString() }.getOrNull() == id) id else "-"

    private fun checkedId(id: String): String {
        if (runCatching { UUID.fromString(id).toString() }.getOrNull() != id) throw Missing()
        return id
    }
    private fun load(id: String): StoredCredential = store.get(checkedId(id))?.takeIf { it.metadata.id == id } ?: throw Missing()
    private fun allowed(actor: Principal, item: StoredCredential, right: Right) {
        if (!AccessPolicy.may(actor, item.metadata, right)) throw Denied()
    }

    fun create(actor: Principal, value: String): CredentialMetadata {
        require(value.isNotEmpty() && value.length <= 64_000) { "Invalid value length" }
        val id = UUID.randomUUID().toString()
        return audited("create", actor, id) {
            val metadata = CredentialMetadata(id, actor)
            store.put(StoredCredential(metadata, value, 0), 0)
            metadata
        }
    }
    fun list(actor: Principal): List<CredentialMetadata> = audited("list", actor, "-") {
        store.keys().mapNotNull { id ->
            // Invalid keys are ignored; fail closed if an existing record is corrupt/unavailable.
            if (runCatching { checkedId(id) }.isFailure) null else store.get(id)?.metadata?.takeIf { it.id == id && AccessPolicy.may(actor, it, Right.READ) }
        }
    }
    fun read(actor: Principal, id: String): String = audited("read", actor, id) {
        val item = load(id); allowed(actor, item, Right.READ); item.value
    }
    fun edit(actor: Principal, id: String, value: String) = audited("edit", actor, id) {
        require(value.isNotEmpty() && value.length <= 64_000) { "Invalid value length" }
        val item = load(id)
        allowed(actor, item, Right.EDIT)
        store.put(item.copy(value = value), item.version)
    }
    fun share(actor: Principal, id: String, grant: Grant): CredentialMetadata = audited("share", actor, id) {
        val item = load(id)
        if (!AccessPolicy.may(actor, item.metadata, Right.SHARE)) throw Denied()
        val updated = try { AccessPolicy.share(actor, item.metadata, grant) } catch (_: IllegalArgumentException) { throw Denied() }
        store.put(item.copy(metadata = updated), item.version)
        updated
    }
    fun revoke(actor: Principal, id: String, recipient: Principal): CredentialMetadata = audited("revoke", actor, id) {
        val item = load(id)
        if (!AccessPolicy.may(actor, item.metadata, Right.SHARE)) throw Denied()
        val updated = AccessPolicy.revoke(actor, item.metadata, recipient)
        store.put(item.copy(metadata = updated), item.version)
        updated
    }
}
