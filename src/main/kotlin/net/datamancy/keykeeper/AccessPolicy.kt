package net.datamancy.keykeeper

/** Both human and agent subjects receive the same rights. Kind affects login, not authorization. */
enum class PrincipalKind { HUMAN, AGENT }
data class Principal(val issuer: String, val subject: String, val kind: PrincipalKind) {
    init {
        require(issuer.isNotBlank() && subject.isNotBlank())
    }
}

enum class Right { READ, EDIT, SHARE }
data class Grant(val recipient: Principal, val rights: Set<Right>) {
    init { require(rights.isNotEmpty()) }
}

data class CredentialMetadata(
    val id: String,
    val owner: Principal,
    val grants: List<Grant> = emptyList(),
    val retired: Boolean = false,
) {
    init { require(id.isNotBlank()) }
}

object AccessPolicy {
    fun may(principal: Principal, item: CredentialMetadata, right: Right): Boolean =
        !item.retired && principal.issuer == item.owner.issuer &&
            ((principal.subject == item.owner.subject && principal.kind == item.owner.kind) || item.grants.any {
                it.recipient.issuer == principal.issuer &&
                    it.recipient.subject == principal.subject && it.recipient.kind == principal.kind && right in it.rights
            })

    fun share(actor: Principal, item: CredentialMetadata, grant: Grant): CredentialMetadata {
        require(may(actor, item, Right.SHARE)) { "Sharing requires SHARE permission" }
        require(grant.rights.all { may(actor, item, it) }) { "Cannot grant rights you do not hold" }
        require(grant.recipient.issuer == item.owner.issuer) { "Cross-issuer grants are not supported" }
        return item.copy(grants = item.grants.filterNot {
            it.recipient.issuer == grant.recipient.issuer && it.recipient.subject == grant.recipient.subject && it.recipient.kind == grant.recipient.kind
        } + grant)
    }

    fun revoke(actor: Principal, item: CredentialMetadata, recipient: Principal): CredentialMetadata {
        require(may(actor, item, Right.SHARE)) { "Revocation requires SHARE permission" }
        return item.copy(grants = item.grants.filterNot {
            it.recipient.issuer == recipient.issuer && it.recipient.subject == recipient.subject && it.recipient.kind == recipient.kind
        })
    }
}
