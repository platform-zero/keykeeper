package net.datamancy.keykeeper

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class AccessPolicyTest {
    private val owner = Principal("https://identity.datamancy.net", "alice", PrincipalKind.HUMAN)
    private val agent = Principal(owner.issuer, "agent-73", PrincipalKind.AGENT)
    private val person = Principal(owner.issuer, "bob", PrincipalKind.HUMAN)

    @Test fun `humans and agents have exactly the granted rights`() {
        val item = CredentialMetadata("entry-1", owner)
        val shared = AccessPolicy.share(owner, item, Grant(agent, setOf(Right.READ, Right.SHARE)))
        val humanShared = AccessPolicy.share(owner, item, Grant(person, setOf(Right.READ, Right.SHARE)))
        for ((principal, credential) in listOf(agent to shared, person to humanShared)) {
            assertTrue(AccessPolicy.may(principal, credential, Right.READ))
            assertTrue(AccessPolicy.may(principal, credential, Right.SHARE))
            assertFalse(AccessPolicy.may(principal, credential, Right.EDIT))
        }
        assertFalse(AccessPolicy.may(person, shared, Right.READ))
        assertFalse(AccessPolicy.may(agent, humanShared, Right.READ))
        assertFailsWith<IllegalArgumentException> {
            AccessPolicy.share(agent, shared, Grant(person, setOf(Right.EDIT)))
        }
    }

    @Test fun `revocation removes agent access immediately from the policy`() {
        val shared = AccessPolicy.share(owner, CredentialMetadata("entry", owner), Grant(agent, setOf(Right.READ)))
        val revoked = AccessPolicy.revoke(owner, shared, agent)
        assertFalse(AccessPolicy.may(agent, revoked, Right.READ))
        assertTrue(AccessPolicy.may(owner, revoked, Right.READ))
    }

    @Test fun `sharing needs a grant and cannot cross identity issuers`() {
        val item = CredentialMetadata("entry", owner)
        assertFailsWith<IllegalArgumentException> {
            AccessPolicy.share(agent, item, Grant(person, setOf(Right.READ)))
        }
        assertFailsWith<IllegalArgumentException> {
            AccessPolicy.share(owner, item, Grant(Principal("other-issuer", "bob", PrincipalKind.HUMAN), setOf(Right.READ)))
        }
        assertEquals(item, item.copy())
    }
}
