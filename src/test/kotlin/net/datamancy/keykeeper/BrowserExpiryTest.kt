package net.datamancy.keykeeper

import java.net.URI
import java.time.Clock
import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset
import kotlin.test.*

class BrowserExpiryTest {
    @Test fun `expired authorization attempts and sessions cannot permanently exhaust capacity`() {
        var seconds = 10000L
        val clock = object : Clock() {
            override fun getZone(): ZoneId = ZoneOffset.UTC
            override fun withZone(zone: ZoneId): Clock = this
            override fun instant(): Instant = Instant.ofEpochSecond(seconds)
        }
        val token = "unit-only-public-fixture-token-at-least-24-bytes"
        val store = object : CredentialStore {
            override fun keys() = emptyList<String>()
            override fun get(id: String): StoredCredential? = null
            override fun put(item: StoredCredential, expectedVersion: Int) = error("No writes expected")
        }
        val vault = Vault(store, LocalTestVerifier(token, Principal("unit", "user", PrincipalKind.HUMAN))) {}
        val oauth = object : OAuthCodeClient {
            override fun authorization(state: String, challenge: String, redirect: URI) = URI("https://unit.invalid/?state=$state")
            override fun exchange(code: String, verifier: String, redirect: URI) = token
        }
        val browser = BrowserOidc(oauth, vault, clock)
        val redirect = URI("https://keeper:8443/auth/callback")
        val oldest = browser.begin(redirect)
        repeat(999) { browser.begin(redirect) }
        assertFails { browser.begin(redirect) }
        seconds += 300
        val next = browser.begin(redirect)
        assertFailsWith<Denied> { browser.finish(oldest.first.rawQuery.substringAfter('='), oldest.second, "code", redirect) }
        var session = browser.finish(next.first.rawQuery.substringAfter('='), next.second, "code", redirect)
        repeat(999) {
            val attempt = browser.begin(redirect)
            session = browser.finish(attempt.first.rawQuery.substringAfter('='), attempt.second, "code", redirect)
        }
        val full = browser.begin(redirect)
        assertFails { browser.finish(full.first.rawQuery.substringAfter('='), full.second, "code", redirect) }
        assertNotNull(browser.session(session))
        seconds += 900
        val fresh = browser.begin(redirect)
        assertNotNull(browser.session(browser.finish(fresh.first.rawQuery.substringAfter('='), fresh.second, "code", redirect)))
        assertNull(browser.session(session))
        val expires = browser.begin(redirect)
        seconds += 300
        assertFailsWith<Denied> { browser.finish(expires.first.rawQuery.substringAfter('='), expires.second, "code", redirect) }
    }
}
