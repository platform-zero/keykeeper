package net.datamancy.keykeeper

import kotlinx.serialization.json.*
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.net.CookieManager
import java.net.CookiePolicy
import java.net.ServerSocket
import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.security.KeyStore
import java.security.SecureRandom
import java.time.Duration
import java.util.Base64
import java.util.Comparator
import java.util.UUID
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import kotlin.test.*

/** Opt-in: copies a local Keycloak distribution into build/ and starts only fresh loopback processes. */
class RealKeycloakBaoTest {
    private fun nonce() = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(18).also(SecureRandom()::nextBytes))
    private fun port() = ServerSocket(0).use { it.localPort }
    private fun form(params: Map<String, String>) = params.entries.joinToString("&") { "${URLEncoder.encode(it.key, Charsets.UTF_8)}=${URLEncoder.encode(it.value, Charsets.UTF_8)}" }
    private fun params(uri: URI) = uri.rawQuery.split('&').associate {
        val pair = it.split('=', limit = 2)
        URLDecoder.decode(pair[0], Charsets.UTF_8) to URLDecoder.decode(pair[1], Charsets.UTF_8)
    }
    private fun copyHome(from: Path, to: Path) {
        Files.walk(from).use { paths -> paths.forEach { src ->
            val dest = to.resolve(from.relativize(src).toString())
            if (Files.isDirectory(src)) Files.createDirectories(dest)
            else Files.copy(src, dest, StandardCopyOption.COPY_ATTRIBUTES)
        } }
    }
    private fun user(username: String, id: String, password: String) = buildJsonObject {
        put("id", id); put("username", username); put("enabled", true)
        put("firstName", username); put("lastName", "Disposable"); put("email", "$username@example.invalid"); put("emailVerified", true)
        put("credentials", JsonArray(listOf(buildJsonObject { put("type", "password"); put("value", password); put("temporary", false) })))
    }
    private fun client(id: String, kind: String, redirect: String? = null, secret: String? = null, otherRedirect: String? = null): JsonObject = buildJsonObject {
        put("clientId", id); put("enabled", true); put("publicClient", secret == null)
        put("standardFlowEnabled", redirect != null); put("directAccessGrantsEnabled", false)
        if (secret != null) { put("secret", secret); put("serviceAccountsEnabled", true) }
        if (redirect != null) put("redirectUris", JsonArray(listOfNotNull(redirect, otherRedirect).map(::JsonPrimitive)))
        if (kind == "AGENT") put("attributes", buildJsonObject {
            put("oauth2.device.authorization.grant.enabled", "true"); put("oauth2.device.polling.interval", "1")
        })
        if (kind != "INTROSPECT") put("protocolMappers", JsonArray(listOf(
            buildJsonObject {
                put("name", "keykeeper-kind"); put("protocol", "openid-connect"); put("protocolMapper", "oidc-hardcoded-claim-mapper")
                put("config", buildJsonObject {
                    put("claim.name", "keykeeper_principal_type"); put("claim.value", kind)
                    put("jsonType.label", "String"); put("access.token.claim", "true")
                })
            }, buildJsonObject {
                put("name", "keykeeper-audience"); put("protocol", "openid-connect"); put("protocolMapper", "oidc-audience-mapper")
                put("config", buildJsonObject { put("included.custom.audience", "vault-api"); put("access.token.claim", "true") })
            }
        )))
    }
    private fun http(cookies: Boolean = false): HttpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3))
        .followRedirects(HttpClient.Redirect.NEVER)
        .apply { if (cookies) cookieHandler(CookieManager(null, CookiePolicy.ACCEPT_ORIGINAL_SERVER)) }.build()
    private fun call(client: HttpClient, url: URI, method: String = "GET", body: String? = null, headers: Map<String, String> = emptyMap()): HttpResponse<String> {
        val req = HttpRequest.newBuilder(url).timeout(Duration.ofSeconds(12))
        headers.forEach { (name, value) -> req.header(name, value) }
        if (body != null) req.header("Content-Type", "application/x-www-form-urlencoded")
        return client.send(req.method(method, if (body == null) HttpRequest.BodyPublishers.noBody()
            else HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString())
    }
    private fun loginPage(client: HttpClient, url: URI, username: String, password: String): HttpResponse<String> {
        var page = call(client, url)
        repeat(5) {
            if (page.statusCode() !in setOf(301, 302, 303)) return@repeat
            val next = URI(page.headers().firstValue("Location").orElseThrow())
            require(next.scheme == url.scheme && next.host == url.host && next.port == url.port)
            page = call(client, next)
        }
        assertEquals(200, page.statusCode(), "Keycloak login page")
        val action = Regex("<form[^>]*id=\"kc-form-login\"[^>]*action=\"([^\"]+)").find(page.body())?.groupValues?.get(1)
            ?.replace("&amp;", "&") ?: error("Keycloak login form missing")
        return call(client, URI(action), "POST", form(mapOf("username" to username, "password" to password)))
    }

    @Test fun `real disposable Keycloak browser PKCE and agent device CLI operate on real disposable Bao`() {
        assumeTrue(System.getenv("KEYKEEPER_TEST_KEYCLOAK_HOME") != null, "Explicit disposable Keycloak home required")
        require(System.getenv("KEYKEEPER_DISPOSABLE_RAFT_CONFIRM") == "YES-NEW-INSTANCE-ONLY")
        val build = Path.of("build").toAbsolutePath().toRealPath()
        val distribution = Path.of(System.getenv("KEYKEEPER_TEST_KEYCLOAK_HOME")).toRealPath()
        require(distribution.startsWith(build) && Files.isRegularFile(distribution.resolve("bin/kc.sh")) &&
            !Files.exists(distribution.resolve("data/h2")) && !Files.exists(distribution.resolve("data/import"))) {
            "Only a pristine extracted distribution inside keykeeper/build is permitted"
        }
        val binary = Path.of(System.getenv("KEYKEEPER_TEST_BAO_BINARY") ?: error("Missing verified Bao binary"))
        require(Files.isExecutable(binary))
        val scratch = Files.createTempDirectory(build, "real-keycloak-bao-")
        val previousTls = SSLContext.getDefault()
        var keycloak: Process? = null
        var bao: DisposableRaftRestoreTest.Node? = null
        var restoreTarget: DisposableRaftRestoreTest.Node? = null
        var web: VaultWeb? = null
        var restoredWeb: VaultWeb? = null
        try {
            val home = scratch.resolve("keycloak")
            copyHome(distribution, home)
            val httpsPort = port(); var httpPort = port(); while (httpPort == httpsPort) httpPort = port()
            var webPort = port(); while (webPort == httpsPort || webPort == httpPort) webPort = port()
            var restoredPort = port(); while (restoredPort == webPort || restoredPort == httpsPort || restoredPort == httpPort) restoredPort = port()
            val realmName = "keykeeper-${UUID.randomUUID().toString().take(8)}"
            val issuer = "https://127.0.0.1:$httpsPort/realms/$realmName"
            val humanId = UUID.randomUUID().toString(); val agentId = UUID.randomUUID().toString()
            val humanPassword = nonce(); val agentPassword = nonce(); val clientSecret = nonce()
            val realm = buildJsonObject {
                put("realm", realmName); put("enabled", true)
                put("users", JsonArray(listOf(user("human", humanId, humanPassword), user("agent", agentId, agentPassword))))
                put("clients", JsonArray(listOf(
                    client("browser", "HUMAN", "http://127.0.0.1:$webPort/auth/callback", otherRedirect = "http://127.0.0.1:$restoredPort/auth/callback"),
                    client("device", "AGENT"), client("introspect", "INTROSPECT", secret = clientSecret)
                )))
            }
            Files.createDirectories(home.resolve("data/import"))
            Files.writeString(home.resolve("data/import/$realmName-realm.json"), realm.toString())
            val tlsPassword = nonce()
            val keystore = scratch.resolve("local-tls.p12")
            val keytool = Path.of(System.getProperty("java.home"), "bin", "keytool")
            val keyProcess = ProcessBuilder(keytool.toString(), "-genkeypair", "-alias", "disposable", "-keyalg", "RSA", "-keysize", "2048",
                "-validity", "1", "-dname", "CN=127.0.0.1", "-ext", "SAN=IP:127.0.0.1", "-storetype", "PKCS12",
                "-keystore", keystore.toString(), "-storepass", tlsPassword, "-keypass", tlsPassword, "-noprompt")
                .redirectErrorStream(true).redirectOutput(scratch.resolve("keytool.log").toFile()).start()
            check(keyProcess.waitFor(15, TimeUnit.SECONDS) && keyProcess.exitValue() == 0) { "Local TLS test key generation failed" }
            val store = KeyStore.getInstance("PKCS12")
            Files.newInputStream(keystore).use { store.load(it, tlsPassword.toCharArray()) }
            val trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            trust.init(store)
            val tls = SSLContext.getInstance("TLS").apply { init(null, trust.trustManagers, SecureRandom()) }
            SSLContext.setDefault(tls) // test JVM only; restored in finally, no disabled hostname checks
            val kc = ProcessBuilder(home.resolve("bin/kc.sh").toString(), "start-dev", "--import-realm",
                "--http-host=127.0.0.1", "--http-port=$httpPort", "--https-port=$httpsPort",
                "--https-key-store-file=$keystore", "--https-key-store-password=$tlsPassword", "--hostname=https://127.0.0.1:$httpsPort", "--db=dev-file")
            kc.environment()["JAVA_HOME"] = System.getProperty("java.home")
            kc.environment()["KC_BOOTSTRAP_ADMIN_USERNAME"] = "disposable"
            kc.environment()["KC_BOOTSTRAP_ADMIN_PASSWORD"] = nonce()
            keycloak = kc.redirectErrorStream(true).redirectOutput(scratch.resolve("keycloak.log").toFile()).start()
            val client = http()
            var ready = false
            for (attempt in 1..120) {
                check(keycloak.isAlive) { "Isolated Keycloak stopped before discovery" }
                if (runCatching { call(client, URI("$issuer/.well-known/openid-configuration")).statusCode() }.getOrNull() == 200) { ready = true; break }
                Thread.sleep(500)
            }
            check(ready) { "Isolated Keycloak did not start" }
            val startup = Files.readString(scratch.resolve("keycloak.log"))
            check(startup.contains("http://127.0.0.1:$httpPort") && startup.contains("https://127.0.0.1:$httpsPort")) {
                "Isolated Keycloak did not bind only configured loopback listeners"
            }
            bao = DisposableRaftRestoreTest.Node(binary, scratch.resolve("bao"), "kc-bao-${UUID.randomUUID()}")
            val baoKeys = bao.initialize()
            val mount = "keykeeper-test-${UUID.randomUUID().toString().take(8)}"
            assertEquals(204, bao.call("POST", "/v1/sys/mounts/$mount", baoKeys.token,
                "{\"type\":\"kv\",\"options\":{\"version\":\"2\"}}".toByteArray()).statusCode())
            // serveOidc is internal to main compilation; exercise the same components with real HTTPS Keycloak.
            val verifier = OidcIdentityVerifier(issuer, "vault-api", mapOf("browser" to PrincipalKind.HUMAN, "device" to PrincipalKind.AGENT),
                PinnedHttpsJwksSource(URI(issuer), URI("$issuer/protocol/openid-connect/certs")),
                PinnedKeycloakIntrospection(URI(issuer), URI("$issuer/protocol/openid-connect/token/introspect"), "introspect", clientSecret),
                agentSubjects = setOf(agentId))
            val events = mutableListOf<AuditEvent>()
            val vault = Vault(OpenBaoStore(bao.base, mount, baoKeys.token), verifier, events::add)
            web = VaultWeb(vault, webPort, BrowserOidc(PinnedKeycloakCodeClient(URI(issuer), "browser"), vault)).also { it.start() }
            val browserCookies = CookieManager(null, CookiePolicy.ACCEPT_ORIGINAL_SERVER)
            val browser = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).cookieHandler(browserCookies).build()
            val login = call(browser, URI("http://127.0.0.1:$webPort/auth/login"))
            assertEquals(303, login.statusCode())
            val authPage = loginPage(browser, URI(login.headers().firstValue("Location").orElseThrow()), "human", humanPassword)
            assertEquals(302, authPage.statusCode(), "Keycloak authorization code redirect")
            val callback = URI(authPage.headers().firstValue("Location").orElseThrow())
            assertEquals("http://127.0.0.1:$webPort/auth/callback", "${callback.scheme}://${callback.authority}${callback.path}")
            assertEquals(issuer, params(callback)["iss"])
            val stateCookie = login.headers().allValues("Set-Cookie").single().substringBefore(';')
            val sentCookies = browserCookies.get(callback, emptyMap())["Cookie"].orEmpty().joinToString(";")
            assertTrue(sentCookies.contains(stateCookie) || sentCookies.contains("kk_state=\"${stateCookie.substringAfter('=')}\""), "state cookie missing on callback")
            val callbackResult = call(browser, callback)
            assertEquals(303, callbackResult.statusCode(), "callback audit=${events.map { it.action to it.outcome }}")
            val csrfResponse = call(browser, URI("http://127.0.0.1:$webPort/auth/session"))
            assertEquals(200, csrfResponse.statusCode(), "real Keycloak token + introspection")
            val csrf = Json.parseToJsonElement(csrfResponse.body()).jsonObject.getValue("csrf").jsonPrimitive.content
            fun api(path: String, method: String = "GET", json: String? = null, csrfHeader: Boolean = false): HttpResponse<String> {
                val headers = mutableMapOf<String, String>()
                if (csrfHeader) { headers["Origin"] = "http://127.0.0.1:$webPort"; headers["X-Keykeeper-CSRF"] = csrf }
                if (json != null) headers["Content-Type"] = "application/json"
                val request = HttpRequest.newBuilder(URI("http://127.0.0.1:$webPort/api/items$path"))
                headers.forEach { (name, value) -> request.header(name, value) }
                return browser.send(request.method(method, if (json == null) HttpRequest.BodyPublishers.noBody()
                    else HttpRequest.BodyPublishers.ofString(json)).build(), HttpResponse.BodyHandlers.ofString())
            }
            val fakeValue = "fake-only-${UUID.randomUUID()}"
            assertEquals(403, api("", "POST", buildJsonObject { put("value", fakeValue) }.toString()).statusCode())
            val payload = buildJsonObject { put("value", fakeValue) }.toString()
            var created: HttpResponse<String>? = null
            for (attempt in 1..20) {
                created = api("", "POST", payload, true)
                if (created.statusCode() != 409) break // fresh KV mount may reject initial CAS=0
                Thread.sleep(500)
            }
            val successful = created ?: error("No disposable KV create response")
            assertEquals(200, successful.statusCode())
            val id = Json.parseToJsonElement(successful.body()).jsonObject.getValue("id").jsonPrimitive.content
            val owner = Principal(issuer, humanId, PrincipalKind.HUMAN)
            val agent = Principal(issuer, agentId, PrincipalKind.AGENT)
            val grant = buildJsonObject {
                put("recipient", buildJsonObject { put("issuer", agent.issuer); put("subject", agent.subject); put("kind", agent.kind.name) })
                put("rights", JsonArray(listOf(JsonPrimitive("READ"))))
            }
            assertEquals(200, api("/$id/share", "POST", grant.toString(), true).statusCode())
            // REAL Keycloak device authorization: a user approves the code on another browser.
            fun deviceCli(expectSuccess: Boolean, port: Int = webPort) {
                val command = ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                    "-Djavax.net.ssl.trustStore=$keystore", "-Djavax.net.ssl.trustStorePassword=$tlsPassword",
                    "-cp", System.getProperty("java.class.path"), "net.datamancy.keykeeper.MainKt", "cli", "--device", "read", id)
                command.environment()["KEYKEEPER_OIDC_ISSUER"] = issuer
                command.environment()["KEYKEEPER_OIDC_AGENT_CLIENT"] = "device"
                command.environment()["KEYKEEPER_URL"] = "http://127.0.0.1:$port"
                val proc = command.start()
                try {
                    val prompt = proc.errorStream.bufferedReader().readLine() ?: error("Device grant unsupported (no CLI prompt)")
                    val match = Regex("Open (https://[^ ]+) and enter code ([A-Za-z0-9-]+)").find(prompt)
                        ?: error("Device grant unsupported or malformed prompt")
                    val verification = URI(match.groupValues[1] + "?user_code=" + URLEncoder.encode(match.groupValues[2], Charsets.UTF_8))
                    val deviceBrowser = http(true)
                    val page = loginPage(deviceBrowser, verification, "agent", agentPassword)
                    val actionPage = if (page.statusCode() in setOf(301, 302, 303))
                        call(deviceBrowser, URI(page.headers().firstValue("Location").orElseThrow())) else page
                    assertEquals(200, actionPage.statusCode())
                    val action = Regex("<form[^>]*action=\"([^\"]*login-actions/consent[^\"]+)\"[^>]*method=\"POST\"")
                        .find(actionPage.body())?.groupValues?.get(1)?.replace("&amp;", "&") ?: error("Device consent form missing")
                    val approvalCode = Regex("<input[^>]*name=\"code\"[^>]*value=\"([^\"]+)\"")
                        .find(actionPage.body())?.groupValues?.get(1) ?: error("Device consent code missing")
                    val approval = call(deviceBrowser, URI(issuer).resolve(action), "POST", form(mapOf("code" to approvalCode, "accept" to "Yes")))
                    val approvalResult = if (approval.statusCode() in setOf(301, 302, 303))
                        call(deviceBrowser, URI(approval.headers().firstValue("Location").orElseThrow())) else approval
                    assertEquals(200, approvalResult.statusCode())
                    check(proc.waitFor(40, TimeUnit.SECONDS)) { "Device CLI did not finish" }
                    val output = proc.inputStream.bufferedReader().readText()
                    if (expectSuccess) { assertEquals(0, proc.exitValue()); assertTrue(output.trim() == fakeValue, "agent CLI read mismatch") }
                    else { assertNotEquals(0, proc.exitValue()); assertFalse(output.contains(fakeValue)) }
                    assertFalse(prompt.contains("eyJ")) // no access token in prompts/logs
                } finally { if (proc.isAlive) proc.destroyForcibly().waitFor() }
            }
            deviceCli(true)
            val snapshot = bao.call("GET", "/v1/sys/storage/raft/snapshot", baoKeys.token, timeoutSeconds = 60)
            assertEquals(200, snapshot.statusCode()); assertTrue(snapshot.body().isNotEmpty())
            assertEquals(200, api("/$id/revoke", "POST", buildJsonObject {
                put("recipient", buildJsonObject { put("issuer", agent.issuer); put("subject", agent.subject); put("kind", agent.kind.name) })
            }.toString(), true).statusCode())
            deviceCli(false)
            assertEquals(200, call(browser, URI("http://127.0.0.1:$webPort/auth/logout"), "POST", headers = mapOf(
                "Origin" to "http://127.0.0.1:$webPort", "X-Keykeeper-CSRF" to csrf)).statusCode())
            assertEquals(403, api("/$id").statusCode())
            // Restore into a separately initialized Bao process and fresh Raft directory.
            restoreTarget = DisposableRaftRestoreTest.Node(binary, scratch.resolve("restored-bao"), "restored-${UUID.randomUUID()}")
            val targetKeys = restoreTarget.initialize()
            assertNotEquals(bao.base, restoreTarget.base)
            assertEquals(404, restoreTarget.call("GET", "/v1/$mount/data/$id", targetKeys.token).statusCode())
            val restored = restoreTarget.call("POST", "/v1/sys/storage/raft/snapshot-force", targetKeys.token,
                snapshot.body(), timeoutSeconds = 60)
            assertTrue(restored.statusCode() in setOf(200, 204))
            val restoredVault = Vault(OpenBaoStore(restoreTarget.base, mount, baoKeys.token), verifier) { }
            val probe = { restoredVault.read(owner, id) == fakeValue && restoredVault.read(agent, id) == fakeValue }
            restoreTarget.awaitRestored("before restart", baoKeys.token, targetKeys.token, baoKeys.unseal, mount, id, probe)
            restoreTarget.restart()
            restoreTarget.awaitActive(baoKeys.unseal)
            restoreTarget.awaitRestored("after restart", baoKeys.token, targetKeys.token, baoKeys.unseal, mount, id, probe)
            restoredWeb = VaultWeb(restoredVault, restoredPort,
                BrowserOidc(PinnedKeycloakCodeClient(URI(issuer), "browser"), restoredVault)).also { it.start() }
            val targetBrowser = http(true)
            val targetBase = "http://127.0.0.1:$restoredPort"
            val targetLogin = call(targetBrowser, URI("$targetBase/auth/login"))
            assertEquals(303, targetLogin.statusCode())
            val targetAuth = loginPage(targetBrowser, URI(targetLogin.headers().firstValue("Location").orElseThrow()), "human", humanPassword)
            assertEquals(302, targetAuth.statusCode())
            val targetCallback = URI(targetAuth.headers().firstValue("Location").orElseThrow())
            assertEquals(issuer, params(targetCallback)["iss"])
            assertEquals(303, call(targetBrowser, targetCallback).statusCode())
            val targetSession = call(targetBrowser, URI("$targetBase/auth/session"))
            assertEquals(200, targetSession.statusCode())
            val targetCsrf = Json.parseToJsonElement(targetSession.body()).jsonObject.getValue("csrf").jsonPrimitive.content
            assertTrue(Json.parseToJsonElement(call(targetBrowser, URI("$targetBase/api/items/$id")).body())
                .jsonObject.getValue("value").jsonPrimitive.content == fakeValue, "target browser value mismatch")
            deviceCli(true, restoredPort)
            val targetRevoke = HttpRequest.newBuilder(URI("$targetBase/api/items/$id/revoke"))
                .header("Origin", targetBase).header("X-Keykeeper-CSRF", targetCsrf).header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(buildJsonObject {
                    put("recipient", buildJsonObject { put("issuer", agent.issuer); put("subject", agent.subject); put("kind", agent.kind.name) })
                }.toString())).build()
            assertEquals(200, targetBrowser.send(targetRevoke, HttpResponse.BodyHandlers.ofString()).statusCode())
            deviceCli(false, restoredPort)
            assertTrue(restoredVault.read(owner, id) == fakeValue, "target owner after revoke mismatch")
            assertFailsWith<Denied> { restoredVault.read(agent, id) }
            // The source retains its post-snapshot revoke and is not the restored target.
            assertFailsWith<Denied> { vault.read(agent, id) }
            assertTrue(vault.read(owner, id) == fakeValue, "source owner value changed during restore")
        } finally {
            restoredWeb?.close()
            web?.close()
            restoreTarget?.close()
            bao?.close()
            keycloak?.destroy()
            if (keycloak?.waitFor(5, TimeUnit.SECONDS) == false) keycloak?.destroyForcibly()?.waitFor()
            SSLContext.setDefault(previousTls)
            Files.walk(scratch).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) } }
        }
    }
}
