package net.datamancy.keykeeper

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import com.sun.net.httpserver.HttpsServer
import com.sun.net.httpserver.HttpsConfigurator
import com.sun.net.httpserver.HttpsParameters
import kotlinx.serialization.json.*
import java.net.InetSocketAddress
import java.nio.charset.StandardCharsets
import java.util.UUID
import java.util.concurrent.Executors

/** HTTP stays loopback-only. External serving requires an explicit TLS endpoint; no proxy header inference. */
class VaultWeb(private val vault: Vault, port: Int = 0, private val browser: BrowserOidc? = null,
               private val https: HttpsEndpoint? = null) : AutoCloseable {
    private val executor = Executors.newFixedThreadPool(4)
    private val server: HttpServer = (if (https == null) HttpServer.create(InetSocketAddress("127.0.0.1", port), 16) else {
        require(port == https.origin.port)
        HttpsServer.create(InetSocketAddress("0.0.0.0", port), 16).apply {
            httpsConfigurator = object : HttpsConfigurator(https.context) {
                override fun configure(parameters: HttpsParameters) {
                    parameters.setSSLParameters(https.context.defaultSSLParameters.apply { protocols = arrayOf("TLSv1.3", "TLSv1.2") })
                }
            }
        }
    }).apply {
        createContext("/") { exchange -> handle(exchange) }
        this.executor = this@VaultWeb.executor
    }
    val port: Int get() = server.address.port
    val origin: String get() = https?.origin?.toString() ?: "http://127.0.0.1:$port"
    private val stateCookie = if (https == null) "kk_state" else "__Host-kk_state"
    private val sessionCookie = if (https == null) "kk_session" else "__Host-kk_session"
    private val statePath = if (https == null) "/auth" else "/"
    private val secure = if (https == null) "" else "; Secure"
    fun start() = server.start()
    override fun close() { server.stop(0); executor.shutdownNow() }

    private fun reply(x: HttpExchange, code: Int, body: String, type: String = "application/json") {
        x.responseHeaders.set("Content-Type", "$type; charset=utf-8")
        x.responseHeaders.set("Cache-Control", "no-store")
        x.responseHeaders.set("X-Content-Type-Options", "nosniff")
        x.responseHeaders.set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
        val bytes = body.toByteArray(StandardCharsets.UTF_8)
        x.sendResponseHeaders(code, bytes.size.toLong())
        x.responseBody.use { it.write(bytes) }
    }
    private fun body(x: HttpExchange): JsonObject {
        if (x.requestHeaders.getFirst("Content-Type")?.substringBefore(';') != "application/json") throw IllegalArgumentException()
        val bytes = x.requestBody.use { it.readNBytes(65537) }
        if (bytes.size > 65536) throw IllegalArgumentException()
        return Json.parseToJsonElement(String(bytes, StandardCharsets.UTF_8)).jsonObject
    }
    private fun cookie(x: HttpExchange, name: String): String? = x.requestHeaders.getFirst("Cookie")?.split(';')
        ?.map { it.trim().split('=', limit = 2) }?.firstOrNull { it.size == 2 && it[0] == name }?.get(1)?.removeSurrounding("\"")
    private fun redirect(x: HttpExchange, url: String) {
        x.responseHeaders.set("Location", url)
        x.responseHeaders.set("Cache-Control", "no-store")
        x.responseHeaders.set("Referrer-Policy", "no-referrer")
        x.sendResponseHeaders(303, -1)
    }
    private fun sameOrigin(x: HttpExchange): Boolean = x.requestHeaders.getFirst("Origin") == origin
    private fun handle(x: HttpExchange) {
        try {
            if (https != null && x.requestHeaders.getFirst("Host") != https.origin.rawAuthority) throw Denied()
            val path = x.requestURI.rawPath
            val redirectUri = java.net.URI("$origin/auth/callback")
            if (browser != null && x.requestMethod == "GET" && path == "/auth/login" && x.requestURI.rawQuery == null) {
                val (url, stateCookie) = browser.begin(redirectUri)
                x.responseHeaders.add("Set-Cookie", "${this.stateCookie}=$stateCookie; HttpOnly; SameSite=Lax; Path=$statePath; Max-Age=300$secure")
                redirect(x, url.toString()); return
            }
            if (browser != null && x.requestMethod == "GET" && path == "/auth/callback") {
                val params = x.requestURI.rawQuery?.split('&')?.map { it.split('=', limit = 2) } ?: emptyList()
                val names = params.map { it[0] }
                if (params.any { it.size != 2 } || names.distinct().size != names.size ||
                    !names.containsAll(listOf("state", "code")) || names.any { it !in setOf("state", "code", "iss", "session_state") }) throw Denied()
                fun param(name: String) = params.firstOrNull { it[0] == name }?.get(1)?.let { java.net.URLDecoder.decode(it, Charsets.UTF_8) }
                val session = browser.finish(param("state")!!, cookie(x, stateCookie), param("code")!!, redirectUri, param("iss"))
                x.responseHeaders.add("Set-Cookie", "$stateCookie=; HttpOnly; SameSite=Lax; Path=$statePath; Max-Age=0$secure")
                x.responseHeaders.add("Set-Cookie", "$sessionCookie=$session; HttpOnly; SameSite=Strict; Path=/; Max-Age=900$secure")
                redirect(x, "/"); return
            }
            if (browser != null && path == "/auth/session" && x.requestMethod == "GET" && x.requestURI.rawQuery == null) {
                val session = browser.session(cookie(x, sessionCookie)) ?: throw Denied()
                vault.authenticate(session.token) // fail closed if revoked/expired since login
                reply(x, 200, buildJsonObject { put("csrf", session.csrf) }.toString()); return
            }
            if (browser != null && path == "/auth/logout" && x.requestMethod == "POST" && x.requestURI.rawQuery == null) {
                val session = browser.session(cookie(x, sessionCookie)) ?: throw Denied()
                if (!sameOrigin(x) || x.requestHeaders.getFirst("X-Keykeeper-CSRF") != session.csrf) throw Denied()
                browser.logout(cookie(x, sessionCookie))
                x.responseHeaders.add("Set-Cookie", "$sessionCookie=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0$secure")
                reply(x, 200, "{}"); return
            }
            if (x.requestURI.rawQuery != null) { reply(x, 400, "{}", "application/json"); return }
            if (x.requestMethod == "GET" && path == "/") {
                reply(x, 200, javaClass.getResource("/vault.html")!!.readText(), "text/html"); return
            }
            if (x.requestMethod == "GET" && path == "/vault.css") {
                reply(x, 200, javaClass.getResource("/vault.css")!!.readText(), "text/css"); return
            }
            if (x.requestMethod == "GET" && path == "/vault.js") {
                reply(x, 200, javaClass.getResource("/vault.js")!!.readText(), "text/javascript"); return
            }
            val auth = x.requestHeaders.getFirst("Authorization")
            val session = if (auth == null) browser?.session(cookie(x, sessionCookie)) else null
            val bearer = if (auth != null) {
                if (!auth.startsWith("Bearer ") || auth.length > 4096) throw Denied()
                auth.removePrefix("Bearer ")
            } else session?.token ?: throw Denied()
            if (session != null && x.requestMethod !in setOf("GET", "HEAD")) {
                if (!sameOrigin(x) || x.requestHeaders.getFirst("X-Keykeeper-CSRF") != session.csrf) throw Denied()
            }
            val actor = vault.authenticate(bearer)
            val parts = path.split('/').drop(1)
            val result: JsonElement = when {
                parts == listOf("api", "items") && x.requestMethod == "GET" ->
                    JsonArray(vault.list(actor).map { it.toJson() })
                parts == listOf("api", "items") && x.requestMethod == "POST" ->
                    vault.create(actor, body(x).getValue("value").jsonPrimitive.content).toJson()
                parts.size == 3 && parts.take(2) == listOf("api", "items") && x.requestMethod == "GET" ->
                    buildJsonObject { put("value", vault.read(actor, parts[2])) }
                parts.size == 3 && parts.take(2) == listOf("api", "items") && x.requestMethod == "PUT" -> {
                    val data = body(x)
                    vault.edit(actor, parts[2], data.getValue("value").jsonPrimitive.content, data["expectedVersion"]?.jsonPrimitive?.int)
                    buildJsonObject { put("updated", true) }
                }
                parts.size == 4 && parts.take(2) == listOf("api", "items") && x.requestMethod == "GET" && parts[3] == "version" ->
                    buildJsonObject { put("version", vault.version(actor, parts[2])) }
                parts.size == 4 && parts.take(2) == listOf("api", "items") && x.requestMethod == "POST" && parts[3] == "rotate" ->
                    vault.rotate(actor, parts[2], body(x).getValue("value").jsonPrimitive.content).toJson()
                parts.size == 4 && parts.take(2) == listOf("api", "items") && x.requestMethod == "POST" && parts[3] == "retire" -> {
                    require(body(x).isEmpty())
                    vault.retire(actor, parts[2]).toJson()
                }
                parts.size == 4 && parts.take(2) == listOf("api", "items") && x.requestMethod == "POST" && parts[3] == "share" -> {
                    val data = body(x)
                    val grant = Grant(data.getValue("recipient").jsonObject.principal(),
                        data.getValue("rights").jsonArray.map { Right.valueOf(it.jsonPrimitive.content) }.toSet())
                    vault.share(actor, parts[2], grant).toJson()
                }
                parts.size == 4 && parts.take(2) == listOf("api", "items") && x.requestMethod == "POST" && parts[3] == "revoke" ->
                    vault.revoke(actor, parts[2], body(x).getValue("recipient").jsonObject.principal()).toJson()
                else -> throw Missing()
            }
            reply(x, 200, result.toString())
        } catch (_: Denied) { reply(x, 403, "{}")
        } catch (_: Missing) { reply(x, 404, "{}")
        } catch (_: Conflict) { reply(x, 409, "{}")
        } catch (_: IllegalArgumentException) { reply(x, 400, "{}")
        } catch (_: NoSuchElementException) { reply(x, 400, "{}")
        } catch (_: Exception) { reply(x, 503, "{}")
        } finally { x.close() }
    }
}
