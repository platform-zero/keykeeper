package net.datamancy.keykeeper

import kotlinx.serialization.json.*
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

/** Device authorization flow for non-interactive agents; token remains in CLI memory. */
class DeviceOidc internal constructor(private val issuer: URI, private val clientId: String, private val allowLocalFake: Boolean = false) {
    init {
        require(issuer.host != null && issuer.rawUserInfo == null && issuer.rawQuery == null && issuer.rawFragment == null && clientId.isNotBlank())
        require(issuer.scheme == "https" || (allowLocalFake && issuer.scheme == "http" && issuer.host == "127.0.0.1"))
    }
    private val http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).followRedirects(HttpClient.Redirect.NEVER).build()
    private fun post(path: String, params: Map<String, String>): Pair<Int, JsonObject> {
        val endpoint = URI(issuer.toString().trimEnd('/') + "/protocol/openid-connect/$path")
        val request = HttpRequest.newBuilder(endpoint).timeout(Duration.ofSeconds(5)).header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(form(params))).build()
        val response = http.send(request, HttpResponse.BodyHandlers.ofInputStream())
        return response.body().use { stream ->
            val bytes = stream.readNBytes(65_537)
            if (bytes.size > 65_536) throw Denied()
            response.statusCode() to Json.parseToJsonElement(bytes.toString(Charsets.UTF_8)).jsonObject
        }
    }
    fun login(show: (String) -> Unit = System.err::println): String {
        val (status, pending) = post("auth/device", mapOf("client_id" to clientId, "scope" to "openid"))
        if (status != 200) throw Denied()
        val code = pending.getValue("device_code").jsonPrimitive.content
        val userCode = pending.getValue("user_code").jsonPrimitive.content
        val url = URI(pending.getValue("verification_uri").jsonPrimitive.content)
        require(url.scheme == issuer.scheme && url.host == issuer.host && url.port == issuer.port &&
            url.rawUserInfo == null && url.rawQuery == null && url.rawFragment == null)
        val expires = pending.getValue("expires_in").jsonPrimitive.int.coerceIn(1, 600)
        var interval = pending.getValue("interval").jsonPrimitive.int.coerceIn(1, 30)
        show("Open $url and enter code $userCode (never enter an access token in arguments)")
        val deadline = System.nanoTime() + Duration.ofSeconds(expires.toLong()).toNanos()
        while (System.nanoTime() < deadline) {
            Thread.sleep(interval * 1000L)
            val (result, payload) = post("token", mapOf("client_id" to clientId,
                "grant_type" to "urn:ietf:params:oauth:grant-type:device_code", "device_code" to code))
            if (result == 200 && payload["token_type"]?.jsonPrimitive?.content == "Bearer")
                return payload.getValue("access_token").jsonPrimitive.content.takeIf { it.isNotBlank() } ?: throw Denied()
            when (payload["error"]?.jsonPrimitive?.content) {
                "authorization_pending" -> Unit
                "slow_down" -> interval = (interval + 5).coerceAtMost(30)
                else -> throw Denied()
            }
        }
        throw Denied()
    }
}
