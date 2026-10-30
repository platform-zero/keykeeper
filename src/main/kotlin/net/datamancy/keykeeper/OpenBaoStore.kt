package net.datamancy.keykeeper

import kotlinx.serialization.json.*
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

/** KV-v2 data and metadata API; deliberately restricted to loopback for this local/test slice. */
class OpenBaoStore(base: URI, private val mount: String, private val token: String) : CredentialStore {
    init {
        require(base.scheme in setOf("http", "https") && base.host in setOf("localhost", "127.0.0.1", "::1") &&
            base.rawUserInfo == null && base.rawQuery == null && base.rawFragment == null && (base.path == "" || base.path == "/"))
        require(mount.matches(Regex("[a-zA-Z0-9_-]+")) && token.isNotBlank())
    }
    private val root = base.toString().trimEnd('/') + "/v1/$mount/"
    private val client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build()
    private val json = Json

    private fun request(method: String, path: String, body: String? = null): HttpResponse<String> {
        val builder = HttpRequest.newBuilder(URI.create(root + path))
            .timeout(Duration.ofSeconds(5)).header("X-Vault-Token", token)
        if (body != null) builder.header("Content-Type", "application/json")
        val req = builder.method(method, if (body == null) HttpRequest.BodyPublishers.noBody() else HttpRequest.BodyPublishers.ofString(body)).build()
        // Never propagate HTTP errors containing token/value or upstream response bodies.
        return try { client.send(req, HttpResponse.BodyHandlers.ofString()) }
        catch (_: Exception) { throw IllegalStateException("OpenBao unavailable") }
    }

    override fun keys(): List<String> {
        val response = request("LIST", "metadata/")
        if (response.statusCode() == 404) return emptyList()
        if (response.statusCode() != 200) throw IllegalStateException("OpenBao list failed")
        return try { json.parseToJsonElement(response.body()).jsonObject.getValue("data").jsonObject.getValue("keys")
            .jsonArray.map { it.jsonPrimitive.content } }
        catch (_: Exception) { throw IllegalStateException("Invalid OpenBao list response") }
    }

    override fun get(id: String): StoredCredential? {
        require(id.matches(Regex("[0-9a-f-]{36}")))
        val response = request("GET", "data/$id")
        if (response.statusCode() == 404) return null
        if (response.statusCode() != 200) throw IllegalStateException("OpenBao read failed")
        return try {
            val envelope = json.parseToJsonElement(response.body()).jsonObject.getValue("data").jsonObject
            val data = envelope.getValue("data").jsonObject
            val record = data.getValue("record").jsonObject
            StoredCredential(record.getValue("metadata").jsonObject.metadata(), record.getValue("value").jsonPrimitive.content,
                envelope.getValue("metadata").jsonObject.getValue("version").jsonPrimitive.int)
        } catch (_: Exception) { throw IllegalStateException("Invalid OpenBao read response") }
    }

    override fun put(item: StoredCredential, expectedVersion: Int) {
        require(item.metadata.id.matches(Regex("[0-9a-f-]{36}")) && expectedVersion >= 0)
        val body = buildJsonObject {
            put("options", buildJsonObject { put("cas", expectedVersion) })
            put("data", buildJsonObject { put("record", buildJsonObject {
                put("metadata", item.metadata.toJson()); put("value", item.value)
            }) })
        }.toString()
        val response = request("POST", "data/${item.metadata.id}", body)
        when (response.statusCode()) {
            200, 204 -> Unit
            400, 409 -> throw Conflict() // KV-v2 CAS mismatches return 400
            else -> throw IllegalStateException("OpenBao write failed")
        }
    }
}
