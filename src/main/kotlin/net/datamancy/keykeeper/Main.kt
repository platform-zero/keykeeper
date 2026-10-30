package net.datamancy.keykeeper

import kotlinx.serialization.json.*
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.io.Reader

private fun env(key: String, environment: (String) -> String? = System::getenv): String =
    environment(key)?.takeIf { it.isNotBlank() } ?: error("Missing $key")

fun main(args: Array<String>) {
    try {
        when (args.firstOrNull()) {
            "serve" -> {
                require(args.toList() == listOf("serve", "--local-test")) { "Explicit --local-test required" }
                val web = serveLocalTest()
                Runtime.getRuntime().addShutdownHook(Thread { web.close() })
                println("Keykeeper LOCAL TEST at http://127.0.0.1:${web.port}/")
            }
            "cli" -> cli(args.drop(1))
            else -> error("Usage: serve --local-test | cli list|read ID|create|edit ID|share ID ISSUER SUBJECT HUMAN|AGENT RIGHTS|revoke ID ISSUER SUBJECT HUMAN|AGENT")
        }
    } catch (_: Exception) {
        System.err.println("Keykeeper request/configuration failed (no secret details printed)")
        kotlin.system.exitProcess(1)
    }
}

internal fun serveLocalTest(environment: (String) -> String? = System::getenv, audit: AuditSink = AuditSink { event ->
    println("audit action=${event.action} actor=${event.actorHash} item=${event.itemId} outcome=${event.outcome}")
}): VaultWeb {
    val principal = Principal(env("KEYKEEPER_TEST_ISSUER", environment), env("KEYKEEPER_TEST_SUBJECT", environment),
        PrincipalKind.valueOf(env("KEYKEEPER_TEST_KIND", environment)))
    val store = OpenBaoStore(URI(env("KEYKEEPER_BAO_URL", environment)), env("KEYKEEPER_BAO_MOUNT", environment),
        env("KEYKEEPER_BAO_TOKEN", environment))
    val subjects = mutableMapOf(env("KEYKEEPER_TEST_TOKEN", environment) to principal)
    environment("KEYKEEPER_TEST_AGENT_TOKEN")?.takeIf { it.isNotBlank() }?.let { token ->
        require(token !in subjects)
        subjects[token] = Principal(principal.issuer, env("KEYKEEPER_TEST_AGENT_SUBJECT", environment), PrincipalKind.AGENT)
    }
    val port = environment("KEYKEEPER_PORT")?.toInt() ?: 8765
    require(port in 1..65535)
    val web = VaultWeb(Vault(store, LocalTestVerifier(subjects), audit), port)
    web.start()
    return web
}

internal fun cli(args: List<String>, environment: (String) -> String? = System::getenv,
                 input: Reader = System.`in`.reader(), output: (String) -> Unit = ::println) {
    val base = URI(environment("KEYKEEPER_URL") ?: "http://127.0.0.1:8765")
    require(base.scheme == "http" && base.host in setOf("127.0.0.1", "localhost", "::1") && base.rawUserInfo == null &&
        base.rawQuery == null && base.rawFragment == null && (base.path == "" || base.path == "/"))
    val token = env("KEYKEEPER_TEST_TOKEN", environment)
    val path: String
    val method: String
    val payload: JsonElement?
    when (args.firstOrNull()) {
        "list" -> { require(args.size == 1); path = ""; method = "GET"; payload = null }
        "read" -> { require(args.size == 2); path = "/${id(args[1])}"; method = "GET"; payload = null }
        "create", "edit" -> {
            require(args.size == if (args[0] == "create") 1 else 2)
            path = if (args[0] == "create") "" else "/${id(args[1])}"
            method = if (args[0] == "create") "POST" else "PUT"
            // The value must be piped via stdin, never passed as an argument or environment variable.
            val value = input.readText()
            payload = buildJsonObject { put("value", value) }
        }
        "share", "revoke" -> {
            require(args.size == if (args[0] == "share") 6 else 5)
            path = "/${id(args[1])}/${args[0]}"; method = "POST"
            val principal = Principal(args[2], args[3], PrincipalKind.valueOf(args[4]))
            payload = buildJsonObject {
                put("recipient", principal.toJson())
                if (args[0] == "share") put("rights", JsonArray(args[5].split(',').map { JsonPrimitive(Right.valueOf(it).name) }))
            }
        }
        else -> error("Unknown command")
    }
    val request = HttpRequest.newBuilder(base.resolve("/api/items$path"))
        .timeout(Duration.ofSeconds(6)).header("Authorization", "Bearer $token")
        .apply { if (payload != null) header("Content-Type", "application/json") }
        .method(method, if (payload == null) HttpRequest.BodyPublishers.noBody() else HttpRequest.BodyPublishers.ofString(payload.toString()))
        .build()
    val response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString())
    require(response.statusCode() == 200) { "Request failed" }
    if (args[0] == "read") output(Json.parseToJsonElement(response.body()).jsonObject.getValue("value").jsonPrimitive.content)
    else output(response.body())
}

private fun id(value: String): String {
    require(runCatching { java.util.UUID.fromString(value).toString() }.getOrNull() == value)
    return value
}
