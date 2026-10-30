package net.datamancy.keykeeper

import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import kotlin.test.*

class ServeTest {
    @Test fun `local server wires two fixed test identities to loopback Bao and rejects invalid config`() {
        val fake = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        fake.createContext("/v1/fake/metadata/") { exchange ->
            val payload = "{\"data\":{\"keys\":[]}}".toByteArray()
            exchange.sendResponseHeaders(200, payload.size.toLong())
            exchange.responseBody.use { it.write(payload) }
        }
        fake.start()
        try {
            val port = ServerSocket(0).use { it.localPort }
            val vars = mapOf("KEYKEEPER_TEST_ISSUER" to "fake", "KEYKEEPER_TEST_SUBJECT" to "person",
                "KEYKEEPER_TEST_KIND" to "HUMAN", "KEYKEEPER_TEST_TOKEN" to "fake-person-token-012345678901234",
                "KEYKEEPER_TEST_AGENT_TOKEN" to "fake-agent-token-0123456789012345", "KEYKEEPER_TEST_AGENT_SUBJECT" to "bot",
                "KEYKEEPER_BAO_URL" to "http://127.0.0.1:${fake.address.port}", "KEYKEEPER_BAO_MOUNT" to "fake",
                "KEYKEEPER_BAO_TOKEN" to "fake-bao-token", "KEYKEEPER_PORT" to "$port")
            val events = mutableListOf<AuditEvent>()
            serveLocalTest(vars::get, events::add).use { web ->
                val req = HttpRequest.newBuilder(URI("http://127.0.0.1:${web.port}/api/items"))
                    .header("Authorization", "Bearer ${vars.getValue("KEYKEEPER_TEST_AGENT_TOKEN")}").build()
                val response = HttpClient.newHttpClient().send(req, HttpResponse.BodyHandlers.ofString())
                assertEquals(200, response.statusCode())
                assertEquals("[]", response.body())
                assertEquals("list", events.single().action)
            }
            assertFailsWith<IllegalArgumentException> { serveLocalTest((vars + ("KEYKEEPER_PORT" to "0"))::get) }
            assertFailsWith<IllegalArgumentException> {
                serveLocalTest((vars + ("KEYKEEPER_TEST_AGENT_TOKEN" to vars.getValue("KEYKEEPER_TEST_TOKEN")))::get)
            }
        } finally { fake.stop(0) }
    }
}
