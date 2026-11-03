package net.datamancy.keykeeper

import java.net.URI
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.security.KeyFactory
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext

/** Explicit direct HTTPS serving. Plain HTTP remains loopback-only; no forwarded-header trust. */
data class HttpsEndpoint(val origin: URI, val context: SSLContext) {
    init {
        require(origin.scheme == "https" && origin.host != null && origin.host == origin.host.lowercase() &&
            origin.rawUserInfo == null && origin.rawQuery == null && origin.rawFragment == null &&
            origin.rawPath.isEmpty() && origin.port in 1..65535) { "An exact HTTPS origin with explicit port is required" }
    }
    companion object {
        fun load(origin: URI, certificate: Path, privateKey: Path): HttpsEndpoint {
            fun bytes(path: Path): ByteArray {
                require(Files.isRegularFile(path, NOFOLLOW_LINKS) && Files.size(path) in 1..65536) { "Invalid TLS input" }
                return Files.readAllBytes(path)
            }
            val certificates = CertificateFactory.getInstance("X.509").generateCertificates(bytes(certificate).inputStream()).toTypedArray()
            require(certificates.isNotEmpty())
            val pem = bytes(privateKey).toString(Charsets.US_ASCII).trim()
            require(pem.startsWith("-----BEGIN PRIVATE KEY-----") && pem.endsWith("-----END PRIVATE KEY-----"))
            val raw = pem.removePrefix("-----BEGIN PRIVATE KEY-----").removeSuffix("-----END PRIVATE KEY-----").filterNot(Char::isWhitespace)
            val key = KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(Base64.getDecoder().decode(raw)))
            // Catch mismatched certificate/key before binding a serving socket.
            val challenge = ByteArray(32).also(java.security.SecureRandom()::nextBytes)
            val signature = java.security.Signature.getInstance("SHA256withRSA").apply { initSign(key); update(challenge) }.sign()
            require(java.security.Signature.getInstance("SHA256withRSA").run { initVerify(certificates.first()); update(challenge); verify(signature) })
            val password = CharArray(0)
            val store = KeyStore.getInstance("PKCS12").apply { load(null, password); setKeyEntry("server", key, password, certificates) }
            val managers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(store, password) }
            return HttpsEndpoint(origin, SSLContext.getInstance("TLS").apply { init(managers.keyManagers, null, null) })
        }
    }
}
