package org.rustls.platformverifier

import android.annotation.SuppressLint
import android.util.Log
import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.request.header
import io.ktor.client.request.prepareGet
import io.ktor.client.statement.bodyAsChannel
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.utils.io.core.readBytes
import kotlinx.coroutines.runBlocking
import org.bouncycastle.asn1.ASN1Encoding
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.DERIA5String
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.CRLDistPoint
import org.bouncycastle.asn1.x509.CertificateList
import org.bouncycastle.asn1.x509.DistributionPointName
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import java.math.BigInteger
import java.net.HttpURLConnection
import java.net.URL
import java.security.cert.CertPathValidatorException
import java.security.cert.Certificate
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.Extensions
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.IssuingDistributionPoint
import org.bouncycastle.asn1.x509.TBSCertList
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import java.security.Signature
import java.security.cert.PKIXCertPathChecker
import java.security.cert.X509Certificate
import java.util.Date

@SuppressLint("LogNotTimber")
class CRLChecker(private val chain: List<X509Certificate>) : PKIXCertPathChecker() {
    companion object {
        private const val TAG = "CRLChecker"
        private const val TIMEOUT_MS = 15_000
        private const val MAX_CRL_SIZE = 32 * 1024 * 1024

        // Ktor CIO opens its own sockets, so it is not subject to the app's network security
        // config, which typically forbids cleartext traffic (unlike HttpURLConnection or OkHttp).
        private val cleartextHttpClient by lazy {
            HttpClient(CIO) {
                expectSuccess = false
                followRedirects = true
                install(HttpTimeout) {
                    connectTimeoutMillis = TIMEOUT_MS.toLong()
                    socketTimeoutMillis = TIMEOUT_MS.toLong()
                    requestTimeoutMillis = TIMEOUT_MS.toLong()
                }
            }
        }

        // Index of the cRLSign bit in X509Certificate.getKeyUsage()
        private const val KEY_USAGE_CRL_SIGN = 6

        // Critical CRL extensions processed by this checker (RFC 5280, section 5.2)
        private val SUPPORTED_CRITICAL_CRL_EXTENSIONS = setOf(Extension.issuingDistributionPoint)

        private val SIGNATURE_ALGORITHMS = mapOf<ASN1ObjectIdentifier, String>(
            PKCSObjectIdentifiers.sha1WithRSAEncryption to "SHA1withRSA",
            PKCSObjectIdentifiers.sha256WithRSAEncryption to "SHA256withRSA",
            PKCSObjectIdentifiers.sha384WithRSAEncryption to "SHA384withRSA",
            PKCSObjectIdentifiers.sha512WithRSAEncryption to "SHA512withRSA",
            X9ObjectIdentifiers.ecdsa_with_SHA1 to "SHA1withECDSA",
            X9ObjectIdentifiers.ecdsa_with_SHA256 to "SHA256withECDSA",
            X9ObjectIdentifiers.ecdsa_with_SHA384 to "SHA384withECDSA",
            X9ObjectIdentifiers.ecdsa_with_SHA512 to "SHA512withECDSA",
            ASN1ObjectIdentifier("1.3.101.112") to "Ed25519", // id-Ed25519
        )
    }

    override fun init(forward: Boolean) {}
    override fun isForwardCheckingSupported(): Boolean = true
    override fun getSupportedExtensions(): Set<String>? = null

    override fun check(cert: Certificate?, unresolvedCritExts: MutableCollection<String>?) {
        if (cert !is X509Certificate) return

        // Only the leaf (end-entity) certificate is checked, parent CAs are skipped
        if (cert != chain.firstOrNull()) return

        val crlUrls = extractCrlUrls(cert)
        if (crlUrls.isEmpty()) return

        val issuer = findIssuer(cert)
        if (issuer == null) {
            Log.w(
                TAG, "Issuer of ${cert.subjectX500Principal} not found in chain, skipping CRL check"
            )
            return
        }

        val isRevoked = checkIsRevoked(cert, issuer, crlUrls)
        if (isRevoked) {
            throw CertPathValidatorException(
                "Certificate revoked - CRL",
                null,
                null,
                -1,
                CertPathValidatorException.BasicReason.REVOKED
            )
        }
    }

    private fun findIssuer(cert: X509Certificate): X509Certificate? {
        val index = chain.indexOf(cert)
        if (index == -1) return null

        // The chain is ordered from the end-entity towards the root
        return chain.getOrNull(index + 1)
            ?: cert.takeIf { it.issuerX500Principal == it.subjectX500Principal }
    }

    private fun extractCrlUrls(cert: X509Certificate): List<String> {
        val crlUrls = mutableListOf<String>()

        // Get the raw DER-encoded OCTET string for the CDP extension (OID 2.5.29.31)
        val extValue =
            cert.getExtensionValue(Extension.cRLDistributionPoints.id) ?: return emptyList()

        try {
            // Step 1: Parse out the wrapping Octet String wrap
            val oStream = ASN1InputStream(extValue)
            val derOctetString =
                oStream.readObject() as? org.bouncycastle.asn1.ASN1OctetString ?: return emptyList()

            // Step 2: Parse the internal content into the BouncyCastle structure
            val crlInputStream = ASN1InputStream(derOctetString.octets)
            val asn1Primitive: ASN1Primitive = crlInputStream.readObject()
            val distPoint = CRLDistPoint.getInstance(asn1Primitive)

            // Step 3: Loop through distribution points to locate Uniform Resource Identifiers (URIs)
            for (dp in distPoint.distributionPoints) {
                crlUrls.addAll(fullNameUris(dp.distributionPoint))
            }
        } catch (e: Throwable) {
            Log.w(TAG, "Failed to extract CRL distribution URL", e)
        }

        return crlUrls
    }

    private fun fullNameUris(dpn: DistributionPointName?): List<String> {
        if (dpn == null || dpn.type != DistributionPointName.FULL_NAME) return emptyList()

        return GeneralNames.getInstance(dpn.name).names
            .filter { it.tagNo == GeneralName.uniformResourceIdentifier }
            .map { DERIA5String.getInstance(it.name).string }
    }

    // checks revocation of the `cert` using its `crlUrls`.
    // returns true only if a valid CRL mentions this certificate
    // returns false if:
    // - a valid CRL is fetched and does not mention the `cert`
    // - or if none of the CRLs are valid/cannot be fetched or the check cannot be performed for a reason (logs error/warning in this case)
    private fun checkIsRevoked(
        cert: X509Certificate, issuer: X509Certificate, crlUrls: List<String>
    ): Boolean {
        // RFC 5280, section 6.3.3 (f): the CRL issuer key must be allowed to sign CRLs.
        // A missing key usage extension places no restriction on the key.
        val keyUsage = issuer.keyUsage
        if (keyUsage != null && keyUsage.getOrNull(KEY_USAGE_CRL_SIGN) != true) {
            Log.e(TAG, "Issuer ${issuer.subjectX500Principal} is not allowed to sign CRLs")
            return false
        }

        for (crlUrl in crlUrls) {
            try {
                val crl = downloadCrl(crlUrl) ?: continue

                val issuerName = X500Name.getInstance(issuer.subjectX500Principal.encoded)
                if (crl.issuer != issuerName) {
                    Log.e(TAG, "CRL from $crlUrl issued by ${crl.issuer}, expected $issuerName")
                    continue
                }
                if (!verifySignature(crl, issuer)) {
                    Log.e(TAG, "Invalid CRL signature from $crlUrl")
                    continue
                }

                val nextUpdate = crl.nextUpdate?.date
                if (nextUpdate != null && nextUpdate.before(Date())) {
                    Log.e(TAG, "CRL from $crlUrl is outdated, nextUpdate: $nextUpdate")
                    continue
                }

                val crlExtensions = crl.tbsCertList.extensions
                if (hasUnsupportedCriticalExtensions(crlExtensions, SUPPORTED_CRITICAL_CRL_EXTENSIONS)) {
                    Log.e(TAG, "CRL from $crlUrl contains unsupported critical extensions")
                    continue
                }
                if (!isInScope(crlExtensions, cert, crlUrls)) {
                    Log.e(TAG, "CRL from $crlUrl does not cover ${cert.subjectX500Principal}")
                    continue
                }

                val isRevoked = findRevocation(crl, cert.serialNumber)

                // CRL successfully downloaded and parsed
                return isRevoked
            } catch (e: Throwable) {
                Log.w(TAG, "Failed to check CRL from $crlUrl", e)
            }
        }

        Log.w(TAG, "No CRL check succeeded")
        return false
    }

    private fun hasUnsupportedCriticalExtensions(
        extensions: Extensions?, supported: Set<ASN1ObjectIdentifier>
    ): Boolean = extensions?.criticalExtensionOIDs?.any { it !in supported } ?: false

    /**
     * Checks the issuing distribution point extension (RFC 5280, section 5.2.5), which restricts
     * the scope of the CRL. Partitioned CRLs not covering [cert] must not be used for it.
     */
    private fun isInScope(extensions: Extensions?, cert: X509Certificate, certCrlUrls: List<String>): Boolean {
        val idpValue = extensions?.getExtensionParsedValue(Extension.issuingDistributionPoint) ?: return true
        val idp = IssuingDistributionPoint.getInstance(idpValue)

        // Indirect CRLs and CRLs partitioned by revocation reason are not supported
        if (idp.isIndirectCRL || idp.onlySomeReasons != null || idp.onlyContainsAttributeCerts()) {
            return false
        }

        val isCA = cert.basicConstraints != -1
        if (idp.onlyContainsUserCerts() && isCA) return false
        if (idp.onlyContainsCACerts() && !isCA) return false

        // The distribution point name must match one of the certificate's distribution points
        val idpName = idp.distributionPoint ?: return true
        if (idpName.type != DistributionPointName.FULL_NAME) return false
        return fullNameUris(idpName).any { it in certCrlUrls }
    }

    private fun findRevocation(crl: CertificateList, serialNumber: BigInteger): Boolean {
        val entries = crl.revokedCertificateEnumeration
        while (entries.hasMoreElements()) {
            val entry = entries.nextElement() as TBSCertList.CRLEntry
            if (entry.userCertificate.value == serialNumber) {
                return true
            }
        }
        return false
    }

    private fun downloadCrl(crlUrl: String): CertificateList? {
        val url = URL(crlUrl)
        return when (url.protocol.lowercase()) {
            // Plain HTTP bypasses the app's network security config (see cleartextHttpClient).
            // This is safe, as the CRL signature is verified against the issuer afterwards.
            "http" -> downloadCrlOverCleartext(url)
            "https" -> downloadCrlOverHttps(url)
            else -> {
                Log.w(TAG, "Unsupported CRL URL scheme: $crlUrl")
                null
            }
        }
    }

    private fun downloadCrlOverHttps(url: URL): CertificateList? {
        val connection = url.openConnection() as HttpURLConnection
        try {
            connection.connectTimeout = TIMEOUT_MS
            connection.readTimeout = TIMEOUT_MS
            connection.requestMethod = "GET"

            if (connection.responseCode != HttpURLConnection.HTTP_OK) {
                Log.w(TAG, "Failed to download CRL from $url: HTTP ${connection.responseCode}")
                return null
            }

            return connection.inputStream.use { readCrl(it) }
        } finally {
            connection.disconnect()
        }
    }

    private fun downloadCrlOverCleartext(url: URL): CertificateList? = runBlocking {
        cleartextHttpClient.prepareGet(url.toString()) {
            header(HttpHeaders.Accept, "application/pkix-crl, */*")
        }.execute { response ->
            if (response.status != HttpStatusCode.OK) {
                Log.w(TAG, "Failed to download CRL from $url: HTTP ${response.status}")
                return@execute null
            }

            val body = response.bodyAsChannel().readRemaining(MAX_CRL_SIZE + 1L).readBytes()
            if (body.size > MAX_CRL_SIZE) throw IOException("CRL from $url too large")

            readCrl(ByteArrayInputStream(body))
        }
    }

    private fun readCrl(input: InputStream): CertificateList =
        ASN1InputStream(input, MAX_CRL_SIZE).use { asn1Stream ->
            CertificateList.getInstance(asn1Stream.readObject())
        }

    private fun verifySignature(crl: CertificateList, issuer: X509Certificate): Boolean {
        val algorithm = crl.signatureAlgorithm.algorithm
        val algorithmName = SIGNATURE_ALGORITHMS[algorithm]
        if (algorithmName == null) {
            Log.w(TAG, "Unsupported CRL signature algorithm: $algorithm")
            return false
        }

        // The outer and the signed (TBS) algorithm identifiers must match
        if (crl.tbsCertList.signature != crl.signatureAlgorithm) {
            Log.w(TAG, "CRL signature algorithm mismatch")
            return false
        }

        return try {
            Signature.getInstance(algorithmName).run {
                initVerify(issuer.publicKey)
                update(crl.tbsCertList.getEncoded(ASN1Encoding.DER))
                verify(crl.signature.octets)
            }
        } catch (e: Throwable) {
            Log.w(TAG, "CRL signature verification failed", e)
            false
        }
    }
}
