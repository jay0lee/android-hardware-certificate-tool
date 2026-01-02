package com.jaylee.hardware_cert_tool

import android.content.Context
import android.content.Intent
import android.os.Build
import android.security.KeyChain
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import org.bouncycastle.util.io.pem.PemObject
import org.bouncycastle.util.io.pem.PemWriter
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.StringWriter
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Security
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Date
import java.security.interfaces.RSAPublicKey
import java.security.interfaces.ECPublicKey

object CryptoManager {
    init {
        Security.removeProvider("BC")
        Security.addProvider(BouncyCastleProvider())
    }

    enum class KeyType(val algorithm: String, val spec: String) {
        RSA_2048("RSA", "2048"),
        RSA_4096("RSA", "4096"),
        EC_P256("EC", "secp256r1"),
        EC_P384("EC", "secp384r1")
    }

    // Helper to prevent crashes if user types "Bob" instead of "CN=Bob"
    private fun fixSubjectDn(input: String): String {
        val trimmed = input.trim()
        if (trimmed.isEmpty()) return "CN=DefaultUser"
        // If it contains an '=', assume user knows what they are doing (e.g. O=Corp, CN=User)
        // If not, assume it's just a Common Name.
        return if (trimmed.contains("=")) trimmed else "CN=$trimmed"
    }

    fun generateKeyPair(type: KeyType): KeyPair {
        val generator = KeyPairGenerator.getInstance(type.algorithm, "BC")
        if (type.algorithm == "RSA") {
            generator.initialize(type.spec.toInt())
        } else {
            generator.initialize(ECGenParameterSpec(type.spec))
        }
        return generator.generateKeyPair()
    }

    fun generateCsr(keyPair: KeyPair, subjectName: String): String {
        // FIX: Sanitize input to prevent X500Name crash
        val validSubject = fixSubjectDn(subjectName)
        val subject = X500Name(validSubject)
        
        val signerAlgorithm = if (keyPair.private.algorithm == "RSA") "SHA256withRSA" else "SHA256withECDSA"
        
        val signer = JcaContentSignerBuilder(signerAlgorithm).build(keyPair.private)
        val builder = JcaPKCS10CertificationRequestBuilder(subject, keyPair.public)
        val csr = builder.build(signer)

        val stringWriter = StringWriter()
        val pemWriter = PemWriter(stringWriter)
        pemWriter.writeObject(PemObject("CERTIFICATE REQUEST", csr.encoded))
        pemWriter.close()
        return stringWriter.toString()
    }

    fun generateSelfSignedCert(keyPair: KeyPair, subjectName: String): String {
        // FIX: Sanitize input to prevent X500Name crash
        val validSubject = fixSubjectDn(subjectName)
        val issuer = X500Name(validSubject)
        
        val serial = BigInteger.valueOf(System.currentTimeMillis())
        val notBefore = Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24) 
        val notAfter = Date(System.currentTimeMillis() + 1000L * 60 * 60 * 24 * 365) 

        val builder = JcaX509v3CertificateBuilder(
            issuer, serial, notBefore, notAfter, issuer, keyPair.public
        )

        val sigAlg = if (keyPair.private.algorithm == "RSA") "SHA256withRSA" else "SHA256withECDSA"
        val signer = JcaContentSignerBuilder(sigAlg).build(keyPair.private)
        
        val certHolder = builder.build(signer)
        val cert = JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder)

        val sw = StringWriter()
        val pw = PemWriter(sw)
        pw.writeObject(PemObject("CERTIFICATE", cert.encoded))
        pw.close()
        return sw.toString()
    }

    fun installToSystem(
        context: Context, 
        keyPair: KeyPair, 
        certPem: String, 
        alias: String
    ) {
        val certFactory = CertificateFactory.getInstance("X.509")
        val cleanPem = certPem.trim() 
        val certStream = ByteArrayInputStream(cleanPem.toByteArray())
        val certificates = certFactory.generateCertificates(certStream)
        val certChain = certificates.map { it as X509Certificate }.toTypedArray()

        val p12Store = KeyStore.getInstance("PKCS12", "BC")
        p12Store.load(null, null)
        val tempPass = charArrayOf() 
        
        p12Store.setKeyEntry(alias, keyPair.private, tempPass, certChain)

        val bos = ByteArrayOutputStream()
        p12Store.store(bos, tempPass)
        val p12Bytes = bos.toByteArray()

        val intent = KeyChain.createInstallIntent().apply {
            putExtra(KeyChain.EXTRA_PKCS12, p12Bytes)
            putExtra("pkcs12_password", "")
            putExtra(KeyChain.EXTRA_NAME, alias)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        context.startActivity(intent)
    }

    fun getKeySecurityLevel(context: Context, alias: String): String {
        return try {
            val privateKey = KeyChain.getPrivateKey(context, alias)
            if (privateKey == null) return "Software / Unknown"

            val factory = KeyFactory.getInstance(privateKey.algorithm, "AndroidKeyStore")
            val keyInfo = factory.getKeySpec(privateKey, KeyInfo::class.java)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                when (keyInfo.securityLevel) {
                    KeyProperties.SECURITY_LEVEL_STRONGBOX -> "STRONGBOX (Titan M/SE)"
                    KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "TEE (TrustZone)"
                    KeyProperties.SECURITY_LEVEL_SOFTWARE -> "SOFTWARE"
                    else -> "UNKNOWN"
                }
            } else {
                if (keyInfo.isInsideSecureHardware) "HARDWARE (TEE)" else "SOFTWARE"
            }
        } catch (e: Exception) {
            "Error: ${e.message}"
        }
    }

    fun getCertificateDetails(context: Context, alias: String): String {
        return try {
            val privateKey = KeyChain.getPrivateKey(context, alias) ?: return "Error: Private Key not found."
            val chain = KeyChain.getCertificateChain(context, alias)
            if (chain.isNullOrEmpty()) return "Error: Certificate chain not found."

            val cert = chain[0]
            val publicKey = cert.publicKey
            val factory = KeyFactory.getInstance(privateKey.algorithm, "AndroidKeyStore")
            val keyInfo = factory.getKeySpec(privateKey, KeyInfo::class.java)

            val sb = StringBuilder()

            val securityLevel = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                when (keyInfo.securityLevel) {
                    KeyProperties.SECURITY_LEVEL_STRONGBOX -> "STRONGBOX (Titan M2/SE)"
                    KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "TEE (TrustZone)"
                    KeyProperties.SECURITY_LEVEL_SOFTWARE -> "SOFTWARE"
                    else -> "UNKNOWN"
                }
            } else {
                if (keyInfo.isInsideSecureHardware) "HARDWARE (TEE)" else "SOFTWARE"
            }
            sb.append("Storage Type:\n  $securityLevel\n\n")

            val algo = publicKey.algorithm
            val bitLength = when (publicKey) {
                is RSAPublicKey -> publicKey.modulus.bitLength()
                is ECPublicKey -> publicKey.params.order.bitLength()
                else -> "Unknown"
            }
            sb.append("Key Info:\n  $algo - $bitLength bits\n\n")

            sb.append("Validity:\n  Start: ${cert.notBefore}\n  End:   ${cert.notAfter}\n\n")

            sb.append("Subject:\n  ${cert.subjectDN.name}\n\n")
            sb.append("Issuer:\n  ${cert.issuerDN.name}")
            
            sb.toString()

        } catch (e: Exception) {
            "Error reading details: ${e.message}"
        }
    }
}
