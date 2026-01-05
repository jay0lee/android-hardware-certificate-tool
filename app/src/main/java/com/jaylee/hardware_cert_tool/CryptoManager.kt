package com.jaylee.hardware_cert_tool

import android.content.Context
import android.security.KeyChain
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import java.util.Base64
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.ExtensionsGenerator
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.*
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Date

object CryptoManager {

    private const val KEYSTORE_PROVIDER = "AndroidKeyStore"

    enum class KeyType {
        EC_P256,
        EC_P384,
        RSA_2048,
        RSA_4096
    }

    private val keyStore: KeyStore by lazy {
        KeyStore.getInstance(KEYSTORE_PROVIDER).apply {
            load(null)
        }
    }

    // --- KEY GENERATION ---

    fun generateKeyPair(alias: String, type: KeyType): KeyPair {
        val kpg = KeyPairGenerator.getInstance(
            if (type.name.startsWith("EC")) KeyProperties.KEY_ALGORITHM_EC else KeyProperties.KEY_ALGORITHM_RSA,
            KEYSTORE_PROVIDER
        )

        val fullAlias = if (alias.startsWith("Cert_")) alias else "Cert_$alias"

        val builder = KeyGenParameterSpec.Builder(
            fullAlias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
        
        when (type) {
            KeyType.EC_P256 -> builder.setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            KeyType.EC_P384 -> builder.setAlgorithmParameterSpec(ECGenParameterSpec("secp384r1"))
            KeyType.RSA_2048 -> {
                builder.setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                builder.setKeySize(2048)
            }
            KeyType.RSA_4096 -> {
                builder.setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                builder.setKeySize(4096)
            }
        }

        kpg.initialize(builder.build())
        return kpg.generateKeyPair()
    }

    // --- CSR GENERATION ---
    fun generateCsr(keyPair: KeyPair, subjectName: String): String {
        val algorithm = if (keyPair.private.algorithm == "EC") "SHA256withECDSA" else "SHA256withRSA"
        
        val signer = JcaContentSignerBuilder(algorithm).build(keyPair.private)
        val builder = JcaPKCS10CertificationRequestBuilder(X500Name(subjectName), keyPair.public)
        
        val extensionsGenerator = ExtensionsGenerator()

        extensionsGenerator.addExtension(
            Extension.keyUsage, true, 
            KeyUsage(KeyUsage.digitalSignature or KeyUsage.keyEncipherment)
        )

        extensionsGenerator.addExtension(
            Extension.extendedKeyUsage, false, 
            ExtendedKeyUsage(arrayOf(KeyPurposeId.id_kp_clientAuth))
        )
        
        extensionsGenerator.addExtension(
            Extension.basicConstraints, true,
            BasicConstraints(false)
        )

        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionsGenerator.generate())

        val csr = builder.build(signer)
        
        val sb = StringBuilder()
        sb.append("-----BEGIN CERTIFICATE REQUEST-----\n")
        sb.append(Base64.getEncoder().encodeToString(csr.encoded))
        sb.append("\n-----END CERTIFICATE REQUEST-----")
        return sb.toString()
    }

    // --- SELF-SIGNED CERT GENERATION ---
    fun generateSelfSignedCert(keyPair: KeyPair, subject: String): String {
        val algorithm = if (keyPair.private.algorithm == "EC") "SHA256withECDSA" else "SHA256withRSA"
        val signer = JcaContentSignerBuilder(algorithm).build(keyPair.private)

        val now = System.currentTimeMillis()
        val startDate = Date(now)
        val endDate = Date(now + 365L * 24 * 60 * 60 * 1000)
        val serialNumber = BigInteger(64, SecureRandom())

        val builder = JcaX509v3CertificateBuilder(
            X500Name(subject),
            serialNumber,
            startDate,
            endDate,
            X500Name(subject),
            keyPair.public
        )

        builder.addExtension(
            Extension.keyUsage, true, 
            KeyUsage(KeyUsage.digitalSignature or KeyUsage.keyEncipherment)
        )
        builder.addExtension(
            Extension.extendedKeyUsage, false, 
            ExtendedKeyUsage(arrayOf(KeyPurposeId.id_kp_clientAuth))
        )
        builder.addExtension(
            Extension.basicConstraints, true, 
            BasicConstraints(false)
        )

        val certHolder = builder.build(signer)
        
        val sb = StringBuilder()
        sb.append("-----BEGIN CERTIFICATE-----\n")
        sb.append(Base64.getEncoder().encodeToString(certHolder.encoded))
        sb.append("\n-----END CERTIFICATE-----")
        return sb.toString()
    }

    // --- INSTALLATION (Fixed Base64 Cleaning) ---
    fun installToSystem(context: Context, keyPair: KeyPair, certPem: String, alias: String) {
        // FIX: Use robust filtering instead of regex to remove headers and whitespace
        val cleanPem = PemUtils.cleanPem(certPem)
            
        val decoded = Base64.getDecoder().decode(cleanPem)
        val factory = CertificateFactory.getInstance("X.509")
        val cert = factory.generateCertificate(ByteArrayInputStream(decoded)) as X509Certificate

        val fullAlias = if (alias.startsWith("Cert_")) alias else "Cert_$alias"
        
        keyStore.setKeyEntry(
            fullAlias,
            keyPair.private,
            null,
            arrayOf(cert)
        )
    }

    // --- INSPECTION ---
    fun getCertificateDetails(context: Context, alias: String): String {
        return try {
            val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
                ?: return "Error: Could not find key entry for alias: $alias"

            val cert = entry.certificate as X509Certificate
            val privateKey = entry.privateKey
            val factory = KeyFactory.getInstance(privateKey.algorithm, KEYSTORE_PROVIDER)
            val keyInfo = factory.getKeySpec(privateKey, KeyInfo::class.java)

            val sb = StringBuilder()
            val isHardware = keyInfo.isInsideSecureHardware
            
            sb.append("Storage Type:\n")
            sb.append(if (isHardware) "  TEE (Trusted Execution Environment)" else "  SOFTWARE (Not Hardware Backed)")
            sb.append("\n\n")

            sb.append("Key Info:\n  ${privateKey.algorithm}\n")
            sb.append("\nValidity:\n  Start: ${cert.notBefore}\n  End:   ${cert.notAfter}\n")
            
            val eku = cert.extendedKeyUsage
            if (eku != null && eku.contains("1.3.6.1.5.5.7.3.2")) {
                sb.append("\nFeatures:\n  [x] Client Authentication\n")
            } else {
                sb.append("\nFeatures:\n  [ ] No Client Auth detected\n")
            }

            sb.append("\nSubject:\n  ${cert.subjectDN.name}\n")
            sb.append("\nIssuer:\n  ${cert.issuerDN.name}\n")

            sb.toString()
        } catch (e: Exception) {
            "Verification Failed:\n${e.message}"
        }
    }
}
