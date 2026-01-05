package com.jaylee.hardware_cert_tool

import android.content.Context
import android.os.Build
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
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
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
    private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }

    enum class KeyType {
        RSA_2048,
        EC_P256
    }

    fun generateInMemoryKeyPair(type: KeyType): KeyPair {
        val kpg = when (type) {
            KeyType.RSA_2048 -> {
                val generator = KeyPairGenerator.getInstance("RSA")
                generator.initialize(2048)
                generator
            }
            KeyType.EC_P256 -> {
                val generator = KeyPairGenerator.getInstance("EC")
                generator.initialize(ECGenParameterSpec("secp256r1"))
                generator
            }
        }
        return kpg.generateKeyPair()
    }

    private fun ensureDnFormat(subject: String): String {
        return if (subject.contains("=")) {
            subject
        } else {
            "CN=$subject"
        }
    }

    // Shared Extension Logic: Ensures CSR and Self-Signed Certs request identical capabilities
    private fun generateStandardExtensions(subjectName: String): org.bouncycastle.asn1.x509.Extensions {
        val generator = ExtensionsGenerator()

        // Key Usage: Digital Signature + Key Encipherment
        generator.addExtension(
            Extension.keyUsage, true,
            KeyUsage(KeyUsage.digitalSignature or KeyUsage.keyEncipherment)
        )

        // Extended Key Usage: Client Auth (OID: 1.3.6.1.5.5.7.3.2)
        generator.addExtension(
            Extension.extendedKeyUsage, false,
            ExtendedKeyUsage(arrayOf(KeyPurposeId.id_kp_clientAuth))
        )

        // Basic Constraints: Not a CA
        generator.addExtension(
            Extension.basicConstraints, true,
            BasicConstraints(false)
        )

        // Subject Alternative Name (SAN)
        // Many modern clients (and Android 10+) require SAN to be present.
        // We will mirror the CN (Common Name) into the SAN as a DNS Name or IP if applicable, 
        // but for simplicity/robustness we'll use DNS Name if it looks like one, or just assume it's a name.
        // Parsing the "CN=" part out if it exists.
        val rawName = if (subjectName.startsWith("CN=")) subjectName.substring(3) else subjectName
        
        // We add it as a DNS Name. If it's an IP, GeneralName automatic detection might not be enough 
        // without InetAddress parsing, but DNSName is the safest generic fallback for "Server/Client" identities.
        val generalName = GeneralName(GeneralName.dNSName, rawName)
        val generalNames = GeneralNames(generalName)
        
        generator.addExtension(
            Extension.subjectAlternativeName, false,
            generalNames
        )

        return generator.generate()
    }

    // --- CSR GENERATION ---
    fun generateCsr(keyPair: KeyPair, subjectName: String): String {
        val validSubject = ensureDnFormat(subjectName)
        val algorithm = if (keyPair.private.algorithm == "EC") "SHA256withECDSA" else "SHA256withRSA"
        
        val signer = JcaContentSignerBuilder(algorithm).build(keyPair.private)
        val builder = JcaPKCS10CertificationRequestBuilder(X500Name(validSubject), keyPair.public)
        
        // Use shared extensions
        val extensions = generateStandardExtensions(subjectName)
        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions)

        val csr = builder.build(signer)
        
        val sb = StringBuilder()
        sb.append("-----BEGIN CERTIFICATE REQUEST-----\n")
        sb.append(Base64.getEncoder().encodeToString(csr.encoded))
        sb.append("\n-----END CERTIFICATE REQUEST-----")
        return sb.toString()
    }

    // --- SELF-SIGNED CERT GENERATION ---
    fun generateSelfSignedCert(keyPair: KeyPair, subject: String): String {
        val validSubject = ensureDnFormat(subject)
        val algorithm = if (keyPair.private.algorithm == "EC") "SHA256withECDSA" else "SHA256withRSA"
        val signer = JcaContentSignerBuilder(algorithm).build(keyPair.private)

        val now = System.currentTimeMillis()
        val startDate = Date(now)
        val endDate = Date(now + 365L * 24 * 60 * 60 * 1000)
        val serialNumber = BigInteger(64, SecureRandom())

        val dnName = X500Name(validSubject)
        val builder = JcaX509v3CertificateBuilder(
            dnName,
            serialNumber,
            startDate,
            endDate,
            dnName,
            keyPair.public
        )

        // Use shared extensions
        val extensions = generateStandardExtensions(subject)
        val oids = extensions.oids()
        while (oids.hasMoreElements()) {
            val oid = oids.nextElement() as org.bouncycastle.asn1.ASN1ObjectIdentifier
            val ext = extensions.getExtension(oid)
            builder.addExtension(ext)
        }

        val certHolder = builder.build(signer)
        
        val sb = StringBuilder()
        sb.append("-----BEGIN CERTIFICATE-----\n")
        sb.append(Base64.getEncoder().encodeToString(certHolder.encoded))
        sb.append("\n-----END CERTIFICATE-----")
        return sb.toString()
    }

    // --- P12 GENERATION ---
    fun createP12(keyPair: KeyPair, certPem: String, alias: String): ByteArray {
        val cleanPem = PemUtils.cleanPem(certPem)
        val decoded = Base64.getDecoder().decode(cleanPem)
        val factory = CertificateFactory.getInstance("X.509")
        val cert = factory.generateCertificate(ByteArrayInputStream(decoded)) as X509Certificate

        val p12 = KeyStore.getInstance("PKCS12")
        p12.load(null, null) 
        
        // P12 requires a password for store, but we can use empty.
        val password = "".toCharArray()
        
        p12.setKeyEntry(
            alias,
            keyPair.private,
            password,
            arrayOf(cert)
        )
        
        val os = java.io.ByteArrayOutputStream()
        p12.store(os, password)
        return os.toByteArray()
    }

    // --- INSTALLATION (Fixed Base64 Cleaning) ---
    fun installToSystem(keyPair: KeyPair, certPem: String, alias: String) {
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
            // First, try loading from the System KeyChain (External/System-wide)
            // Note: This requires the alias to be one the user has granted access to via KeyChain.choosePrivateKeyAlias
            var privateKey = KeyChain.getPrivateKey(context, alias)
            var certChain = KeyChain.getCertificateChain(context, alias)
            var cert: X509Certificate? = null

            if (privateKey != null && certChain != null && certChain.isNotEmpty()) {
                 cert = certChain[0] as X509Certificate
            } else {
                // Fallback: Try App Internal KeyStore
                val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
                if (entry != null) {
                    privateKey = entry.privateKey
                    cert = entry.certificate as X509Certificate
                }
            }

            if (privateKey == null || cert == null) {
                return "Error: Could not find key entry for alias: $alias"
            }

            val sb = StringBuilder()
            
            // Check Hardware Backing
            // For KeyChain keys, we might need KeyFactory with "AndroidKeyStore" if the key is hardware backed.
            // If it's a software key from KeyChain, the provider might be different.
            var isHardware = false
            try {
                val factory = KeyFactory.getInstance(privateKey.algorithm, "AndroidKeyStore")
                val keyInfo = factory.getKeySpec(privateKey, KeyInfo::class.java)
                
                isHardware = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    keyInfo.securityLevel != KeyProperties.SECURITY_LEVEL_SOFTWARE
                } else {
                    @Suppress("DEPRECATION")
                    keyInfo.isInsideSecureHardware
                }
            } catch (e: Exception) {
                // If we can't get KeyInfo via AndroidKeyStore provider, it might be a purely software key
                // or we don't have access to the material.
                // However, user requirement is about TEE. 
            }

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