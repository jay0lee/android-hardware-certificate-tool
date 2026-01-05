package com.jaylee.hardware_cert_tool

import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider

class CryptoManagerTest {

    init {
        // Ensure BouncyCastle provider is registered for the test execution
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    @Test
    fun generateCsr_returnsValidCsrString() {
        // Generate a standard Java KeyPair for testing logic
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        val keyPair = kpg.generateKeyPair()

        val subject = "CN=Test User, O=Test Org"
        
        val csr = CryptoManager.generateCsr(keyPair, subject)

        assertTrue("CSR should start with header", csr.contains("-----BEGIN CERTIFICATE REQUEST-----"))
        assertTrue("CSR should end with footer", csr.contains("-----END CERTIFICATE REQUEST-----"))
    }

    @Test
    fun generateSelfSignedCert_returnsValidCertString() {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        val keyPair = kpg.generateKeyPair()

        val subject = "CN=Test User, O=Test Org"
        
        val cert = CryptoManager.generateSelfSignedCert(keyPair, subject)

        assertTrue("Cert should start with header", cert.contains("-----BEGIN CERTIFICATE-----"))
        assertTrue("Cert should end with footer", cert.contains("-----END CERTIFICATE-----"))
    }

    @Test
    fun generateCsr_withSimpleString_succeeds() {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        val keyPair = kpg.generateKeyPair()

        val subject = "User" // Plain string, not a DN
        
        val csr = CryptoManager.generateCsr(keyPair, subject)

        assertTrue("CSR should start with header", csr.contains("-----BEGIN CERTIFICATE REQUEST-----"))
    }
}