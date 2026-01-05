package com.jaylee.hardware_cert_tool

import org.junit.Assert.assertEquals
import org.junit.Test

class PemUtilsTest {

    @Test
    fun cleanPem_removesHeadersAndWhitespace() {
        val input = """
            -----BEGIN CERTIFICATE-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
            -----END CERTIFICATE-----
        """.trimIndent()

        // The expected string should not contain any headers or whitespace
        val expected = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"
        
        val result = PemUtils.cleanPem(input)
        
        assertEquals(expected, result)
    }

    @Test
    fun cleanPem_handlesNewlinesAndSpaces() {
        val input = " A B \n C \r D \t E "
        val expected = "ABCDE"
        
        val result = PemUtils.cleanPem(input)
        
        assertEquals(expected, result)
    }
    
    @Test
    fun cleanPem_handlesEmptyString() {
        val input = ""
        val expected = ""
        val result = PemUtils.cleanPem(input)
        assertEquals(expected, result)
    }

    @Test
    fun cleanPem_extractsOnlyBase64_whenMetadataIsPresent() {
        val input = """
            Certificate:
                Data:
                    Version: 3 (0x2)
            -----BEGIN CERTIFICATE-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
            -----END CERTIFICATE-----
            Some trailing text
        """.trimIndent()

        // We expect only the Base64 part
        val expected = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"
        
        val result = PemUtils.cleanPem(input)
        
        assertEquals(expected, result)
    }
}

