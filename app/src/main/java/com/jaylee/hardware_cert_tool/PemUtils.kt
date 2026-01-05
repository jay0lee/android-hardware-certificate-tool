package com.jaylee.hardware_cert_tool

object PemUtils {
    /**
     * Removes the PEM header, footer, and all whitespace (newlines, spaces, etc.) from a certificate string.
     */
    fun cleanPem(certPem: String): String {
        return certPem
            .replace("-----BEGIN CERTIFICATE-----", "")
            .replace("-----END CERTIFICATE-----", "")
            .filter { !it.isWhitespace() }
    }
}
