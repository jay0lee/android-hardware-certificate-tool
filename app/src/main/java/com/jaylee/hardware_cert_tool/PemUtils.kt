package com.jaylee.hardware_cert_tool

object PemUtils {
    /**
     * Extracts the Base64 content from a PEM string.
     * It looks for the pattern -----BEGIN ...----- [BASE64] -----END ...-----
     * and returns the [BASE64] part with all whitespace removed.
     * If no headers are found, it assumes the entire string is the content (fallback).
     */
    fun cleanPem(certPem: String): String {
        // Regex to match anything between BEGIN and END tags, capturing the middle content.
        // (?s) enables dot-matches-newline mode.
        val regex = Regex("-----BEGIN [^-]+-----(.*?)-----END [^-]+-----", RegexOption.DOT_MATCHES_ALL)
        
        val matchResult = regex.find(certPem)
        val content = matchResult?.groupValues?.get(1) ?: certPem

        return content.filter { !it.isWhitespace() }
    }

    /**
     * Encodes the content to Base64 and wraps it in PEM headers/footers.
     * Splits lines at 64 characters to comply with strict PEM parsers.
     */
    fun toPem(type: String, content: ByteArray): String {
        val base64 = java.util.Base64.getEncoder().encodeToString(content)
        val chunked = base64.chunked(64).joinToString("\n")
        return "-----BEGIN $type-----\n$chunked\n-----END $type-----"
    }
}
