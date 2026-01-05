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
}
