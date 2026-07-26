package com.customvpn.app.utils

import android.util.Base64

object PayloadBuilder {

    fun buildSshPayload(config: com.customvpn.app.models.VpnConfig): String {
        val sb = StringBuilder()
        sb.appendLine("GET / HTTP/1.1[crlf]")
        sb.appendLine("Host: ${config.sni.ifEmpty { config.serverAddress }}[crlf]")
        sb.appendLine("User-Agent: [ua][crlf]")
        sb.appendLine("Connection: Upgrade[crlf]")
        sb.appendLine("Upgrade: websocket; HTTP/1.1[crlf]")
        sb.appendLine("Sec-WebSocket-Key: [random_key][crlf]")
        sb.appendLine("Sec-WebSocket-Version: 13[crlf]")
        sb.appendLine("[crlf]")
        return sb.toString()
    }

    fun buildCustomPayload(
        serverAddress: String,
        sni: String,
        method: String = "GET",
        keepAlive: Boolean = true
    ): String {
        val host = sni.ifEmpty { serverAddress }
        val sb = StringBuilder()
        sb.appendLine("$method / HTTP/1.1[crlf]")
        sb.appendLine("Host: $host[crlf]")
        sb.appendLine("User-Agent: Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36[crlf]")
        if (keepAlive) {
            sb.appendLine("Connection: keep-alive[crlf]")
        }
        sb.appendLine("Upgrade: websocket; HTTP/1.1[crlf]")
        sb.appendLine("Sec-WebSocket-Version: 13[crlf]")
        sb.appendLine("Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits[crlf]")
        sb.appendLine("Sec-WebSocket-Key: ${generateRandomKey()}[crlf]")
        sb.appendLine("[crlf]")
        return sb.toString()
    }

    fun preparePayloadForSsh(payload: String): String {
        var prepared = payload.trim()
        prepared = prepared.replace("[crlf]", "\r\n", ignoreCase = true)
        prepared = prepared.replace("[cr]", "\r", ignoreCase = true)
        prepared = prepared.replace("[lf]", "\n", ignoreCase = true)
        prepared = prepared.replace("[ua]", "Mozilla/5.0 (Linux; Android 13)", ignoreCase = true)
        prepared = prepared.replace("[random_key]", generateRandomKey(), ignoreCase = true)
        prepared = prepared.replace("[timestamp]", (System.currentTimeMillis() / 1000).toString(), ignoreCase = true)
        return prepared
    }

    fun buildSniPayload(host: String, path: String = "/"): String {
        val sb = StringBuilder()
        sb.appendLine("CONNECT $host:443 HTTP/1.1")
        sb.appendLine("Host: $host:443")
        sb.appendLine("Proxy-Connection: keep-alive")
        sb.appendLine("[crlf]")
        return sb.toString()
    }

    fun encodePayload(payload: String): String {
        return Base64.encodeToString(payload.toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
    }

    fun decodePayload(encoded: String): String {
        return String(Base64.decode(encoded, Base64.NO_WRAP), Charsets.UTF_8)
    }

    private fun generateRandomKey(): String {
        val chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        return (1..32).map { chars.random() }.joinToString("")
    }
}
