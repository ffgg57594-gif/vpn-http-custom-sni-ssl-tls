package com.customvpn.app.ssl

import com.customvpn.app.models.VpnConfig
import com.customvpn.app.utils.PayloadBuilder
import java.io.*
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.*

class SslTunnel(
    private val config: VpnConfig,
    private val listener: TunnelListener? = null,
    private val socketProtector: ((Socket) -> Unit)? = null,
    private val datagramSocketProtector: ((DatagramSocket) -> Unit)? = null
) {

    interface TunnelListener {
        fun onConnected()
        fun onDisconnected(reason: String)
        fun onError(error: String)
        fun onLog(message: String)
    }

    @Volatile
    private var isRunning = false
    private var serverSocket: java.net.ServerSocket? = null
    private var localPort: Int = 0
    private var acceptThread: Thread? = null

    val port: Int get() = localPort

    private val trustAllManager = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    }

    fun start(localBindPort: Int = 0): Int {
        isRunning = true
        listener?.onLog("Starting SSL/TLS tunnel to ${config.serverAddress}:${config.serverPort}")
        listener?.onLog("SNI: ${config.sni.ifEmpty { config.serverAddress }}")

        if (config.serverAddress.isEmpty()) {
            throw IOException("Server address is empty")
        }

        try {
            serverSocket = java.net.ServerSocket(
                localBindPort, 50, java.net.InetAddress.getByName("127.0.0.1")
            )
            localPort = serverSocket!!.localPort
            listener?.onLog("Local HTTP/SOCKS proxy listening on 127.0.0.1:$localPort")

            acceptThread = Thread({
                try {
                    while (isRunning) {
                        val clientSocket = serverSocket?.accept() ?: break
                        try {
                            clientSocket.soTimeout = 30000
                        } catch (_: Exception) {}
                        Thread { handleClient(clientSocket) }.start()
                    }
                } catch (e: Exception) {
                    if (isRunning) {
                        listener?.onError("SSL server accept error: ${e.message}")
                    }
                }
            }, "SslTunnel-Accept")
            acceptThread?.isDaemon = true
            acceptThread?.start()

            listener?.onConnected()
            return localPort
        } catch (e: Exception) {
            listener?.onError("Failed to start SSL tunnel: ${e.message}")
            stop()
            throw e
        }
    }

    private fun handleClient(clientSocket: Socket) {
        try {
            val buf = ByteArray(4096)
            val input = clientSocket.getInputStream()
            val readLen = input.read(buf)
            if (readLen <= 0) {
                try { clientSocket.close() } catch (_: Exception) {}
                return
            }

            val headerStr = String(buf, 0, readLen, Charsets.US_ASCII).trimStart()

            if (headerStr.startsWith("GET ") || headerStr.startsWith("POST ") ||
                headerStr.startsWith("PUT ") || headerStr.startsWith("DELETE ") ||
                headerStr.startsWith("HEAD ") || headerStr.startsWith("CONNECT ")) {
                handleHttpProxy(clientSocket, buf, readLen)
                return
            }

            if ((buf[0].toInt() and 0xFF) == 0x05) {
                handleSocks5(clientSocket, input)
                return
            }

            // DNS-over-TCP: first 2 bytes are the message length, not an ASCII char.
            // If the length is plausible AND the first two bytes don't form a printable
            // ASCII character pair, treat as DNS.
            val firstByte = buf[0].toInt() and 0xFF
            val secondByte = buf[1].toInt() and 0xFF
            val looksLikeDns = readLen >= 2 && (firstByte < 0x20 || secondByte < 0x20)
            if (looksLikeDns) {
                handleDnsOverTcp(clientSocket, buf, readLen)
                return
            }

            listener?.onLog("Unknown protocol byte: 0x${"%02X".format(firstByte)}")
            try { clientSocket.close() } catch (_: Exception) {}
        } catch (e: Exception) {
            listener?.onLog("SSL client error: ${e.message}")
            try { clientSocket.close() } catch (_: Exception) {}
        }
    }

    /**
     * Handles DNS-over-TCP (RFC 7766) on the local side. The local
     * VpnTunnelService sends a 2-byte length followed by the raw DNS
     * query. We forward the query to a public DNS-over-HTTPS (DoH,
     * RFC 8484) endpoint through the TLS tunnel and pipe the response
     * back the same way. This is the same approach HTTP Custom uses
     * for DNS resolution: it works even when the remote VPN server
     * blocks plain DNS (port 53) and DNS-over-TLS (port 853), because
     * port 443 is always forwarded normally.
     */
    private fun handleDnsOverTcp(clientSocket: Socket, firstChunk: ByteArray, firstChunkLen: Int) {
        Thread({
            try {
                val msgLen = ((firstChunk[0].toInt() and 0xFF) shl 8) or (firstChunk[1].toInt() and 0xFF)
                if (msgLen <= 0 || msgLen > 65535) {
                    listener?.onLog("DNS-over-TCP: bad query length $msgLen")
                    clientSocket.close()
                    return@Thread
                }
                val dnsQuery = ByteArray(msgLen)
                val alreadyRead = (firstChunkLen - 2).coerceAtMost(msgLen)
                if (alreadyRead > 0) {
                    System.arraycopy(firstChunk, 2, dnsQuery, 0, alreadyRead)
                }
                var off = alreadyRead
                val input = clientSocket.getInputStream()
                while (off < msgLen) {
                    val n = input.read(dnsQuery, off, msgLen - off)
                    if (n <= 0) break
                    off += n
                }
                if (off < msgLen) {
                    clientSocket.close()
                    return@Thread
                }

                val dnsResponse = forwardDnsOverTls(dnsQuery)
                if (dnsResponse != null) {
                    val out = clientSocket.getOutputStream()
                    out.write(((dnsResponse.size shr 8) and 0xFF))
                    out.write(dnsResponse.size and 0xFF)
                    out.write(dnsResponse)
                    out.flush()
                }
            } catch (e: Exception) {
                listener?.onLog("DNS-over-TCP error: ${e.message}")
            } finally {
                try { clientSocket.close() } catch (_: Exception) {}
            }
        }, "SslTunnel-DNS").start()
    }

    /**
     * Forwards a DNS query to a public DNS-over-HTTPS (DoH, RFC 8484)
     * endpoint through the existing TLS tunnel.
     *
     * Why DoH and not raw DNS-over-TCP: the remote VPN server is a
     * generic HTTPS reverse proxy that only forwards TCP traffic
     * whitelisted by port. Plain DNS (port 53) and DNS-over-TLS
     * (port 853) are both blocked - the server replies with a fake
     * HTTP/1.1 response (we saw a Content-Length of 100 GB) to stall
     * the client. Port 443, on the other hand, is forwarded normally,
     * so we can ride on the proven HTTP-CONNECT path: open a tunnel to
     * 1.1.1.1:443 (Cloudflare) or 8.8.8.8:443 (Google), send a DoH
     * POST /dns-query request, read the DNS response from the body.
     *
     * This is the same approach HTTP Custom uses for DNS resolution.
     *
     * Steps:
     *   1. Open a TLS connection to the configured server (with SNI)
     *   2. Send an inner-SOCKS CONNECT request to the DoH endpoint on
     *      port 443 (the only DNS-related port the remote forwards).
     *   3. Send an HTTP/1.1 POST /dns-query with the raw DNS query
     *      bytes as the body and Content-Type: application/dns-message.
     *   4. Read the HTTP response, strip headers, return the body.
     */
    private fun forwardDnsOverTls(dnsQuery: ByteArray): ByteArray? {
        // DoH endpoints, in order of preference. We use the IP rather
        // than the hostname so the inner-SOCKS ATYP=0x01 (IPv4) format
        // is enough - we don't need a resolver to look up the endpoint.
        val candidates = listOf(
            "1.1.1.1" to "cloudflare-dns.com",
            "1.0.0.1" to "cloudflare-dns.com",
            "8.8.8.8" to "dns.google",
            "8.8.4.4" to "dns.google"
        )
        for ((host, dohHost) in candidates) {
            listener?.onLog("DNS over HTTPS via $host ($dohHost)")
            val result = forwardDnsOverHttpsOnce(dnsQuery, host, dohHost)
            if (result != null) return result
        }
        listener?.onLog("DNS over HTTPS: all candidates failed")
        return null
    }

    /**
     * One DoH attempt: open a TLS tunnel to the remote VPN server, ask
     * it to forward to <host>:443, send an HTTP POST /dns-query, read
     * the response body.
     */
    private fun forwardDnsOverHttpsOnce(
        dnsQuery: ByteArray,
        host: String,
        dohHost: String
    ): ByteArray? {
        var remoteSocket: Socket? = null
        try {
            remoteSocket = createTlsConnection() ?: return null

            val out = remoteSocket.getOutputStream()
            val input = remoteSocket.getInputStream()

            // Ask the remote to forward bytes to <host>:443
            val innerSocks = buildInnerSocksRequest(host, 443)
            out.write(innerSocks)
            out.flush()

            // Send DoH POST request. Use HTTP/1.0 + Connection: close so
            // the DoH server closes the connection after the response
            // (much easier to parse than reading a Content-Length).
            val httpReq = buildString {
                append("POST /dns-query HTTP/1.0\r\n")
                append("Host: $dohHost\r\n")
                append("Content-Type: application/dns-message\r\n")
                append("Content-Length: ${dnsQuery.size}\r\n")
                append("Accept: application/dns-message\r\n")
                append("User-Agent: CustomVPN/1.0\r\n")
                append("Connection: close\r\n")
                append("\r\n")
            }
            out.write(httpReq.toByteArray(Charsets.US_ASCII))
            out.write(dnsQuery)
            out.flush()
            remoteSocket.soTimeout = 10000

            // Read the full HTTP response (headers + body) until EOF
            // (the DoH server will close the connection when done).
            return readDohResponse(input)
        } catch (e: Exception) {
            listener?.onLog("DNS over HTTPS attempt to $host failed: ${e.message}")
            return null
        } finally {
            try { remoteSocket?.close() } catch (_: Exception) {}
        }
    }

    /**
     * Reads the full HTTP response from the input stream and returns
     * the body bytes. The DoH server is expected to close the
     * connection after sending the response (we sent Connection:
     * close), so we just read until EOF.
     */
    private fun readDohResponse(input: java.io.InputStream): ByteArray? {
        return try {
            // Read all bytes until EOF. We have to be careful about the
            // size cap to avoid OOM if the server sends garbage.
            val maxBytes = 65535 + 4096  // 64 KB response + 4 KB headers
            val all = java.io.ByteArrayOutputStream()
            val buf = ByteArray(4096)
            while (all.size() < maxBytes) {
                val n = try {
                    input.read(buf)
                } catch (_: java.net.SocketTimeoutException) {
                    -1
                }
                if (n <= 0) break
                all.write(buf, 0, n)
            }
            val raw = all.toByteArray()
            // Find end of headers
            val headerEnd = indexOfCrlfCrlf(raw)
            if (headerEnd < 0) {
                listener?.onLog("DNS over HTTPS: no header terminator in response")
                return null
            }
            val headers = String(raw, 0, headerEnd, Charsets.US_ASCII)
            // Look at the status line to ensure success
            val statusLine = headers.lineSequence().firstOrNull() ?: ""
            if (!statusLine.contains(" 200 ") && !statusLine.contains(" 201 ")) {
                val preview = headers.lineSequence().take(3).joinToString(" | ")
                listener?.onLog("DNS over HTTPS: non-200 status: $preview")
                // Cloudflare/Google may return 413 for huge responses,
                // or 400 for malformed input. Fall through to the next
                // candidate by returning null.
                return null
            }
            // Locate the Content-Length header so we can trim the body
            // to exactly the right number of bytes (in case the server
            // appends extra garbage after the body).
            var contentLength = -1
            for (line in headers.lineSequence()) {
                val lower = line.lowercase()
                if (lower.startsWith("content-length:")) {
                    contentLength = lower.substring(15).trim().toIntOrNull() ?: -1
                }
            }
            val bodyStart = headerEnd + 4
            if (contentLength in 0..(raw.size - bodyStart)) {
                return raw.copyOfRange(bodyStart, bodyStart + contentLength)
            }
            // No (or bogus) Content-Length; return everything after the
            // headers. Since the server closed the connection, this
            // should be the entire body.
            return raw.copyOfRange(bodyStart, raw.size)
        } catch (e: Exception) {
            listener?.onLog("DNS over HTTPS: error reading response: ${e.message}")
            null
        }
    }

    /** Returns the index of the first \r\n\r\n in the buffer, or -1. */
    private fun indexOfCrlfCrlf(buf: ByteArray): Int {
        if (buf.size < 4) return -1
        for (i in 0..(buf.size - 4)) {
            if (buf[i] == 0x0D.toByte() && buf[i + 1] == 0x0A.toByte() &&
                buf[i + 2] == 0x0D.toByte() && buf[i + 3] == 0x0A.toByte()
            ) {
                return i
            }
        }
        return -1
    }

    private fun handleSocks5(clientSocket: Socket, input: java.io.InputStream) {
        try {
            // SOCKS5 greeting reply: VER=5, METHOD=0 (no auth)
            clientSocket.getOutputStream().write(byteArrayOf(0x05, 0x00))
            clientSocket.getOutputStream().flush()

            val connectBuf = ByteArray(512)
            val connectLen = input.read(connectBuf)
            if (connectLen < 7) {
                clientSocket.close()
                return
            }

            val version = connectBuf[0].toInt() and 0xFF
            val cmd = connectBuf[1].toInt() and 0xFF
            if (version != 0x05 || cmd != 0x01) {
                clientSocket.getOutputStream().write(byteArrayOf(0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                clientSocket.getOutputStream().flush()
                clientSocket.close()
                return
            }

            val atyp = connectBuf[3].toInt() and 0xFF
            val targetHost: String
            val targetPort: Int

            when (atyp) {
                0x01 -> {
                    if (connectLen < 10) { clientSocket.close(); return }
                    targetHost = "${connectBuf[4].toInt() and 0xFF}.${connectBuf[5].toInt() and 0xFF}.${connectBuf[6].toInt() and 0xFF}.${connectBuf[7].toInt() and 0xFF}"
                    targetPort = ((connectBuf[8].toInt() and 0xFF) shl 8) or (connectBuf[9].toInt() and 0xFF)
                }
                0x03 -> {
                    val domainLen = connectBuf[4].toInt() and 0xFF
                    if (connectLen < 5 + domainLen + 2) { clientSocket.close(); return }
                    targetHost = String(connectBuf, 5, domainLen, Charsets.US_ASCII)
                    targetPort = ((connectBuf[5 + domainLen].toInt() and 0xFF) shl 8) or (connectBuf[6 + domainLen].toInt() and 0xFF)
                }
                0x04 -> {
                    if (connectLen < 22) { clientSocket.close(); return }
                    val ipv6 = ByteArray(16)
                    System.arraycopy(connectBuf, 4, ipv6, 0, 16)
                    targetHost = InetAddress.getByAddress(ipv6).hostAddress ?: ""
                    targetPort = ((connectBuf[20].toInt() and 0xFF) shl 8) or (connectBuf[21].toInt() and 0xFF)
                }
                else -> {
                    clientSocket.getOutputStream().write(byteArrayOf(0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                    clientSocket.getOutputStream().flush()
                    clientSocket.close()
                    return
                }
            }

            listener?.onLog("SOCKS5 CONNECT to $targetHost:$targetPort via SSL/TLS tunnel")
            val remoteSocket = createTlsConnection()
            if (remoteSocket != null) {
                val reply = byteArrayOf(
                    0x05, 0x00, 0x00, 0x01,
                    0, 0, 0, 0, 0, 0
                )
                clientSocket.getOutputStream().write(reply)
                clientSocket.getOutputStream().flush()
                // Inform remote about the actual target via a SOCKS-like handshake inside TLS
                pipe(clientSocket, remoteSocket, buildInnerSocksRequest(targetHost, targetPort))
            } else {
                clientSocket.getOutputStream().write(byteArrayOf(0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                clientSocket.getOutputStream().flush()
                clientSocket.close()
            }
        } catch (e: Exception) {
            listener?.onLog("SOCKS5 handling error: ${e.message}")
            try { clientSocket.close() } catch (_: Exception) {}
        }
    }

    private fun buildInnerSocksRequest(host: String, port: Int): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        out.write(byteArrayOf(0x05, 0x01, 0x00, 0x03))
        val hostBytes = host.toByteArray(Charsets.US_ASCII)
        out.write(hostBytes.size and 0xFF)
        out.write(hostBytes)
        out.write((port shr 8) and 0xFF)
        out.write(port and 0xFF)
        return out.toByteArray()
    }

    private fun handleHttpProxy(clientSocket: Socket, header: ByteArray, headerLen: Int) {
        try {
            val headerStr = String(header, 0, headerLen, Charsets.US_ASCII)
            val firstLine = headerStr.lineSequence().firstOrNull() ?: ""
            val parts = firstLine.split(" ")

            if (parts.size < 2) {
                clientSocket.getOutputStream().write("HTTP/1.1 400 Bad Request\r\n\r\n".toByteArray())
                clientSocket.getOutputStream().flush()
                clientSocket.close()
                return
            }

            val targetHost: String
            val targetPort: Int
            val isConnect = parts[0] == "CONNECT"

            if (isConnect) {
                val hostPort = parts[1].split(":")
                targetHost = hostPort[0]
                targetPort = hostPort.getOrNull(1)?.toIntOrNull() ?: 443
            } else {
                val url = java.net.URL(parts[1])
                targetHost = url.host
                targetPort = if (url.port > 0) url.port else if (url.protocol == "https") 443 else 80
            }

            listener?.onLog("HTTP ${parts[0]} -> $targetHost:$targetPort via SSL/TLS tunnel")
            val remoteSocket = createTlsConnection()
            if (remoteSocket != null) {
                if (isConnect) {
                    // Send a 200 to the local client immediately so it can start piping data.
                    clientSocket.getOutputStream().write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray())
                    clientSocket.getOutputStream().flush()
                    // For CONNECT, also tell the remote server where to forward via a SOCKS-like request.
                    pipe(clientSocket, remoteSocket, buildInnerSocksRequest(targetHost, targetPort))
                } else {
                    // For non-CONNECT, forward the original request through TLS
                    pipe(clientSocket, remoteSocket, header.copyOfRange(0, headerLen))
                }
            } else {
                clientSocket.getOutputStream().write("HTTP/1.1 502 Bad Gateway\r\n\r\n".toByteArray())
                clientSocket.getOutputStream().flush()
                clientSocket.close()
            }
        } catch (e: Exception) {
            listener?.onLog("HTTP proxy error: ${e.message}")
            try { clientSocket.close() } catch (_: Exception) {}
        }
    }

    /**
     * Creates a TLS connection to the configured VPN server.
     * Returns a Socket that is ready to be piped to a local client.
     */
    private fun createTlsConnection(): Socket? {
        return try {
            val sslContext = SSLContext.getInstance("TLS")
            sslContext.init(null, arrayOf<TrustManager>(trustAllManager), SecureRandom())

            val factory = sslContext.socketFactory as SSLSocketFactory
            val sock = factory.createSocket() as SSLSocket

            // Protect the socket so VPN traffic doesn't loop back into the tunnel
            try { socketProtector?.invoke(sock) } catch (_: Exception) {}

            val sniHost = config.sni.ifEmpty { config.serverAddress }
            val isSniHostAnIp = isIpAddress(sniHost)

            // Set SNI only if the configured value is a valid hostname (not an IP literal).
            // SNIHostName throws IllegalArgumentException for IP addresses per RFC 6066.
            if (!isSniHostAnIp) {
                val params = sock.sslParameters
                try {
                    val sniNames = listOf<SNIServerName>(SNIHostName(sniHost))
                    params.serverNames = sniNames
                    sock.sslParameters = params
                    listener?.onLog("SNI hostname set to: $sniHost")
                } catch (e: Exception) {
                    listener?.onLog("SNI could not be set ('$sniHost'): ${e.message}")
                }
            } else {
                listener?.onLog("Skipping SNI for IP literal: $sniHost")
            }

            val serverPort = if (config.serverPort > 0) config.serverPort else 443
            sock.connect(InetSocketAddress(config.serverAddress, serverPort), 15000)
            sock.soTimeout = 60000
            sock.tcpNoDelay = true

            sock.startHandshake()
            listener?.onLog("SSL/TLS handshake completed (SNI: $sniHost -> ${config.serverAddress}:$serverPort)")

            // Send the configured payload (if any) once the TLS tunnel is up.
            // This is the obfuscation header that some servers expect.
            if (config.payload.isNotEmpty()) {
                val payload = PayloadBuilder.preparePayloadForSsh(config.payload)
                sock.getOutputStream().write(payload.toByteArray(Charsets.UTF_8))
                sock.getOutputStream().flush()
                listener?.onLog("Custom payload sent through SSL tunnel (${payload.length} bytes)")
            }

            sock
        } catch (e: Exception) {
            listener?.onError("SSL connection failed to ${config.serverAddress}:${config.serverPort}: ${e.message}")
            null
        }
    }

    private fun isIpAddress(host: String): Boolean {
        if (host.isEmpty()) return false
        // IPv6 literal in brackets or raw
        if (host.startsWith("[") && host.endsWith("]")) return true
        if (host.contains(":")) return true // simple heuristic for IPv6
        // IPv4: four dotted octets
        val parts = host.split(".")
        if (parts.size == 4) {
            return parts.all { it.toIntOrNull()?.let { v -> v in 0..255 } == true }
        }
        return false
    }

    private fun pipe(client: Socket, remote: Socket, initialData: ByteArray? = null) {
        try {
            if (initialData != null && initialData.isNotEmpty()) {
                remote.getOutputStream().write(initialData)
                remote.getOutputStream().flush()
            }

            val clientToRemote = Thread({
                try {
                    val buf = ByteArray(32768)
                    val clientInput = client.getInputStream()
                    while (isRunning && !client.isClosed && !remote.isClosed) {
                        val read = clientInput.read(buf)
                        if (read == -1) break
                        remote.getOutputStream().write(buf, 0, read)
                        remote.getOutputStream().flush()
                    }
                } catch (_: Exception) {
                } finally {
                    try { remote.close() } catch (_: Exception) {}
                }
            }, "SslTunnel-C2R")
            clientToRemote.isDaemon = true
            clientToRemote.start()

            val buf = ByteArray(32768)
            val remoteInput = remote.getInputStream()
            while (isRunning && !client.isClosed && !remote.isClosed) {
                val read = remoteInput.read(buf)
                if (read == -1) break
                client.getOutputStream().write(buf, 0, read)
                client.getOutputStream().flush()
            }
        } catch (_: Exception) {
        } finally {
            try { client.close() } catch (_: Exception) {}
            try { remote.close() } catch (_: Exception) {}
        }
    }

    fun stop() {
        isRunning = false
        try { serverSocket?.close() } catch (_: Exception) {}
        serverSocket = null
        listener?.onDisconnected("SSL tunnel stopped")
    }
}
