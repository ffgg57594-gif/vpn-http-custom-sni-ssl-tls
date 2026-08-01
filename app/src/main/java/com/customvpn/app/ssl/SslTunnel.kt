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
     * query. We forward the query to the VPN server's configured
     * upstream DNS resolver through the TLS tunnel by sending the
     * same length-prefixed query as the inner bytes (no SOCKS, no
     * HTTP wrapping) and reading the length-prefixed response. This
     * mirrors how HTTP Custom resolves DNS: the SNI is the routing
     * key, the inner bytes are forwarded transparently, the server
     * uses the SNI to know which user / destination the bytes are
     * for.
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
     * Forwards a DNS query to the VPN server's upstream DNS resolver
     * over the same TLS tunnel used for normal traffic.
     *
     * The VPN server (modeled on HTTP Custom) acts as a transparent
     * TCP forwarder once the TLS handshake is done: it picks the
     * destination based on the SNI we sent during the handshake and
     * pipes raw bytes back and forth. The SNI in the app config
     * (e.g. www.eand.com.eg) is the routing key.
     *
     * For DNS specifically, we send the DNS query as raw length-
     * prefixed bytes (RFC 7766) right after the TLS handshake and any
     * configured payload. The VPN server detects that the first 2
     * bytes look like a DNS message length, opens a TCP connection
     * to its configured upstream DNS resolver, and starts piping.
     * The response is also raw length-prefixed, so we read it the
     * same way the local client sent it.
     *
     * Compared to the previous attempts:
     *   - Inner-SOCKS approach: the server is a generic HTTPS
     *     reverse proxy, not a SOCKS5 forwarder, so the SOCKS
     *     header got interpreted as garbage.
     *   - DoH (HTTP/1.0 POST /dns-query) sent over the same tunnel:
     *     the server replied "101 Switching Protocols" because it
     *     treats the inner HTTP as a WebSocket upgrade request,
     *     not a real DoH client.
     *   - DoH through HTTP CONNECT 1.1.1.1:443: same problem, the
     *     upstream (eand's webserver) doesn't understand CONNECT.
     *
     * The only path the server actually understands is: TLS
     * handshake with a recognizable SNI, payload (if configured),
     * then raw bytes. So we send raw DNS-over-TCP bytes.
     */
    private fun forwardDnsOverTls(dnsQuery: ByteArray): ByteArray? {
        var remoteSocket: Socket? = null
        try {
            remoteSocket = createTlsConnection() ?: return null

            val out = remoteSocket.getOutputStream()
            val input = remoteSocket.getInputStream()

            // Send the raw DNS query length-prefixed (RFC 7766). The
            // server treats the bytes after the TLS handshake as the
            // inner stream and routes them to the DNS resolver it has
            // configured for this SNI.
            val lenPrefix = byteArrayOf(
                ((dnsQuery.size shr 8) and 0xFF).toByte(),
                (dnsQuery.size and 0xFF).toByte()
            )
            out.write(lenPrefix)
            out.write(dnsQuery)
            out.flush()
            remoteSocket.soTimeout = 10000

            // Read the length-prefixed DNS response.
            val lenBuf = ByteArray(2)
            readFullyOrTimeout(input, lenBuf) ?: return null
            val respLen = ((lenBuf[0].toInt() and 0xFF) shl 8) or (lenBuf[1].toInt() and 0xFF)
            if (respLen <= 0 || respLen > 65535) {
                listener?.onLog("DNS over TLS: bad response length $respLen")
                return null
            }
            val body = ByteArray(respLen)
            readFullyOrTimeout(input, body) ?: return null
            return body
        } catch (e: Exception) {
            listener?.onLog("DNS over TLS failed: ${e.message}")
            return null
        } finally {
            try { remoteSocket?.close() } catch (_: Exception) {}
        }
    }

    /**
     * Reads exactly buf.size bytes from input, honouring the
     * underlying socket's soTimeout. Returns null on timeout, EOF,
     * or any IO error.
     */
    private fun readFullyOrTimeout(input: java.io.InputStream, buf: ByteArray): ByteArray? {
        return try {
            var off = 0
            while (off < buf.size) {
                val n = input.read(buf, off, buf.size - off)
                if (n <= 0) return null
                off += n
            }
            buf
        } catch (_: java.net.SocketTimeoutException) {
            null
        } catch (_: Exception) {
            null
        }
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
