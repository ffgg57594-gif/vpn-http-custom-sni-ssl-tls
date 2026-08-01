package com.customvpn.app.ssh

import com.customvpn.app.models.VpnConfig
import com.customvpn.app.utils.PayloadBuilder
import java.io.*
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

class SshTunnel(
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

    private var localPort: Int = 0
    @Volatile
    private var isRunning = false
    private var serverSocket: java.net.ServerSocket? = null
    private var acceptThread: Thread? = null

    val port: Int get() = localPort

    fun start(localBindPort: Int = 0): Int {
        isRunning = true
        listener?.onLog("Starting tunnel to ${config.serverAddress}:${config.sshPort}")
        listener?.onLog("SNI: ${config.sni.ifEmpty { config.serverAddress }}")

        if (config.serverAddress.isEmpty()) {
            throw IOException("Server address is empty")
        }

        try {
            serverSocket = java.net.ServerSocket(
                localBindPort, 50, java.net.InetAddress.getByName("127.0.0.1")
            )
            localPort = serverSocket!!.localPort
            listener?.onLog("Local SOCKS5/HTTP proxy listening on 127.0.0.1:$localPort")

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
                        listener?.onError("Server accept error: ${e.message}")
                    }
                }
            }, "SshTunnel-Accept")
            acceptThread?.isDaemon = true
            acceptThread?.start()

            listener?.onConnected()
            return localPort
        } catch (e: Exception) {
            listener?.onError("Failed to start tunnel: ${e.message}")
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

            // DNS-over-TCP: first 2 bytes are the message length.
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
            listener?.onLog("Client error: ${e.message}")
            try { clientSocket.close() } catch (_: Exception) {}
        }
    }

    private fun handleDnsOverTcp(clientSocket: Socket, firstChunk: ByteArray, firstChunkLen: Int) {
        Thread({
            try {
                val msgLen = ((firstChunk[0].toInt() and 0xFF) shl 8) or (firstChunk[1].toInt() and 0xFF)
                if (msgLen <= 0 || msgLen > 4096) {
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

                val dnsResponse = forwardDnsOverUdp(dnsQuery)
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
        }, "SshTunnel-DNS").start()
    }

    private fun forwardDnsOverUdp(dnsQuery: ByteArray): ByteArray? {
        return try {
            val socket = DatagramSocket()
            try { datagramSocketProtector?.invoke(socket) } catch (_: Exception) {}
            socket.soTimeout = 5000
            val target = InetAddress.getByName("8.8.8.8")
            val sendPacket = DatagramPacket(dnsQuery, dnsQuery.size, target, 53)
            socket.send(sendPacket)
            val buf = ByteArray(4096)
            val reply = DatagramPacket(buf, buf.size)
            socket.receive(reply)
            socket.close()
            buf.copyOf(reply.length)
        } catch (e: Exception) {
            null
        }
    }

    private fun handleSocks5(clientSocket: Socket, input: java.io.InputStream) {
        try {
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

            listener?.onLog("SOCKS5 CONNECT to $targetHost:$targetPort")
            val remoteSocket = createUpstreamConnection()
            if (remoteSocket != null) {
                val reply = byteArrayOf(
                    0x05, 0x00, 0x00, 0x01,
                    0, 0, 0, 0, 0, 0
                )
                clientSocket.getOutputStream().write(reply)
                clientSocket.getOutputStream().flush()
                // Inform upstream of the actual target
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

            listener?.onLog("HTTP ${parts[0]} -> $targetHost:$targetPort")
            val remoteSocket = createUpstreamConnection()
            if (remoteSocket != null) {
                if (isConnect) {
                    clientSocket.getOutputStream().write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray())
                    clientSocket.getOutputStream().flush()
                    pipe(clientSocket, remoteSocket, null)
                } else {
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
     * Opens a raw TCP connection to the configured server (SSH or direct mode)
     * and writes the obfuscation payload if one is configured.
     */
    private fun createUpstreamConnection(): Socket? {
        return try {
            val sock = Socket()
            try { socketProtector?.invoke(sock) } catch (_: Exception) {}
            val serverPort = if (config.sshPort > 0) config.sshPort else 22
            sock.connect(InetSocketAddress(config.serverAddress, serverPort), 15000)
            sock.soTimeout = 60000
            sock.tcpNoDelay = true

            listener?.onLog("Upstream connected to ${config.serverAddress}:$serverPort")

            if (config.payload.isNotEmpty()) {
                val payload = PayloadBuilder.preparePayloadForSsh(config.payload)
                sock.getOutputStream().write(payload.toByteArray(Charsets.UTF_8))
                sock.getOutputStream().flush()
                listener?.onLog("Custom payload sent (${payload.length} bytes)")
            }
            // NOTE: Without an SSH library we cannot do a real SSH handshake.
            // The connection is used in "raw passthrough" mode where the server
            // is expected to forward bytes after seeing the obfuscation header.

            sock
        } catch (e: Exception) {
            listener?.onError("Upstream connection failed: ${e.message}")
            null
        }
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
            }, "SshTunnel-C2R")
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
        listener?.onDisconnected("Tunnel stopped")
    }
}
