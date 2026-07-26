package com.customvpn.app.ssh

import com.customvpn.app.models.VpnConfig
import java.io.*
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer

class SshTunnel(
    private val config: VpnConfig,
    private val listener: TunnelListener? = null
) {

    interface TunnelListener {
        fun onConnected()
        fun onDisconnected(reason: String)
        fun onError(error: String)
        fun onLog(message: String)
    }

    private var socket: Socket? = null
    private var localPort: Int = 0
    @Volatile
    private var isRunning = false
    private var serverSocket: java.net.ServerSocket? = null

    val port: Int get() = localPort

    fun start(localBindPort: Int = 0): Int {
        isRunning = true
        listener?.onLog("Starting SSH tunnel to ${config.serverAddress}:${config.sshPort}")

        try {
            serverSocket = java.net.ServerSocket(localBindPort, 1, java.net.InetAddress.getByName("127.0.0.1"))
            localPort = serverSocket!!.localPort
            listener?.onLog("Local SOCKS proxy listening on port $localPort")

            Thread {
                try {
                    while (isRunning) {
                        val clientSocket = serverSocket?.accept() ?: break
                        Thread { handleClient(clientSocket) }.start()
                    }
                } catch (e: Exception) {
                    if (isRunning) {
                        listener?.onError("Server accept error: ${e.message}")
                    }
                }
            }.start()

            return localPort
        } catch (e: Exception) {
            listener?.onError("Failed to start tunnel: ${e.message}")
            stop()
            throw e
        }
    }

    private fun handleClient(clientSocket: Socket) {
        var remoteSocket: Socket? = null
        try {
            clientSocket.soTimeout = 30000

            val buf = ByteArray(1024)
            val input = clientSocket.getInputStream()
            val readLen = input.read(buf)
            if (readLen <= 0) {
                clientSocket.close()
                return
            }

            val headerStr = String(buf, 0, readLen, Charsets.US_ASCII)

            if (headerStr.startsWith("GET ") || headerStr.startsWith("POST ") || headerStr.startsWith("CONNECT ")) {
                handleHttpProxy(clientSocket, buf, readLen, headerStr)
                return
            }

            // SOCKS5 protocol
            if (buf[0] == 0x05.toByte()) {
                // Greeting: version + nmethods + methods
                // Reply with no-auth
                clientSocket.getOutputStream().write(byteArrayOf(0x05, 0x00))
                clientSocket.getOutputStream().flush()

                // Read CONNECT request
                val connectBuf = ByteArray(256)
                val connectLen = input.read(connectBuf)
                if (connectLen < 7) {
                    clientSocket.close()
                    return
                }

                val cmd = connectBuf[1].toInt() and 0xFF
                if (cmd != 0x01) { // Only CONNECT supported
                    clientSocket.getOutputStream().write(byteArrayOf(0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                    clientSocket.getOutputStream().flush()
                    clientSocket.close()
                    return
                }

                val atyp = connectBuf[3].toInt() and 0xFF
                val targetHost: String
                val targetPort: Int

                when (atyp) {
                    0x01 -> { // IPv4
                        if (connectLen < 10) { clientSocket.close(); return }
                        targetHost = "${connectBuf[4].toInt() and 0xFF}.${connectBuf[5].toInt() and 0xFF}.${connectBuf[6].toInt() and 0xFF}.${connectBuf[7].toInt() and 0xFF}"
                        targetPort = ((connectBuf[8].toInt() and 0xFF) shl 8) or (connectBuf[9].toInt() and 0xFF)
                    }
                    0x03 -> { // Domain
                        val domainLen = connectBuf[4].toInt() and 0xFF
                        if (connectLen < 5 + domainLen + 2) { clientSocket.close(); return }
                        targetHost = String(connectBuf, 5, domainLen)
                        targetPort = ((connectBuf[5 + domainLen].toInt() and 0xFF) shl 8) or (connectBuf[6 + domainLen].toInt() and 0xFF)
                    }
                    0x04 -> { // IPv6
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
                remoteSocket = createSshConnection(targetHost, targetPort)
                if (remoteSocket != null) {
                    // Success reply
                    val reply = ByteArray(10)
                    reply[0] = 0x05
                    reply[1] = 0x00 // Success
                    reply[2] = 0x00
                    reply[3] = 0x01
                    clientSocket.getOutputStream().write(reply)
                    clientSocket.getOutputStream().flush()

                    pipe(clientSocket, remoteSocket, null, 0, 0)
                } else {
                    // Failure reply
                    val reply = byteArrayOf(0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0)
                    clientSocket.getOutputStream().write(reply)
                    clientSocket.getOutputStream().flush()
                    clientSocket.close()
                }
                return
            }

            // Fallback - try as raw proxy
            clientSocket.close()
        } catch (e: Exception) {
            listener?.onLog("Client connection error: ${e.message}")
            try { clientSocket.close() } catch (_: Exception) {}
            try { remoteSocket?.close() } catch (_: Exception) {}
        }
    }

    private fun handleHttpProxy(clientSocket: Socket, header: ByteArray, headerLen: Int, headerStr: String) {
        try {
            val firstLine = headerStr.lines().first()
            val parts = firstLine.split(" ")

            val targetHost: String
            val targetPort: Int

            if (parts[0] == "CONNECT") {
                val hostPort = parts[1].split(":")
                targetHost = hostPort[0]
                targetPort = hostPort.getOrNull(1)?.toIntOrNull() ?: 443
            } else {
                val url = java.net.URL(parts[1])
                targetHost = url.host
                targetPort = if (url.port > 0) url.port else if (url.protocol == "https") 443 else 80
            }

            val remoteSocket = createSshConnection(targetHost, targetPort)
            if (remoteSocket != null) {
                if (parts[0] == "CONNECT") {
                    clientSocket.getOutputStream().write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray())
                    clientSocket.getOutputStream().flush()
                } else {
                    remoteSocket.getOutputStream().write(header, 0, headerLen)
                    remoteSocket.getOutputStream().flush()
                }
                pipe(clientSocket, remoteSocket, null, 0, 0)
            } else {
                clientSocket.getOutputStream().write("HTTP/1.1 502 Bad Gateway\r\n\r\n".toByteArray())
                clientSocket.close()
            }
        } catch (e: Exception) {
            try { clientSocket.close() } catch (_: Exception) {}
        }
    }

    private fun createSshConnection(targetHost: String, targetPort: Int): Socket? {
        return try {
            val sock = Socket()
            sock.connect(InetSocketAddress(config.serverAddress, config.sshPort), 10000)
            sock.soTimeout = 60000

            if (config.payload.isNotEmpty()) {
                val payload = com.customvpn.app.utils.PayloadBuilder.preparePayloadForSsh(config.payload)
                sock.getOutputStream().write(payload.toByteArray())
                sock.getOutputStream().flush()
                Thread.sleep(200)
            }

            val connectPacket = buildSocksConnect(targetHost, targetPort)
            sock.getOutputStream().write(connectPacket)
            sock.getOutputStream().flush()

            val response = ByteArray(10)
            val readLen = sock.getInputStream().read(response)
            if (readLen > 0) {
                val respStr = String(response, 0, readLen)
                listener?.onLog("SSH connect response: ${respStr.take(100)}")
            }

            sock
        } catch (e: Exception) {
            listener?.onError("SSH connection failed: ${e.message}")
            null
        }
    }

    private fun buildSocksConnect(host: String, port: Int): ByteArray {
        val buf = ByteBuffer.allocate(512)
        buf.put(0x05)
        buf.put(0x01)
        buf.put(0x00)
        buf.put(0x03)
        val hostBytes = host.toByteArray()
        buf.put(hostBytes.size.toByte())
        buf.put(hostBytes)
        buf.putShort(port.toShort())
        val result = ByteArray(buf.position())
        buf.flip()
        buf.get(result)
        return result
    }

    private fun sendSocksResponse(clientSocket: Socket, status: Byte) {
        val response = byteArrayOf(0x05, status, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
        try {
            clientSocket.getOutputStream().write(response)
            clientSocket.getOutputStream().flush()
        } catch (_: Exception) {}
    }

    private fun pipe(client: Socket, remote: Socket, initialData: ByteArray?, initialOffset: Int, initialLen: Int) {
        try {
            if (initialData != null && initialLen > 0) {
                remote.getOutputStream().write(initialData, initialOffset, initialLen)
                remote.getOutputStream().flush()
            }

            Thread {
                try {
                    val buf = ByteArray(32768)
                    val clientInput = client.getInputStream()
                    while (isRunning) {
                        val read = clientInput.read(buf)
                        if (read == -1) break
                        remote.getOutputStream().write(buf, 0, read)
                        remote.getOutputStream().flush()
                    }
                } catch (_: Exception) {}
                finally {
                    try { remote.close() } catch (_: Exception) {}
                }
            }.start()

            val buf = ByteArray(32768)
            val remoteInput = remote.getInputStream()
            while (isRunning) {
                val read = remoteInput.read(buf)
                if (read == -1) break
                client.getOutputStream().write(buf, 0, read)
                client.getOutputStream().flush()
            }
        } catch (_: Exception) {}
        finally {
            try { client.close() } catch (_: Exception) {}
            try { remote.close() } catch (_: Exception) {}
        }
    }

    fun stop() {
        isRunning = false
        try { serverSocket?.close() } catch (_: Exception) {}
        try { socket?.close() } catch (_: Exception) {}
        listener?.onDisconnected("Tunnel stopped")
    }
}
