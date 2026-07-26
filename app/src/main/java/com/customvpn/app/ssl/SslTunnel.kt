package com.customvpn.app.ssl

import com.customvpn.app.models.VpnConfig
import java.io.*
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.*

class SslTunnel(
    private val config: VpnConfig,
    private val listener: TunnelListener? = null
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

    val port: Int get() = localPort

    private val trustAllManager = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    }

    fun start(localBindPort: Int = 0): Int {
        isRunning = true
        listener?.onLog("Starting SSL/TLS tunnel to ${config.serverAddress}:${config.serverPort}")
        listener?.onLog("SNI: ${config.sni.ifEmpty { "(none)" }}")

        try {
            serverSocket = java.net.ServerSocket(localBindPort, 1, java.net.InetAddress.getByName("127.0.0.1"))
            localPort = serverSocket!!.localPort
            listener?.onLog("Local proxy listening on port $localPort")

            Thread {
                try {
                    while (isRunning) {
                        val clientSocket = serverSocket?.accept() ?: break
                        Thread { handleClient(clientSocket) }.start()
                    }
                } catch (e: Exception) {
                    if (isRunning) {
                        listener?.onError("SSL server accept error: ${e.message}")
                    }
                }
            }.start()

            return localPort
        } catch (e: Exception) {
            listener?.onError("Failed to start SSL tunnel: ${e.message}")
            stop()
            throw e
        }
    }

    private fun handleClient(clientSocket: Socket) {
        var sslSocket: SSLSocket? = null
        try {
            clientSocket.soTimeout = 30000

            val buf = ByteArray(32768)
            val input = clientSocket.getInputStream()
            val read = input.read(buf)
            if (read <= 0) {
                clientSocket.close()
                return
            }

            val headerStr = String(buf, 0, read, Charsets.US_ASCII)
            val firstLine = headerStr.lines().firstOrNull() ?: ""
            val parts = firstLine.split(" ")

            val targetHost: String
            val targetPort: Int
            val isConnect: Boolean
            var remainingData: ByteArray? = null

            if (parts[0] == "CONNECT") {
                val hostPort = parts[1].split(":")
                targetHost = hostPort[0]
                targetPort = hostPort.getOrNull(1)?.toIntOrNull() ?: 443
                isConnect = true

                val headerEnd = headerStr.indexOf("\r\n\r\n")
                if (headerEnd > 0 && headerEnd + 4 < read) {
                    remainingData = buf.copyOfRange(headerEnd + 4, read)
                }
            } else if (parts.size >= 3) {
                val url = try { java.net.URL(parts[1]) } catch (_: Exception) { return }
                targetHost = url.host
                targetPort = if (url.port > 0) url.port else 443
                isConnect = false
                remainingData = buf.copyOfRange(0, read)
            } else {
                clientSocket.close()
                return
            }

            listener?.onLog("Connecting to $targetHost:$targetPort via SSL/TLS")

            sslSocket = createSslConnection(targetHost, targetPort)

            if (sslSocket != null) {
                if (isConnect) {
                    clientSocket.getOutputStream().write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray())
                    clientSocket.getOutputStream().flush()
                }

                if (remainingData != null && remainingData.isNotEmpty()) {
                    sslSocket.outputStream.write(remainingData)
                    sslSocket.outputStream.flush()
                }

                pipe(clientSocket, sslSocket)
            } else {
                if (isConnect) {
                    clientSocket.getOutputStream().write("HTTP/1.1 502 Bad Gateway\r\n\r\n".toByteArray())
                }
                clientSocket.close()
            }
        } catch (e: Exception) {
            listener?.onLog("SSL client error: ${e.message}")
            try { clientSocket.close() } catch (_: Exception) {}
            try { sslSocket?.close() } catch (_: Exception) {}
        }
    }

    private fun createSslConnection(targetHost: String, targetPort: Int): SSLSocket? {
        return try {
            val sslContext = SSLContext.getInstance("TLS")
            sslContext.init(null, arrayOf<TrustManager>(trustAllManager), SecureRandom())

            val factory = sslContext.socketFactory as SSLSocketFactory
            val sock = factory.createSocket() as SSLSocket

            sock.connect(InetSocketAddress(config.serverAddress, config.serverPort), 15000)
            sock.soTimeout = 60000

            try {
                val hostnameField = sock.javaClass.getDeclaredField("host")
                hostnameField.isAccessible = true
                hostnameField.set(sock, targetHost)
            } catch (_: Exception) {}

            sock.startHandshake()
            listener?.onLog("SSL/TLS handshake completed with $targetHost")

            sock
        } catch (e: Exception) {
            listener?.onError("SSL connection failed to $targetHost:$targetPort: ${e.message}")
            null
        }
    }

    private fun pipe(local: Socket, remote: SSLSocket) {
        try {
            Thread {
                try {
                    val buf = ByteArray(32768)
                    val input = local.getInputStream()
                    while (isRunning) {
                        val n = input.read(buf)
                        if (n == -1) break
                        remote.outputStream.write(buf, 0, n)
                        remote.outputStream.flush()
                    }
                } catch (_: Exception) {}
                finally {
                    try { remote.close() } catch (_: Exception) {}
                }
            }.start()

            val buf = ByteArray(32768)
            val input = remote.inputStream
            while (isRunning) {
                val n = input.read(buf)
                if (n == -1) break
                local.outputStream.write(buf, 0, n)
                local.outputStream.flush()
            }
        } catch (_: Exception) {}
        finally {
            try { local.close() } catch (_: Exception) {}
            try { remote.close() } catch (_: Exception) {}
        }
    }

    fun stop() {
        isRunning = false
        try { serverSocket?.close() } catch (_: Exception) {}
        listener?.onDisconnected("SSL tunnel stopped")
    }
}
