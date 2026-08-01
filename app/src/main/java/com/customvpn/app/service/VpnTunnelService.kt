package com.customvpn.app.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import com.customvpn.app.R
import com.customvpn.app.models.ConnectionState
import com.customvpn.app.models.LogEntry
import com.customvpn.app.models.VpnConfig
import com.customvpn.app.ssh.SshTunnel
import com.customvpn.app.ssl.SslTunnel
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.LinkedHashSet
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.random.Random

class VpnTunnelService : VpnService() {

    companion object {
        private const val TAG = "VpnTunnelService"
        private const val CHANNEL_ID = "CustomVPN_channel"
        private const val NOTIFICATION_ID = 1
        const val ACTION_START = "com.customvpn.app.START"
        const val ACTION_STOP = "com.customvpn.app.STOP"
        const val ACTION_CONNECT = "com.customvpn.app.CONNECT"
        const val ACTION_DISCONNECT = "com.customvpn.app.DISCONNECT"

        @Volatile
        private var connectionState = ConnectionState.DISCONNECTED
        private val logQueue = java.util.concurrent.ConcurrentLinkedQueue<LogEntry>()
        @Volatile
        private var lastErrorMessage: String? = null
        @Volatile
        private var currentConfig: VpnConfig? = null

        fun getState(): ConnectionState = connectionState
        fun getLogs(): List<LogEntry> = logQueue.toList()
        fun getCurrentConfig(): VpnConfig? = currentConfig
        fun getLastError(): String? = lastErrorMessage
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var sshTunnel: SshTunnel? = null
    private var sslTunnel: SslTunnel? = null
    private var tunnelThread: Thread? = null
    @Volatile
    private var isRunning = false
    private var localProxyPort: Int = 0

    private var vpnOutputWriter: FileOutputStream? = null
    private val packetQueue = LinkedBlockingQueue<ByteArray>()
    private var packetWriterThread: Thread? = null

    private val tcpSessions = ConcurrentHashMap<String, TcpSession>()

    /**
     * Keyed by "<clientIp>:<clientPort>:<dstIp>:<dstPort>" so we can support
     * multiple connections to the same client port from different targets.
     */
    private data class TcpSession(
        val clientIp: InetAddress,
        val serverIp: InetAddress,
        val clientPort: Int,
        val serverPort: Int,
        var clientSeq: Long = 0,
        var serverSeq: Long = 0,
        var proxySocket: Socket? = null,
        @Volatile var state: State = State.SYN_RECEIVED,
        @Volatile var established: Boolean = false,
        @Volatile var lastAckedClientSeq: Long = 0
    ) {
        enum class State { SYN_RECEIVED, ESTABLISHED, CLOSING, CLOSED }

        fun key(): String = "$clientIp:$clientPort->$serverIp:$serverPort"
    }

    override fun onBind(intent: Intent?) = super.onBind(intent)

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Always promote to foreground first so Android 8+ does not kill the service.
        if (intent?.action != ACTION_DISCONNECT && intent?.action != ACTION_STOP) {
            showNotification("Custom VPN starting...")
        }

        when (intent?.action) {
            ACTION_CONNECT, ACTION_START -> {
                val config = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableExtra("config", VpnConfig::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableExtra("config") as? VpnConfig
                }
                if (config != null) {
                    connect(config)
                } else {
                    setFailed("No configuration provided")
                }
            }
            ACTION_DISCONNECT, ACTION_STOP -> {
                disconnect()
            }
        }
        return START_STICKY
    }

    fun connect(config: VpnConfig) {
        if (connectionState == ConnectionState.CONNECTED || connectionState == ConnectionState.CONNECTING) {
            addLog(LogEntry(level = LogEntry.Level.WARNING, message = "Already connected or connecting"))
            return
        }

        connectionState = ConnectionState.CONNECTING
        lastErrorMessage = null
        currentConfig = config
        localProxyPort = 0
        isRunning = true
        addLog(LogEntry(level = LogEntry.Level.INFO, message = "Connecting via ${config.connectionMode.displayName}..."))
        showNotification("Connecting via ${config.connectionMode.displayName}...")

        tunnelThread = Thread({
            try {
                if (config.serverAddress.isEmpty()) {
                    setFailed("Server address is empty")
                    return@Thread
                }

                when (config.connectionMode) {
                    VpnConfig.ConnectionMode.SSL_TLS,
                    VpnConfig.ConnectionMode.SSL_TLS_SNI -> connectSslSsh(config)
                    VpnConfig.ConnectionMode.SSH,
                    VpnConfig.ConnectionMode.DIRECT_SSH -> connectSsh(config)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Connection exception", e)
                setFailed("Connection failed: ${e.message}")
            }
        }, "VpnTunnel-Connect")
        tunnelThread?.start()
    }

    private fun setFailed(message: String) {
        lastErrorMessage = message
        connectionState = ConnectionState.FAILED
        addLog(LogEntry(level = LogEntry.Level.ERROR, message = message))
        isRunning = false
        showNotification("Connection failed: $message")
    }

    private fun connectSslSsh(config: VpnConfig) {
        addLog(LogEntry(level = LogEntry.Level.INFO, message = "Starting SSL/TLS tunnel..."))
        addLog(LogEntry(level = LogEntry.Level.INFO, message = "Server: ${config.serverAddress}:${config.serverPort}"))
        addLog(LogEntry(level = LogEntry.Level.INFO, message = "SNI: ${config.sni.ifEmpty { config.serverAddress }}"))

        val tunnel = SslTunnel(config, object : SslTunnel.TunnelListener {
            override fun onConnected() {
                addLog(LogEntry(level = LogEntry.Level.INFO, message = "SSL/TLS local proxy ready"))
            }
            override fun onDisconnected(reason: String) {
                addLog(LogEntry(level = LogEntry.Level.INFO, message = "SSL tunnel: $reason"))
                if (isRunning) {
                    setFailed("SSL tunnel disconnected: $reason")
                }
            }
            override fun onError(error: String) {
                addLog(LogEntry(level = LogEntry.Level.ERROR, message = "SSL error: $error"))
            }
            override fun onLog(message: String) {
                addLog(LogEntry(level = LogEntry.Level.DEBUG, message = message))
            }
        }, socketProtector = { s -> protect(s) }, datagramSocketProtector = { ds -> protect(ds) })
        sslTunnel = tunnel

        try {
            localProxyPort = tunnel.start(0)
        } catch (e: Exception) {
            setFailed("Failed to start SSL proxy: ${e.message}")
            return
        }
        addLog(LogEntry(level = LogEntry.Level.INFO, message = "Local SSL proxy on 127.0.0.1:$localProxyPort"))

        establishVpn(config)
    }

    private fun connectSsh(config: VpnConfig) {
        addLog(LogEntry(level = LogEntry.Level.INFO, message = "Starting SSH tunnel..."))
        addLog(LogEntry(level = LogEntry.Level.INFO, message = "Server: ${config.serverAddress}:${config.sshPort}"))

        val tunnel = SshTunnel(config, object : SshTunnel.TunnelListener {
            override fun onConnected() {
                addLog(LogEntry(level = LogEntry.Level.INFO, message = "SSH local proxy ready"))
            }
            override fun onDisconnected(reason: String) {
                addLog(LogEntry(level = LogEntry.Level.INFO, message = "SSH tunnel: $reason"))
                if (isRunning) {
                    setFailed("SSH tunnel disconnected: $reason")
                }
            }
            override fun onError(error: String) {
                addLog(LogEntry(level = LogEntry.Level.ERROR, message = "SSH error: $error"))
            }
            override fun onLog(message: String) {
                addLog(LogEntry(level = LogEntry.Level.DEBUG, message = message))
            }
        }, socketProtector = { s -> protect(s) }, datagramSocketProtector = { ds -> protect(ds) })
        sshTunnel = tunnel

        try {
            localProxyPort = tunnel.start(0)
        } catch (e: Exception) {
            setFailed("Failed to start SSH proxy: ${e.message}")
            return
        }
        addLog(LogEntry(level = LogEntry.Level.INFO, message = "Local proxy on 127.0.0.1:$localProxyPort"))

        establishVpn(config)
    }

    private fun establishVpn(config: VpnConfig) {
        if (localProxyPort <= 0) {
            setFailed("Local proxy port is invalid")
            return
        }

        val builder = Builder()
        builder.setSession("Custom VPN")
        builder.setMtu(config.mtu.coerceIn(576, 1500))
        builder.addAddress("10.0.0.2", 32)
        builder.addRoute("0.0.0.0", 0)
        builder.addDnsServer(config.dns1.ifEmpty { "8.8.8.8" })
        if (config.dns2.isNotEmpty()) {
            builder.addDnsServer(config.dns2)
        }

        try {
            builder.addDisallowedApplication(packageName)
        } catch (_: Exception) {}

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }

        try {
            vpnInterface = builder.establish()
        } catch (e: Exception) {
            setFailed("Failed to create VPN interface: ${e.message}")
            return
        }

        if (vpnInterface == null) {
            setFailed("Failed to create VPN interface. Make sure VPN permission is granted.")
            return
        }

        vpnOutputWriter = FileOutputStream(vpnInterface!!.fileDescriptor)

        packetWriterThread = Thread({
            try {
                while (isRunning) {
                    val packet = packetQueue.poll(200, TimeUnit.MILLISECONDS) ?: continue
                    try {
                        vpnOutputWriter?.write(packet)
                        vpnOutputWriter?.flush()
                    } catch (e: Exception) {
                        if (isRunning) {
                            Log.e(TAG, "Packet writer error: ${e.message}")
                        }
                    }
                }
            } catch (_: InterruptedException) {
                // Expected on shutdown
            }
        }, "VpnTunnel-PacketWriter")
        packetWriterThread?.isDaemon = true
        packetWriterThread?.start()

        addLog(LogEntry(level = LogEntry.Level.INFO, message = "VPN interface established"))
        connectionState = ConnectionState.CONNECTED
        showNotification("Connected via ${config.connectionMode.displayName}")

        Thread({ startPacketForwarding() }, "VpnTunnel-PacketReader").start()
    }

    // ==================== PACKET FORWARDING ====================

    private fun startPacketForwarding() {
        val vpnFd = vpnInterface ?: return
        val fd = vpnFd.fileDescriptor
        val input = FileInputStream(fd)

        val packet = ByteArray(32767)
        addLog(LogEntry(level = LogEntry.Level.INFO, message = "Packet forwarding started"))

        while (isRunning) {
            try {
                val length = input.read(packet)
                if (length <= 0) {
                    Thread.sleep(5)
                    continue
                }

                val version = (packet[0].toInt() and 0xF0) ushr 4
                when (version) {
                    4 -> handleIPv4Packet(packet, length)
                    6 -> { /* IPv6 - skip */ }
                }
            } catch (_: InterruptedException) {
                break
            } catch (e: Exception) {
                if (isRunning) {
                    Log.e(TAG, "Packet forwarding error: ${e.message}")
                }
            }
        }

        try { input.close() } catch (_: Exception) {}
        addLog(LogEntry(level = LogEntry.Level.INFO, message = "Packet forwarding stopped"))
    }

    private fun handleIPv4Packet(packet: ByteArray, length: Int) {
        try {
            if (length < 20) return
            val protocol = packet[9].toInt() and 0xFF
            when (protocol) {
                6 -> handleTcpPacket(packet, length)
                17 -> handleUdpPacket(packet, length)
                1 -> {
                    // ICMP - just bounce back unchanged so pings work minimally
                    val echo = packet.copyOfRange(0, length)
                    swapIpAddresses(echo)
                    recalculateChecksums(echo, length)
                    packetQueue.offer(echo)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "IPv4 handling error: ${e.message}")
        }
    }

    private fun swapIpAddresses(packet: ByteArray) {
        for (i in 0..3) {
            val tmp = packet[12 + i]
            packet[12 + i] = packet[16 + i]
            packet[16 + i] = tmp
        }
    }

    // ==================== TCP HANDLING ====================

    private fun handleTcpPacket(packet: ByteArray, length: Int) {
        try {
            val ipHeaderLen = (packet[0].toInt() and 0x0F) * 4
            if (length < ipHeaderLen + 20) return

            val tcpHeaderOffset = ipHeaderLen
            val flags = packet[tcpHeaderOffset + 13].toInt() and 0xFF
            val syn = (flags and 0x02) != 0
            val ack = (flags and 0x10) != 0
            val fin = (flags and 0x01) != 0
            val rst = (flags and 0x04) != 0

            val srcPort = ((packet[tcpHeaderOffset].toInt() and 0xFF) shl 8) or
                    (packet[tcpHeaderOffset + 1].toInt() and 0xFF)
            val dstPort = ((packet[tcpHeaderOffset + 2].toInt() and 0xFF) shl 8) or
                    (packet[tcpHeaderOffset + 3].toInt() and 0xFF)

            val srcAddr = InetAddress.getByAddress(byteArrayOf(packet[12], packet[13], packet[14], packet[15]))
            val dstAddr = InetAddress.getByAddress(byteArrayOf(packet[16], packet[17], packet[18], packet[19]))

            val clientSeqNum = readSeqNumber(packet, tcpHeaderOffset + 4)

            val tcpDataOffsetField = ((packet[tcpHeaderOffset + 12].toInt() and 0xF0) ushr 4)
            val tcpDataOffset = tcpHeaderOffset + (tcpDataOffsetField * 4)
            val tcpDataLen = if (tcpDataOffset < length) length - tcpDataOffset else 0

            val sessionKey = "$srcAddr:$srcPort->$dstAddr:$dstPort"

            if (rst) {
                val session = tcpSessions.remove(sessionKey)
                session?.proxySocket?.let { try { it.close() } catch (_: Exception) {} }
                return
            }

            if (syn && !ack) {
                handleTcpSyn(srcAddr, dstAddr, srcPort, dstPort, clientSeqNum)
            } else if (fin) {
                handleTcpFin(srcAddr, dstAddr, srcPort, dstPort, clientSeqNum)
            } else if (ack) {
                val session = tcpSessions[sessionKey] ?: return

                if (session.state == TcpSession.State.SYN_RECEIVED) {
                    session.state = TcpSession.State.ESTABLISHED
                    session.established = true
                    session.lastAckedClientSeq = clientSeqNum
                    addLog(LogEntry(level = LogEntry.Level.DEBUG, message = "TCP handshake complete: $sessionKey"))
                }

                if (tcpDataLen > 0 && session.proxySocket != null) {
                    // Only forward new data (avoid duplicates on retransmits)
                    if (clientSeqNum >= session.lastAckedClientSeq) {
                        val data = packet.copyOfRange(tcpDataOffset, tcpDataOffset + tcpDataLen)
                        session.lastAckedClientSeq = clientSeqNum + tcpDataLen
                        session.clientSeq = clientSeqNum + tcpDataLen
                        // ACK the data
                        queueTcpPacket(dstAddr, srcAddr, dstPort, srcPort,
                            session.serverSeq, clientSeqNum + tcpDataLen, 0x10, null, 0)
                        forwardDataToProxy(session, data)
                    } else if (clientSeqNum + tcpDataLen > session.lastAckedClientSeq) {
                        // Partial overlap
                        val skip = (session.lastAckedClientSeq - clientSeqNum).toInt()
                        if (skip in 0 until tcpDataLen) {
                            val data = packet.copyOfRange(tcpDataOffset + skip, tcpDataOffset + tcpDataLen)
                            session.lastAckedClientSeq = clientSeqNum + tcpDataLen
                            session.clientSeq = clientSeqNum + tcpDataLen
                            queueTcpPacket(dstAddr, srcAddr, dstPort, srcPort,
                                session.serverSeq, clientSeqNum + tcpDataLen, 0x10, null, 0)
                            forwardDataToProxy(session, data)
                        }
                    }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "TCP handling error: ${e.message}")
        }
    }

    private fun handleTcpSyn(
        srcAddr: InetAddress, dstAddr: InetAddress,
        srcPort: Int, dstPort: Int,
        clientSeq: Long
    ) {
        val serverIsn = Random.nextLong(0xFFFFFFFFL)
        val sessionKey = "$srcAddr:$srcPort->$dstAddr:$dstPort"
        val session = TcpSession(
            clientIp = srcAddr,
            serverIp = dstAddr,
            clientPort = srcPort,
            serverPort = dstPort,
            clientSeq = clientSeq + 1,
            serverSeq = serverIsn,
            state = TcpSession.State.SYN_RECEIVED,
            lastAckedClientSeq = clientSeq + 1
        )
        tcpSessions[sessionKey] = session

        // Send SYN-ACK
        queueTcpPacket(dstAddr, srcAddr, dstPort, srcPort, serverIsn, clientSeq + 1, 0x12, null, 0)

        addLog(LogEntry(level = LogEntry.Level.DEBUG, message = "TCP SYN: $sessionKey"))

        // Open a connection to the local proxy in a worker thread
        Thread({
            try {
                val proxyClient = Socket()
                protect(proxyClient)
                proxyClient.connect(InetSocketAddress("127.0.0.1", localProxyPort), 15000)
                // Use a longer soTimeout so the SSL handshake to the remote server
                // has enough time to complete before we give up reading the proxy response.
                proxyClient.soTimeout = 90000
                proxyClient.tcpNoDelay = true

                val connectRequest = "CONNECT ${dstAddr.hostAddress}:$dstPort HTTP/1.1\r\n" +
                        "Host: ${dstAddr.hostAddress}:$dstPort\r\n" +
                        "Proxy-Connection: keep-alive\r\n" +
                        "User-Agent: CustomVPN/1.0\r\n" +
                        "\r\n"
                val reqBytes = connectRequest.toByteArray(Charsets.US_ASCII)
                proxyClient.getOutputStream().write(reqBytes)
                proxyClient.getOutputStream().flush()

                // Read the proxy response fully (until \r\n\r\n) so we don't accidentally
                // treat part of the response as the first data byte.
                val response = readHttpResponse(proxyClient)
                if (response.isEmpty()) {
                    addLog(LogEntry(level = LogEntry.Level.WARNING, message = "Proxy response timed out ($sessionKey)"))
                    proxyClient.close()
                    tcpSessions.remove(sessionKey)
                    return@Thread
                }

                val responseStr = String(response, Charsets.US_ASCII)
                if (!responseStr.contains("200")) {
                    addLog(LogEntry(level = LogEntry.Level.WARNING, message = "Proxy rejected: ${responseStr.lineSequence().firstOrNull() ?: ""}"))
                    proxyClient.close()
                    tcpSessions.remove(sessionKey)
                    return@Thread
                }

                synchronized(session) {
                    session.proxySocket = proxyClient
                }
                addLog(LogEntry(level = LogEntry.Level.DEBUG, message = "Proxy connected for $sessionKey"))

                relayFromProxyToTun(session)
            } catch (e: java.net.SocketTimeoutException) {
                addLog(LogEntry(level = LogEntry.Level.ERROR, message = "Pull time out ($sessionKey): SSL handshake to remote server took too long"))
                val s = tcpSessions.remove(sessionKey)
                try { s?.proxySocket?.close() } catch (_: Exception) {}
            } catch (e: Exception) {
                addLog(LogEntry(level = LogEntry.Level.ERROR, message = "Proxy connect failed ($sessionKey): ${e.message}"))
                val s = tcpSessions.remove(sessionKey)
                try { s?.proxySocket?.close() } catch (_: Exception) {}
            }
        }, "VpnTunnel-ProxyConnect").start()
    }

    /**
     * Reads the proxy response until the end-of-headers marker is seen
     * or the read times out. Returns the response bytes (without trailing CRLF).
     */
    private fun readHttpResponse(socket: Socket): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val buf = ByteArray(1024)
        val deadline = System.currentTimeMillis() + socket.soTimeout.toLong()
        while (System.currentTimeMillis() < deadline) {
            val remaining = (deadline - System.currentTimeMillis()).toInt().coerceAtLeast(1)
            try {
                socket.soTimeout = remaining
                val n = socket.getInputStream().read(buf)
                if (n <= 0) break
                out.write(buf, 0, n)
                // ByteArrayOutputStream.toString(Charset) is API 33+, so use String constructor
                // which is available since API 1.
                val text = String(out.toByteArray(), Charsets.US_ASCII)
                if (text.contains("\r\n\r\n")) {
                    return out.toByteArray()
                }
            } catch (_: java.net.SocketTimeoutException) {
                break
            }
        }
        return out.toByteArray()
    }

    private fun handleTcpFin(
        srcAddr: InetAddress, dstAddr: InetAddress,
        srcPort: Int, dstPort: Int, clientSeq: Long
    ) {
        val sessionKey = "$srcAddr:$srcPort->$dstAddr:$dstPort"
        val session = tcpSessions.remove(sessionKey) ?: return

        // ACK the FIN
        queueTcpPacket(
            srcIp = dstAddr, dstIp = srcAddr,
            srcPort = dstPort, dstPort = srcPort,
            seqNum = session.serverSeq, ackNum = clientSeq + 1,
            flags = 0x10, data = null, dataLen = 0
        )
        // Send our own FIN
        queueTcpPacket(
            srcIp = dstAddr, dstIp = srcAddr,
            srcPort = dstPort, dstPort = srcPort,
            seqNum = session.serverSeq, ackNum = clientSeq + 1,
            flags = 0x11, data = null, dataLen = 0
        )

        session.state = TcpSession.State.CLOSED
        try { session.proxySocket?.close() } catch (_: Exception) {}
        addLog(LogEntry(level = LogEntry.Level.DEBUG, message = "TCP FIN: $sessionKey closed"))
    }

    private fun forwardDataToProxy(session: TcpSession, data: ByteArray) {
        Thread({
            try {
                val sock = session.proxySocket ?: return@Thread
                synchronized(sock) {
                    sock.getOutputStream().write(data)
                    sock.getOutputStream().flush()
                }
            } catch (e: Exception) {
                addLog(LogEntry(level = LogEntry.Level.DEBUG, message = "Forward to proxy error: ${e.message}"))
                val key = session.key()
                tcpSessions.remove(key)
                try { session.proxySocket?.close() } catch (_: Exception) {}
            }
        }, "VpnTunnel-C2R").start()
    }

    private fun relayFromProxyToTun(session: TcpSession) {
        Thread({
            try {
                val buf = ByteArray(32768)
                val input = session.proxySocket?.getInputStream() ?: return@Thread
                while (isRunning && session.state != TcpSession.State.CLOSED) {
                    val n = input.read(buf)
                    if (n == -1) break
                    val data = buf.copyOfRange(0, n)
                    synchronized(session) {
                        session.serverSeq += n
                        queueTcpPacket(
                            srcIp = session.serverIp, dstIp = session.clientIp,
                            srcPort = session.serverPort, dstPort = session.clientPort,
                            seqNum = session.serverSeq, ackNum = session.lastAckedClientSeq,
                            flags = 0x18, // PSH+ACK
                            data = data, dataLen = n
                        )
                    }
                }
            } catch (e: Exception) {
                if (isRunning) {
                    addLog(LogEntry(level = LogEntry.Level.DEBUG, message = "Proxy relay ended for ${session.clientPort}: ${e.message}"))
                }
            } finally {
                try { session.proxySocket?.close() } catch (_: Exception) {}
                tcpSessions.remove(session.key())
            }
        }, "VpnTunnel-R2T").start()
    }

    // ==================== UDP / DNS HANDLING ====================

    private fun handleUdpPacket(packet: ByteArray, length: Int) {
        try {
            val ipHeaderLen = (packet[0].toInt() and 0x0F) * 4
            if (length < ipHeaderLen + 8) return

            val udpOffset = ipHeaderLen
            val srcPort = ((packet[udpOffset].toInt() and 0xFF) shl 8) or (packet[udpOffset + 1].toInt() and 0xFF)
            val dstPort = ((packet[udpOffset + 2].toInt() and 0xFF) shl 8) or (packet[udpOffset + 3].toInt() and 0xFF)
            val udpLen = ((packet[udpOffset + 4].toInt() and 0xFF) shl 8) or (packet[udpOffset + 5].toInt() and 0xFF)
            val udpDataOffset = udpOffset + 8
            val udpDataLen = if (udpLen > 8) (udpLen - 8).coerceAtMost(length - udpDataOffset) else 0
            if (udpDataLen <= 0) return

            val srcAddr = InetAddress.getByAddress(byteArrayOf(packet[12], packet[13], packet[14], packet[15]))
            val dstAddr = InetAddress.getByAddress(byteArrayOf(packet[16], packet[17], packet[18], packet[19]))

            // Route DNS through the local proxy via TCP using the proxy's port.
            // For other UDP, try direct forwarding first.
            if (dstPort == 53) {
                handleDnsQuery(srcAddr, dstAddr, srcPort, packet, udpDataOffset, udpDataLen)
            } else {
                handleGenericUdp(srcAddr, dstAddr, srcPort, dstPort, packet, udpDataOffset, udpDataLen)
            }
        } catch (e: Exception) {
            Log.e(TAG, "UDP handling error: ${e.message}")
        }
    }

    private fun handleDnsQuery(
        srcAddr: InetAddress, dstAddr: InetAddress,
        srcPort: Int, packet: ByteArray, dataOffset: Int, dataLen: Int
    ) {
        Thread({
            try {
                val dnsData = packet.copyOfRange(dataOffset, dataOffset + dataLen)
                val transactionId = if (dnsData.size >= 2) {
                    ((dnsData[0].toInt() and 0xFF) shl 8) or (dnsData[1].toInt() and 0xFF)
                } else 0

                val dnsResponse = dnsOverTcp(dnsData)

                if (dnsResponse != null) {
                    val responsePacket = buildUdpResponse(srcAddr, dstAddr, srcPort, 53, dnsResponse, dnsResponse.size)
                    packetQueue.offer(responsePacket)
                } else {
                    addLog(LogEntry(level = LogEntry.Level.DEBUG, message = "DNS query failed: Poll timed out (txid=$transactionId)"))
                }
            } catch (e: Exception) {
                addLog(LogEntry(level = LogEntry.Level.DEBUG, message = "DNS query failed: ${e.message}"))
            }
        }, "VpnTunnel-DNS").start()
    }

    /**
     * Performs a DNS query through the local proxy over TCP (RFC 7766).
     *
     * This uses the EXACT same path the regular HTTP CONNECT flow uses
     * for any TCP traffic (we see "Proxy connected for ... 8.8.8.8:853"
     * succeeding in the regular HTTP CONNECT logs). The local proxy
     * accepts an HTTP CONNECT for 8.8.8.8:853 (Google DNS-over-TLS),
     * opens a TLS tunnel to that endpoint, and pipes the DNS bytes
     * back and forth.
     *
     * Why this works for DNS where the previous attempts didn't:
     *   - Port 853 (DoT) is the only DNS-related port the remote
     *     actually forwards. Port 53 is blocked (fake Content-Length:
     *     100 GB page).
     *   - Going through the HTTP CONNECT path means the SslTunnel
     *     uses its own proven `handleHttpProxy` code, not the
     *     custom inner-SOCKS / raw-bytes paths that all kept
     *     getting misinterpreted or EOFed by the remote.
     *
     * Each candidate gets its own socket so a partial CONNECT
     * response from one attempt doesn't pollute the next.
     */
    private fun dnsOverTcp(dnsData: ByteArray): ByteArray? {
        val resolver = currentConfig?.dns1?.ifEmpty { "8.8.8.8" } ?: "8.8.8.8"
        val candidates = listOf(
            resolver,
            "1.1.1.1",
            "8.8.8.8",
            "8.8.4.4"
        )
        // De-duplicate while preserving order
        val tried = LinkedHashSet<String>().apply { addAll(candidates) }

        for (host in tried) {
            val response = tryDnsOverTcpOnHost(dnsData, host)
            if (response != null) return response
        }
        addLog(LogEntry(level = LogEntry.Level.DEBUG, message = "DNS over TCP: all DoT candidates failed"))
        return null
    }

    /**
     * Open a fresh socket to the local proxy, send HTTP CONNECT
     * to <host>:853, send the length-prefixed DNS query, read the
     * length-prefixed response. Returns null on any failure.
     */
    private fun tryDnsOverTcpOnHost(dnsData: ByteArray, host: String): ByteArray? {
        var socket: Socket? = null
        try {
            socket = Socket()
            protect(socket)
            socket.connect(InetSocketAddress("127.0.0.1", localProxyPort), 15000)
            // Generous timeout: the SslTunnel has to open a fresh
            // TLS to the remote, do the inner-SOCKS handshake, and
            // pipe to <host>:853 before we get our DNS reply.
            socket.soTimeout = 30000
            socket.tcpNoDelay = true

            val out = socket.getOutputStream()
            val input = socket.getInputStream()

            // HTTP CONNECT to a public DoT endpoint on port 853.
            // The SslTunnel sees this and uses the exact same code
            // path as the regular HTTPS traffic: opens a new TLS
            // connection to the remote, sends inner-SOCKS for the
            // target, replies 200 to us, then bi-directionally
            // pipes the bytes.
            val connectReq = "CONNECT $host:853 HTTP/1.0\r\n" +
                    "Host: $host\r\n" +
                    "User-Agent: CustomVPN/1.0\r\n" +
                    "\r\n"
            out.write(connectReq.toByteArray(Charsets.US_ASCII))
            out.flush()

            val connectResp = readHttpResponse(socket)
            if (connectResp == null) {
                addLog(LogEntry(level = LogEntry.Level.DEBUG, message = "DNS over TCP: CONNECT to $host:853 timed out"))
                return null
            }
            val connectRespStr = String(connectResp, Charsets.US_ASCII)
            if (!connectRespStr.contains(" 200 ")) {
                val preview = connectRespStr.lineSequence().firstOrNull() ?: ""
                addLog(LogEntry(level = LogEntry.Level.DEBUG, message = "DNS over TCP: CONNECT to $host:853 rejected: $preview"))
                return null
            }
            addLog(LogEntry(level = LogEntry.Level.DEBUG, message = "DNS over TCP: CONNECT to $host:853 succeeded"))

            // Send the length-prefixed DNS query (RFC 7766) on the
            // now-transparent TCP forward.
            val len = dnsData.size
            out.write(((len shr 8) and 0xFF))
            out.write(len and 0xFF)
            out.write(dnsData)
            out.flush()

            // Read the length-prefixed DNS response.
            val lenBuf = ByteArray(2)
            readFully(input, lenBuf)
            val respLen = ((lenBuf[0].toInt() and 0xFF) shl 8) or (lenBuf[1].toInt() and 0xFF)
            if (respLen <= 0 || respLen > 65535) {
                addLog(LogEntry(level = LogEntry.Level.DEBUG, message = "DNS over TCP: bad response length $respLen"))
                return null
            }
            val resp = ByteArray(respLen)
            readFully(input, resp)
            return resp
        } catch (e: Exception) {
            addLog(LogEntry(level = LogEntry.Level.DEBUG, message = "DNS over TCP to $host:853 failed: ${e.message}"))
            return null
        } finally {
            try { socket?.close() } catch (_: Exception) {}
        }
    }

    private fun readFully(input: java.io.InputStream, buf: ByteArray) {
        var off = 0
        while (off < buf.size) {
            val n = input.read(buf, off, buf.size - off)
            if (n <= 0) throw java.io.IOException("Unexpected EOF reading ${buf.size - off} bytes")
            off += n
        }
    }

    private fun handleGenericUdp(
        srcAddr: InetAddress, dstAddr: InetAddress,
        srcPort: Int, dstPort: Int, packet: ByteArray, dataOffset: Int, dataLen: Int
    ) {
        Thread({
            try {
                val socket = DatagramSocket()
                protect(socket)
                socket.soTimeout = 15000

                val data = packet.copyOfRange(dataOffset, dataOffset + dataLen)
                val dp = DatagramPacket(data, data.size, dstAddr, dstPort)
                socket.send(dp)

                val buf = ByteArray(4096)
                val reply = DatagramPacket(buf, buf.size)
                socket.receive(reply)

                val responsePacket = buildUdpResponse(srcAddr, dstAddr, srcPort, dstPort, buf, reply.length)
                packetQueue.offer(responsePacket)
                socket.close()
            } catch (e: Exception) {
                addLog(LogEntry(level = LogEntry.Level.DEBUG, message = "UDP forward failed: ${e.message}"))
            }
        }, "VpnTunnel-UDP").start()
    }

    private fun buildUdpResponse(
        srcIp: InetAddress, dstIp: InetAddress,
        srcPort: Int, dstPort: Int,
        data: ByteArray, dataLen: Int
    ): ByteArray {
        val ipHeaderLen = 20
        val udpHeaderLen = 8
        val totalLen = ipHeaderLen + udpHeaderLen + dataLen
        val packet = ByteArray(totalLen)

        // IP header
        packet[0] = 0x45.toByte()
        packet[1] = 0x00
        packet[2] = ((totalLen shr 8) and 0xFF).toByte()
        packet[3] = (totalLen and 0xFF).toByte()
        packet[4] = 0x00; packet[5] = 0x00
        packet[6] = 0x40.toByte(); packet[7] = 0x00
        packet[8] = 64
        packet[9] = 17 // UDP
        System.arraycopy(srcIp.address, 0, packet, 12, 4)
        System.arraycopy(dstIp.address, 0, packet, 16, 4)

        // UDP header
        val udp = ipHeaderLen
        packet[udp] = ((srcPort shr 8) and 0xFF).toByte()
        packet[udp + 1] = (srcPort and 0xFF).toByte()
        packet[udp + 2] = ((dstPort shr 8) and 0xFF).toByte()
        packet[udp + 3] = (dstPort and 0xFF).toByte()
        packet[udp + 4] = (((totalLen - ipHeaderLen) shr 8) and 0xFF).toByte()
        packet[udp + 5] = ((totalLen - ipHeaderLen) and 0xFF).toByte()
        packet[udp + 6] = 0; packet[udp + 7] = 0

        System.arraycopy(data, 0, packet, ipHeaderLen + udpHeaderLen, dataLen)

        recalculateChecksums(packet, totalLen)
        return packet
    }

    // ==================== PACKET CONSTRUCTION ====================

    private fun queueTcpPacket(
        srcIp: InetAddress, dstIp: InetAddress,
        srcPort: Int, dstPort: Int,
        seqNum: Long, ackNum: Long,
        flags: Int, data: ByteArray?, dataLen: Int
    ) {
        val packet = buildTcpPacket(srcIp, dstIp, srcPort, dstPort, seqNum, ackNum, flags, data, dataLen)
        if (packet != null) {
            packetQueue.offer(packet)
        }
    }

    private fun buildTcpPacket(
        srcIp: InetAddress, dstIp: InetAddress,
        srcPort: Int, dstPort: Int,
        seqNum: Long, ackNum: Long,
        flags: Int,
        data: ByteArray?, dataLen: Int
    ): ByteArray? {
        val ipHeaderLen = 20
        val tcpHeaderLen = 20
        val totalLen = ipHeaderLen + tcpHeaderLen + (data?.size ?: 0)
        val packet = ByteArray(totalLen)

        // IP header
        packet[0] = 0x45.toByte()
        packet[1] = 0x00
        packet[2] = ((totalLen shr 8) and 0xFF).toByte()
        packet[3] = (totalLen and 0xFF).toByte()
        packet[4] = 0x00; packet[5] = 0x00
        packet[6] = 0x40.toByte(); packet[7] = 0x00
        packet[8] = 64
        packet[9] = 6 // TCP
        System.arraycopy(srcIp.address, 0, packet, 12, 4)
        System.arraycopy(dstIp.address, 0, packet, 16, 4)

        // TCP header
        val tcp = ipHeaderLen
        packet[tcp] = ((srcPort shr 8) and 0xFF).toByte()
        packet[tcp + 1] = (srcPort and 0xFF).toByte()
        packet[tcp + 2] = ((dstPort shr 8) and 0xFF).toByte()
        packet[tcp + 3] = (dstPort and 0xFF).toByte()

        packet[tcp + 4] = ((seqNum shr 24) and 0xFF).toByte()
        packet[tcp + 5] = ((seqNum shr 16) and 0xFF).toByte()
        packet[tcp + 6] = ((seqNum shr 8) and 0xFF).toByte()
        packet[tcp + 7] = (seqNum and 0xFF).toByte()

        packet[tcp + 8] = ((ackNum shr 24) and 0xFF).toByte()
        packet[tcp + 9] = ((ackNum shr 16) and 0xFF).toByte()
        packet[tcp + 10] = ((ackNum shr 8) and 0xFF).toByte()
        packet[tcp + 11] = (ackNum and 0xFF).toByte()

        packet[tcp + 12] = 0x50.toByte() // data offset = 5 (20 bytes)
        packet[tcp + 13] = flags.toByte()
        packet[tcp + 14] = 0xFF.toByte() // window
        packet[tcp + 15] = 0xFF.toByte()
        packet[tcp + 16] = 0; packet[tcp + 17] = 0
        packet[tcp + 18] = 0; packet[tcp + 19] = 0

        if (data != null && dataLen > 0) {
            System.arraycopy(data, 0, packet, tcp + tcpHeaderLen, dataLen)
        }

        recalculateChecksums(packet, totalLen)
        return packet.copyOfRange(0, totalLen)
    }

    private fun readSeqNumber(packet: ByteArray, offset: Int): Long {
        return ((packet[offset].toLong() and 0xFF) shl 24) or
                ((packet[offset + 1].toLong() and 0xFF) shl 16) or
                ((packet[offset + 2].toLong() and 0xFF) shl 8) or
                (packet[offset + 3].toLong() and 0xFF)
    }

    // ==================== CHECKSUMS ====================

    private fun recalculateChecksums(packet: ByteArray, length: Int) {
        if (length < 20) return
        val ipHeaderLen = (packet[0].toInt() and 0x0F) * 4
        val protocol = packet[9].toInt() and 0xFF

        packet[10] = 0; packet[11] = 0
        val ipChecksum = calculateChecksum(packet, ipHeaderLen)
        packet[10] = ((ipChecksum shr 8) and 0xFF).toByte()
        packet[11] = (ipChecksum and 0xFF).toByte()

        if (protocol == 6 && length >= ipHeaderLen + 20) {
            val tcpOffset = ipHeaderLen
            packet[tcpOffset + 16] = 0; packet[tcpOffset + 17] = 0
            val tcpLen = length - ipHeaderLen
            val tcpChecksum = calculateTcpChecksum(packet, ipHeaderLen, tcpLen)
            packet[tcpOffset + 16] = ((tcpChecksum shr 8) and 0xFF).toByte()
            packet[tcpOffset + 17] = (tcpChecksum and 0xFF).toByte()
        } else if (protocol == 17 && length >= ipHeaderLen + 8) {
            val udpOffset = ipHeaderLen
            packet[udpOffset + 6] = 0; packet[udpOffset + 7] = 0
            val udpLen = length - udpOffset
            val udpChecksum = calculateTcpChecksum(packet, ipHeaderLen, udpLen)
            packet[udpOffset + 6] = ((udpChecksum shr 8) and 0xFF).toByte()
            packet[udpOffset + 7] = (udpChecksum and 0xFF).toByte()
        }
    }

    private fun calculateChecksum(data: ByteArray, length: Int): Int {
        var sum = 0L
        var i = 0
        while (i + 1 < length && i + 1 < data.size) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < length && i < data.size) {
            sum += (data[i].toInt() and 0xFF) shl 8
        }
        while (sum shr 16 != 0L) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        return (sum.toInt().inv()) and 0xFFFF
    }

    private fun calculateTcpChecksum(packet: ByteArray, ipHeaderLen: Int, segmentLength: Int): Int {
        val srcAddr = ByteArray(4)
        val dstAddr = ByteArray(4)
        System.arraycopy(packet, 12, srcAddr, 0, 4)
        System.arraycopy(packet, 16, dstAddr, 0, 4)

        val pseudoHeader = ByteArray(12)
        System.arraycopy(srcAddr, 0, pseudoHeader, 0, 4)
        System.arraycopy(dstAddr, 0, pseudoHeader, 4, 4)
        pseudoHeader[8] = 0
        pseudoHeader[9] = packet[9]
        pseudoHeader[10] = ((segmentLength shr 8) and 0xFF).toByte()
        pseudoHeader[11] = (segmentLength and 0xFF).toByte()

        var sum = 0L
        for (i in pseudoHeader.indices step 2) {
            sum += ((pseudoHeader[i].toInt() and 0xFF) shl 8) or (pseudoHeader[i + 1].toInt() and 0xFF)
        }

        val end = (ipHeaderLen + segmentLength).coerceAtMost(packet.size)
        if (ipHeaderLen < end) {
            val data = packet.copyOfRange(ipHeaderLen, end)
            for (i in data.indices step 2) {
                sum += if (i + 1 < data.size) {
                    ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
                } else {
                    (data[i].toInt() and 0xFF) shl 8
                }
            }
        }

        while (sum shr 16 != 0L) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        return (sum.toInt().inv()) and 0xFFFF
    }

    // ==================== LIFECYCLE ====================

    fun disconnect() {
        disconnectInternal(announce = true)
    }

    private fun disconnectInternal(announce: Boolean) {
        val wasFailed = connectionState == ConnectionState.FAILED
        isRunning = false
        val wasConnected = connectionState == ConnectionState.CONNECTED
        connectionState = ConnectionState.DISCONNECTED

        try { packetWriterThread?.interrupt() } catch (_: Exception) {}
        packetWriterThread = null
        packetQueue.clear()

        tcpSessions.values.forEach { session ->
            try { session.proxySocket?.close() } catch (_: Exception) {}
        }
        tcpSessions.clear()

        try { sshTunnel?.stop() } catch (_: Exception) {}
        sshTunnel = null

        try { sslTunnel?.stop() } catch (_: Exception) {}
        sslTunnel = null

        try { vpnOutputWriter?.close() } catch (_: Exception) {}
        vpnOutputWriter = null
        try { vpnInterface?.close() } catch (_: Exception) {}
        vpnInterface = null

        try { stopForeground(STOP_FOREGROUND_REMOVE) } catch (_: Exception) {}

        if (announce && (wasConnected || wasFailed)) {
            addLog(LogEntry(level = LogEntry.Level.INFO, message = "Disconnected"))
        }
    }

    private fun addLog(entry: LogEntry) {
        logQueue.add(entry)
        while (logQueue.size > 200) {
            logQueue.poll()
        }
        Log.d(TAG, "[${entry.level.tag}] ${entry.message}")
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "VPN Connection",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Custom VPN connection status"
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun showNotification(text: String) {
        val intent = Intent(this, com.customvpn.app.ui.MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val disconnectIntent = Intent(this, VpnTunnelService::class.java).apply {
            action = ACTION_DISCONNECT
        }
        val disconnectPending = PendingIntent.getService(
            this, 1, disconnectIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val notification = Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("Custom VPN")
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_vpn_key)
            .setContentIntent(pendingIntent)
            .addAction(R.drawable.ic_power_settings, "Disconnect", disconnectPending)
            .setOngoing(true)
            .build()

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start foreground: ${e.message}")
        }
    }

    override fun onRevoke() {
        disconnect()
        super.onRevoke()
    }

    override fun onDestroy() {
        disconnect()
        super.onDestroy()
    }
}
