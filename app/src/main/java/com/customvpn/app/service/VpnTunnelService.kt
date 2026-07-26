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
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
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
        private val logQueue = ConcurrentLinkedQueue<LogEntry>()
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

    private val tcpSessions = ConcurrentHashMap<Int, TcpSession>()

    private data class TcpSession(
        val clientIp: InetAddress,
        val serverIp: InetAddress,
        val clientPort: Int,
        val serverPort: Int,
        var clientSeq: Long = 0,
        var serverSeq: Long = 0,
        var proxySocket: Socket? = null,
        @Volatile var state: State = State.SYN_RECEIVED,
        var established: Boolean = false
    ) {
        enum class State { SYN_RECEIVED, ESTABLISHED, CLOSING, CLOSED }
    }

    override fun onBind(intent: Intent?) = super.onBind(intent)

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
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
        isRunning = true
        addLog(LogEntry(level = LogEntry.Level.INFO, message = "Connecting via ${config.connectionMode.displayName}..."))

        tunnelThread = Thread {
            try {
                if (config.serverAddress.isEmpty()) {
                    setFailed("Server address is empty")
                    return@Thread
                }

                when (config.connectionMode) {
                    VpnConfig.ConnectionMode.SSL_TLS,
                    VpnConfig.ConnectionMode.SSL_TLS_SNI -> connectSslSsh(config)
                    VpnConfig.ConnectionMode.SSH -> connectSsh(config)
                    VpnConfig.ConnectionMode.DIRECT_SSH -> connectSsh(config)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Connection exception", e)
                setFailed("Connection failed: ${e.message}")
            }
        }
        tunnelThread?.start()
    }

    private fun setFailed(message: String) {
        lastErrorMessage = message
        connectionState = ConnectionState.FAILED
        addLog(LogEntry(level = LogEntry.Level.ERROR, message = message))
        isRunning = false
    }

    private fun connectSslSsh(config: VpnConfig) {
        addLog(LogEntry(level = LogEntry.Level.INFO, message = "Starting SSL/TLS tunnel with SNI..."))
        addLog(LogEntry(level = LogEntry.Level.INFO, message = "Server: ${config.serverAddress}:${config.serverPort}"))
        addLog(LogEntry(level = LogEntry.Level.INFO, message = "SNI: ${config.sni.ifEmpty { config.serverAddress }}"))

        sslTunnel = SslTunnel(config, object : SslTunnel.TunnelListener {
            override fun onConnected() {
                addLog(LogEntry(level = LogEntry.Level.INFO, message = "SSL/TLS tunnel established"))
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
        }, socketProtector = { s -> protect(s) })

        try {
            localProxyPort = sslTunnel!!.start(0)
        } catch (e: Exception) {
            setFailed("Failed to start SSL proxy: ${e.message}")
            return
        }
        addLog(LogEntry(level = LogEntry.Level.INFO, message = "SSL proxy on port $localProxyPort"))

        establishVpn(config)
    }

    private fun connectSsh(config: VpnConfig) {
        addLog(LogEntry(level = LogEntry.Level.INFO, message = "Starting SSH tunnel..."))

        sshTunnel = SshTunnel(config, object : SshTunnel.TunnelListener {
            override fun onConnected() {
                addLog(LogEntry(level = LogEntry.Level.INFO, message = "SSH tunnel established"))
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
        }, socketProtector = { s -> protect(s) })

        try {
            localProxyPort = sshTunnel!!.start(0)
        } catch (e: Exception) {
            setFailed("Failed to start SSH proxy: ${e.message}")
            return
        }
        addLog(LogEntry(level = LogEntry.Level.INFO, message = "SSH SOCKS proxy on port $localProxyPort"))

        establishVpn(config)
    }

    private fun establishVpn(config: VpnConfig) {
        val builder = Builder()
        builder.setSession("Custom VPN")
        builder.setMtu(config.mtu)
        builder.addAddress("10.0.0.2", 32)
        builder.addRoute("0.0.0.0", 0)
        builder.addDnsServer(config.dns1)
        builder.addDnsServer(config.dns2)

        try {
            builder.addDisallowedApplication(packageName)
        } catch (_: Exception) {}

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }

        vpnInterface = builder.establish()

        if (vpnInterface == null) {
            setFailed("Failed to create VPN interface. Make sure VPN permission is granted.")
            return
        }

        vpnOutputWriter = FileOutputStream(vpnInterface!!.fileDescriptor)

        packetWriterThread = Thread {
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
            } catch (e: InterruptedException) {
                // Expected on shutdown
            }
        }
        packetWriterThread?.start()

        addLog(LogEntry(level = LogEntry.Level.INFO, message = "VPN interface established"))
        connectionState = ConnectionState.CONNECTED
        showNotification("Connected via ${config.connectionMode.displayName}")

        Thread { startPacketForwarding() }.start()
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
                    Thread.sleep(10)
                    continue
                }

                val version = (packet[0].toInt() and 0xF0) ushr 4
                when (version) {
                    4 -> handleIPv4Packet(packet, length)
                    6 -> { /* IPv6 - skip */ }
                }
            } catch (e: InterruptedException) {
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
            val protocol = packet[9].toInt() and 0xFF
            when (protocol) {
                6 -> handleTcpPacket(packet, length)
                17 -> handleUdpPacket(packet, length)
                1 -> {
                    recalculateChecksums(packet, length)
                    packetQueue.offer(packet.copyOfRange(0, length))
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "IPv4 handling error: ${e.message}")
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
            val ackNum = readAckNumber(packet, tcpHeaderOffset + 8)

            val tcpDataOffsetField = ((packet[tcpHeaderOffset + 12].toInt() and 0xF0) ushr 4)
            val tcpDataOffset = tcpHeaderOffset + (tcpDataOffsetField * 4)
            val tcpDataLen = if (tcpDataOffset < length) length - tcpDataOffset else 0

            if (dstPort == 53) {
                handleDnsOverTcp(packet, length, ipHeaderLen, srcPort, dstPort, srcAddr, dstAddr, clientSeqNum)
                return
            }

            if (rst) {
                val session = tcpSessions.remove(srcPort)
                session?.proxySocket?.let { try { it.close() } catch (_: Exception) {} }
                return
            }

            if (syn && !ack) {
                handleTcpSyn(packet, ipHeaderLen, tcpHeaderOffset, srcPort, dstPort, srcAddr, dstAddr, clientSeqNum)
            } else if (fin) {
                handleTcpFin(srcPort, dstPort, srcAddr, dstAddr, clientSeqNum)
            } else if (ack && tcpSessions.containsKey(srcPort)) {
                val session = tcpSessions[srcPort] ?: return

                if (!session.established) {
                    session.state = TcpSession.State.ESTABLISHED
                    session.established = true
                    addLog(LogEntry(level = LogEntry.Level.DEBUG, message = "TCP handshake complete: $srcPort->$dstPort:$dstAddr"))
                }

                if (tcpDataLen > 0) {
                    val data = packet.copyOfRange(tcpDataOffset, tcpDataOffset + tcpDataLen)
                    session.clientSeq += tcpDataLen
                    queueTcpPacket(dstAddr, srcAddr, dstPort, srcPort, session.serverSeq, session.clientSeq, 0x10, null, 0)
                    forwardDataToProxy(session, data)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "TCP handling error: ${e.message}")
        }
    }

    private fun handleTcpSyn(
        packet: ByteArray,
        ipHeaderLen: Int, tcpHeaderOffset: Int,
        srcPort: Int, dstPort: Int,
        srcAddr: InetAddress, dstAddr: InetAddress,
        clientSeq: Long
    ) {
        val serverIsn = Random.nextLong(0xFFFFFFFFL)
        val session = TcpSession(
            clientIp = srcAddr,
            serverIp = dstAddr,
            clientPort = srcPort,
            serverPort = dstPort,
            clientSeq = clientSeq + 1,
            serverSeq = serverIsn,
            state = TcpSession.State.SYN_RECEIVED
        )
        tcpSessions[srcPort] = session

        queueTcpPacket(dstAddr, srcAddr, dstPort, srcPort, serverIsn, clientSeq + 1, 0x12, null, 0)

        addLog(LogEntry(level = LogEntry.Level.DEBUG, message = "TCP SYN: $srcPort -> $dstAddr:$dstPort, sent SYN-ACK"))

        Thread {
            try {
                val client = Socket()
                protect(client)
                client.connect(InetSocketAddress("127.0.0.1", localProxyPort), 15000)
                client.soTimeout = 30000

                val connectRequest = "CONNECT ${dstAddr.hostAddress}:$dstPort HTTP/1.1\r\nHost: ${dstAddr.hostAddress}:$dstPort\r\nProxy-Connection: keep-alive\r\n\r\n"
                client.getOutputStream().write(connectRequest.toByteArray())
                client.getOutputStream().flush()

                val response = ByteArray(1024)
                val readLen = client.getInputStream().read(response)
                if (readLen <= 0) {
                    client.close()
                    tcpSessions.remove(srcPort)
                    return@Thread
                }

                val responseStr = String(response, 0, readLen)
                if (!responseStr.contains("200") && !responseStr.contains("HTTP")) {
                    addLog(LogEntry(level = LogEntry.Level.WARNING, message = "Proxy rejected: ${responseStr.take(100)}"))
                    client.close()
                    tcpSessions.remove(srcPort)
                    return@Thread
                }

                session.proxySocket = client
                addLog(LogEntry(level = LogEntry.Level.DEBUG, message = "Proxy connected for $srcPort -> $dstAddr:$dstPort"))

                relayFromProxyToTun(session)

            } catch (e: Exception) {
                addLog(LogEntry(level = LogEntry.Level.ERROR, message = "Proxy connect failed: ${e.message}"))
                tcpSessions.remove(srcPort)
            }
        }.start()
    }

    private fun handleTcpFin(srcPort: Int, dstPort: Int, srcAddr: InetAddress, dstAddr: InetAddress, clientSeq: Long) {
        val session = tcpSessions.remove(srcPort) ?: return

        queueTcpPacket(
            srcIp = dstAddr, dstIp = srcAddr,
            srcPort = dstPort, dstPort = srcPort,
            seqNum = session.serverSeq, ackNum = clientSeq + 1,
            flags = 0x10, data = null, dataLen = 0
        )

        queueTcpPacket(
            srcIp = dstAddr, dstIp = srcAddr,
            srcPort = dstPort, dstPort = srcPort,
            seqNum = session.serverSeq, ackNum = clientSeq + 1,
            flags = 0x11, data = null, dataLen = 0
        )

        session.state = TcpSession.State.CLOSED
        try { session.proxySocket?.close() } catch (_: Exception) {}
        addLog(LogEntry(level = LogEntry.Level.DEBUG, message = "TCP FIN: $srcPort closed"))
    }

    private fun forwardDataToProxy(session: TcpSession, data: ByteArray) {
        Thread {
            try {
                session.proxySocket?.getOutputStream()?.write(data)
                session.proxySocket?.getOutputStream()?.flush()
            } catch (e: Exception) {
                addLog(LogEntry(level = LogEntry.Level.ERROR, message = "Forward to proxy error: ${e.message}"))
                tcpSessions.remove(session.clientPort)
                try { session.proxySocket?.close() } catch (_: Exception) {}
            }
        }.start()
    }

    private fun relayFromProxyToTun(session: TcpSession) {
        Thread {
            try {
                val buf = ByteArray(32768)
                val input = session.proxySocket?.getInputStream() ?: return@Thread
                while (isRunning && session.state != TcpSession.State.CLOSED) {
                    val n = input.read(buf)
                    if (n == -1) break
                    val data = buf.copyOfRange(0, n)
                    queueTcpPacket(
                        srcIp = session.serverIp, dstIp = session.clientIp,
                        srcPort = session.serverPort, dstPort = session.clientPort,
                        seqNum = session.serverSeq, ackNum = session.clientSeq,
                        flags = 0x18, // PSH+ACK
                        data = data, dataLen = n
                    )
                    session.serverSeq += n
                }
            } catch (e: Exception) {
                if (isRunning) {
                    addLog(LogEntry(level = LogEntry.Level.DEBUG, message = "Proxy relay ended for ${session.clientPort}: ${e.message}"))
                }
            } finally {
                try { session.proxySocket?.close() } catch (_: Exception) {}
            }
        }.start()
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
            val udpDataLen = udpLen - 8

            val srcAddr = InetAddress.getByAddress(byteArrayOf(packet[12], packet[13], packet[14], packet[15]))
            val dstAddr = InetAddress.getByAddress(byteArrayOf(packet[16], packet[17], packet[18], packet[19]))

            if (dstPort == 53) {
                handleDnsQuery(packet, udpDataOffset, udpDataLen, srcPort, srcAddr, dstAddr)
                return
            }

            Thread {
                try {
                    val socket = DatagramSocket()
                    protect(socket)
                    socket.soTimeout = 5000

                    val dnsData = packet.copyOfRange(udpDataOffset, udpDataOffset + udpDataLen)
                    val dp = DatagramPacket(dnsData, dnsData.size, dstAddr, dstPort)
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
            }.start()
        } catch (e: Exception) {
            Log.e(TAG, "UDP handling error: ${e.message}")
        }
    }

    private fun handleDnsQuery(
        packet: ByteArray, dataOffset: Int, dataLen: Int,
        srcPort: Int, srcAddr: InetAddress, dstAddr: InetAddress
    ) {
        Thread {
            try {
                val socket = DatagramSocket()
                protect(socket)
                socket.soTimeout = 5000

                val dnsData = packet.copyOfRange(dataOffset, dataOffset + dataLen)
                val dp = DatagramPacket(dnsData, dnsData.size, dstAddr, 53)
                socket.send(dp)

                val buf = ByteArray(4096)
                val reply = DatagramPacket(buf, buf.size)
                socket.receive(reply)

                val responsePacket = buildUdpResponse(srcAddr, dstAddr, srcPort, 53, buf, reply.length)
                packetQueue.offer(responsePacket)
                socket.close()
            } catch (e: Exception) {
                addLog(LogEntry(level = LogEntry.Level.DEBUG, message = "DNS query failed: ${e.message}"))
            }
        }.start()
    }

    private fun handleDnsOverTcp(
        packet: ByteArray, length: Int,
        ipHeaderLen: Int, srcPort: Int, dstPort: Int,
        srcAddr: InetAddress, dstAddr: InetAddress,
        clientSeq: Long
    ) {
        val session = TcpSession(
            clientIp = srcAddr, serverIp = dstAddr,
            clientPort = srcPort, serverPort = dstPort,
            clientSeq = clientSeq, serverSeq = Random.nextLong(0xFFFFFFFFL),
            state = TcpSession.State.SYN_RECEIVED
        )
        tcpSessions[srcPort] = session

        val synAckPkt = buildTcpPacket(dstAddr, srcAddr, dstPort, srcPort, session.serverSeq, clientSeq + 1, 0x12, null, 0)
        if (synAckPkt != null) packetQueue.offer(synAckPkt)

        Thread {
            try {
                val socket = Socket()
                protect(socket)
                socket.connect(InetSocketAddress(dstAddr, 53), 5000)
                socket.soTimeout = 5000

                val tcpDataOffset = ipHeaderLen + 20
                val tcpDataLen = length - tcpDataOffset
                if (tcpDataLen > 0) {
                    socket.getOutputStream().write(packet.copyOfRange(tcpDataOffset, tcpDataOffset + tcpDataLen))
                    socket.getOutputStream().flush()
                }

                val buf = ByteArray(4096)
                val n = socket.getInputStream().read(buf)
                if (n > 0) {
                    session.serverSeq += n
                    val respPkt = buildTcpPacket(dstAddr, srcAddr, dstPort, srcPort, session.serverSeq, clientSeq + 1 + tcpDataLen, 0x18, buf.copyOfRange(0, n), n)
                    if (respPkt != null) packetQueue.offer(respPkt)
                }

                socket.close()
                tcpSessions.remove(srcPort)
            } catch (e: Exception) {
                addLog(LogEntry(level = LogEntry.Level.DEBUG, message = "DNS over TCP failed: ${e.message}"))
                tcpSessions.remove(srcPort)
            }
        }.start()
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
        packet[udp] = ((dstPort shr 8) and 0xFF).toByte()
        packet[udp + 1] = (dstPort and 0xFF).toByte()
        packet[udp + 2] = ((srcPort shr 8) and 0xFF).toByte()
        packet[udp + 3] = (srcPort and 0xFF).toByte()
        packet[udp + 4] = ((totalLen - ipHeaderLen shr 8) and 0xFF).toByte()
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

        packet[tcp + 12] = 0x50.toByte()
        packet[tcp + 13] = flags.toByte()
        packet[tcp + 14] = 0xFF.toByte()
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

    private fun readAckNumber(packet: ByteArray, offset: Int): Long {
        return ((packet[offset].toLong() and 0xFF) shl 24) or
                ((packet[offset + 1].toLong() and 0xFF) shl 16) or
                ((packet[offset + 2].toLong() and 0xFF) shl 8) or
                (packet[offset + 3].toLong() and 0xFF)
    }

    // ==================== CHECKSUMS ====================

    private fun recalculateChecksums(packet: ByteArray, length: Int) {
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
        while (i < length && i + 1 < data.size) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
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

        val end = ipHeaderLen + segmentLength
        if (end <= packet.size) {
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

        sshTunnel?.stop()
        sshTunnel = null

        sslTunnel?.stop()
        sslTunnel = null

        try { vpnOutputWriter?.close() } catch (_: Exception) {}
        vpnOutputWriter = null
        try { vpnInterface?.close() } catch (_: Exception) {}
        vpnInterface = null

        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()

        if (wasConnected || wasFailed) {
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
            this, 0, intent, PendingIntent.FLAG_IMMUTABLE
        )

        val notification = Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("Custom VPN")
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_vpn_key)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notification)
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
