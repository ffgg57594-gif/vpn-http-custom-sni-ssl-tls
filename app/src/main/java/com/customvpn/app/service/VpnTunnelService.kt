package com.customvpn.app.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
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
    private val activeConnections = ConcurrentHashMap<Int, Socket>()

    override fun onBind(intent: Intent?) = super.onBind(intent)

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT, ACTION_START -> {
                val config = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    intent.getSerializableExtra("config", VpnConfig::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getSerializableExtra("config") as? VpnConfig
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
        })

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
        })

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

        addLog(LogEntry(level = LogEntry.Level.INFO, message = "VPN interface established"))
        connectionState = ConnectionState.CONNECTED
        showNotification("Connected via ${config.connectionMode.displayName}")

        Thread { startPacketForwarding() }.start()
    }

    private fun startPacketForwarding() {
        val vpnFd = vpnInterface ?: return
        val fd = vpnFd.fileDescriptor
        val input = FileInputStream(fd)
        val output = FileOutputStream(fd)

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
                    4 -> handleIPv4Packet(packet, length, output)
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
        try { output.close() } catch (_: Exception) {}
        addLog(LogEntry(level = LogEntry.Level.INFO, message = "Packet forwarding stopped"))
    }

    private fun handleIPv4Packet(packet: ByteArray, length: Int, vpnOutput: FileOutputStream) {
        try {
            val protocol = packet[9].toInt() and 0xFF
            when (protocol) {
                6 -> handleTcpPacket(packet, length, vpnOutput)
                17 -> handleUdpPacket(packet, length, vpnOutput)
                1 -> {
                    recalculateChecksums(packet, length)
                    vpnOutput.write(packet, 0, length)
                    vpnOutput.flush()
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "IPv4 handling error: ${e.message}")
        }
    }

    private fun handleTcpPacket(packet: ByteArray, length: Int, vpnOutput: FileOutputStream) {
        try {
            val ipHeaderLen = (packet[0].toInt() and 0x0F) * 4
            if (length < ipHeaderLen + 20) return

            val tcpHeaderOffset = ipHeaderLen
            val tcpHeader = ByteBuffer.wrap(packet, tcpHeaderOffset, 20)
            tcpHeader.position(12)
            val flags = tcpHeader.get().toInt() and 0xFF
            val syn = (flags and 0x02) != 0
            val ack = (flags and 0x10) != 0
            val fin = (flags and 0x01) != 0

            val dstPort = ByteBuffer.wrap(packet, tcpHeaderOffset + 2, 2).short.toInt() and 0xFFFF
            val srcPort = ByteBuffer.wrap(packet, tcpHeaderOffset, 2).short.toInt() and 0xFFFF

            val dstAddr = InetAddress.getByAddress(byteArrayOf(packet[16], packet[17], packet[18], packet[19]))
            val srcAddr = InetAddress.getByAddress(byteArrayOf(packet[12], packet[13], packet[14], packet[15]))

            if (dstPort == 53) {
                handleTcpDns(packet, length, vpnOutput, ipHeaderLen, srcPort, srcAddr, dstAddr)
                return
            }

            if (syn && !ack) {
                handleTcpSyn(packet, length, vpnOutput, ipHeaderLen, tcpHeaderOffset, srcPort, dstPort, srcAddr, dstAddr)
            } else if (fin) {
                handleTcpFin(packet, length, vpnOutput, ipHeaderLen, tcpHeaderOffset, srcPort, srcAddr, dstAddr)
            } else if (activeConnections.containsKey(srcPort)) {
                handleTcpData(packet, length, vpnOutput, ipHeaderLen, tcpHeaderOffset, srcPort, srcAddr, dstAddr)
            } else {
                recalculateChecksums(packet, length)
                vpnOutput.write(packet, 0, length)
                vpnOutput.flush()
            }
        } catch (e: Exception) {
            Log.e(TAG, "TCP handling error: ${e.message}")
        }
    }

    private fun handleTcpSyn(
        packet: ByteArray, length: Int, vpnOutput: FileOutputStream,
        ipHeaderLen: Int, tcpHeaderOffset: Int,
        srcPort: Int, dstPort: Int,
        srcAddr: InetAddress, dstAddr: InetAddress
    ) {
        Thread {
            try {
                val client = Socket()
                protect(client)
                client.connect(InetSocketAddress("127.0.0.1", localProxyPort), 10000)

                val connectRequest = "CONNECT ${dstAddr.hostAddress}:$dstPort HTTP/1.1\r\nHost: ${dstAddr.hostAddress}:$dstPort\r\nProxy-Connection: keep-alive\r\n\r\n"
                client.outputStream.write(connectRequest.toByteArray())
                client.outputStream.flush()

                val response = ByteArray(1024)
                val readLen = client.inputStream.read(response)
                if (readLen <= 0) {
                    client.close()
                    return@Thread
                }

                val responseStr = String(response, 0, readLen)
                if (!responseStr.contains("200") && !responseStr.contains("HTTP")) {
                    addLog(LogEntry(level = LogEntry.Level.WARNING, message = "Proxy rejected: ${responseStr.take(100)}"))
                    client.close()
                    return@Thread
                }

                activeConnections[srcPort] = client
                addLog(LogEntry(level = LogEntry.Level.DEBUG, message = "TCP connected: ${dstAddr.hostAddress}:$dstPort"))

                val localSockPort = client.localPort
                sendTcpResponse(vpnOutput, srcAddr, dstAddr, dstPort, srcPort, length, flags = 0x12, window = 65535)

                forwardProxiedTraffic(client, vpnOutput, srcPort, srcAddr, dstAddr, dstPort, ipHeaderLen)

            } catch (e: Exception) {
                Log.e(TAG, "TCP SYN error: ${e.message}")
                activeConnections.remove(srcPort)
            }
        }.start()
    }

    private fun handleTcpData(
        packet: ByteArray, length: Int, vpnOutput: FileOutputStream,
        ipHeaderLen: Int, tcpHeaderOffset: Int,
        srcPort: Int,
        srcAddr: InetAddress, dstAddr: InetAddress
    ) {
        Thread {
            try {
                val client = activeConnections[srcPort] ?: return@Thread
                val payloadOffset = tcpHeaderLen(packet, ipHeaderLen) + ipHeaderLen
                val payloadLength = length - payloadOffset
                if (payloadLength > 0) {
                    val payload = ByteArray(payloadLength)
                    System.arraycopy(packet, payloadOffset, payload, 0, payloadLength)
                    client.outputStream.write(payload)
                    client.outputStream.flush()
                }
            } catch (e: Exception) {
                Log.e(TAG, "TCP data forward error: ${e.message}")
                activeConnections.remove(srcPort)
            }
        }.start()
    }

    private fun handleTcpFin(
        packet: ByteArray, length: Int, vpnOutput: FileOutputStream,
        ipHeaderLen: Int, tcpHeaderOffset: Int,
        srcPort: Int,
        srcAddr: InetAddress, dstAddr: InetAddress
    ) {
        val client = activeConnections.remove(srcPort)
        try { client?.close() } catch (_: Exception) {}

        sendTcpResponse(vpnOutput, srcAddr, dstAddr, 0, srcPort, length, flags = 0x14, window = 0)
    }

    private fun forwardProxiedTraffic(
        client: Socket, vpnOutput: FileOutputStream, originalSrcPort: Int,
        srcAddr: InetAddress, dstAddr: InetAddress, dstPort: Int, ipHeaderLen: Int
    ) {
        try {
            val buf = ByteArray(32767)
            val input = client.getInputStream()
            while (isRunning) {
                val n = input.read(buf)
                if (n == -1) break

                val tcpHeaderLen = 20
                val ipLen = ipHeaderLen + tcpHeaderLen + n
                val responsePacket = ByteArray(ipLen)

                responsePacket[0] = 0x45.toByte()
                responsePacket[1] = 0x00
                responsePacket[2] = ((ipLen shr 8) and 0xFF).toByte()
                responsePacket[3] = (ipLen and 0xFF).toByte()
                responsePacket[4] = 0x00
                responsePacket[5] = 0x00
                responsePacket[6] = 0x40.toByte()
                responsePacket[7] = 0x00
                responsePacket[8] = 64
                responsePacket[9] = 6

                System.arraycopy(dstAddr.address, 0, responsePacket, 12, 4)
                System.arraycopy(srcAddr.address, 0, responsePacket, 16, 4)

                val tcpOffset = ipHeaderLen
                responsePacket[tcpOffset] = ((dstPort shr 8) and 0xFF).toByte()
                responsePacket[tcpOffset + 1] = (dstPort and 0xFF).toByte()
                responsePacket[tcpOffset + 2] = ((originalSrcPort shr 8) and 0xFF).toByte()
                responsePacket[tcpOffset + 3] = (originalSrcPort and 0xFF).toByte()

                responsePacket[tcpOffset + 4] = 0
                responsePacket[tcpOffset + 5] = 0
                responsePacket[tcpOffset + 6] = 0
                responsePacket[tcpOffset + 7] = 0

                responsePacket[tcpOffset + 12] = 0x50.toByte()
                responsePacket[tcpOffset + 13] = 0x10
                responsePacket[tcpOffset + 14] = 0x00
                responsePacket[tcpOffset + 15] = 0x01

                System.arraycopy(buf, 0, responsePacket, tcpOffset + tcpHeaderLen, n)

                recalculateChecksums(responsePacket, ipLen)
                vpnOutput.write(responsePacket, 0, ipLen)
                vpnOutput.flush()
            }
        } catch (_: Exception) {
        } finally {
            activeConnections.remove(originalSrcPort)
            try { client.close() } catch (_: Exception) {}
        }
    }

    private fun handleTcpDns(
        packet: ByteArray, length: Int, vpnOutput: FileOutputStream,
        ipHeaderLen: Int, srcPort: Int,
        srcAddr: InetAddress, dstAddr: InetAddress
    ) {
        Thread {
            try {
                val client = Socket()
                protect(client)
                client.connect(InetSocketAddress("127.0.0.1", localProxyPort), 10000)

                val connectRequest = "CONNECT ${dstAddr.hostAddress}:53 HTTP/1.1\r\nHost: ${dstAddr.hostAddress}:53\r\nProxy-Connection: keep-alive\r\n\r\n"
                client.outputStream.write(connectRequest.toByteArray())
                client.outputStream.flush()

                val response = ByteArray(1024)
                val readLen = client.inputStream.read(response)
                if (readLen <= 0) {
                    client.close()
                    return@Thread
                }

                val tcpHeaderLen = 20
                val ipLen = ipHeaderLen + tcpHeaderLen
                val responsePacket = ByteArray(ipLen)

                responsePacket[0] = 0x45.toByte()
                responsePacket[1] = 0x00
                responsePacket[2] = ((ipLen shr 8) and 0xFF).toByte()
                responsePacket[3] = (ipLen and 0xFF).toByte()
                responsePacket[4] = 0x00
                responsePacket[5] = 0x00
                responsePacket[6] = 0x40.toByte()
                responsePacket[7] = 0x00
                responsePacket[8] = 64
                responsePacket[9] = 6

                System.arraycopy(dstAddr.address, 0, responsePacket, 12, 4)
                System.arraycopy(srcAddr.address, 0, responsePacket, 16, 4)

                val tcpOffset = ipHeaderLen
                responsePacket[tcpOffset] = ((53 shr 8) and 0xFF).toByte()
                responsePacket[tcpOffset + 1] = (53 and 0xFF).toByte()
                responsePacket[tcpOffset + 2] = ((srcPort shr 8) and 0xFF).toByte()
                responsePacket[tcpOffset + 3] = (srcPort and 0xFF).toByte()

                responsePacket[tcpOffset + 4] = 0
                responsePacket[tcpOffset + 5] = 0
                responsePacket[tcpOffset + 6] = 0
                responsePacket[tcpOffset + 7] = 0

                responsePacket[tcpOffset + 12] = 0x50.toByte()
                responsePacket[tcpOffset + 13] = 0x14
                responsePacket[tcpOffset + 14] = 0x00
                responsePacket[tcpOffset + 15] = 0x01

                recalculateChecksums(responsePacket, ipLen)
                vpnOutput.write(responsePacket, 0, ipLen)
                vpnOutput.flush()

                client.close()
            } catch (e: Exception) {
                Log.e(TAG, "TCP DNS error: ${e.message}")
            }
        }.start()
    }

    private fun handleUdpPacket(packet: ByteArray, length: Int, vpnOutput: FileOutputStream) {
        try {
            val ipHeaderLen = (packet[0].toInt() and 0x0F) * 4
            if (length < ipHeaderLen + 8) return

            val udpHeaderOffset = ipHeaderLen
            val srcPort = ByteBuffer.wrap(packet, udpHeaderOffset, 2).short.toInt() and 0xFFFF
            val dstPort = ByteBuffer.wrap(packet, udpHeaderOffset + 2, 2).short.toInt() and 0xFFFF

            if (dstPort == 53) {
                val cfg = currentConfig
                Thread {
                    try {
                        val dnsSocket = DatagramSocket()
                        protect(dnsSocket)
                        val dnsData = ByteArray(length - udpHeaderOffset - 8)
                        System.arraycopy(packet, udpHeaderOffset + 8, dnsData, 0, dnsData.size)

                        val dnsPacket = DatagramPacket(
                            dnsData, dnsData.size,
                            InetAddress.getByName(cfg?.dns1 ?: "8.8.8.8"), 53
                        )
                        dnsSocket.send(dnsPacket)

                        val responseBuf = ByteArray(1024)
                        val responsePacket = DatagramPacket(responseBuf, responseBuf.size)
                        dnsSocket.soTimeout = 5000
                        dnsSocket.receive(responsePacket)

                        val responseIp = buildUdpResponse(packet, responseBuf, responsePacket.length, udpHeaderOffset)
                        vpnOutput.write(responseIp, 0, responseIp.size)
                        vpnOutput.flush()
                        dnsSocket.close()
                    } catch (e: Exception) {
                        Log.e(TAG, "DNS forwarding error: ${e.message}")
                    }
                }.start()
            } else {
                recalculateChecksums(packet, length)
                vpnOutput.write(packet, 0, length)
                vpnOutput.flush()
            }
        } catch (e: Exception) {
            Log.e(TAG, "UDP handling error: ${e.message}")
        }
    }

    private fun sendTcpResponse(
        vpnOutput: FileOutputStream,
        srcAddr: InetAddress, dstAddr: InetAddress,
        srcPort: Int, dstPort: Int,
        originalLength: Int, flags: Int, window: Int
    ) {
        try {
            val ipHeaderLen = 20
            val tcpHeaderLen = 20
            val totalLen = ipHeaderLen + tcpHeaderLen
            val packet = ByteArray(totalLen)

            packet[0] = 0x45.toByte()
            packet[1] = 0x00
            packet[2] = ((totalLen shr 8) and 0xFF).toByte()
            packet[3] = (totalLen and 0xFF).toByte()
            packet[4] = 0x00
            packet[5] = 0x00
            packet[6] = 0x40.toByte()
            packet[7] = 0x00
            packet[8] = 64
            packet[9] = 6

            System.arraycopy(srcAddr.address, 0, packet, 12, 4)
            System.arraycopy(dstAddr.address, 0, packet, 16, 4)

            val tcpOffset = ipHeaderLen
            packet[tcpOffset] = ((srcPort shr 8) and 0xFF).toByte()
            packet[tcpOffset + 1] = (srcPort and 0xFF).toByte()
            packet[tcpOffset + 2] = ((dstPort shr 8) and 0xFF).toByte()
            packet[tcpOffset + 3] = (dstPort and 0xFF).toByte()

            packet[tcpOffset + 4] = 0
            packet[tcpOffset + 5] = 0
            packet[tcpOffset + 6] = 0
            packet[tcpOffset + 7] = 0

            packet[tcpOffset + 8] = 0
            packet[tcpOffset + 9] = 0
            packet[tcpOffset + 10] = 0
            packet[tcpOffset + 11] = 1

            packet[tcpOffset + 12] = 0x50.toByte()
            packet[tcpOffset + 13] = flags.toByte()
            packet[tcpOffset + 14] = ((window shr 8) and 0xFF).toByte()
            packet[tcpOffset + 15] = (window and 0xFF).toByte()

            recalculateChecksums(packet, totalLen)
            vpnOutput.write(packet, 0, totalLen)
            vpnOutput.flush()
        } catch (e: Exception) {
            Log.e(TAG, "Send TCP response error: ${e.message}")
        }
    }

    private fun buildUdpResponse(originalPacket: ByteArray, dnsResponse: ByteArray, dnsLen: Int, udpOffset: Int): ByteArray {
        val ipHeaderLen = 20
        val totalLen = ipHeaderLen + 8 + dnsLen
        val result = ByteArray(totalLen)

        result[0] = 0x45.toByte()
        result[1] = 0x00
        result[2] = ((totalLen shr 8) and 0xFF).toByte()
        result[3] = (totalLen and 0xFF).toByte()
        result[4] = 0x00
        result[5] = 0x00
        result[6] = 0x40.toByte()
        result[7] = 0x00
        result[8] = 64
        result[9] = 17

        System.arraycopy(originalPacket, 16, result, 12, 4)
        System.arraycopy(originalPacket, 12, result, 16, 4)

        val udpBuf = ByteBuffer.wrap(result, ipHeaderLen, 8)
        udpBuf.putShort(originalPacket[udpOffset + 2].toUByte().toShort())
        udpBuf.putShort(originalPacket[udpOffset].toUByte().toShort())
        udpBuf.putShort((8 + dnsLen).toShort())
        udpBuf.putShort(0)

        System.arraycopy(dnsResponse, 0, result, ipHeaderLen + 8, dnsLen)
        recalculateChecksums(result, totalLen)
        return result
    }

    private fun tcpHeaderLen(packet: ByteArray, ipHeaderLen: Int): Int {
        if (ipHeaderLen + 12 >= packet.size) return 20
        return ((packet[ipHeaderLen + 12].toInt() and 0xF0) ushr 2)
    }

    private fun recalculateChecksums(packet: ByteArray, length: Int) {
        if (length < 20) return

        packet[10] = 0
        packet[11] = 0
        val ipChecksum = calculateChecksum(packet, 20)
        packet[10] = (ipChecksum shr 8).toByte()
        packet[11] = (ipChecksum and 0xFF).toByte()

        val protocol = packet[9].toInt() and 0xFF
        val ipHeaderLen = (packet[0].toInt() and 0x0F) * 4

        if (protocol == 6 && length >= ipHeaderLen + 20) {
            val tcpOffset = ipHeaderLen
            packet[tcpOffset + 16] = 0
            packet[tcpOffset + 17] = 0
            val tcpLen = length - tcpOffset
            val tcpChecksum = calculateTcpChecksum(packet, ipHeaderLen, tcpLen)
            packet[tcpOffset + 16] = (tcpChecksum shr 8).toByte()
            packet[tcpOffset + 17] = (tcpChecksum and 0xFF).toByte()
        } else if (protocol == 17 && length >= ipHeaderLen + 8) {
            val udpOffset = ipHeaderLen
            packet[udpOffset + 6] = 0
            packet[udpOffset + 7] = 0
            val udpLen = length - udpOffset
            val udpChecksum = calculateTcpChecksum(packet, ipHeaderLen, udpLen)
            packet[udpOffset + 6] = (udpChecksum shr 8).toByte()
            packet[udpOffset + 7] = (udpChecksum and 0xFF).toByte()
        }
    }

    private fun calculateChecksum(data: ByteArray, length: Int): Int {
        var sum = 0L
        var i = 0
        while (i < length && i + 1 < data.size) {
            val word = ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            sum += word
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
                val word = if (i + 1 < data.size) {
                    ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
                } else {
                    (data[i].toInt() and 0xFF) shl 8
                }
                sum += word
            }
        }

        while (sum shr 16 != 0L) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        return (sum.toInt().inv()) and 0xFFFF
    }

    fun disconnect() {
        val wasFailed = connectionState == ConnectionState.FAILED
        isRunning = false
        val wasConnected = connectionState == ConnectionState.CONNECTED
        connectionState = ConnectionState.DISCONNECTED

        activeConnections.values.forEach { socket ->
            try { socket.close() } catch (_: Exception) {}
        }
        activeConnections.clear()

        sshTunnel?.stop()
        sshTunnel = null

        sslTunnel?.stop()
        sslTunnel = null

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

        startForeground(NOTIFICATION_ID, notification)
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
