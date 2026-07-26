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
        private var currentConfig: VpnConfig? = null

        fun getState(): ConnectionState = connectionState
        fun getLogs(): List<LogEntry> = logQueue.toList()
        fun getCurrentConfig(): VpnConfig? = currentConfig
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var sshTunnel: SshTunnel? = null
    private var sslTunnel: SslTunnel? = null
    private var tunnelThread: Thread? = null
    @Volatile
    private var isRunning = false
    private var localProxyPort: Int = 0

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
        currentConfig = config
        isRunning = true
        addLog(LogEntry(level = LogEntry.Level.INFO, message = "Connecting via ${config.connectionMode.displayName}..."))

        tunnelThread = Thread {
            try {
                when (config.connectionMode) {
                    VpnConfig.ConnectionMode.SSL_TLS,
                    VpnConfig.ConnectionMode.SSL_TLS_SNI -> connectSslSsh(config)
                    VpnConfig.ConnectionMode.SSH -> connectSsh(config)
                    VpnConfig.ConnectionMode.DIRECT_SSH -> connectSsh(config)
                }
            } catch (e: Exception) {
                addLog(LogEntry(level = LogEntry.Level.ERROR, message = "Connection failed: ${e.message}"))
                connectionState = ConnectionState.FAILED
                disconnect()
            }
        }
        tunnelThread?.start()
    }

    private fun connectSslSsh(config: VpnConfig) {
        addLog(LogEntry(level = LogEntry.Level.INFO, message = "Starting SSL/TLS tunnel with SNI..."))

        sslTunnel = SslTunnel(config, object : SslTunnel.TunnelListener {
            override fun onConnected() {
                addLog(LogEntry(level = LogEntry.Level.INFO, message = "SSL/TLS tunnel established"))
            }

            override fun onDisconnected(reason: String) {
                addLog(LogEntry(level = LogEntry.Level.INFO, message = "SSL tunnel: $reason"))
            }

            override fun onError(error: String) {
                addLog(LogEntry(level = LogEntry.Level.ERROR, message = "SSL error: $error"))
            }

            override fun onLog(message: String) {
                addLog(LogEntry(level = LogEntry.Level.DEBUG, message = message))
            }
        })

        localProxyPort = sslTunnel!!.start(0)
        addLog(LogEntry(level = LogEntry.Level.INFO, message = "SSL proxy on port $localProxyPort"))

        Thread.sleep(500)
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
            }

            override fun onError(error: String) {
                addLog(LogEntry(level = LogEntry.Level.ERROR, message = "SSH error: $error"))
            }

            override fun onLog(message: String) {
                addLog(LogEntry(level = LogEntry.Level.DEBUG, message = message))
            }
        })

        localProxyPort = sshTunnel!!.start(0)
        addLog(LogEntry(level = LogEntry.Level.INFO, message = "SSH SOCKS proxy on port $localProxyPort"))

        Thread.sleep(500)
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
            addLog(LogEntry(level = LogEntry.Level.ERROR, message = "Failed to create VPN interface"))
            connectionState = ConnectionState.FAILED
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

                val ipPacket = ByteBuffer.wrap(packet, 0, length)
                val version = (ipPacket.get(0).toInt() and 0xF0) ushr 4

                when (version) {
                    4 -> handleIPv4Packet(packet, length, output)
                    6 -> { /* IPv6 passthrough - simplified */ }
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
            val tcpHeaderOffset = 20
            if (length < tcpHeaderOffset + 20) return

            val tcpHeader = ByteBuffer.wrap(packet, tcpHeaderOffset, 20)
            tcpHeader.position(12)
            val flags = tcpHeader.get().toInt() and 0xFF
            val syn = (flags and 0x02) != 0
            val ack = (flags and 0x10) != 0

            tcpHeader.position(2)
            val dstPort = tcpHeader.short.toInt() and 0xFFFF

            val dstAddr = InetAddress.getByAddress(byteArrayOf(packet[16], packet[17], packet[18], packet[19]))

            if (syn && !ack) {
                Thread {
                    try {
                        val client = Socket()
                        protect(client)
                        client.connect(InetSocketAddress("127.0.0.1", localProxyPort), 10000)

                        val socksConnect = buildSocksConnect(dstAddr.hostAddress ?: "0.0.0.0", dstPort)
                        client.outputStream.write(socksConnect)
                        client.outputStream.flush()

                        val response = ByteArray(10)
                        client.inputStream.read(response)

                        if (response[1] == 0x00.toByte()) {
                            val localPort = client.localPort
                            rewriteDstPort(packet, tcpHeaderOffset, localPort)
                            rewriteDstAddr(packet, byteArrayOf(127, 0, 0, 1))
                            recalculateChecksums(packet, length)
                            vpnOutput.write(packet, 0, length)
                            vpnOutput.flush()
                        }

                        client.close()
                    } catch (e: Exception) {
                        Log.e(TAG, "TCP connect error: ${e.message}")
                    }
                }.start()
            } else {
                recalculateChecksums(packet, length)
                vpnOutput.write(packet, 0, length)
                vpnOutput.flush()
            }
        } catch (e: Exception) {
            Log.e(TAG, "TCP handling error: ${e.message}")
        }
    }

    private fun handleUdpPacket(packet: ByteArray, length: Int, vpnOutput: FileOutputStream) {
        try {
            val udpHeaderOffset = 20
            if (length < udpHeaderOffset + 8) return

            val udpHeader = ByteBuffer.wrap(packet, udpHeaderOffset, 8)
            val srcPort = udpHeader.short.toInt() and 0xFFFF
            val dstPort = udpHeader.short.toInt() and 0xFFFF

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

    private fun rewriteDstPort(packet: ByteArray, tcpHeaderOffset: Int, newPort: Int) {
        val buf = ByteBuffer.wrap(packet, tcpHeaderOffset + 2, 2)
        buf.putShort(newPort.toShort())
    }

    private fun rewriteDstAddr(packet: ByteArray, addr: ByteArray) {
        packet[16] = addr[0]
        packet[17] = addr[1]
        packet[18] = addr[2]
        packet[19] = addr[3]
    }

    private fun buildUdpResponse(originalPacket: ByteArray, dnsResponse: ByteArray, dnsLen: Int, udpOffset: Int): ByteArray {
        val totalLen = 20 + 8 + dnsLen
        val result = ByteArray(totalLen)

        System.arraycopy(originalPacket, 0, result, 0, 20)

        result[12] = originalPacket[16]
        result[13] = originalPacket[17]
        result[14] = originalPacket[18]
        result[15] = originalPacket[19]
        result[16] = originalPacket[12]
        result[17] = originalPacket[13]
        result[18] = originalPacket[14]
        result[19] = originalPacket[15]

        result[9] = 17
        val ipHeaderBuf = ByteBuffer.wrap(result, 2, 2)
        ipHeaderBuf.putShort(totalLen.toShort())

        val udpBuf = ByteBuffer.wrap(result, 20, 8)
        udpBuf.putShort(originalPacket[udpOffset + 2].toUByte().toShort())
        udpBuf.putShort(originalPacket[udpOffset].toUByte().toShort())
        udpBuf.putShort((8 + dnsLen).toShort())
        udpBuf.putShort(0)

        System.arraycopy(dnsResponse, 0, result, 28, dnsLen)
        return result
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
        while (i < length) {
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

        val data = packet.copyOfRange(ipHeaderLen, ipHeaderLen + segmentLength)
        for (i in data.indices step 2) {
            val word = if (i + 1 < data.size) {
                ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            } else {
                (data[i].toInt() and 0xFF) shl 8
            }
            sum += word
        }

        while (sum shr 16 != 0L) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        return (sum.toInt().inv()) and 0xFFFF
    }

    fun disconnect() {
        isRunning = false
        connectionState = ConnectionState.DISCONNECTED

        sshTunnel?.stop()
        sshTunnel = null

        sslTunnel?.stop()
        sslTunnel = null

        try { vpnInterface?.close() } catch (_: Exception) {}
        vpnInterface = null

        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()

        addLog(LogEntry(level = LogEntry.Level.INFO, message = "Disconnected"))
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
