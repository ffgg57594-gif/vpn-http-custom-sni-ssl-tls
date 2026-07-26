package com.customvpn.app.models

import java.io.Serializable
import java.util.ArrayList

data class VpnConfig(
    val name: String = "",
    val serverAddress: String = "",
    val serverPort: Int = 443,
    val username: String = "",
    val password: String = "",
    val sni: String = "",
    val payload: String = "",
    val connectionMode: ConnectionMode = ConnectionMode.SSL_TLS,
    val sshPort: Int = 22,
    val proxyPort: Int = 8989,
    val dns1: String = "8.8.8.8",
    val dns2: String = "8.8.4.4",
    val mtu: Int = 1500,
    val compress: Boolean = false,
    val enableUDPDns: Boolean = true,
    val bypassApps: ArrayList<String> = ArrayList()
) : Serializable {

    enum class ConnectionMode(val displayName: String) {
        SSH("SSH Tunnel"),
        SSL_TLS("SSL/TLS + SSH"),
        SSL_TLS_SNI("SSL/TLS + SNI"),
        DIRECT_SSH("Direct SSH")
    }
}
