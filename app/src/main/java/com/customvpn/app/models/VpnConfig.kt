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

    fun toServerString(): String {
        return if (username.isNotEmpty() && password.isNotEmpty()) {
            "$serverAddress:$serverPort@$username:$password"
        } else if (serverPort != 443) {
            "$serverAddress:$serverPort"
        } else {
            serverAddress
        }
    }

    companion object {
        fun parseServerConfig(input: String): VpnConfig {
            val trimmed = input.trim()
            if (trimmed.isEmpty()) {
                return VpnConfig()
            }

            var address = trimmed
            var port = 443
            var username = ""
            var password = ""

            // Extract user:pass@ part
            val atIdx = trimmed.lastIndexOf('@')
            if (atIdx > 0) {
                val userPass = trimmed.substring(0, atIdx)
                address = trimmed.substring(atIdx + 1)

                val colonIdx = userPass.indexOf(':')
                if (colonIdx > 0) {
                    username = userPass.substring(0, colonIdx)
                    password = userPass.substring(colonIdx + 1)
                } else {
                    username = userPass
                }
            }

            // Extract ip:port
            val colonIdx = address.lastIndexOf(':')
            if (colonIdx > 0) {
                val portStr = address.substring(colonIdx + 1)
                val portNum = portStr.toIntOrNull()
                if (portNum != null) {
                    port = portNum
                    address = address.substring(0, colonIdx)
                }
            }

            return VpnConfig(
                serverAddress = address,
                serverPort = port,
                username = username,
                password = password
            )
        }
    }
}
