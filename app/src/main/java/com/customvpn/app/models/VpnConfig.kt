package com.customvpn.app.models

import android.os.Parcel
import android.os.Parcelable
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
) : Parcelable {

    enum class ConnectionMode(val displayName: String) {
        SSH("SSH Tunnel"),
        SSL_TLS("SSL/TLS + SSH"),
        SSL_TLS_SNI("SSL/TLS + SNI"),
        DIRECT_SSH("Direct SSH")
    }

    constructor(parcel: Parcel) : this(
        parcel.readString() ?: "",
        parcel.readString() ?: "",
        parcel.readInt(),
        parcel.readString() ?: "",
        parcel.readString() ?: "",
        parcel.readString() ?: "",
        parcel.readString() ?: "",
        ConnectionMode.values()[parcel.readInt()],
        parcel.readInt(),
        parcel.readInt(),
        parcel.readString() ?: "8.8.8.8",
        parcel.readString() ?: "8.8.4.4",
        parcel.readInt(),
        parcel.readByte() != 0.toByte(),
        parcel.readByte() != 0.toByte(),
        parcel.createStringArrayList() ?: ArrayList()
    )

    override fun writeToParcel(parcel: Parcel, flags: Int) {
        parcel.writeString(name)
        parcel.writeString(serverAddress)
        parcel.writeInt(serverPort)
        parcel.writeString(username)
        parcel.writeString(password)
        parcel.writeString(sni)
        parcel.writeString(payload)
        parcel.writeInt(connectionMode.ordinal)
        parcel.writeInt(sshPort)
        parcel.writeInt(proxyPort)
        parcel.writeString(dns1)
        parcel.writeString(dns2)
        parcel.writeInt(mtu)
        parcel.writeByte(if (compress) 1 else 0)
        parcel.writeByte(if (enableUDPDns) 1 else 0)
        parcel.writeStringList(bypassApps)
    }

    override fun describeContents(): Int {
        return 0
    }

    fun toServerString(): String {
        val server = if (serverPort != 443) {
            "$serverAddress:$serverPort"
        } else {
            serverAddress
        }
        return if (username.isNotEmpty() && password.isNotEmpty()) {
            "$server@$username:$password"
        } else {
            server
        }
    }

    companion object CREATOR : Parcelable.Creator<VpnConfig> {
        override fun createFromParcel(parcel: Parcel): VpnConfig {
            return VpnConfig(parcel)
        }

        override fun newArray(size: Int): Array<VpnConfig?> {
            return arrayOfNulls(size)
        }

        /**
         * Parses server config in format: ip:port@username:password
         * Example: 1.2.3.4:443@user:pass
         * Port defaults to 443, username/password are optional.
         */
        fun parseServerConfig(input: String): VpnConfig {
            val trimmed = input.trim()
            if (trimmed.isEmpty()) {
                return VpnConfig()
            }

            var addressPart = trimmed
            var username = ""
            var password = ""

            // Extract credentials after @
            val atIdx = trimmed.lastIndexOf('\'@')
            if (atIdx > 0) {
                addressPart = trimmed.substring(0, atIdx)
                val credentials = trimmed.substring(atIdx + 1)

                val colonIdx = credentials.indexOf(':')
                if (colonIdx > 0) {
                    username = credentials.substring(0, colonIdx)
                    password = credentials.substring(colonIdx + 1)
                } else {
                    username = credentials
                }
            }

            // Extract ip:port
            var serverAddress = addressPart
            var serverPort = 443

            val colonIdx = addressPart.lastIndexOf(':')
            if (colonIdx > 0) {
                val portStr = addressPart.substring(colonIdx + 1)
                val portNum = portStr.toIntOrNull()
                if (portNum != null && portNum in 1..65535) {
                    serverPort = portNum
                    serverAddress = addressPart.substring(0, colonIdx)
                }
            }

            return VpnConfig(
                serverAddress = serverAddress,
                serverPort = serverPort,
                username = username,
                password = password
            )
        }
    }
}
