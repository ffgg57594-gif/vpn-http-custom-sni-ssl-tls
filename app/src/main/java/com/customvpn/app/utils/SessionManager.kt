package com.customvpn.app.utils

import android.content.Context
import android.content.SharedPreferences
import com.customvpn.app.models.VpnConfig
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken

class SessionManager(context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences("CustomVPN_prefs", Context.MODE_PRIVATE)
    private val gson = Gson()

    var isConnected: Boolean
        get() = prefs.getBoolean("is_connected", false)
        set(value) = prefs.edit().putBoolean("is_connected", value).apply()

    var lastConfig: VpnConfig?
        get() {
            val json = prefs.getString("last_config", null) ?: return null
            return try {
                gson.fromJson(json, VpnConfig::class.java)
            } catch (e: Exception) {
                null
            }
        }
        set(value) {
            prefs.edit().putString("last_config", gson.toJson(value)).apply()
        }

    fun saveConfigs(configs: List<VpnConfig>) {
        prefs.edit().putString("saved_configs", gson.toJson(configs)).apply()
    }

    fun getSavedConfigs(): List<VpnConfig> {
        val json = prefs.getString("saved_configs", null) ?: return emptyList()
        return try {
            val type = object : TypeToken<List<VpnConfig>>() {}.type
            gson.fromJson(json, type)
        } catch (e: Exception) {
            emptyList()
        }
    }

    fun clearAll() {
        prefs.edit().clear().apply()
    }
}
