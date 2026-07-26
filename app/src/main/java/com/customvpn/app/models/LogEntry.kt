package com.customvpn.app.models

data class LogEntry(
    val timestamp: Long = System.currentTimeMillis(),
    val level: Level = Level.INFO,
    val message: String
) {
    enum class Level(val tag: String) {
        INFO("INFO"),
        WARNING("WARN"),
        ERROR("ERROR"),
        DEBUG("DEBUG")
    }
}
