package com.customvpn.app.ui

import android.app.Activity
import android.content.Intent
import android.content.res.ColorStateList
import android.graphics.Color
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.*
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.customvpn.app.R
import com.customvpn.app.models.ConnectionState
import com.customvpn.app.models.VpnConfig
import com.customvpn.app.service.VpnTunnelService
import com.customvpn.app.utils.PayloadBuilder
import com.customvpn.app.utils.SessionManager
import com.google.android.material.button.MaterialButton
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.appbar.MaterialToolbar

class MainActivity : AppCompatActivity() {

    private lateinit var sessionManager: SessionManager
    private lateinit var logAdapter: LogAdapter
    private lateinit var configAdapter: ConfigAdapter
    private val handler = Handler(Looper.getMainLooper())
    private var pollingRunnable: Runnable? = null

    private lateinit var btnConnect: MaterialButton
    private lateinit var statusText: TextView
    private lateinit var statusIcon: ImageView
    private lateinit var connectionInfo: TextView
    private lateinit var etServerAddress: TextInputEditText
    private lateinit var etServerPort: TextInputEditText
    private lateinit var etSshPort: TextInputEditText
    private lateinit var etSni: TextInputEditText
    private lateinit var etUsername: TextInputEditText
    private lateinit var etPassword: TextInputEditText
    private lateinit var etPayload: TextInputEditText
    private lateinit var spinnerMode: AutoCompleteTextView
    private lateinit var rvLogs: RecyclerView
    private lateinit var btnSaveConfig: MaterialButton
    private lateinit var btnOpenConfig: MaterialButton
    private lateinit var btnGeneratePayload: MaterialButton
    private lateinit var btnClearLogs: MaterialButton

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startVpn()
        } else {
            Toast.makeText(this, "VPN permission is required", Toast.LENGTH_LONG).show()
        }
    }

    private var pendingConfig: VpnConfig? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        sessionManager = SessionManager(this)
        initViews()
        setupToolbar()
        setupModeSpinner()
        setupRecyclerViews()
        setupButtons()
        loadLastConfig()
        startStatusPolling()
    }

    private fun initViews() {
        btnConnect = findViewById(R.id.btnConnect)
        statusText = findViewById(R.id.statusText)
        statusIcon = findViewById(R.id.statusIcon)
        connectionInfo = findViewById(R.id.connectionInfo)
        etServerAddress = findViewById(R.id.etServerAddress)
        etServerPort = findViewById(R.id.etServerPort)
        etSshPort = findViewById(R.id.etSshPort)
        etSni = findViewById(R.id.etSni)
        etUsername = findViewById(R.id.etUsername)
        etPassword = findViewById(R.id.etPassword)
        etPayload = findViewById(R.id.etPayload)
        spinnerMode = findViewById(R.id.spinnerMode)
        rvLogs = findViewById(R.id.rvLogs)
        btnSaveConfig = findViewById(R.id.btnSaveConfig)
        btnOpenConfig = findViewById(R.id.btnOpenConfig)
        btnGeneratePayload = findViewById(R.id.btnGeneratePayload)
        btnClearLogs = findViewById(R.id.btnClearLogs)
    }

    private fun setupToolbar() {
        val toolbar = findViewById<MaterialToolbar>(R.id.toolbar)
        toolbar.setOnMenuItemClickListener { item ->
            when (item.itemId) {
                R.id.action_about -> {
                    showAboutDialog()
                    true
                }
                else -> false
            }
        }
    }

    private fun setupModeSpinner() {
        val modes = VpnConfig.ConnectionMode.values().map { it.displayName }.toTypedArray()
        val adapter = ArrayAdapter(this, android.R.layout.simple_dropdown_item_1line, modes)
        spinnerMode.setAdapter(adapter)
        spinnerMode.setText(VpnConfig.ConnectionMode.SSL_TLS_SNI.displayName, false)
    }

    private fun setupRecyclerViews() {
        logAdapter = LogAdapter()
        rvLogs.apply {
            layoutManager = LinearLayoutManager(this@MainActivity)
            adapter = logAdapter
        }

        configAdapter = ConfigAdapter(
            onConfigSelected = { config -> loadConfig(config) },
            onDeleteConfig = { config -> deleteConfig(config) }
        )
    }

    private fun setupButtons() {
        btnConnect.setOnClickListener {
            if (VpnTunnelService.getState() == ConnectionState.CONNECTED ||
                VpnTunnelService.getState() == ConnectionState.CONNECTING) {
                stopVpn()
            } else {
                prepareAndStartVpn()
            }
        }

        btnSaveConfig.setOnClickListener {
            showSaveConfigDialog()
        }

        btnOpenConfig.setOnClickListener {
            showLoadConfigDialog()
        }

        btnGeneratePayload.setOnClickListener {
            val config = buildConfigFromInputs()
            val payload = PayloadBuilder.buildCustomPayload(
                config.serverAddress,
                config.sni.ifEmpty { config.serverAddress }
            )
            etPayload.setText(payload)
            Toast.makeText(this, "Payload generated", Toast.LENGTH_SHORT).show()
        }

        btnClearLogs.setOnClickListener {
            logAdapter.clear()
        }
    }

    private fun loadLastConfig() {
        val config = sessionManager.lastConfig ?: return
        populateInputs(config)
    }

    private fun populateInputs(config: VpnConfig) {
        etServerAddress.setText(config.serverAddress)
        etServerPort.setText(config.serverPort.toString())
        etSshPort.setText(config.sshPort.toString())
        etSni.setText(config.sni)
        etUsername.setText(config.username)
        etPassword.setText(config.password)
        etPayload.setText(config.payload)
        spinnerMode.setText(config.connectionMode.displayName, false)
    }

    private fun buildConfigFromInputs(): VpnConfig {
        return VpnConfig(
            serverAddress = etServerAddress.text.toString().trim(),
            serverPort = etServerPort.text.toString().trim().toIntOrNull() ?: 443,
            sshPort = etSshPort.text.toString().trim().toIntOrNull() ?: 22,
            sni = etSni.text.toString().trim(),
            username = etUsername.text.toString().trim(),
            password = etPassword.text.toString().trim(),
            payload = etPayload.text.toString().trim(),
            connectionMode = VpnConfig.ConnectionMode.values().firstOrNull {
                it.displayName == spinnerMode.text.toString()
            } ?: VpnConfig.ConnectionMode.SSL_TLS_SNI
        )
    }

    private fun prepareAndStartVpn() {
        val config = buildConfigFromInputs()

        if (config.serverAddress.isEmpty()) {
            etServerAddress.error = "Server address is required"
            return
        }

        pendingConfig = config
        sessionManager.lastConfig = config

        val vpnIntent = VpnService.prepare(this)
        if (vpnIntent != null) {
            vpnPermissionLauncher.launch(vpnIntent)
        } else {
            startVpn()
        }
    }

    private fun startVpn() {
        val config = pendingConfig ?: return
        val intent = Intent(this, VpnTunnelService::class.java).apply {
            action = VpnTunnelService.ACTION_CONNECT
            putExtra("config", config)
        }
        startForegroundService(intent)
    }

    private fun stopVpn() {
        val intent = Intent(this, VpnTunnelService::class.java).apply {
            action = VpnTunnelService.ACTION_DISCONNECT
        }
        startForegroundService(intent)
    }

    private fun showSaveConfigDialog() {
        val dialogView = layoutInflater.inflate(R.layout.dialog_save_config, null)
        val etConfigName = dialogView.findViewById<TextInputEditText>(R.id.etConfigName)

        AlertDialog.Builder(this)
            .setTitle("Save Configuration")
            .setView(dialogView)
            .setPositiveButton("Save") { _, _ ->
                val name = etConfigName.text.toString().trim()
                if (name.isNotEmpty()) {
                    val config = buildConfigFromInputs().copy(name = name)
                    saveConfig(config)
                    Toast.makeText(this, "Configuration saved", Toast.LENGTH_SHORT).show()
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun showLoadConfigDialog() {
        val configs = sessionManager.getSavedConfigs()
        if (configs.isEmpty()) {
            Toast.makeText(this, "No saved configurations", Toast.LENGTH_SHORT).show()
            return
        }

        val names = configs.map { "${it.name} - ${it.serverAddress}:${it.serverPort}" }.toTypedArray()

        AlertDialog.Builder(this)
            .setTitle("Load Configuration")
            .setItems(names) { _, which ->
                loadConfig(configs[which])
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun loadConfig(config: VpnConfig) {
        populateInputs(config)
        Toast.makeText(this, "Configuration loaded: ${config.name}", Toast.LENGTH_SHORT).show()
    }

    private fun deleteConfig(config: VpnConfig) {
        AlertDialog.Builder(this)
            .setTitle("Delete Configuration")
            .setMessage("Delete '${config.name}'?")
            .setPositiveButton("Delete") { _, _ ->
                val configs = sessionManager.getSavedConfigs().toMutableList()
                configs.removeAll { it.name == config.name }
                sessionManager.saveConfigs(configs)
                Toast.makeText(this, "Configuration deleted", Toast.LENGTH_SHORT).show()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun saveConfig(config: VpnConfig) {
        val configs = sessionManager.getSavedConfigs().toMutableList()
        configs.removeAll { it.name == config.name }
        configs.add(config)
        sessionManager.saveConfigs(configs)
    }

    private fun showAboutDialog() {
        AlertDialog.Builder(this)
            .setTitle("Custom VPN")
            .setMessage("Custom VPN - SSH/SSL/SNI Tunnel\n\nVersion 1.0.0\n\nSimilar to HTTP Custom VPN.\n\nFeatures:\n• SSH Tunnel\n• SSL/TLS Tunnel\n• Custom SNI\n• HTTP Payload\n• SOCKS5 Proxy")
            .setPositiveButton("OK", null)
            .show()
    }

    private fun startStatusPolling() {
        pollingRunnable = object : Runnable {
            override fun run() {
                updateUI()
                handler.postDelayed(this, 500)
            }
        }
        handler.post(pollingRunnable!!)
    }

    private fun updateUI() {
        val state = VpnTunnelService.getState()
        val config = VpnTunnelService.getCurrentConfig()

        when (state) {
            ConnectionState.CONNECTED -> {
                statusText.text = "Connected"
                statusText.setTextColor(Color.parseColor("#4CAF50"))
                statusIcon.setColorFilter(Color.parseColor("#4CAF50"))
                btnConnect.text = "Disconnect"
                btnConnect.backgroundTintList = ColorStateList.valueOf(Color.parseColor("#B71C1C"))
                if (config != null) {
                    connectionInfo.text = "${config.connectionMode.displayName} \u2192 ${config.serverAddress}:${config.serverPort}"
                    connectionInfo.visibility = View.VISIBLE
                }
            }
            ConnectionState.CONNECTING -> {
                statusText.text = "Connecting..."
                statusText.setTextColor(Color.parseColor("#FF9800"))
                statusIcon.setColorFilter(Color.parseColor("#FF9800"))
                btnConnect.text = "Cancel"
                btnConnect.backgroundTintList = ColorStateList.valueOf(Color.parseColor("#757575"))
                connectionInfo.visibility = View.GONE
            }
            ConnectionState.FAILED -> {
                statusText.text = "Connection Failed"
                statusText.setTextColor(Color.parseColor("#F44336"))
                statusIcon.setColorFilter(Color.parseColor("#F44336"))
                btnConnect.text = "Connect"
                btnConnect.backgroundTintList = ColorStateList.valueOf(Color.parseColor("#00C853"))
                connectionInfo.visibility = View.GONE
            }
            else -> {
                statusText.text = "Disconnected"
                statusText.setTextColor(Color.parseColor("#9E9E9E"))
                statusIcon.setColorFilter(Color.parseColor("#9E9E9E"))
                btnConnect.text = "Connect"
                btnConnect.backgroundTintList = ColorStateList.valueOf(Color.parseColor("#00C853"))
                connectionInfo.visibility = View.GONE
            }
        }

        val logs = VpnTunnelService.getLogs()
        if (logAdapter.itemCount != logs.size) {
            logAdapter.setLogs(logs)
            if (logs.isNotEmpty()) {
                rvLogs.scrollToPosition(logs.size - 1)
            }
        }
    }

    override fun onDestroy() {
        pollingRunnable?.let { handler.removeCallbacks(it) }
        super.onDestroy()
    }
}
