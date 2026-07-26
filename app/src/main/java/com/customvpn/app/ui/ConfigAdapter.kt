package com.customvpn.app.ui

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageButton
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.customvpn.app.R
import com.customvpn.app.models.VpnConfig

class ConfigAdapter(
    private val onConfigSelected: (VpnConfig) -> Unit,
    private val onDeleteConfig: (VpnConfig) -> Unit
) : RecyclerView.Adapter<ConfigAdapter.ViewHolder>() {

    private val configs = mutableListOf<VpnConfig>()

    fun setConfigs(newConfigs: List<VpnConfig>) {
        configs.clear()
        configs.addAll(newConfigs)
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_config, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val config = configs[position]
        holder.tvName.text = config.name.ifEmpty { "Unnamed" }
        holder.tvDetails.text = "${config.serverAddress}:${config.serverPort} • ${config.connectionMode.displayName}"
        holder.itemView.setOnClickListener { onConfigSelected(config) }
        holder.btnDelete.setOnClickListener { onDeleteConfig(config) }
    }

    override fun getItemCount() = configs.size

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val tvName: TextView = view.findViewById(R.id.tvConfigName)
        val tvDetails: TextView = view.findViewById(R.id.tvConfigDetails)
        val btnDelete: ImageButton = view.findViewById(R.id.btnDeleteConfig)
    }
}
