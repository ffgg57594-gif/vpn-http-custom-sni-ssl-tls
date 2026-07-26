package com.customvpn.app.ui

import android.graphics.Color
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.customvpn.app.R
import com.customvpn.app.models.LogEntry
import java.text.SimpleDateFormat
import java.util.*

class LogAdapter : RecyclerView.Adapter<LogAdapter.ViewHolder>() {

    private val logs = mutableListOf<LogEntry>()
    private val dateFormat = SimpleDateFormat("HH:mm:ss", Locale.getDefault())

    fun addLog(entry: LogEntry) {
        logs.add(entry)
        notifyItemInserted(logs.size - 1)
    }

    fun setLogs(newLogs: List<LogEntry>) {
        logs.clear()
        logs.addAll(newLogs)
        notifyDataSetChanged()
    }

    fun clear() {
        logs.clear()
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_log, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val entry = logs[position]
        holder.tvTime.text = dateFormat.format(Date(entry.timestamp))
        holder.tvLevel.text = entry.level.tag
        holder.tvMessage.text = entry.message

        val color = when (entry.level) {
            LogEntry.Level.INFO -> Color.parseColor("#4FC3F7")
            LogEntry.Level.WARNING -> Color.parseColor("#FFB74D")
            LogEntry.Level.ERROR -> Color.parseColor("#EF5350")
            LogEntry.Level.DEBUG -> Color.parseColor("#81C784")
        }
        holder.tvLevel.setTextColor(color)
    }

    override fun getItemCount() = logs.size

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val tvTime: TextView = view.findViewById(R.id.tvLogTime)
        val tvLevel: TextView = view.findViewById(R.id.tvLogLevel)
        val tvMessage: TextView = view.findViewById(R.id.tvLogMessage)
    }
}
