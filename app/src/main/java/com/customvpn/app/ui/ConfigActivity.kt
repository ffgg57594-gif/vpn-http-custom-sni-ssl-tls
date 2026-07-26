package com.customvpn.app.ui

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.customvpn.app.R

class ConfigActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_config)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        supportActionBar?.title = "Server Configuration"
    }

    override fun onSupportNavigateUp(): Boolean {
        finish()
        return true
    }
}
