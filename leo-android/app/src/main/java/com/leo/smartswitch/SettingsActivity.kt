package com.leo.smartswitch

import android.graphics.Color
import android.os.Bundle
import android.view.Gravity
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.cardview.widget.CardView
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch

class SettingsActivity : AppCompatActivity() {

    private lateinit var store: DeviceStore
    private lateinit var discoveredContainer: LinearLayout
    private lateinit var savedContainer: LinearLayout

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)
        store = DeviceStore(this)
        discoveredContainer = findViewById(R.id.discoveredContainer)
        savedContainer = findViewById(R.id.savedContainer)

        findViewById<Button>(R.id.discover).setOnClickListener { startDiscovery() }

        findViewById<Button>(R.id.save).setOnClickListener {
            val host = findViewById<EditText>(R.id.ip).text.toString().trim()
            if (host.isEmpty()) return@setOnClickListener
            
            val user = findViewById<EditText>(R.id.user).text.toString()
            val pass = findViewById<EditText>(R.id.pass).text.toString()
            
            lifecycleScope.launch {
                val parts = host.removePrefix("http://").split(":")
                val h = parts[0]
                val p = parts.getOrNull(1)?.toIntOrNull() ?: 80
                
                var token: String? = null
                if (user.isNotEmpty()) {
                    token = DeviceApi.login("http://$h:$p", user, pass)
                }
                
                val device = SavedDevice(id = "$h:$p", host = h, port = p, name = h, token = token)
                store.addDevice(device)
                toast("Added $h")
                refreshSaved()
            }
        }

        findViewById<ImageView>(R.id.backBtn).setOnClickListener { finish() }

        refreshSaved()
    }

    private fun startDiscovery() {
        discoveredContainer.removeAllViews()
        lifecycleScope.launch {
            Discovery(this@SettingsActivity).discoverAll().collect { found ->
                addDiscoveredCard(found)
            }
        }
    }

    private fun addDiscoveredCard(found: Found) {
        // Avoid duplicates in UI
        for (i in 0 until discoveredContainer.childCount) {
            val v = discoveredContainer.getChildAt(i)
            if (v.tag == found.host) return
        }

        val card = CardView(this).apply {
            tag = found.host
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                setMargins(0, 0, 0, 12.dpToPx())
            }
            setCardBackgroundColor(ContextCompat.getColor(context, R.color.moondust_surface))
            radius = 16.dpToPx().toFloat()
            cardElevation = 0f
        }

        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(16.dpToPx(), 16.dpToPx(), 16.dpToPx(), 16.dpToPx())
            gravity = Gravity.CENTER_VERTICAL
        }

        val txt = TextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
            text = "${found.name}\n${found.host}"
            setTextColor(ContextCompat.getColor(context, R.color.moondust_text_primary))
            textSize = 14f
        }

        val addBtn = Button(this, null, com.google.android.material.R.attr.materialButtonStyle).apply {
            text = getString(R.string.add_btn)
            backgroundTintList = android.content.res.ColorStateList.valueOf(ContextCompat.getColor(context, R.color.moondust_accent))
            setTextColor(Color.parseColor("#003135"))
            textSize = 12f
            setOnClickListener {
                store.addDevice(SavedDevice(id = "${found.host}:${found.port}", host = found.host, port = found.port, name = found.name))
                toast("Added ${found.name}")
                refreshSaved()
            }
        }

        row.addView(txt)
        row.addView(addBtn)
        card.addView(row)
        discoveredContainer.addView(card)
    }

    private fun refreshSaved() {
        savedContainer.removeAllViews()
        store.getDevices().forEach { device ->
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                setPadding(0, 10.dpToPx(), 0, 10.dpToPx())
                gravity = Gravity.CENTER_VERTICAL
            }

            val txt = TextView(this).apply {
                layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
                text = "${device.name} (${device.host})"
                setTextColor(ContextCompat.getColor(context, R.color.moondust_text_secondary))
                textSize = 15f
            }

            val delBtn = ImageView(this).apply {
                setImageResource(android.R.drawable.ic_menu_delete)
                setColorFilter(ContextCompat.getColor(context, R.color.moondust_danger))
                background = ContextCompat.getDrawable(context, android.R.drawable.screen_background_dark_transparent)?.apply { alpha = 20 }
                setPadding(8.dpToPx(), 8.dpToPx(), 8.dpToPx(), 8.dpToPx())
                layoutParams = LinearLayout.LayoutParams(40.dpToPx(), 40.dpToPx())
                setOnClickListener {
                    store.removeDevice(device.id)
                    refreshSaved()
                }
            }

            row.addView(txt)
            row.addView(delBtn)
            savedContainer.addView(row)
        }
    }

    private fun Int.dpToPx(): Int = (this * resources.displayMetrics.density).toInt()
    private fun toast(m: String) = Toast.makeText(this, m, Toast.LENGTH_SHORT).show()
}
