package com.leo.smartswitch

import android.content.res.ColorStateList
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.view.Gravity
import android.view.ViewGroup
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import androidx.lifecycle.lifecycleScope
import com.google.android.material.button.MaterialButton
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch

class AddDeviceActivity : GlassActivity() {

    private lateinit var store: DeviceStore
    private lateinit var discovered: LinearLayout
    private lateinit var saved: LinearLayout

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        store = DeviceStore(this)
        val c = scaffold("Add a device")

        // ---- discovery
        c.addView(sectionLabel("On your network"))
        val scanCard = glassCard()
        scanCard.addView(body("Find LEO switches advertising on Wi-Fi (mDNS)."))
        scanCard.addView(primaryBtn("Scan network") { startScan() })
        discovered = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dp(6) }
        }
        scanCard.addView(discovered)
        c.addView(scanCard)

        // ---- manual
        c.addView(sectionLabel("By IP address"))
        val manual = glassCard()
        val ip = inputField("Device IP, e.g. 192.168.1.154")
        val user = inputField("Username (optional)")
        val pass = inputField("Password (optional)", password = true)
        manual.addView(ip); manual.addView(user); manual.addView(pass)
        manual.addView(primaryBtn("Add device") { addManual(ip, user, pass) })
        c.addView(manual)

        // ---- saved
        c.addView(sectionLabel("Saved devices"))
        saved = glassCard()
        c.addView(saved)

        refreshSaved()
    }

    private fun startScan() {
        discovered.removeAllViews()
        flash("Scanning…")
        lifecycleScope.launch {
            Discovery(this@AddDeviceActivity).discoverAll().collect { found -> addDiscovered(found) }
        }
    }

    private fun addDiscovered(found: Found) {
        for (i in 0 until discovered.childCount) if (discovered.getChildAt(i).tag == found.host) return
        val row = LinearLayout(this).apply {
            tag = found.host
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, dp(10), 0, dp(10))
        }
        row.addView(TextView(this).apply {
            text = "${found.name}\n${found.host}"
            setTextColor(col(R.color.moondust_text_primary)); textSize = 14f
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        })
        row.addView(MaterialButton(this).apply {
            text = "Add"; isAllCaps = false; textSize = 13f
            setTypeface(typeface, Typeface.BOLD); cornerRadius = dp(14)
            stateListAnimator = null; insetTop = 0; insetBottom = 0
            backgroundTintList = ColorStateList.valueOf(col(R.color.moondust_accent))
            setTextColor(col(R.color.on_accent_text))
            setOnClickListener {
                store.addDevice(SavedDevice("${found.host}:${found.port}", found.host, found.port, found.name))
                flash("Added ${found.name}"); refreshSaved()
            }
        })
        discovered.addView(row)
    }

    private fun addManual(ipF: EditText, userF: EditText, passF: EditText) {
        val raw = ipF.text.toString().trim().removePrefix("http://").removeSuffix("/")
        if (raw.isEmpty()) { flash("Enter an IP address", ok = false); return }
        val parts = raw.split(":")
        val h = parts[0]; val p = parts.getOrNull(1)?.toIntOrNull() ?: 80
        val user = userF.text.toString(); val pass = passF.text.toString()
        flash("Adding $h…")
        lifecycleScope.launch {
            var token: String? = null
            if (user.isNotEmpty()) {
                token = DeviceApi.login("http://$h:$p", user, pass)
                if (token == null) { flash("Login failed", ok = false); return@launch }
            }
            val reachable = DeviceApi.state(SavedDevice("$h:$p", h, p, h, token)) != null
            store.addDevice(SavedDevice("$h:$p", h, p, h, token))
            ipF.text.clear(); userF.text.clear(); passF.text.clear()
            flash(if (reachable) "Added $h" else "Saved $h (not reachable yet)", ok = reachable)
            refreshSaved()
        }
    }

    private fun refreshSaved() {
        saved.removeAllViews()
        val devices = store.getDevices()
        if (devices.isEmpty()) { saved.addView(body("Nothing saved yet.")); return }
        devices.forEach { d ->
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
                setPadding(0, dp(10), 0, dp(10))
            }
            row.addView(TextView(this).apply {
                text = "${d.name}\n${d.host}:${d.port}"
                setTextColor(col(R.color.moondust_text_primary)); textSize = 14f
                layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
            })
            row.addView(MaterialButton(this).apply {
                text = "Remove"; isAllCaps = false; textSize = 13f
                cornerRadius = dp(14); stateListAnimator = null; insetTop = 0; insetBottom = 0
                backgroundTintList = ColorStateList.valueOf(android.graphics.Color.parseColor("#1AFF5A6E"))
                setTextColor(col(R.color.moondust_danger))
                setOnClickListener {
                    store.removeDevice(d.id); LiveManager.disconnect(d.id)
                    flash("Removed ${d.name}"); refreshSaved()
                }
            })
            saved.addView(row)
        }
    }
}
