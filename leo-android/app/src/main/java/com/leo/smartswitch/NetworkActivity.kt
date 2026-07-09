package com.leo.smartswitch

import android.graphics.Typeface
import android.os.Bundle
import android.view.Gravity
import android.view.ViewGroup
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch

class NetworkActivity : GlassActivity() {

    private lateinit var store: DeviceStore
    private var deviceId: String? = null
    private lateinit var idBox: LinearLayout
    private lateinit var netList: LinearLayout
    private lateinit var ssidField: EditText
    private lateinit var mdnsField: EditText

    private fun device() = store.getDevices().find { it.id == deviceId }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        store = DeviceStore(this)
        deviceId = intent.getStringExtra("DEVICE_ID")
        val c = scaffold("Network & Wi-Fi")

        c.addView(sectionLabel("Identity"))
        val idCard = glassCard()
        idBox = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        idCard.addView(idBox)
        c.addView(idCard)

        c.addView(sectionLabel("Join a Wi-Fi network"))
        val wifi = glassCard()
        wifi.addView(ghostBtn("Scan for networks") { scan() })
        netList = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        wifi.addView(netList)
        ssidField = inputField("Network name (SSID)")
        val wpass = inputField("Wi-Fi password", password = true)
        wifi.addView(ssidField); wifi.addView(wpass)
        wifi.addView(primaryBtn("Join & reconnect") { join(ssidField, wpass) })
        wifi.addView(body("The device reboots to join; it keeps its own access point as a fallback.").apply { setPadding(0, dp(8), 0, 0) })
        c.addView(wifi)

        c.addView(sectionLabel("Access point"))
        val ap = glassCard()
        val apSsid = inputField("AP name")
        val apPass = inputField("AP password (min 8)", password = true)
        ap.addView(apSsid); ap.addView(apPass)
        ap.addView(ghostBtn("Save access point") { setAp(apSsid, apPass) })
        c.addView(ap)

        c.addView(sectionLabel("mDNS name"))
        val md = glassCard()
        mdnsField = inputField("leoswitch  (or type 'auto')")
        md.addView(mdnsField)
        md.addView(ghostBtn("Apply mDNS name") { applyMdns() })
        md.addView(body("Default 'auto': one unit owns leoswitch.local with failover; others use leo-<id>.local.").apply { setPadding(0, dp(8), 0, 0) })
        c.addView(md)

        loadIdentity()
    }

    private fun loadIdentity() {
        lifecycleScope.launch {
            val d = device() ?: return@launch
            val j = DeviceApi.identity(d) ?: run { flash("Device unreachable", ok = false); return@launch }
            idBox.removeAllViews()
            listOf(
                "Device ID" to j.optString("id", "—"),
                "AP name" to j.optString("ap", "—"),
                "mDNS" to j.optString("mdns", "—"),
                "IP" to j.optString("ip", "—")
            ).forEach { (k, v) -> idBox.addView(kvRow(k, v).first) }
            mdnsField.setText(j.optString("mdns", "").removeSuffix(".local"))
        }
    }

    private fun scan() {
        netList.removeAllViews(); flash("Scanning Wi-Fi…")
        lifecycleScope.launch {
            val d = device() ?: return@launch
            val j = DeviceApi.scan(d)
            val nets = j?.optJSONArray("nets")
            if (nets == null || nets.length() == 0) { flash("No networks found", ok = false); return@launch }
            val items = (0 until nets.length()).map { nets.getJSONObject(it) }
                .sortedByDescending { it.optInt("rssi", -100) }
            items.forEach { o ->
                val ssid = o.optString("ssid"); if (ssid.isEmpty()) return@forEach
                val row = LinearLayout(this@NetworkActivity).apply {
                    orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
                    isClickable = true; setPadding(0, dp(10), 0, dp(10))
                    setOnClickListener { ssidField.setText(ssid); flash("Selected $ssid") }
                }
                row.addView(TextView(this@NetworkActivity).apply {
                    text = (if (o.optBoolean("lock")) "🔒 " else "") + ssid
                    setTextColor(col(R.color.moondust_text_primary)); textSize = 14f
                    layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
                })
                row.addView(TextView(this@NetworkActivity).apply {
                    text = "${o.optInt("rssi")} dBm"
                    setTextColor(col(R.color.moondust_text_secondary)); textSize = 12f
                })
                netList.addView(row)
            }
        }
    }

    private fun join(ssidF: EditText, passF: EditText) {
        val ssid = ssidF.text.toString().trim()
        if (ssid.isEmpty()) { flash("Enter a network name", ok = false); return }
        lifecycleScope.launch {
            val d = device() ?: return@launch
            flash(if (DeviceApi.joinWifi(d, ssid, passF.text.toString())) "Saved — device reconnecting…" else "Save failed",
                ok = true)
        }
    }

    private fun setAp(ssidF: EditText, passF: EditText) {
        lifecycleScope.launch {
            val d = device() ?: return@launch
            flash(if (DeviceApi.setAp(d, ssidF.text.toString().trim(), passF.text.toString())) "Access point saved — rebooting…" else "Save failed")
        }
    }

    private fun applyMdns() {
        val host = mdnsField.text.toString().trim()
        lifecycleScope.launch {
            val d = device() ?: return@launch
            flash(if (DeviceApi.setMdns(d, host)) "mDNS updated" else "Invalid name", ok = true)
            loadIdentity()
        }
    }
}
