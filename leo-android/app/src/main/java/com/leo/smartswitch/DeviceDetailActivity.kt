package com.leo.smartswitch

import android.content.Intent
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.Typeface
import android.net.Uri
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import androidx.lifecycle.lifecycleScope
import com.google.android.material.button.MaterialButton
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
import java.util.Locale

class DeviceDetailActivity : GlassActivity() {

    private lateinit var store: DeviceStore
    private var deviceId: String? = null
    private lateinit var powerTxt: TextView
    private lateinit var costTxt: TextView
    private lateinit var relayBox: LinearLayout
    private val statVals = HashMap<String, TextView>()

    private fun device(): SavedDevice? = store.getDevices().find { it.id == deviceId }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        store = DeviceStore(this)
        deviceId = intent.getStringExtra("DEVICE_ID")
        val dev = device()
        val c = scaffold(dev?.name ?: "Device")

        // hero: live power + cost
        val hero = glassCard(pad = 24).apply {
            background = androidx.core.content.ContextCompat.getDrawable(this@DeviceDetailActivity, R.drawable.glass_card_hero)
            gravity = Gravity.CENTER_HORIZONTAL
        }
        powerTxt = TextView(this).apply {
            text = "0.0 W"; setTextColor(col(R.color.moondust_text_primary)); textSize = 50f
            setTypeface(typeface, Typeface.BOLD)
            setShadowLayer(30f, 0f, 0f, col(R.color.moondust_accent))   // neon glow
        }
        hero.addView(powerTxt)
        hero.addView(body("Current draw").apply { gravity = Gravity.CENTER })
        costTxt = TextView(this).apply {
            text = "₹ —/hr"; setTextColor(col(R.color.moondust_accent)); textSize = 15f
            setTypeface(typeface, Typeface.BOLD); gravity = Gravity.CENTER
            setPadding(0, dp(10), 0, 0)
        }
        hero.addView(costTxt)
        c.addView(hero)

        // relays
        c.addView(sectionLabel("Relays"))
        val relayCard = glassCard()
        relayBox = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        relayCard.addView(relayBox)
        c.addView(relayCard)

        // stats
        c.addView(sectionLabel("System"))
        val statCard = glassCard()
        listOf("Model","Firmware","Uptime","IP","mDNS").forEach { k ->
            val (row, v) = kvRow(k); statVals[k] = v; statCard.addView(row)
        }
        c.addView(statCard)

        // dedicated sub-screens
        c.addView(sectionLabel("Manage"))
        val nav = glassCard()
        nav.addView(navRow("Energy & usage") { open(EnergyActivity::class.java) })
        nav.addView(divider())
        nav.addView(navRow("Network & Wi-Fi") { open(NetworkActivity::class.java) })
        nav.addView(divider())
        nav.addView(navRow("Device settings & LED") { open(DeviceSettingsActivity::class.java) })
        nav.addView(divider())
        nav.addView(navRow("Open web console") {
            device()?.let { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(it.baseUrl()))) }
        })
        c.addView(nav)

        Anim.entrance(hero, 0); Anim.entrance(relayCard, 1); Anim.entrance(statCard, 2); Anim.entrance(nav, 3)

        lifecycleScope.launch {
            val d = device() ?: return@launch
            LiveManager.connect(d)
            DeviceApi.state(d)?.let { updateUi(it) }
        }
        lifecycleScope.launch {
            LiveManager.updates.filter { it.id == deviceId }.collect { updateUi(it) }
        }
    }

    private fun open(cls: Class<*>) =
        startActivity(Intent(this, cls).putExtra("DEVICE_ID", deviceId))

    private fun navRow(label: String, onClick: () -> Unit): View {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
            isClickable = true; setPadding(0, dp(13), 0, dp(13))
            setOnClickListener { onClick() }
        }
        Anim.pressable(row, 0.98f)
        row.addView(TextView(this).apply {
            text = label; setTextColor(col(R.color.moondust_text_primary)); textSize = 15f
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        })
        row.addView(TextView(this).apply {
            text = "›"; setTextColor(col(R.color.moondust_text_secondary)); textSize = 22f
        })
        return row
    }

    private fun divider() = View(this).apply {
        setBackgroundColor(Color.parseColor("#16FFFFFF"))
        layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(1))
    }

    private fun updateUi(s: DeviceState) {
        Anim.countTo(powerTxt, s.totalWatts.toFloat()) { String.format(Locale.US, "%.1f W", it) }
        Anim.gradientText(powerTxt, col(R.color.moondust_accent), col(R.color.moondust_accent3))
        costTxt.text = String.format(Locale.US, "₹ %.2f /hr", s.totalWatts / 1000.0 * s.tariff)
        statVals["Model"]?.text = s.model
        statVals["Firmware"]?.text = s.version
        statVals["Uptime"]?.text = s.uptime
        statVals["IP"]?.text = s.ip.ifEmpty { "—" }
        relayBox.removeAllViews()
        s.relays.forEachIndexed { i, r -> relayBox.addView(relayRow(i, r)) }
        // mDNS comes from identity (state has no mdns field in older builds)
        lifecycleScope.launch { device()?.let { d -> DeviceApi.identity(d)?.let { statVals["mDNS"]?.text = it.optString("mdns", "—") } } }
    }

    private fun relayRow(index: Int, relay: Relay): View {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
            setPadding(0, dp(10), 0, dp(10))
        }
        val info = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        }
        info.addView(TextView(this).apply {
            text = relay.name; setTextColor(col(R.color.moondust_text_primary)); textSize = 16f
        })
        info.addView(TextView(this).apply {
            text = if (relay.on) String.format(Locale.US, "%.0f W", relay.watts) else "Off"
            setTextColor(col(if (relay.on) R.color.moondust_accent else R.color.moondust_text_secondary))
            textSize = 12f
        })
        row.addView(info)

        val toggle = MaterialButton(this).apply {
            isAllCaps = false; textSize = 12f; setTypeface(typeface, Typeface.BOLD)
            cornerRadius = dp(16); stateListAnimator = null; insetTop = 0; insetBottom = 0; minWidth = dp(74)
            setPadding(dp(16), dp(11), dp(16), dp(11))
        }
        paintToggle(toggle, relay.on)
        toggle.setOnClickListener {
            val next = toggle.tag != true
            val from = if (toggle.tag == true) col(R.color.moondust_accent) else Color.parseColor("#16FFFFFF")
            val to = if (next) col(R.color.moondust_accent) else Color.parseColor("#16FFFFFF")
            toggle.tag = next
            toggle.text = if (next) "ON" else "OFF"
            toggle.setTextColor(if (next) col(R.color.on_accent_text) else col(R.color.moondust_text_secondary))
            Anim.tintTo(toggle, from, to); Anim.bounce(toggle)
            (info.getChildAt(1) as TextView).apply {
                text = if (next) "On" else "Off"
                setTextColor(col(if (next) R.color.moondust_accent else R.color.moondust_text_secondary))
            }
            lifecycleScope.launch {
                val d = device() ?: return@launch
                if (!DeviceApi.setRelay(d.baseUrl(), d.token, index, next)) {
                    paintToggle(toggle, !next); flash("Couldn't switch ${relay.name}", ok = false)
                }
            }
        }
        row.addView(toggle)
        return row
    }

    private fun paintToggle(btn: MaterialButton, on: Boolean) {
        btn.tag = on
        btn.text = if (on) "ON" else "OFF"
        btn.backgroundTintList = ColorStateList.valueOf(
            if (on) col(R.color.moondust_accent) else Color.parseColor("#16FFFFFF"))
        btn.setTextColor(if (on) col(R.color.on_accent_text) else col(R.color.moondust_text_secondary))
    }
}
