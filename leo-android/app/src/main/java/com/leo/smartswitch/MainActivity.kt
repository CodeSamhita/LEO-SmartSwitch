package com.leo.smartswitch

import android.content.Intent
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.GridLayout
import android.widget.LinearLayout
import android.widget.TextView
import androidx.glance.appwidget.updateAll
import androidx.lifecycle.lifecycleScope
import com.google.android.material.button.MaterialButton
import com.leo.smartswitch.widget.LeoWidget
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
import java.util.Locale

class MainActivity : GlassActivity() {

    private lateinit var store: DeviceStore
    private lateinit var content: LinearLayout
    private lateinit var headerSub: TextView
    private lateinit var masterCard: View
    private lateinit var deviceList: LinearLayout
    private lateinit var emptyCard: View

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        store = DeviceStore(this)
        content = scaffold(title = null, showBack = false)
        buildHeader()
        buildMaster()
        deviceList = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        content.addView(deviceList)
        buildEmpty()

        lifecycleScope.launch { LiveManager.updates.collect { updateCard(it) } }
    }

    override fun onResume() {
        super.onResume()
        refresh()
        store.getDevices().forEach { LiveManager.connect(it) }
    }

    // Was only disconnecting in onDestroy() when finishing, so backgrounding
    // the app (Home button, screen off, switching apps) left every saved
    // device's WebSocket open indefinitely - onPause() always precedes
    // onDestroy(), so this covers both cases. onResume() reconnects whatever
    // is actually needed when the dashboard becomes visible again.
    override fun onPause() {
        super.onPause()
        LiveManager.disconnectAll()
    }

    private fun buildHeader() {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(16) }
        }
        val titleCol = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        }
        titleCol.addView(titleText("Your Devices", 26f))
        headerSub = body("—").apply { setPadding(0, dp(2), 0, 0) }
        titleCol.addView(headerSub)
        row.addView(titleCol)

        val add = MaterialButton(this).apply {
            text = "Add"; isAllCaps = false; textSize = 14f
            setTypeface(typeface, Typeface.BOLD)
            cornerRadius = dp(20)
            icon = androidx.core.content.ContextCompat.getDrawable(context, R.drawable.ic_plus)
            iconGravity = MaterialButton.ICON_GRAVITY_TEXT_START
            iconPadding = dp(4); iconSize = dp(18)
            backgroundTintList = ColorStateList.valueOf(col(R.color.moondust_accent))
            setTextColor(col(R.color.on_accent_text))
            stateListAnimator = null; insetTop = 0; insetBottom = 0
            setPadding(dp(16), dp(12), dp(18), dp(12))
            setOnClickListener { startActivity(Intent(this@MainActivity, AddDeviceActivity::class.java)) }
        }
        row.addView(add)
        content.addView(row)
    }

    private fun buildMaster() {
        masterCard = glassCard(pad = 16).apply {
            orientation = LinearLayout.HORIZONTAL
            addView(masterBtn("All On", true), LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { marginEnd = dp(6) })
            addView(masterBtn("All Off", false), LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { marginStart = dp(6) })
        }
        content.addView(masterCard)
    }

    private fun masterBtn(label: String, on: Boolean) = MaterialButton(this).apply {
        text = label; isAllCaps = false; textSize = 14f
        setTypeface(typeface, Typeface.BOLD)
        cornerRadius = dp(16)
        stateListAnimator = null; insetTop = 0; insetBottom = 0
        setPadding(0, dp(14), 0, dp(14))
        if (on) { backgroundTintList = ColorStateList.valueOf(col(R.color.moondust_accent)); setTextColor(col(R.color.on_accent_text)) }
        else { backgroundTintList = ColorStateList.valueOf(Color.parseColor("#16FFFFFF")); setTextColor(col(R.color.moondust_text_primary)) }
        setOnClickListener { masterAll(on) }
    }

    private fun buildEmpty() {
        emptyCard = glassCard(pad = 28).apply {
            gravity = Gravity.CENTER_HORIZONTAL
            addView(titleText("No devices yet", 18f).apply { gravity = Gravity.CENTER })
            addView(body("Add your LEO switch — discovered on the network or by IP.").apply {
                gravity = Gravity.CENTER; setPadding(0, dp(8), 0, dp(16))
            })
            addView(primaryBtn("Find / Add a device") {
                startActivity(Intent(this@MainActivity, AddDeviceActivity::class.java))
            })
        }
        content.addView(emptyCard)
    }

    private fun masterAll(on: Boolean) {
        val devices = store.getDevices()
        if (devices.isEmpty()) return
        flash(if (on) "Turning everything on…" else "Turning everything off…")
        lifecycleScope.launch {
            var fail = 0
            devices.forEach { if (!DeviceApi.setAll(it.baseUrl(), it.token, on)) fail++ }
            if (fail > 0) flash("$fail device(s) didn't respond", ok = false)
        }
    }

    private fun refresh() {
        val devices = store.getDevices()
        headerSub.text = if (devices.isEmpty()) "Nothing connected"
            else "${devices.size} device${if (devices.size == 1) "" else "s"} connected"
        emptyCard.visibility = if (devices.isEmpty()) View.VISIBLE else View.GONE
        masterCard.visibility = if (devices.isEmpty()) View.GONE else View.VISIBLE

        deviceList.removeAllViews()
        devices.forEachIndexed { i, d -> addDeviceCard(d, i) }
        lifecycleScope.launch { runCatching { LeoWidget().updateAll(this@MainActivity) } }
    }

    private fun addDeviceCard(device: SavedDevice, index: Int) {
        val card = glassCard(pad = 18).apply {
            tag = device.id
            isClickable = true
            setOnClickListener {
                startActivity(Intent(this@MainActivity, DeviceDetailActivity::class.java)
                    .putExtra("DEVICE_ID", device.id))
            }
        }
        val header = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
        header.addView(TextView(this).apply {
            tag = "name"; text = device.name
            setTextColor(col(R.color.moondust_text_primary)); textSize = 18f
            setTypeface(typeface, Typeface.BOLD); maxLines = 1
            ellipsize = android.text.TextUtils.TruncateAt.END
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        })
        header.addView(TextView(this).apply {
            tag = "power"; textSize = 14f
            setTextColor(col(R.color.moondust_accent)); setTypeface(typeface, Typeface.BOLD)
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { marginEnd = dp(10) }
            visibility = View.INVISIBLE
        })
        header.addView(View(this).apply {
            tag = "dot"
            background = GradientDrawable().apply { shape = GradientDrawable.OVAL; setColor(col(R.color.moondust_text_secondary)) }
            layoutParams = LinearLayout.LayoutParams(dp(10), dp(10))
        })
        card.addView(header)

        card.addView(GridLayout(this).apply {
            tag = "relays"; columnCount = relayColumns()
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { topMargin = dp(14) }
        })
        deviceList.addView(card)
        Anim.pressable(card)
        Anim.entrance(card, index)

        lifecycleScope.launch {
            val s = DeviceApi.state(device)
            if (s != null) updateCard(s) else setDot(card, false)
        }
    }

    /** 2 relay columns on phones, 3 once there's room (large/landscape/tablet). */
    private fun relayColumns(): Int = if (resources.configuration.screenWidthDp >= 600) 3 else 2

    private fun setDot(card: View, online: Boolean) {
        val dot = card.findViewWithTag<View>("dot")
        (dot.background as GradientDrawable)
            .setColor(if (online) col(R.color.moondust_accent) else col(R.color.moondust_danger))
        if (online && !dot.isSelected) { dot.isSelected = true; Anim.pulse(dot) }
        else if (!online && dot.isSelected) { dot.isSelected = false; Anim.stop(dot) }
    }

    private fun updateCard(s: DeviceState) {
        val card = deviceList.findViewWithTag<View>(s.id) ?: return
        card.findViewWithTag<TextView>("power").apply {
            visibility = View.VISIBLE
            Anim.countTo(this, s.totalWatts.toFloat()) { String.format(Locale.US, "%.1f W", it) }
            Anim.gradientText(this, col(R.color.moondust_accent), col(R.color.moondust_accent2))
        }
        setDot(card, true)
        val grid = card.findViewWithTag<GridLayout>("relays")
        grid.removeAllViews()
        s.relays.forEachIndexed { i, r -> grid.addView(relayPill(s.id, i, r)) }
    }

    private fun relayPill(deviceId: String, index: Int, relay: Relay): MaterialButton {
        val btn = MaterialButton(this).apply {
            text = relay.name; isAllCaps = false; textSize = 12f
            maxLines = 1; ellipsize = android.text.TextUtils.TruncateAt.END
            cornerRadius = dp(16)
            stateListAnimator = null; insetTop = 0; insetBottom = 0; minHeight = 0; minimumHeight = 0
            setPadding(dp(6), dp(12), dp(6), dp(12))
            layoutParams = GridLayout.LayoutParams().apply {
                width = 0; height = ViewGroup.LayoutParams.WRAP_CONTENT
                columnSpec = GridLayout.spec(GridLayout.UNDEFINED, 1, 1f)
                rowSpec = GridLayout.spec(GridLayout.UNDEFINED)
                val m = dp(4); setMargins(m, m, m, m)
            }
        }
        paintPill(btn, relay.on)
        btn.setOnClickListener {
            val next = btn.tag != true
            val from = if (btn.tag == true) col(R.color.moondust_accent) else Color.parseColor("#16FFFFFF")
            val to = if (next) col(R.color.moondust_accent) else Color.parseColor("#16FFFFFF")
            btn.tag = next
            btn.setTextColor(if (next) col(R.color.on_accent_text) else col(R.color.moondust_text_secondary))
            Anim.tintTo(btn, from, to); Anim.bounce(btn)           // optimistic + animated
            lifecycleScope.launch {
                val d = store.getDevices().find { it.id == deviceId } ?: return@launch
                if (!DeviceApi.setRelay(d.baseUrl(), d.token, index, next)) {
                    paintPill(btn, !next); flash("Couldn't reach ${d.name}", ok = false)
                }
            }
        }
        return btn
    }

    private fun paintPill(btn: MaterialButton, on: Boolean) {
        btn.tag = on
        btn.backgroundTintList = ColorStateList.valueOf(
            if (on) col(R.color.moondust_accent) else Color.parseColor("#16FFFFFF"))
        btn.setTextColor(if (on) col(R.color.on_accent_text) else col(R.color.moondust_text_secondary))
    }
}
