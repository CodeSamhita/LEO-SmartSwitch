package com.leo.smartswitch

import android.graphics.Typeface
import android.os.Bundle
import android.view.Gravity
import android.view.ViewGroup
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import androidx.lifecycle.lifecycleScope
import com.google.android.material.slider.Slider
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject

class DeviceSettingsActivity : GlassActivity() {

    private lateinit var store: DeviceStore
    private var deviceId: String? = null

    private lateinit var nameField: EditText
    private var role = "none"
    private var ledMode = "status"
    private var ledBright = 40
    private lateinit var ledTimeoutField: EditText
    private val mapNames = ArrayList<EditText>()
    private val mapWatts = ArrayList<EditText>()
    private val mapGpios = ArrayList<Int>()
    private lateinit var relayMapBox: LinearLayout

    private fun device() = store.getDevices().find { it.id == deviceId }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        store = DeviceStore(this)
        deviceId = intent.getStringExtra("DEVICE_ID")
        val c = scaffold("Device settings")

        // name
        c.addView(sectionLabel("Name"))
        val nameCard = glassCard()
        nameField = inputField("Friendly name")
        nameCard.addView(nameField)
        nameCard.addView(primaryBtn("Save name") { saveName() })
        c.addView(nameCard)

        // role
        c.addView(sectionLabel("Role in the group"))
        val roleCard = glassCard()
        roleCard.addView(body("The master owns leoswitch.local; others fail over automatically."))
        roleCard.addView(segmented(listOf("None", "Master", "Slave"), 0) {
            role = listOf("none", "master", "slave")[it]; saveRole()
        })
        c.addView(roleCard)

        // LED
        c.addView(sectionLabel("Status LED"))
        val ledCard = glassCard()
        ledCard.addView(body("Auto-off lights on changes then sleeps once steady online, so it isn't drawing power 24/7."))
        ledCard.addView(segmented(listOf("Off", "Auto-off", "Always"), 1) {
            ledMode = listOf("off", "status", "always")[it]
        })
        val brightLabel = TextView(this).apply {
            text = "Brightness"; setTextColor(col(R.color.moondust_text_secondary)); textSize = 12.5f
            setPadding(0, dp(12), 0, 0)
        }
        ledCard.addView(brightLabel)
        val slider = Slider(this).apply {
            valueFrom = 0f; valueTo = 255f; value = ledBright.toFloat(); stepSize = 1f
            addOnChangeListener { _, v, _ -> ledBright = v.toInt() }
        }
        ledCard.addView(slider)
        ledTimeoutField = inputField("Auto-off after (seconds, 0 = never)").apply {
            inputType = android.text.InputType.TYPE_CLASS_NUMBER; setText("30")
        }
        ledCard.addView(ledTimeoutField)
        val ledBtns = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        ledBtns.addView(primaryBtn("Save LED") { saveLed() }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { marginEnd = dp(6) })
        ledBtns.addView(ghostBtn("Identify") { identify() }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { marginStart = dp(6) })
        ledCard.addView(ledBtns)
        c.addView(ledCard)

        // relay map
        c.addView(sectionLabel("Relay names & power"))
        val mapCard = glassCard()
        relayMapBox = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        mapCard.addView(relayMapBox)
        mapCard.addView(primaryBtn("Save relays") { saveMap() })
        c.addView(mapCard)

        loadAll()
    }

    private fun loadAll() {
        lifecycleScope.launch {
            val d = device() ?: return@launch
            DeviceApi.identity(d)?.let { nameField.setText(it.optString("name", "")); role = it.optString("role", "none") }
            DeviceApi.ledGet(d)?.let {
                ledMode = it.optString("mode", "status"); ledBright = it.optInt("brightness", 40)
                ledTimeoutField.setText(it.optInt("timeout", 30).toString())
            }
            DeviceApi.relayMapGet(d)?.let { buildMap(it.optJSONArray("relays")) }
        }
    }

    private fun buildMap(relays: JSONArray?) {
        relayMapBox.removeAllViews(); mapNames.clear(); mapWatts.clear(); mapGpios.clear()
        if (relays == null) return
        for (i in 0 until relays.length()) {
            val o = relays.getJSONObject(i)
            mapGpios.add(o.optInt("gpio", -1))
            val wrap = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL; setPadding(0, dp(8), 0, dp(8))
            }
            wrap.addView(TextView(this).apply {
                text = "Relay ${i + 1}  ·  GPIO ${o.optInt("gpio", -1)}"
                setTextColor(col(R.color.moondust_text_secondary)); textSize = 12f
            })
            val rowFields = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
            val name = inputField("Name").apply { setText(o.optString("name", "Relay ${i + 1}")) }
            val watts = inputField("Watts").apply {
                inputType = android.text.InputType.TYPE_CLASS_NUMBER or android.text.InputType.TYPE_NUMBER_FLAG_DECIMAL
                setText(o.optDouble("watts", 0.0).toInt().toString())
            }
            rowFields.addView(name, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 2f).apply { marginEnd = dp(6) })
            rowFields.addView(watts, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { marginStart = dp(6) })
            mapNames.add(name); mapWatts.add(watts)
            wrap.addView(rowFields)
            relayMapBox.addView(wrap)
        }
    }

    private fun saveName() {
        val n = nameField.text.toString().trim(); if (n.isEmpty()) { flash("Enter a name", ok = false); return }
        lifecycleScope.launch { val d = device() ?: return@launch
            flash(if (DeviceApi.setName(d, n)) "Name saved" else "Save failed") }
    }
    private fun saveRole() {
        lifecycleScope.launch { val d = device() ?: return@launch
            flash(if (DeviceApi.setRole(d, role)) "Role set to $role" else "Save failed") }
    }
    private fun saveLed() {
        val t = ledTimeoutField.text.toString().toIntOrNull() ?: 30
        lifecycleScope.launch { val d = device() ?: return@launch
            flash(if (DeviceApi.setLed(d, ledMode, ledBright, t)) "LED settings saved" else "Save failed") }
    }
    private fun identify() {
        lifecycleScope.launch { val d = device() ?: return@launch
            flash(if (DeviceApi.identify(d)) "Blinking the device LED" else "Couldn't reach device", ok = true) }
    }
    private fun saveMap() {
        val arr = JSONArray()
        mapNames.indices.forEach { i ->
            arr.put(JSONObject()
                .put("name", mapNames[i].text.toString().ifBlank { "Relay ${i + 1}" })
                .put("gpio", mapGpios.getOrElse(i) { -1 })
                .put("watts", mapWatts[i].text.toString().toDoubleOrNull() ?: 0.0))
        }
        lifecycleScope.launch { val d = device() ?: return@launch
            flash(if (DeviceApi.setRelayMap(d, arr)) "Relays saved" else "Save failed") }
    }
}
