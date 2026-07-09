package com.leo.smartswitch

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.LinearGradient
import android.graphics.Paint
import android.graphics.Path
import android.graphics.Shader
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import java.util.Locale

class EnergyActivity : GlassActivity() {

    private lateinit var store: DeviceStore
    private var deviceId: String? = null
    private lateinit var kwhTxt: TextView
    private lateinit var costTxt: TextView
    private lateinit var chart: ChartView
    private lateinit var tariffField: EditText

    private fun device() = store.getDevices().find { it.id == deviceId }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        store = DeviceStore(this)
        deviceId = intent.getStringExtra("DEVICE_ID")
        val c = scaffold("Energy & usage")

        val totals = glassCard(pad = 20).apply { orientation = LinearLayout.HORIZONTAL }
        kwhTxt = bigStat("—", "kWh · 30d")
        costTxt = bigStat("—", "Cost · 30d")
        totals.addView(wrapStat(kwhTxt, "kWh · 30 days"), LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        totals.addView(wrapStat(costTxt, "Cost · 30 days"), LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        c.addView(totals)

        c.addView(sectionLabel("Daily consumption"))
        val chartCard = glassCard()
        chart = ChartView(this)
        chartCard.addView(chart, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(160)))
        c.addView(chartCard)

        c.addView(sectionLabel("Tariff"))
        val tcard = glassCard()
        tariffField = inputField("₹ per kWh").apply { inputType = android.text.InputType.TYPE_CLASS_NUMBER or android.text.InputType.TYPE_NUMBER_FLAG_DECIMAL }
        tcard.addView(tariffField)
        tcard.addView(primaryBtn("Save tariff") { saveTariff() })
        c.addView(tcard)

        load()
    }

    private fun bigStat(value: String, @Suppress("UNUSED_PARAMETER") cap: String) = TextView(this).apply {
        text = value; setTextColor(col(R.color.moondust_text_primary)); textSize = 26f
        setTypeface(typeface, android.graphics.Typeface.BOLD); gravity = Gravity.CENTER
    }
    private fun wrapStat(value: TextView, cap: String): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL; gravity = Gravity.CENTER
        addView(value)
        addView(TextView(this@EnergyActivity).apply {
            text = cap; setTextColor(col(R.color.moondust_text_secondary)); textSize = 12f; gravity = Gravity.CENTER
        })
    }

    private fun load() {
        lifecycleScope.launch {
            val d = device() ?: return@launch
            val j = DeviceApi.energy(d)
            if (j == null) { flash("Couldn't load energy data", ok = false); return@launch }
            tariffField.setText(String.format(Locale.US, "%.2f", j.optDouble("tariff", 6.5)))
            val days = j.optJSONArray("days")
            var kwh = 0.0; var cost = 0.0
            val series = ArrayList<Float>()
            if (days != null) for (i in 0 until days.length()) {
                val o = days.getJSONObject(i)
                kwh += o.optDouble("kwh", 0.0); cost += o.optDouble("cost", 0.0)
                series.add(o.optDouble("kwh", 0.0).toFloat())
            }
            kwhTxt.text = String.format(Locale.US, "%.2f", kwh)
            costTxt.text = String.format(Locale.US, "₹%.0f", cost)
            chart.setData(series)
        }
    }

    private fun saveTariff() {
        val t = tariffField.text.toString().toDoubleOrNull() ?: run { flash("Enter a number", ok = false); return }
        lifecycleScope.launch {
            val d = device() ?: return@launch
            flash(if (DeviceApi.setTariff(d, t)) "Tariff saved" else "Save failed", ok = true)
            load()
        }
    }

    /** Minimal area+line chart for the daily kWh series. */
    class ChartView(ctx: Context) : View(ctx) {
        private var data: List<Float> = emptyList()
        private val dens = resources.displayMetrics.density
        private val line = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.parseColor("#22E8E0"); style = Paint.Style.STROKE
            strokeWidth = 2f * dens; strokeJoin = Paint.Join.ROUND; strokeCap = Paint.Cap.ROUND
        }
        private val fill = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.FILL }
        private val grid = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.parseColor("#1AFFFFFF"); strokeWidth = 1f
        }
        private val empty = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = Color.parseColor("#8B9AA8"); textSize = 13f * dens }

        fun setData(d: List<Float>) { data = d; invalidate() }

        override fun onDraw(canvas: Canvas) {
            val w = width.toFloat(); val h = height.toFloat(); val pad = 10f * dens
            for (g in 0..3) { val y = pad + (h - 2 * pad) * g / 3f; canvas.drawLine(pad, y, w - pad, y, grid) }
            if (data.isEmpty()) { canvas.drawText("No data yet", pad, h / 2, empty); return }
            val max = (data.maxOrNull() ?: 0f).coerceAtLeast(0.001f)
            val n = data.size
            fun x(i: Int) = pad + (w - 2 * pad) * (if (n < 2) 0.5f else i.toFloat() / (n - 1))
            fun y(v: Float) = h - pad - (h - 2 * pad) * (v / max)
            val path = Path(); val area = Path()
            data.forEachIndexed { i, v ->
                if (i == 0) { path.moveTo(x(i), y(v)); area.moveTo(x(i), h - pad); area.lineTo(x(i), y(v)) }
                else { path.lineTo(x(i), y(v)); area.lineTo(x(i), y(v)) }
            }
            area.lineTo(x(n - 1), h - pad); area.close()
            fill.shader = LinearGradient(0f, pad, 0f, h - pad,
                Color.parseColor("#5522E8E0"), Color.parseColor("#0022E8E0"), Shader.TileMode.CLAMP)
            canvas.drawPath(area, fill)
            canvas.drawPath(path, line)
        }
    }
}
