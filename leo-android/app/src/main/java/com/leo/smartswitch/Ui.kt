package com.leo.smartswitch

import android.content.Context
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.Typeface
import android.text.InputType
import android.text.TextUtils
import android.view.Gravity
import android.view.ViewGroup
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import androidx.core.content.ContextCompat
import com.google.android.material.button.MaterialButton

/* ---- Glass/3D design-language builders (top-level Context extensions) ---- */

fun Context.dp(v: Int): Int = (v * resources.displayMetrics.density).toInt()
fun Context.col(id: Int): Int = ContextCompat.getColor(this, id)
private fun Context.lpMW() =
    LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)

/** A frosted glass card (vertical container) with soft elevation for depth. */
fun Context.glassCard(pad: Int = 20, accent: Boolean = false): LinearLayout =
    LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        background = ContextCompat.getDrawable(this@glassCard,
            if (accent) R.drawable.glass_card_on else R.drawable.glass_card)
        elevation = dp(10).toFloat()
        setPadding(dp(pad), dp(pad), dp(pad), dp(pad))
        layoutParams = lpMW().apply { bottomMargin = dp(14) }
    }

fun Context.sectionLabel(text: String): TextView = TextView(this).apply {
    this.text = text.uppercase()
    setTextColor(col(R.color.moondust_text_secondary))
    textSize = 11.5f
    letterSpacing = 0.12f
    setTypeface(typeface, Typeface.BOLD)
    layoutParams = lpMW().apply { topMargin = dp(6); bottomMargin = dp(10) }
}

fun Context.titleText(text: String, size: Float = 22f): TextView = TextView(this).apply {
    this.text = text
    setTextColor(col(R.color.moondust_text_primary))
    textSize = size
    setTypeface(typeface, Typeface.BOLD)
}

fun Context.body(text: String, secondary: Boolean = true, size: Float = 13.5f): TextView =
    TextView(this).apply {
        this.text = text
        setTextColor(col(if (secondary) R.color.moondust_text_secondary else R.color.moondust_text_primary))
        textSize = size
        layoutParams = lpMW()
    }

private fun MaterialButton.flatten() {
    stateListAnimator = null
    insetTop = 0; insetBottom = 0; minHeight = 0; minimumHeight = 0
}

fun Context.primaryBtn(text: String, onClick: () -> Unit): MaterialButton =
    MaterialButton(this).apply {
        this.text = text; isAllCaps = false; textSize = 15f
        setTypeface(typeface, Typeface.BOLD)
        cornerRadius = dp(18)
        backgroundTintList = ColorStateList.valueOf(col(R.color.moondust_accent))
        setTextColor(col(R.color.on_accent_text))
        flatten(); setPadding(dp(16), dp(14), dp(16), dp(14))
        layoutParams = lpMW().apply { topMargin = dp(6) }
        Anim.pressable(this)
        setOnClickListener { onClick() }
    }

fun Context.ghostBtn(text: String, onClick: () -> Unit): MaterialButton =
    MaterialButton(this).apply {
        this.text = text; isAllCaps = false; textSize = 14f
        cornerRadius = dp(18)
        backgroundTintList = ColorStateList.valueOf(Color.parseColor("#14FFFFFF"))
        setTextColor(col(R.color.moondust_text_primary))
        strokeColor = ColorStateList.valueOf(col(R.color.glass_stroke))
        strokeWidth = dp(1)
        flatten(); setPadding(dp(16), dp(13), dp(16), dp(13))
        layoutParams = lpMW().apply { topMargin = dp(8) }
        Anim.pressable(this)
        setOnClickListener { onClick() }
    }

fun Context.inputField(hint: String, password: Boolean = false): EditText = EditText(this).apply {
    this.hint = hint
    setHintTextColor(col(R.color.moondust_text_secondary))
    setTextColor(col(R.color.moondust_text_primary))
    textSize = 15f
    background = ContextCompat.getDrawable(this@inputField, R.drawable.field_bg)
    setPadding(dp(14), dp(13), dp(14), dp(13))
    inputType = if (password) (InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD)
                else InputType.TYPE_CLASS_TEXT
    layoutParams = lpMW().apply { topMargin = dp(8) }
}

/** key/value row; returns (row, valueView) so callers can update the value live. */
fun Context.kvRow(key: String, value: String = "—"): Pair<LinearLayout, TextView> {
    val row = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        layoutParams = lpMW().apply { topMargin = dp(7); bottomMargin = dp(7) }
    }
    val k = TextView(this).apply {
        text = key; setTextColor(col(R.color.moondust_text_secondary)); textSize = 13f
        layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
    }
    val v = TextView(this).apply {
        text = value; setTextColor(col(R.color.moondust_text_primary)); textSize = 13f
        setTypeface(typeface, Typeface.BOLD); maxLines = 1; ellipsize = TextUtils.TruncateAt.END
    }
    row.addView(k); row.addView(v)
    return row to v
}

/** Segmented control; onSelect gives the chosen index. */
fun Context.segmented(options: List<String>, selected: Int, onSelect: (Int) -> Unit): LinearLayout {
    val row = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        layoutParams = lpMW().apply { topMargin = dp(8) }
    }
    val btns = ArrayList<MaterialButton>()
    fun paint(sel: Int) {
        btns.forEachIndexed { i, b ->
            val on = i == sel
            b.backgroundTintList = ColorStateList.valueOf(
                if (on) col(R.color.moondust_accent) else Color.parseColor("#14FFFFFF"))
            b.setTextColor(if (on) col(R.color.on_accent_text) else col(R.color.moondust_text_secondary))
        }
    }
    options.forEachIndexed { i, label ->
        val b = MaterialButton(this).apply {
            text = label; isAllCaps = false; textSize = 13f
            cornerRadius = dp(14); flatten()
            setPadding(dp(6), dp(12), dp(6), dp(12))
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
                marginStart = if (i == 0) 0 else dp(6)
            }
            setOnClickListener { paint(i); onSelect(i) }
        }
        btns.add(b); row.addView(b)
    }
    paint(selected)
    return row
}
