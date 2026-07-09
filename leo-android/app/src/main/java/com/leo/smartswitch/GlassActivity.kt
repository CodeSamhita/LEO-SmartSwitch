package com.leo.smartswitch

import android.graphics.Color
import android.graphics.RenderEffect
import android.graphics.Shader
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat

/** Shared glass/3D shell: gradient backdrop, blurred glow orbs, edge-to-edge
 *  insets, a scaffold (top bar + scroll column) and a floating notifier. */
open class GlassActivity : AppCompatActivity() {

    protected lateinit var rootFrame: FrameLayout
    private var topInset = 0
    private var toast: View? = null

    /** Build a screen. Returns the scrollable content column for adding cards. */
    protected fun scaffold(title: String?, showBack: Boolean = true): LinearLayout {
        WindowCompat.setDecorFitsSystemWindows(window, false)

        rootFrame = FrameLayout(this).apply {
            background = ContextCompat.getDrawable(this@GlassActivity, R.drawable.bg_app)
        }
        // soft glowing orbs behind the glass (real blur on API 31+), gently drifting
        val o1 = orb(Color.parseColor("#5522E8E0"), dp(360), dp(-110), dp(-150))
        val o2 = orb(Color.parseColor("#3D6E7BFF"), dp(440), dp(150), dp(520))
        val o3 = orb(Color.parseColor("#33E86AD0"), dp(320), dp(-80), dp(300))
        rootFrame.addView(o1); rootFrame.addView(o2); rootFrame.addView(o3)
        Anim.floatOrb(o1, dp(60).toFloat(), dp(40).toFloat(), 7000)
        Anim.floatOrb(o2, dp(-50).toFloat(), dp(-70).toFloat(), 9000)
        Anim.floatOrb(o3, dp(70).toFloat(), dp(-30).toFloat(), 8000)

        // Side margin scales with the device via values-w600dp / values-w840dp
        // (18dp phones, 32dp large/foldables, 64dp tablets) so cards don't
        // stretch edge-to-edge on wide screens. These resources previously
        // existed but were never referenced anywhere.
        val margin = resources.getDimensionPixelSize(R.dimen.screen_margin)

        val column = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }

        val bar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(margin, dp(10), margin, dp(10))
        }
        if (showBack) bar.addView(ImageView(this).apply {
            setImageResource(R.drawable.ic_back)
            val s = dp(40)
            layoutParams = LinearLayout.LayoutParams(s, s).apply { marginEnd = dp(6) }
            setPadding(dp(8), dp(8), dp(8), dp(8))
            isClickable = true
            background = rippleCircle()
            setOnClickListener { finish() }
        })
        if (title != null) bar.addView(titleText(title, 21f))
        column.addView(bar)

        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(margin, dp(6), margin, dp(28))
        }
        val scroll = ScrollView(this).apply {
            overScrollMode = View.OVER_SCROLL_NEVER
            isVerticalScrollBarEnabled = false
            addView(content)
        }
        column.addView(scroll, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))

        rootFrame.addView(column)
        setContentView(rootFrame)

        ViewCompat.setOnApplyWindowInsetsListener(rootFrame) { _, insets ->
            val sb = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            topInset = sb.top
            bar.setPadding(margin, dp(10) + sb.top, margin, dp(10))
            content.setPadding(margin, dp(6), margin, dp(28) + sb.bottom)
            insets
        }
        return content
    }

    private fun orb(centerColor: Int, sizePx: Int, leftPx: Int, topPx: Int): View {
        val gd = GradientDrawable().apply {
            shape = GradientDrawable.OVAL
            gradientType = GradientDrawable.RADIAL_GRADIENT
            gradientRadius = sizePx / 2f
            colors = intArrayOf(centerColor, Color.TRANSPARENT)
        }
        return View(this).apply {
            background = gd
            layoutParams = FrameLayout.LayoutParams(sizePx, sizePx).apply {
                leftMargin = leftPx; topMargin = topPx
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                setRenderEffect(RenderEffect.createBlurEffect(70f, 70f, Shader.TileMode.DECAL))
            }
        }
    }

    private fun rippleCircle(): android.graphics.drawable.Drawable {
        val mask = GradientDrawable().apply { shape = GradientDrawable.OVAL; setColor(Color.WHITE) }
        return android.graphics.drawable.RippleDrawable(
            android.content.res.ColorStateList.valueOf(Color.parseColor("#33FFFFFF")), null, mask)
    }

    /** Floating notification (top, glass pill, auto-dismiss) — success or error. */
    protected fun flash(message: String, ok: Boolean = true) {
        runOnUiThread {
            toast?.let { rootFrame.removeView(it) }
            val pill = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                background = ContextCompat.getDrawable(this@GlassActivity, R.drawable.toast_glass)
                elevation = dp(18).toFloat()
                setPadding(dp(16), dp(13), dp(18), dp(13))
            }
            val dotColor = if (ok) col(R.color.moondust_good) else col(R.color.moondust_danger)
            pill.addView(View(this).apply {
                background = GradientDrawable().apply { shape = GradientDrawable.OVAL; setColor(dotColor) }
                layoutParams = LinearLayout.LayoutParams(dp(9), dp(9)).apply { marginEnd = dp(11) }
            })
            pill.addView(TextView(this).apply {
                text = message
                setTextColor(col(R.color.moondust_text_primary))
                textSize = 13.5f
                maxWidth = dp(280)
            })
            pill.layoutParams = FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                gravity = Gravity.TOP or Gravity.CENTER_HORIZONTAL
                topMargin = topInset + dp(12)
                leftMargin = dp(20); rightMargin = dp(20)
            }
            rootFrame.addView(pill)
            toast = pill
            pill.alpha = 0f
            pill.translationY = -dp(24).toFloat()
            pill.animate().alpha(1f).translationY(0f).setDuration(220).start()
            pill.postDelayed({
                pill.animate().alpha(0f).translationY(-dp(24).toFloat()).setDuration(200)
                    .withEndAction { rootFrame.removeView(pill); if (toast === pill) toast = null }
                    .start()
            }, 2600)
        }
    }
}
