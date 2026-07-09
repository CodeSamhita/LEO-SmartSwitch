package com.leo.smartswitch

import android.animation.ArgbEvaluator
import android.animation.ObjectAnimator
import android.animation.ValueAnimator
import android.annotation.SuppressLint
import android.content.res.ColorStateList
import android.graphics.LinearGradient
import android.graphics.Shader
import android.view.MotionEvent
import android.view.View
import android.view.animation.AccelerateDecelerateInterpolator
import android.view.animation.DecelerateInterpolator
import android.view.animation.OvershootInterpolator
import android.widget.TextView
import androidx.core.view.ViewCompat
import java.util.WeakHashMap

/** Lightweight motion helpers — springy, 3D-ish feedback used across the app. */
object Anim {
    private val lastVal = WeakHashMap<TextView, Float>()

    /** Press feedback: scale down on touch, spring back — keeps the click working. */
    @SuppressLint("ClickableViewAccessibility")
    fun pressable(v: View, scale: Float = 0.96f) {
        v.setOnTouchListener { view, ev ->
            when (ev.actionMasked) {
                MotionEvent.ACTION_DOWN ->
                    view.animate().scaleX(scale).scaleY(scale).setDuration(110)
                        .setInterpolator(DecelerateInterpolator()).start()
                MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL ->
                    view.animate().scaleX(1f).scaleY(1f).setDuration(180)
                        .setInterpolator(OvershootInterpolator(2.4f)).start()
            }
            false
        }
    }

    /** Staggered entrance: fade + rise + scale. */
    fun entrance(v: View, index: Int) {
        v.alpha = 0f; v.translationY = 46f; v.scaleX = 0.95f; v.scaleY = 0.95f
        v.animate().alpha(1f).translationY(0f).scaleX(1f).scaleY(1f)
            .setStartDelay(50L + index * 70L).setDuration(440)
            .setInterpolator(DecelerateInterpolator(1.5f)).start()
    }

    /** Gentle infinite pulse (live status dot). */
    fun pulse(v: View) {
        ObjectAnimator.ofFloat(v, "scaleX", 1f, 1.7f).apply {
            duration = 1100; repeatCount = ValueAnimator.INFINITE; repeatMode = ValueAnimator.REVERSE; start()
        }
        ObjectAnimator.ofFloat(v, "scaleY", 1f, 1.7f).apply {
            duration = 1100; repeatCount = ValueAnimator.INFINITE; repeatMode = ValueAnimator.REVERSE; start()
        }
        ObjectAnimator.ofFloat(v, "alpha", 1f, 0.45f).apply {
            duration = 1100; repeatCount = ValueAnimator.INFINITE; repeatMode = ValueAnimator.REVERSE; start()
        }
    }

    fun stop(v: View) { v.clearAnimation(); v.animate().cancel(); v.scaleX = 1f; v.scaleY = 1f; v.alpha = 1f }

    /** Animate a numeric readout from its previous value to [target]. */
    fun countTo(tv: TextView, target: Float, fmt: (Float) -> String) {
        val from = lastVal[tv] ?: target.let { if (it == 0f) 0f else 0f }
        lastVal[tv] = target
        ValueAnimator.ofFloat(from, target).apply {
            duration = 650; interpolator = DecelerateInterpolator()
            addUpdateListener { tv.text = fmt(it.animatedValue as Float) }
            start()
        }
    }

    /** Animate any view's background tint between two ARGB colors. */
    fun tintTo(v: View, from: Int, to: Int, dur: Long = 280) {
        ValueAnimator.ofObject(ArgbEvaluator(), from, to).apply {
            duration = dur
            addUpdateListener { ViewCompat.setBackgroundTintList(v, ColorStateList.valueOf(it.animatedValue as Int)) }
            start()
        }
    }

    /** Quick squash-and-spring bounce. */
    fun bounce(v: View) {
        v.animate().scaleX(1.12f).scaleY(1.12f).setDuration(120).withEndAction {
            v.animate().scaleX(1f).scaleY(1f).setDuration(200).setInterpolator(OvershootInterpolator(3.5f)).start()
        }.start()
    }

    /** Slow infinite drift — used to make the background orbs feel alive. */
    fun floatOrb(v: View, dx: Float, dy: Float, dur: Long) {
        ObjectAnimator.ofFloat(v, "translationX", 0f, dx).apply {
            duration = dur; repeatCount = ValueAnimator.INFINITE; repeatMode = ValueAnimator.REVERSE
            interpolator = AccelerateDecelerateInterpolator(); start()
        }
        ObjectAnimator.ofFloat(v, "translationY", 0f, dy).apply {
            duration = (dur * 1.35).toLong(); repeatCount = ValueAnimator.INFINITE; repeatMode = ValueAnimator.REVERSE
            interpolator = AccelerateDecelerateInterpolator(); start()
        }
        ObjectAnimator.ofFloat(v, "scaleX", 1f, 1.18f).apply {
            duration = (dur * 1.7).toLong(); repeatCount = ValueAnimator.INFINITE; repeatMode = ValueAnimator.REVERSE; start()
        }
        ObjectAnimator.ofFloat(v, "scaleY", 1f, 1.18f).apply {
            duration = (dur * 1.7).toLong(); repeatCount = ValueAnimator.INFINITE; repeatMode = ValueAnimator.REVERSE; start()
        }
    }

    /** Paint a horizontal gradient across a TextView's glyphs. */
    fun gradientText(tv: TextView, c0: Int, c1: Int) {
        tv.post {
            val w = (if (tv.width > 0) tv.width else tv.paint.measureText(tv.text.toString()).toInt()).toFloat()
            if (w <= 0f) return@post
            tv.paint.shader = LinearGradient(0f, 0f, w, 0f, c0, c1, Shader.TileMode.CLAMP)
            tv.invalidate()
        }
    }
}
