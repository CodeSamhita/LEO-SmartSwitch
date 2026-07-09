package com.leo.smartswitch

import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import java.util.concurrent.TimeUnit

/** Live mirror of the device's Serial.println() debug output, streamed over
 *  the firmware's /console WebSocket - the same lines a USB serial monitor
 *  would show, but reachable over WiFi. */
class ConsoleActivity : GlassActivity() {

    private lateinit var store: DeviceStore
    private var deviceId: String? = null
    private lateinit var consoleText: TextView
    private lateinit var consoleScroll: ScrollView

    private val client = OkHttpClient.Builder()
        .pingInterval(20, TimeUnit.SECONDS)
        .readTimeout(0, TimeUnit.MILLISECONDS)   // never time out a live stream
        .build()
    private var socket: WebSocket? = null
    private var wanted = false
    private val lines = ArrayDeque<String>()
    private val maxLines = 500

    private fun device() = store.getDevices().find { it.id == deviceId }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        store = DeviceStore(this)
        deviceId = intent.getStringExtra("DEVICE_ID")
        val c = scaffold("Live console")

        c.addView(body("Mirrors the device's debug output in real time — handy for diagnosing WiFi/mDNS issues without a USB cable."))

        val card = glassCard(pad = 0)
        consoleScroll = ScrollView(this).apply {
            overScrollMode = View.OVER_SCROLL_NEVER
            isVerticalScrollBarEnabled = false
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(420))
        }
        consoleText = TextView(this).apply {
            setTextColor(Color.parseColor("#A9B7C2"))
            textSize = 11.5f
            typeface = Typeface.MONOSPACE
            setPadding(dp(14), dp(12), dp(14), dp(12))
            text = "Connecting…"
        }
        consoleScroll.addView(consoleText)
        card.addView(consoleScroll)
        c.addView(card)

        val btnRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        btnRow.addView(ghostBtn("Clear") { lines.clear(); consoleText.text = "" },
            LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { marginEnd = dp(6) })
        btnRow.addView(ghostBtn("Reconnect") { connect() },
            LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { marginStart = dp(6) })
        c.addView(btnRow)

        connect()
    }

    private fun connect() {
        val d = device() ?: return
        wanted = true
        socket?.close(1000, null)
        consoleText.text = "Connecting…"
        val url = d.baseUrl().replace("http://", "ws://") + "/console"
        val request = Request.Builder().url(url)
            .apply { d.token?.let { addHeader("X-Auth-Token", it) } }
            .build()
        socket = client.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                runOnUiThread { lines.clear(); consoleText.text = "" }
            }
            override fun onMessage(webSocket: WebSocket, text: String) {
                runOnUiThread { append(text) }
            }
            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                if (!wanted) return
                runOnUiThread { append("— disconnected, retrying —") }
                consoleText.postDelayed({ if (wanted) connect() }, 3000)
            }
            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {}
        })
    }

    private fun append(line: String) {
        lines.addLast(line)
        while (lines.size > maxLines) lines.removeFirst()
        consoleText.text = lines.joinToString("\n")
        consoleScroll.post { consoleScroll.fullScroll(View.FOCUS_DOWN) }
    }

    override fun onDestroy() {
        super.onDestroy()
        wanted = false
        socket?.close(1000, "leaving")
    }
}
