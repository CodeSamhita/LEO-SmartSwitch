package com.leo.smartswitch

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.launch
import okhttp3.*
import org.json.JSONObject
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

/** Manages real-time WebSocket telemetry from LEO devices, with auto-reconnect. */
object LiveManager {
    private val client = OkHttpClient.Builder()
        .pingInterval(20, TimeUnit.SECONDS)         // keep NAT/router mappings alive
        .readTimeout(0, TimeUnit.MILLISECONDS)      // never time out the stream
        .build()

    private val scope = CoroutineScope(SupervisorJob())
    private val sockets = ConcurrentHashMap<String, WebSocket>()
    private val wanted = ConcurrentHashMap<String, SavedDevice>()  // devices we want connected

    private val _updates = MutableSharedFlow<DeviceState>(
        extraBufferCapacity = 64,
        onBufferOverflow = BufferOverflow.DROP_OLDEST
    )
    val updates: SharedFlow<DeviceState> = _updates

    fun connect(device: SavedDevice) {
        val prev = wanted.put(device.id, device)
        // re-open if the host/port/token changed (e.g. after logging in)
        if (prev != null && (prev.baseUrl() != device.baseUrl() || prev.token != device.token)) {
            sockets.remove(device.id)?.close(1000, "reconfigure")
        }
        openSocket(device)
    }

    @Synchronized
    private fun openSocket(device: SavedDevice) {
        if (sockets.containsKey(device.id)) return
        val url = device.baseUrl().replace("http://", "ws://") + "/ws"
        val request = Request.Builder()
            .url(url)
            .apply { device.token?.let { addHeader("X-Auth-Token", it) } }
            .build()

        val socket = client.newWebSocket(request, object : WebSocketListener() {
            override fun onMessage(webSocket: WebSocket, text: String) {
                runCatching {
                    val state = DeviceApi.parseState(JSONObject(text), device.baseUrl(), forceId = device.id)
                    _updates.tryEmit(state.copy(online = true, name = state.name.ifEmpty { device.name }))
                }
            }

            // remove(key, value): only drop the map entry if it is still THIS
            // socket - a late callback from an old socket used to remove the
            // newer replacement, leaving a live socket nobody could close.
            // A server-side close (device reboot, firmware dropping a slow
            // client) also reconnects now; previously only onFailure did, so
            // live updates silently stopped until the screen was reopened.
            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                webSocket.close(1000, null)
                if (sockets.remove(device.id, webSocket)) scheduleReconnect(device.id)
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                if (sockets.remove(device.id, webSocket)) scheduleReconnect(device.id)
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                if (sockets.remove(device.id, webSocket)) scheduleReconnect(device.id)
            }
        })
        sockets[device.id] = socket
    }

    private fun scheduleReconnect(id: String) {
        scope.launch {
            delay(3000)
            val d = wanted[id] ?: return@launch     // user removed it -> stop retrying
            openSocket(d)
        }
    }

    fun disconnect(id: String) {
        wanted.remove(id)
        sockets.remove(id)?.close(1000, "User disconnect")
    }

    fun disconnectAll() {
        wanted.clear()
        sockets.keys.toList().forEach { sockets.remove(it)?.close(1000, "stop") }
    }
}
