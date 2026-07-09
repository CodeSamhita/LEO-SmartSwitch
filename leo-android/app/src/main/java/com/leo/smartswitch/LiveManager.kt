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
        wanted[device.id] = device
        openSocket(device)
    }

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

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                webSocket.close(1000, null)
                sockets.remove(device.id)
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                sockets.remove(device.id)
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                sockets.remove(device.id)
                scheduleReconnect(device.id)
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
