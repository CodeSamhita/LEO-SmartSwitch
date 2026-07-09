package com.leo.smartswitch

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

data class Relay(val name: String, val gpio: Int, val on: Boolean, val watts: Double = 0.0)

data class DeviceState(
    val id: String,
    val name: String,
    val online: Boolean,
    val ip: String,
    val conn: String,
    val relays: List<Relay>,
    val uptime: String = "",
    val totalWatts: Double = 0.0,
    val version: String = "1.0.0",
    val model: String = "LEO-C3",
    val tariff: Double = 6.50
)

/** Local representation of a device saved by the user. */
data class SavedDevice(
    val id: String,
    val host: String,
    val port: Int,
    val name: String,
    val token: String? = null,
    val cachedRelays: String? = null
) {
    fun baseUrl() = "http://$host:$port"
}

/** Thin client over the LEO firmware REST API (org.json, no extra deps). */
object DeviceApi {

    /** Parse a firmware /state or /ws JSON payload into a DeviceState.
     *  [forceId] keeps the id aligned with the locally-saved device id so that
     *  live updates always match the right card. */
    fun parseState(o: JSONObject, fallbackBase: String, forceId: String? = null): DeviceState {
        val arr = o.getJSONArray("relays")
        var onLoad = 0.0
        val relays = (0 until arr.length()).map { i ->
            val r = arr.getJSONObject(i)
            val w = r.optDouble("watts", 0.0)
            val on = r.optBoolean("on")
            if (on) onLoad += w                 // only energized relays draw power
            Relay(
                name = r.optString("name", "Relay ${i + 1}"),
                gpio = r.optInt("gpio", -1),
                on = on,
                watts = w
            )
        }
        return DeviceState(
            id = forceId ?: o.optString("id", o.optString("ip", fallbackBase)),
            name = o.optString("name", "LEO Smart Switch"),
            online = o.optString("conn") == "WIFI",
            ip = o.optString("ip", ""),
            conn = o.optString("conn", "AP"),
            relays = relays,
            uptime = formatUptime(o.optLong("uptime", 0L)),
            totalWatts = o.optDouble("total_watts", onLoad),
            version = o.optString("version", "1.0.0"),
            model = o.optString("model", "LEO-C3"),
            tariff = o.optDouble("tariff", 6.50)
        )
    }

    fun formatUptime(seconds: Long): String {
        if (seconds <= 0) return "—"
        val d = seconds / 86400
        val h = (seconds % 86400) / 3600
        val m = (seconds % 3600) / 60
        return when {
            d > 0 -> "${d}d ${h}h"
            h > 0 -> "${h}h ${m}m"
            else -> "${m}m"
        }
    }

    private fun open(urlStr: String, method: String, token: String?): HttpURLConnection {
        val c = (URL(urlStr).openConnection() as HttpURLConnection)
        c.requestMethod = method
        c.connectTimeout = 1500
        c.readTimeout = 1500
        token?.let { c.setRequestProperty("X-Auth-Token", it) }
        if (method == "POST") {
            c.doOutput = true
            c.setRequestProperty("Content-Type", "application/json")
        }
        return c
    }

    private fun post(base: String, path: String, body: String, token: String?): Int =
        runCatching {
            val c = open("$base$path", "POST", token)
            c.outputStream.use { it.write(body.toByteArray()) }
            val code = c.responseCode
            c.disconnect()
            code
        }.getOrDefault(-1)

    /** Fetch state for a saved device (id stays aligned with the saved device). */
    suspend fun state(device: SavedDevice): DeviceState? =
        state(device.baseUrl(), device.token, device.id)

    suspend fun state(base: String, token: String?, forceId: String? = null): DeviceState? =
        withContext(Dispatchers.IO) {
            runCatching {
                val c = open("$base/api/state", "GET", token)
                val txt = c.inputStream.bufferedReader().use { it.readText() }
                c.disconnect()
                parseState(JSONObject(txt), base, forceId)
            }.getOrNull()
        }

    suspend fun setRelay(base: String, token: String?, index: Int, on: Boolean): Boolean =
        withContext(Dispatchers.IO) {
            post(base, "/api/relay", JSONObject().put("i", index).put("on", on).toString(), token) in 200..299
        }

    suspend fun setAll(base: String, token: String?, on: Boolean): Boolean =
        withContext(Dispatchers.IO) {
            post(base, "/api/all", JSONObject().put("on", on).toString(), token) in 200..299
        }

    /** Returns a token on success, null otherwise. */
    suspend fun login(base: String, user: String, pass: String): String? =
        withContext(Dispatchers.IO) {
            runCatching {
                val c = open("$base/api/login", "POST", null)
                c.outputStream.use {
                    it.write(JSONObject().put("user", user).put("pass", pass).toString().toByteArray())
                }
                if (c.responseCode !in 200..299) { c.disconnect(); return@runCatching null }
                val txt = c.inputStream.bufferedReader().use { it.readText() }
                c.disconnect()
                JSONObject(txt).optString("token").ifEmpty { null }
            }.getOrNull()
        }

    /* ---- generic helpers for the dedicated screens ---- */
    suspend fun getJson(d: SavedDevice, path: String): JSONObject? =
        withContext(Dispatchers.IO) {
            runCatching {
                val c = open(d.baseUrl() + path, "GET", d.token)
                val t = c.inputStream.bufferedReader().use { it.readText() }
                c.disconnect(); JSONObject(t)
            }.getOrNull()
        }

    suspend fun postJson(d: SavedDevice, path: String, body: JSONObject): Boolean =
        withContext(Dispatchers.IO) { post(d.baseUrl(), path, body.toString(), d.token) in 200..299 }

    suspend fun identity(d: SavedDevice): JSONObject? = getJson(d, "/api/identity")
    suspend fun energy(d: SavedDevice): JSONObject? = getJson(d, "/api/energy")
    suspend fun ledGet(d: SavedDevice): JSONObject? = getJson(d, "/api/led")
    suspend fun timeGet(d: SavedDevice): JSONObject? = getJson(d, "/api/timecfg")
    suspend fun relayMapGet(d: SavedDevice): JSONObject? = getJson(d, "/api/relaymap")

    suspend fun setLed(d: SavedDevice, mode: String, brightness: Int, timeout: Int): Boolean =
        postJson(d, "/api/led", JSONObject().put("mode", mode).put("brightness", brightness).put("timeout", timeout))
    suspend fun identify(d: SavedDevice): Boolean =
        withContext(Dispatchers.IO) { post(d.baseUrl(), "/api/led/identify", "{}", d.token) in 200..299 }
    suspend fun setRole(d: SavedDevice, role: String): Boolean =
        postJson(d, "/api/role", JSONObject().put("role", role))
    suspend fun setName(d: SavedDevice, name: String): Boolean =
        postJson(d, "/api/devicename", JSONObject().put("name", name))
    suspend fun setMdns(d: SavedDevice, host: String): Boolean =
        postJson(d, "/api/mdns", JSONObject().put("mdns", host))
    suspend fun setTariff(d: SavedDevice, tariff: Double): Boolean =
        postJson(d, "/api/tariff", JSONObject().put("tariff", tariff))
    suspend fun joinWifi(d: SavedDevice, ssid: String, pass: String): Boolean =
        postJson(d, "/api/network", JSONObject().put("ssid", ssid).put("pass", pass))
    suspend fun setAp(d: SavedDevice, ssid: String, pass: String): Boolean =
        postJson(d, "/api/ap", JSONObject().put("ssid", ssid).put("pass", pass))
    suspend fun setRelayMap(d: SavedDevice, relays: org.json.JSONArray): Boolean =
        postJson(d, "/api/relaymap/set", JSONObject().put("relays", relays))

    /** Poll /api/scan (returns 202 while scanning) and return the net list JSON. */
    suspend fun scan(d: SavedDevice): JSONObject? = withContext(Dispatchers.IO) {
        for (i in 0 until 8) {
            val c = runCatching { open(d.baseUrl() + "/api/scan", "GET", d.token) }.getOrNull() ?: return@withContext null
            val code = runCatching { c.responseCode }.getOrDefault(-1)
            if (code == 202) { runCatching { c.disconnect() }; kotlinx.coroutines.delay(1200); continue }
            val t = runCatching { c.inputStream.bufferedReader().use { it.readText() } }.getOrNull()
            runCatching { c.disconnect() }
            return@withContext t?.let { runCatching { JSONObject(it) }.getOrNull() }
        }
        null
    }
}
