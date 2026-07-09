package com.leo.smartswitch

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/** Manages multiple saved devices in SharedPreferences. */
class DeviceStore(context: Context) {
    private val sp = context.applicationContext
        .getSharedPreferences("leo_multi", Context.MODE_PRIVATE)

    fun getDevices(): List<SavedDevice> {
        val s = sp.getString("devices", null) ?: return emptyList()
        return runCatching {
            val a = JSONArray(s)
            (0 until a.length()).map { i ->
                val o = a.getJSONObject(i)
                SavedDevice(
                    id = o.getString("id"),
                    host = o.getString("host"),
                    port = o.getInt("port"),
                    name = o.getString("name"),
                    // isNull() first: a JSONObject.put(key, null) can round-trip
                    // through org.json as either a missing key or a literal JSON
                    // null depending on version, and optString() on a JSON null
                    // can return the 4-character string "null" rather than "" -
                    // which ifEmpty{null} would NOT catch, silently turning a
                    // device with no login configured into one sending a literal
                    // "X-Auth-Token: null" header on every request.
                    token = if (o.isNull("token")) null else o.optString("token").ifEmpty { null },
                    cachedRelays = if (o.isNull("relays")) null else o.optString("relays").ifEmpty { null }
                )
            }
        }.getOrDefault(emptyList())
    }

    fun saveDevices(devices: List<SavedDevice>) {
        val a = JSONArray()
        devices.forEach { d ->
            val o = JSONObject()
                .put("id", d.id)
                .put("host", d.host)
                .put("port", d.port)
                .put("name", d.name)
                .put("token", d.token)
                .put("relays", d.cachedRelays)
            a.put(o)
        }
        sp.edit().putString("devices", a.toString()).apply()
    }

    fun addDevice(d: SavedDevice) {
        val list = getDevices().toMutableList()
        val existing = list.indexOfFirst { it.id == d.id || (it.host == d.host && it.port == d.port) }
        if (existing >= 0) list[existing] = d else list.add(d)
        saveDevices(list)
    }

    fun removeDevice(id: String) {
        val list = getDevices().filter { it.id != id }
        saveDevices(list)
    }

    fun updateDevice(d: SavedDevice) {
        addDevice(d) // same logic
    }
}
