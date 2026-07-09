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
                    token = o.optString("token").ifEmpty { null },
                    cachedRelays = o.optString("relays").ifEmpty { null }
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
