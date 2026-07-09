package com.leo.smartswitch

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.net.wifi.WifiManager
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

data class Found(val host: String, val port: Int, val name: String)

/** Discovers devices on the LAN via their dedicated `_leoswitch._tcp` service. */
class Discovery(context: Context) {
    private val appCtx = context.applicationContext
    private val nsd = appCtx.getSystemService(Context.NSD_SERVICE) as NsdManager
    private val wifi = appCtx.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
    private val lock = wifi.createMulticastLock("leo-nsd").apply { setReferenceCounted(true) }

    companion object { const val TYPE = "_leoswitch._tcp." }

    /** Resolves to the first LEO device found, or null on timeout. */
    suspend fun discoverOnce(): Found? = suspendCancellableCoroutine { cont ->
        lock.acquire()
        var finished = false

        val resolveListener = object : NsdManager.ResolveListener {
            override fun onResolveFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {}
            override fun onServiceResolved(serviceInfo: NsdServiceInfo) {
                if (finished) return
                val addr = serviceInfo.host?.hostAddress ?: return
                finished = true
                if (cont.isActive) cont.resume(Found(addr, serviceInfo.port, serviceInfo.serviceName))
            }
        }

        val discoveryListener = object : NsdManager.DiscoveryListener {
            override fun onDiscoveryStarted(serviceType: String) {}
            override fun onDiscoveryStopped(serviceType: String) {}
            override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {
                if (cont.isActive) cont.resume(null)
            }
            override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) {}
            override fun onServiceLost(serviceInfo: NsdServiceInfo) {}
            override fun onServiceFound(serviceInfo: NsdServiceInfo) {
                @Suppress("DEPRECATION")
                runCatching { nsd.resolveService(serviceInfo, resolveListener) }
            }
        }

        runCatching { nsd.discoverServices(TYPE, NsdManager.PROTOCOL_DNS_SD, discoveryListener) }

        cont.invokeOnCancellation {
            runCatching { nsd.stopServiceDiscovery(discoveryListener) }
            if (lock.isHeld) lock.release()
        }
    }

    /** Emits every LEO device found on the network. */
    fun discoverAll(): Flow<Found> = callbackFlow {
        lock.acquire()

        val resolveListener = object : NsdManager.ResolveListener {
            override fun onResolveFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {}
            override fun onServiceResolved(serviceInfo: NsdServiceInfo) {
                val addr = serviceInfo.host?.hostAddress ?: return
                trySend(Found(addr, serviceInfo.port, serviceInfo.serviceName))
            }
        }

        val discoveryListener = object : NsdManager.DiscoveryListener {
            override fun onDiscoveryStarted(serviceType: String) {}
            override fun onDiscoveryStopped(serviceType: String) {}
            override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) { close() }
            override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) {}
            override fun onServiceLost(serviceInfo: NsdServiceInfo) {}
            override fun onServiceFound(serviceInfo: NsdServiceInfo) {
                @Suppress("DEPRECATION")
                runCatching { nsd.resolveService(serviceInfo, resolveListener) }
            }
        }

        runCatching { nsd.discoverServices(TYPE, NsdManager.PROTOCOL_DNS_SD, discoveryListener) }

        awaitClose {
            runCatching { nsd.stopServiceDiscovery(discoveryListener) }
            if (lock.isHeld) lock.release()
        }
    }
}
