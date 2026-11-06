package com.leo.smartswitch

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.net.wifi.WifiManager
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.suspendCancellableCoroutine
import java.util.ArrayDeque
import kotlin.coroutines.resume

data class Found(val host: String, val port: Int, val name: String)

/** Discovers devices on the LAN via their dedicated `_leoswitch._tcp` service.
 *
 *  NsdManager.resolveService() only allows ONE resolve in flight (before
 *  Android 14 a second concurrent call fails with FAILURE_ALREADY_ACTIVE), and
 *  a ResolveListener instance can't be reused while active. The old code fired
 *  a resolve for every found service at once with a shared listener, so with
 *  two or more switches only the first one ever showed up. Resolves are now
 *  queued and run one at a time, each with a fresh listener. */
class Discovery(context: Context) {
    private val appCtx = context.applicationContext
    private val nsd = appCtx.getSystemService(Context.NSD_SERVICE) as NsdManager
    private val wifi = appCtx.getSystemService(Context.WIFI_SERVICE) as WifiManager
    private val lock = wifi.createMulticastLock("leo-nsd").apply { setReferenceCounted(true) }

    companion object { const val TYPE = "_leoswitch._tcp." }

    /** Serial resolver: one resolveService() at a time. */
    private class Resolver(val nsd: NsdManager, val onResolved: (NsdServiceInfo) -> Unit) {
        private val queue = ArrayDeque<NsdServiceInfo>()
        private var busy = false
        @Volatile var stopped = false

        @Synchronized fun enqueue(info: NsdServiceInfo) {
            if (stopped) return
            if (queue.any { it.serviceName == info.serviceName }) return
            queue.add(info); next()
        }

        @Synchronized private fun next() {
            if (busy || stopped) return
            val info = queue.poll() ?: return
            busy = true
            val l = object : NsdManager.ResolveListener {
                override fun onResolveFailed(serviceInfo: NsdServiceInfo, errorCode: Int) = done()
                override fun onServiceResolved(serviceInfo: NsdServiceInfo) {
                    if (!stopped) onResolved(serviceInfo)
                    done()
                }
            }
            @Suppress("DEPRECATION")
            runCatching { nsd.resolveService(info, l) }.onFailure { busy = false; next() }
        }

        @Synchronized private fun done() { busy = false; next() }
    }

    /** Resolves to the first LEO device found, or null on failure. */
    suspend fun discoverOnce(): Found? = suspendCancellableCoroutine { cont ->
        lock.acquire()
        val resolver = Resolver(nsd) { info ->
            val addr = info.host?.hostAddress ?: return@Resolver
            if (cont.isActive) cont.resume(Found(addr, info.port, info.serviceName))
        }
        val discoveryListener = object : NsdManager.DiscoveryListener {
            override fun onDiscoveryStarted(serviceType: String) {}
            override fun onDiscoveryStopped(serviceType: String) {}
            override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {
                if (cont.isActive) cont.resume(null)
            }
            override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) {}
            override fun onServiceLost(serviceInfo: NsdServiceInfo) {}
            override fun onServiceFound(serviceInfo: NsdServiceInfo) = resolver.enqueue(serviceInfo)
        }
        runCatching { nsd.discoverServices(TYPE, NsdManager.PROTOCOL_DNS_SD, discoveryListener) }

        cont.invokeOnCancellation {
            resolver.stopped = true
            runCatching { nsd.stopServiceDiscovery(discoveryListener) }
            if (lock.isHeld) lock.release()
        }
    }

    /** Emits every LEO device found on the network until the collector is cancelled. */
    fun discoverAll(): Flow<Found> = callbackFlow {
        lock.acquire()
        val resolver = Resolver(nsd) { info ->
            val addr = info.host?.hostAddress ?: return@Resolver
            trySend(Found(addr, info.port, info.serviceName))
        }
        val discoveryListener = object : NsdManager.DiscoveryListener {
            override fun onDiscoveryStarted(serviceType: String) {}
            override fun onDiscoveryStopped(serviceType: String) {}
            override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) { close() }
            override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) {}
            override fun onServiceLost(serviceInfo: NsdServiceInfo) {}
            override fun onServiceFound(serviceInfo: NsdServiceInfo) = resolver.enqueue(serviceInfo)
        }
        runCatching { nsd.discoverServices(TYPE, NsdManager.PROTOCOL_DNS_SD, discoveryListener) }

        awaitClose {
            resolver.stopped = true
            runCatching { nsd.stopServiceDiscovery(discoveryListener) }
            if (lock.isHeld) lock.release()
        }
    }
}
