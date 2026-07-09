# LEO Smart Switch — Android app

Local-first controller for one or more LEO Smart Switches. It auto-discovers
devices on your WiFi (mDNS), streams **live state over WebSocket**, gives each
device a detail screen, and ships a **home-screen widget** with quick relay
toggles. No cloud, no account.

> This is the buildable source project, not a prebuilt APK. Build it in one step
> (see below) — a compiled `.apk` can't be produced outside an Android SDK.

## What changed in this pass
- **Live console.** A new screen (from a device's detail page → *Live console*)
  streams the firmware's debug output in real time over the `/console`
  WebSocket — the same lines it prints over USB serial, viewable without a
  cable. Auto-reconnects if the socket drops.
- **Responsive layouts.** The dashboard now flows into a width-adaptive grid:
  **1 column on phones, 2 on large/landscape, 3 on tablets** (`GridLayout`,
  span chosen from `screenWidthDp`). Screen margins scale up via
  `values-w600dp` / `values-w840dp`, and the device detail screen has a
  `layout-w600dp` variant that places **System Status and Energy side by side**.
- **Live-update bug fixed.** Cards are now keyed by the saved device id and
  incoming states are stamped with the same id (`DeviceApi.parseState(forceId=…)`),
  so WebSocket/REST updates reliably match the right card. Previously the
  firmware's `ip`-based id didn't match the saved `host:port` id and live
  refreshes silently missed.
- **Correct "current load."** Power now sums only **energized** relays instead of
  every relay's rated wattage. The detail screen's cost estimate uses the
  device's **actual tariff** (broadcast by the firmware) instead of a hardcoded
  value.
- **Snappier toggles.** Relay buttons flip optimistically on tap and revert if
  the request fails; the 1 s WebSocket push reconciles the truth.
- **Robust live connection.** `LiveManager` auto-reconnects with backoff after a
  drop and keeps sockets pinned, and sockets are released when the app finishes.
- **Shared parser.** REST and WebSocket now use one `DeviceApi.parseState`, and
  uptime is formatted (`3d 4h`) instead of raw seconds.

## Build the APK
**Android Studio:** *File → Open* this folder → let Gradle sync →
*Build → Build APK(s)* → install `app/build/outputs/apk/debug/app-debug.apk`.

**Command line** (JDK 17 + Android SDK):
```bash
./gradlew assembleDebug      # app/build/outputs/apk/debug/app-debug.apk
./gradlew installDebug       # to a connected device
```

## Using it
1. Phone and switch on the same WiFi.
2. **Settings (gear)** → *Find devices* (mDNS `_leoswitch._tcp`) or add an IP
   manually; log in if the device requires it.
3. The dashboard shows each device with live power and per-relay toggles; tap a
   card for the detail screen, or the globe icon to open its web console.
4. Long-press home screen → **Widgets → LEO Smart Switch** for the quick widget.

## Structure
```
app/src/main/java/com/leo/smartswitch/
  MainActivity.kt           dashboard (adaptive device grid, optimistic toggles)
  DeviceDetailActivity.kt   per-device detail (live)
  ConsoleActivity.kt        live serial/debug console (/console WebSocket)
  SettingsActivity.kt       discovery + manual add + saved devices
  DeviceApi.kt              REST client + shared JSON parser + models
  LiveManager.kt            WebSocket telemetry with auto-reconnect
  Discovery.kt              NSD (mDNS) discovery
  DeviceStore.kt            multi-device persistence
  widget/LeoWidget.kt       Glance home-screen widget
app/src/main/res/
  layout/ , layout-w600dp/  phone + wide-screen layouts
  values/ , values-w600dp/ , values-w840dp/   responsive margins
```

## Notes
- mDNS discovery resolves to a numeric IP; `.local` names don't always resolve
  through `HttpURLConnection`, so enter the IP if discovery is blocked.
- The widget shows up to 2 devices and refreshes on tap + every ~30 min (the
  Android minimum); the in-app screens are the live, real-time view.
- The mDNS service type `_leoswitch._tcp` must match the firmware.
