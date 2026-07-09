# LEO Smart Switch — Android app

Local-first controller for one or more LEO Smart Switches. It auto-discovers
devices on your WiFi (mDNS), streams **live state over WebSocket**, gives each
device a detail screen, and ships a **home-screen widget** with quick relay
toggles. No cloud, no account.

> This is the buildable source project, not a prebuilt APK. Build it in one step
> (see below) — a compiled `.apk` can't be produced outside an Android SDK.

## What changed in this pass
- **Widget improvements.** The home-screen widget used its own hand-picked
  colors that had drifted from the app's actual "moondust" palette (including
  a generic red instead of `moondust_danger` for the offline dot) — now
  matches exactly. It also hard-capped at 2 devices with no way to see more;
  it now fetches up to 6 and shows them in a scrollable `LazyColumn`, so
  devices beyond the first couple are reachable instead of invisible.
- **Removed dead code.** `SettingsActivity.kt` was an orphaned, unregistered
  screen with a broken reference (`R.string.add_btn`, which didn't exist —
  it wouldn't compile) that duplicated `AddDeviceActivity` with a different,
  inconsistent (non-"glass") design. It, its layout, and several other unused
  layout/drawable resources left over from earlier iterations are gone. Every
  real screen builds its UI programmatically through `GlassActivity`; there
  were no other classic XML layouts actually wired up via `setContentView`.
- **Actually responsive now.** `values-w600dp` / `values-w840dp` margin
  overrides existed but were never referenced by any screen — every screen
  used a hardcoded 18dp margin regardless of device size. `GlassActivity.scaffold()`
  (shared by every screen) now reads `R.dimen.screen_margin`, so margins
  genuinely scale (18dp phones → 32dp large/foldables → 64dp tablets). The
  dashboard's relay-pill grid also now picks 2 or 3 columns from the real
  `screenWidthDp` at runtime instead of a hardcoded 2.
- **Live console.** A new screen (from a device's detail page → *Live console*)
  streams the firmware's debug output in real time over the `/console`
  WebSocket — the same lines it prints over USB serial, viewable without a
  cable. Auto-reconnects if the socket drops.
- **Fixed a live-data bug.** The detail screen was calling `/api/identity` on
  every WebSocket telemetry tick (~once/second, forever) just to read the
  mDNS field — needless load on the device's web server. It's now fetched
  once and cached.
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
2. On the dashboard, tap **Add** → *Scan network* (mDNS `_leoswitch._tcp`) or
   add an IP manually; log in if the device requires it.
3. The dashboard shows each device with live power and per-relay toggles; tap a
   card for the detail screen, which links out to Energy, Network, Device
   settings, the live console, and the web console.
4. Long-press home screen → **Widgets → LEO Smart Switch** for the quick widget.

## Structure
```
app/src/main/java/com/leo/smartswitch/
  MainActivity.kt           dashboard (adaptive device grid, optimistic toggles)
  DeviceDetailActivity.kt   per-device detail (live)
  AddDeviceActivity.kt      discovery + manual add + saved devices
  EnergyActivity.kt         30-day kWh/cost chart + tariff
  NetworkActivity.kt        identity, Wi-Fi join, AP, mDNS
  DeviceSettingsActivity.kt name, role, status LED, relay GPIO map
  ConsoleActivity.kt        live serial/debug console (/console WebSocket)
  DeviceApi.kt              REST client + shared JSON parser + models
  LiveManager.kt            WebSocket telemetry with auto-reconnect
  Discovery.kt              NSD (mDNS) discovery
  DeviceStore.kt            multi-device persistence
  GlassActivity.kt / Ui.kt / Anim.kt   shared "glass" design system
  widget/LeoWidget.kt       Glance home-screen widget
app/src/main/res/
  values/ , values-w600dp/ , values-w840dp/   responsive screen_margin,
  read by GlassActivity.scaffold() (shared by every screen)
```

## Notes
- mDNS discovery resolves to a numeric IP; `.local` names don't always resolve
  through `HttpURLConnection`, so enter the IP if discovery is blocked.
- The widget shows up to 6 devices (scroll if you have more) and refreshes on
  tap + every ~30 min (the Android minimum); the in-app screens are the live,
  real-time view.
- The mDNS service type `_leoswitch._tcp` must match the firmware.
