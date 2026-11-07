# LEO Home Hub + edge devices

One **ESP32-S3 hub** joins your home WiFi and serves a single web app for every
device. **Edge devices** (LEO switch, AquaNode tank) talk only to the hub over
**ESP-NOW**: no WiFi password, no web server, no hotspot on the edges.

```
phone / PC ──WiFi──► HUB (ESP32-S3) ──ESP-NOW──► switch edge (ESP32-C3)
                    web app, OTA          └────► tank edge (ESP32-C3)  [next]
```

| Sketch | Board | Partition scheme |
|---|---|---|
| `LEO_Hub/LEO_Hub.ino` | ESP32S3 Dev Module, Flash 8MB, USB Mode *Hardware CDC and JTAG*, USB CDC On Boot *Enabled* | **8M with spiffs (3MB APP/1.5MB SPIFFS)** |
| `LEO_SwitchEdge/LEO_SwitchEdge.ino` | ESP32C3 Dev Module, USB CDC On Boot *Enabled* | **Minimal SPIFFS (1.9MB APP with OTA)** |

Libraries: ESPAsyncWebServer + AsyncTCP (ESP32Async), ArduinoJson 7, Adafruit NeoPixel.

## Using it
- Open **`http://leohub.local`** (PC/iPhone) or the hub's IP (Android). On Android,
  Chrome may block local addresses — use another browser or allow Chrome's
  local-network permission.
- **First boot without WiFi:** the hub opens hotspot `LEO-Hub-XXXXXX`
  (password `leo12345`) → `http://192.168.4.1` → **Hub → WiFi**.
  Over USB you can instead send `SETWIFI<TAB>ssid<TAB>password<LF>` at 115200 baud.
- **Pairing:** power an edge on near the hub — it finds the hub's channel and pairs
  automatically. If the router changes channel, edges re-find the hub on their own.
- **Edges keep working without the hub**: relays hold their state (all OFF only after
  a power cut).

## Switch edge hardware (2.1.0)
| Function | GPIO |
|---|---|
| Relays 1–4 (active-low) | 0, 1, 3, 10 |
| Touch buttons 1–4 (TTP223 OUT, HIGH = touched) | 4, 5, 6, 7 |
| Status LED (WS2812 / NeoPixel) | 2 |

- **Touch buttons** toggle their relay directly, so they work even when the hub is offline.
  The hub logs the change when it hears the switch again. Unwired pins are pulled down and
  never trigger. For modules that pull LOW when touched, set `TOUCH_ACTIVE_HIGH 0`.
  Night lock only blocks the app, not a person at the switch.
- **Status LED** (replaces the power LED): one quick, faint breath (0.8 s), dark the rest of the time.
  The peak is 5/255 when the room is lit and 2/255 when it's dark.
  - Green every 5 s: linked.
  - Amber every 2 s: looking for the hub.
  - Blue every 2 s: never paired.
  - Cyan, fast: firmware update in progress.
  - Quick white blinks: identify.
- **Touch buttons** are off by default; turn them on in *Devices → Touch buttons* once the pads are wired.

## Tank edge (`LEO_TankEdge/LEO_TankEdge.ino`, 1.0.1)
Same board settings as the switch edge (ESP32C3 Dev Module, Minimal SPIFFS). Wiring follows
tank_v9 / AquaNode v2.12:

| Function | GPIO |
|---|---|
| HC-SR04 TRIG / ECHO | 4 / 3 |
| 9× WS2812B (0–6 = level, 7 spare, 8 = status blink) | 2 |
| LDR (higher = brighter) | 0 |
| Push button to GND | 1 |
| Buzzer (HIGH = sound) | 10 |

- **Level:** 15 cm from the sensor = 100 %, 103 cm = 0 %.
- **Alerts:** FULL at ≥ 95 % (long beeps, green) and LOW at ≤ 10 % (short beeps, red), 10 rounds each.
  Alerts re-arm once the level is back between 15 and 90 %. The button silences the current alert.
  The buzzer only sounds when the room is lit.
- **Works without the hub:** level LEDs, alerts and the button all run on the tank itself.
  The hub shows the level, distance and state.
- **No sensor:** with no ultrasonic sensor, or no echo, it reports *Sensor not connected*: level LEDs off,
  no alarms, red status blink.

## Room light: one sensor for the whole room (hub 1.3.0)
The tank's LDR is the room's light sensor. The tank sends its reading to the hub, which decides
**bright** or **dark** (bright above 120, dark again below 80, so it doesn't flicker at dusk). The hub
passes that to every device in its keep-alive, and every status LED uses it for its brightness.
If no tank is online, the clock decides instead (07:00–18:00 = day).
The tank's buzzer stays quiet when the room is dark **or** between 22:00 and 06:00.
The tank card in the web app shows *Room light: bright/dark (reading)*.

## Power-on light (hub 1.4.0, switch 2.4.0, tank 1.2.0)
The moment a board gets power, before any WiFi, hub or file work, its LED lights for about 1.5 s.
This shows that power is good and the board is booting.
- **Hub and switch:** a soft warm-white glow. Each saves the last room light it heard, so after a
  power cut it is 14/255 if the room was lit and 3/255 if it was dark or never known.
- **Tank:** reads its own LDR first, then runs its red, blue and green sweep: 25/255 with a chirp in a
  lit room, 3/255 and silent in a dark one.

## Synced breathing (hub 1.5.0, switch 2.5.0, tank 1.3.0)
Each keep-alive also carries the hub's beat (`millis() % 10000`). Edges keep an offset to it,
so every LEO status LED breathes at the same moment. Big differences are corrected at once and
small radio jitter is smoothed. Without the hub, each device keeps breathing on its own clock.

## Hub status LED
The onboard RGB LED (GPIO 48, or 38 on DevKitC v1.1) gives the same quick faint breath:
- Green every 5 s: on WiFi.
- Cyan every 2 s: pairing open.
- Amber every 2 s: WiFi lost or connecting.
- Blue every 2 s: emergency hotspot on.

## Updating firmware (no cable)
- **Hub:** Arduino *Export Compiled Binary* → web app **Hub → Update hub firmware** → `LEO_Hub.ino.bin`.
- **Edge:** *Export Compiled Binary* of the edge sketch → web app **Devices → (device) →
  Update firmware** → e.g. `LEO_SwitchEdge.ino.bin`. The hub stores it, then streams it
  over ESP-NOW (≈1 MB in under a minute). A failed transfer leaves the old firmware running.

## Security (hub 1.1.0 / switch edge 2.0.0)
- **Signed radio link:** every hub↔edge packet (except the pairing HELLO) carries an
  HMAC-SHA256 tag made with that device's own 128-bit key, bound to a per-session random
  nonce and a strictly increasing counter — forged or replayed commands are ignored.
  The hub also sends a signed keep-alive every 3 s; an edge that hears no signed packet
  for 10 s re-links with a fresh session.
- **Pairing needs permission:** keys are issued only while *Devices → Allow new devices*
  is open (2 min), automatically for the first devices of a brand-new hub, or once to a
  device the hub already knew before keys existed. *Forget* tells the device to drop its
  key. If a device and hub disagree on keys, send `UNPAIR` to the edge over USB.
- **Web login:** *Hub → Security* sets a password (salted SHA-256); signed-in browsers are
  remembered (cookie), 5 wrong tries pause sign-in for 30 s. Forgot it? Send `RESETPASS`
  to the hub over USB.
- **Emergency hotspot** uses a random per-hub password (shown/changed in *Hub → Security*;
  `SHOWAP` over USB prints it).
- **Night lock** (*Hub → Night lock*): manual or scheduled; while active every **ON**
  command is refused (HTTP 423) and recorded as BLOCKED. OFF always works.
- **Activity log** (*Activity* tab): every ON/OFF with time and the requesting IP,
  blocked attempts, pairing, firmware updates, password changes, and device restarts
  ("restarted (power cut?) — all relays start OFF").
- Relays are never saved: after any power cut every relay starts **OFF**.

Known limits: the key is sent once in clear during pairing (keep pairing windows short);
packets are authenticated, not encrypted (someone in radio range could see *that* a relay
changed, but cannot cause it).

## Protocol (ESP-NOW, v2)
Packed structs, identical in every sketch (`LEO EDGE PROTOCOL v2` block): `HELLO` →
`WELCOME` pairing, `SW_STATE` every 2 s (heartbeat) + on change, `SW_INFO` (names,
watts, GPIOs), `CMD` (relay, all, identify, rename, relay meta, reboot, info, unpair), `PING`,
`OTA_BEGIN/DATA/END/ACK` (stop-and-wait, 200-byte chunks, resend on timeout).
Edges accept commands only from the hub they paired with.

## Tested on hardware (2026-11-06)
Hub on WiFi in ~1 s; switch edge paired in ~6 s; relay commands confirmed by the
edge's own reports; edge OTA through the hub 1.04 MB in 49 s at −85 dBm; automatic
re-pairing after the router moved from channel 9 to 3.
