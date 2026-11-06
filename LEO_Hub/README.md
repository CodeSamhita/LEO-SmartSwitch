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

## Updating firmware (no cable)
- **Hub:** Arduino *Export Compiled Binary* → web app **Hub → Update hub firmware** → `LEO_Hub.ino.bin`.
- **Edge:** *Export Compiled Binary* of the edge sketch → web app **Devices → (device) →
  Update firmware** → e.g. `LEO_SwitchEdge.ino.bin`. The hub stores it, then streams it
  over ESP-NOW (≈1 MB in under a minute). A failed transfer leaves the old firmware running.

## Protocol (ESP-NOW, v1)
Packed structs, identical in every sketch (`LEO EDGE PROTOCOL v1` block): `HELLO` →
`WELCOME` pairing, `SW_STATE` every 2 s (heartbeat) + on change, `SW_INFO` (names,
watts, GPIOs), `CMD` (relay, all, identify, rename, relay meta, reboot, info),
`OTA_BEGIN/DATA/END/ACK` (stop-and-wait, 200-byte chunks, resend on timeout).
Edges accept commands only from the hub they paired with.

## Tested on hardware (2026-11-06)
Hub on WiFi in ~1 s; switch edge paired in ~6 s; relay commands confirmed by the
edge's own reports; edge OTA through the hub 1.04 MB in 49 s at −85 dBm; automatic
re-pairing after the router moved from channel 9 to 3.
