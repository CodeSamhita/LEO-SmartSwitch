# LEO Smart Home

A small, private smart-home system built on ESP32 boards. One **hub** joins your home WiFi and
serves a web app. **Edge devices**, a 4-relay **smart switch** and a **water-tank monitor**, talk
only to the hub, over a signed ESP-NOW radio link. They need no WiFi password, run no web server
and open no hotspot.

```
 phone / PC ──WiFi──►  LEO Hub (ESP32-S3)  ──ESP-NOW (signed)──►  Smart Switch (ESP32-C3)
                       web app, OTA, logs   └────────────────────►  Water Tank   (ESP32-C3)
```

| Folder | Device | Firmware |
|---|---|---|
| [`LEO_Hub/`](LEO_Hub/LEO_Hub.ino) | Hub, ESP32-S3 (8 MB) | 1.9.0 |
| [`LEO_SwitchEdge/`](LEO_SwitchEdge/LEO_SwitchEdge.ino) | 4-relay smart switch, ESP32-C3 Super Mini | 2.6.0 |
| [`LEO_TankEdge/`](LEO_TankEdge/LEO_TankEdge.ino) | Water-tank monitor, ESP32-C3 Super Mini | 1.7.1 |

Each folder is a single Arduino sketch (`.ino`). The web app is built into the hub firmware.

## What it does
- **One web app** at `http://leohub.local` (or the hub's IP address). It works on any phone or PC on your WiFi.
  - The **Home** page shows quick controls; tap a device for all of its options.
  - **Switch:** relays, names and watts, unused relays hidden, touch buttons, power chart (24 h / yesterday / 7 days).
  - **Tank:** level, up to 6 alarm rules (sound, times, colour), calibration, LED colours per LED, daytime display, level chart.
  - **Activity:** every ON/OFF, setting change, blocked attempt and restart, with time.
  - **Hub:** night lock, password, WiFi, firmware updates, and an *Advanced* section with chip details,
    live log and factory reset.
- **Wireless updates** for every board. The hub updates itself over WiFi and passes edge updates on over ESP-NOW.
- **Works without the hub:**
  - Relays keep their state, and the touch pads still work.
  - The tank keeps measuring, showing the level and sounding its alarms.
- **Safe after a power cut:** every relay starts OFF.
- **Room light:** the tank's light sensor is the light sensor for the whole room. Status lights,
  the tank's buzzer and its display follow it.
- **Security:**
  - Signed and replay-proof radio packets.
  - Web password.
  - Pairing only when you allow it.
  - Night lock.
  - Activity log.

## Quick start
1. **Install the tools:** Arduino IDE 2 with the **esp32** core 3.3.x, plus the libraries
   *ESPAsyncWebServer* and *AsyncTCP* (ESP32Async), *ArduinoJson* 7 and *Adafruit NeoPixel*.
2. **Hub:** flash `LEO_Hub` over USB, using the board settings in [docs/firmware.md](docs/firmware.md).
   On first start, join the hotspot **LEO-Hub-xxxxxx** and open `http://192.168.4.1` → *Hub → WiFi*.
3. **Set a password:** open `http://leohub.local`, then go to *Hub → Security*.
4. **Edges:** flash `LEO_SwitchEdge` / `LEO_TankEdge` over USB once. Then in the web app go to
   *Devices → Allow new devices* and power the device on near the hub. It pairs by itself.
5. **From now on,** every update is wireless (see [docs/firmware.md](docs/firmware.md)).

## Documentation
| | |
|---|---|
| [docs/setup.md](docs/setup.md) | **Start here:** set up the hub, add or remove devices, factory reset |
| [docs/architecture.md](docs/architecture.md) | How the pieces fit together, room light, history, status LEDs |
| [docs/hardware.md](docs/hardware.md) | Boards, pins and wiring for hub, switch and tank |
| [docs/web-app.md](docs/web-app.md) | Using the web app, every page and setting |
| [docs/firmware.md](docs/firmware.md) | Building, first USB flash, wireless updates, factory reset |
| [docs/protocol.md](docs/protocol.md) | The ESP-NOW protocol (v2) between hub and edges |
| [docs/security.md](docs/security.md) | What is protected, and how |
| [docs/troubleshooting.md](docs/troubleshooting.md) | Common problems and fixes |
