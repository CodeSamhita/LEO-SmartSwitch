# Architecture

```
            your WiFi router
                  │  (WiFi, normal home network)
   phone / PC ────┤
                  │
            ┌─────┴──────┐   ESP-NOW, signed (protocol v2)   ┌──────────────────┐
            │  LEO Hub   │ ────────────────────────────────► │  Smart Switch    │ 4 relays, touch pads
            │  ESP32-S3  │ ◄──────────────────────────────── │  ESP32-C3        │
            │ web app    │                                   └──────────────────┘
            │ OTA, logs  │ ────────────────────────────────► ┌──────────────────┐
            │ history    │ ◄──────────────────────────────── │  Water Tank      │ HC-SR04, 9 LEDs,
            └────────────┘                                   │  ESP32-C3        │ LDR, button, buzzer
                                                             └──────────────────┘
```

## Roles
- **Hub:** the only device on your WiFi.
  - Serves the web app and its WebSocket (live state).
  - Keeps the device list, keys, activity log and 24 h history.
  - Updates its own firmware and the edges' firmware.
  - Mirrors the router's WiFi channel for ESP-NOW.
- **Edges (switch and tank):** they never join WiFi.
  - They find the hub by trying channels, pair once and then accept only signed packets from that hub.
  - All their own logic runs locally, so they keep working when the hub is away.

## Link and timing
| What | Interval |
|---|---|
| Hub → edge keep-alive (signed, carries time, room light, beat) | every 3 s; 0.3 s retry after a missed radio ACK |
| Edge → hub state | every 2 s, and immediately on a change |
| Edge re-links after hearing nothing verified | 10 s |
| Hub marks an edge offline | after 9 s |
| Edge chip details (Advanced view) | on link, on request, every 60 s |

When the router changes WiFi channel, the hub follows it and logs *"Router moved WiFi from channel X
to Y"*. The edges find the hub again on their own, trying the last known channel first.

## Room light (one sensor for the whole room)
The tank's LDR is the room's light sensor:
1. The tank sends its reading to the hub.
2. The hub decides **bright** (above 120) or **dark** (below 80). The gap stops it flickering at dusk.
3. The hub sends that in every keep-alive.

Every status LED uses it for its brightness, and the switch and hub save the last value for the power-on glow.
With no tank online, the clock decides instead (07:00–18:00 = day).

## Status LEDs (all devices)
- **Power-on:** the moment a board gets power, it glows warm white for about 1.5 s, before any radio work.
  It is dim if the room was dark last time. The tank runs its red → blue → green sweep instead.
- **After that:** one quick, faint breath (0.8 s), in step on every device. The hub's beat is shared in
  the keep-alive.

| Colour | Meaning |
|---|---|
| green, every 5 s | all good (hub on WiFi / edge linked) |
| amber, every 2 s | hub: WiFi lost · edge: looking for the hub |
| blue, every 2 s | hub: emergency hotspot on · edge: never paired |
| cyan, every 2 s / fast | hub: pairing open · edge: firmware update running |
| red, every 2 s | tank: no sensor reading |
| red blink, getting faster and brighter → solid red | BOOT held for a factory reset (accepted at 15 s) |
| white, quick blinks | "Identify" from the web app |

The peak brightness is 5/255 in a lit room and 2/255 in a dark one.

## History
- **What is recorded:** for every device, the hub keeps one value per 5 minutes for 24 hours, and one per hour for 7 days. That is
  average watts for a switch (from the watts set per relay) and average level for the tank.
- **Saving:** it is written to flash every 30 minutes, so a restart loses at most 30 minutes.
- **Gaps:** when a device was offline, or the tank had no reading, the chart shows a gap.

## Files on the hub (LittleFS)
| File | Content |
|---|---|
| `/devices.json` | paired devices: MAC, type, name, key, relays not in use |
| `/activity.log` | activity log, JSON lines, newest half kept at 48 KB |
| `/hist.bin` | 24 h history |
| `/edge.bin` | an edge update being passed on (deleted afterwards) |

Settings such as WiFi, password hash, hub name, night lock, room light and hotspot password live in NVS (`Preferences`, namespace `leohub`).
