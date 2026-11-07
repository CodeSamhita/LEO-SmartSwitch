# ESP-NOW protocol v2

The protocol block is **identical in all three sketches**; keep it that way. Messages are packed
little-endian structs.
- Every message starts with `LeoHdr {u16 magic=0x4C45; u8 proto=2; u8 type; u8 dev; u8 seq}`.
- Every message except `HELLO` ends with `LeoAuth {u32 ctr; u8 tag[8]}`, where
  `tag = HMAC-SHA256(key, session ‖ body ‖ ctr)[0..7]`.
  - `key` is the device's own 128-bit key, received once at pairing.
  - `session` is the random nonce from the edge's latest HELLO.
  - `ctr` must strictly increase in each direction, so replays are dropped.

## Messages
| Type | Name | Direction | Content |
|---|---|---|---|
| 1 | HELLO | edge → hub | nonce, hasKey, fw, name (unsigned) |
| 2 | WELCOME | hub → edge | channel, key (only when pairing is allowed), hub name |
| 3 | SW_STATE | switch → hub | relay count, on-mask, uptime, on-seconds |
| 4 | SW_INFO | switch → hub | name, fw, relay names, watts, GPIOs, touch enabled |
| 5 | TANK_STATE | tank → hub | level %, distance, LEDs, state, sensorOk, flags, uptime, text, LDR |
| 6 | TANK_INFO | tank → hub | calibration, alarm %, buzzer, quiet hours, palette, LED count, daytime display, min brightness |
| 7 | CMD | hub → edge | cmd, idx, val, f, text |
| 10–13 | OTA_BEGIN/DATA/END/ACK | both | stop-and-wait firmware transfer, 200-byte chunks |
| 14 | PING | hub → edge | keep-alive: local time (minutes), room light, beat (ms % 10000); with g = 1 also the global home settings (quiet hours, daytime hours, status-light brightness day/night, room-light thresholds) |
| 15 | DIAG | edge → hub | chip temperature, heap, storage, flash, firmware size, reset reason, CPU MHz, ESP-IDF version |
| 16 | TANK_RULES | tank → hub | 6 alarm rules × {on, level %, dir (0 rises to, 1 drops to), sound 0–5, repeats, flash colour 0–5} |

## Commands (`CMD.cmd`)
| # | Command | Used by |
|---|---|---|
| 1 | RELAY (idx, val) | switch |
| 2 | ALL (val) | switch |
| 3 | IDENTIFY | all |
| 4 | RENAME (text) | all |
| 5 | RELAY_META (idx, text name, f watts) | switch |
| 6 | REBOOT | all |
| 7 | INFO, which asks for INFO/TANK_INFO/DIAG | all |
| 8 | UNPAIR | all |
| 9 | TOUCH (val) | switch |
| 10 | TANK_SET (idx, f) | tank |
| 11 | SILENCE | tank |
| 12 | BEEP: idx 0 = short beep, idx 1–6 = play sound idx-1 once, val = flash colour | tank |
| 13 | FACTORY | all |
| 14 | TANK_RULE: idx = rule 0–5, text[0..5] = rule bytes | tank |

`TANK_SET` indexes:

| idx | Setting |
|---|---|
| 1 | full cm |
| 2 | empty cm |
| 3 | full % |
| 4 | low % |
| 5 | buzzer |
| 6 | quiet from (hour) |
| 7 | quiet to (hour) |
| 8 | palette (0 red-blue, 1 red-green, 2 custom, 3 spectrum) |
| 9 | LED count |
| 10 | display from (hour) |
| 11 | display to (hour) |
| 12 | minimum brightness |
| 13–20 | custom colour of LED 1–8 (0xRRGGBB) |
| 21 | current-level highlight 0–100 % |
| 22–29 | (colour matching, unused by the app) |
| 30 | light every level LED for n s |
| 31 | light sensor dark reading (0–4000) |
| 32 | light sensor daylight reading (≥ dark + 50, ≤ 4095) |
| 40 | simulation: water level % |
| 41 | simulation: light sensor reading |
| 42 | simulation: daytime hours (0/1) |
| 43 | simulation: sensor fault (0/1) |
| 44 | simulation: run for n s (5–600), 0 = stop. 40–43 also start a 3-minute run. Not saved. |

TANK_INFO ends with `ldrMin, ldrMax` (tank 1.9+). PING ends with `ledStyle` (0 breath, 1 blink, 2 double blink,
3 steady, 4 off), `ledPeriod` (ms: 1000, 2000, 2500, 5000 or 10000, so the beat stays in step) and the all-well
colour `okR, okG, okB` (hub 2.1+).

## Compatibility rule
New fields are only ever **appended** to a struct. Receivers accept the older, shorter length and use
defaults for the missing fields. This lets the hub and the edges be updated one at a time.
