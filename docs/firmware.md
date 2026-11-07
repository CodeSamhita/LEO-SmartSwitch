# Firmware: building, flashing, updating, resetting

## Tools
- **Arduino IDE 2**, or `arduino-cli`, with the **esp32 by Espressif** core 3.3.x.
- **Libraries:**
  - ESPAsyncWebServer and AsyncTCP (by ESP32Async). These are needed by the hub only.
  - ArduinoJson 7
  - Adafruit NeoPixel

## Board settings
| Sketch | Board | Settings |
|---|---|---|
| `LEO_Hub` | ESP32S3 Dev Module | Flash Size 8MB · Partition **8M with spiffs (3MB APP/1.5MB SPIFFS)** · USB Mode Hardware CDC and JTAG · USB CDC On Boot Enabled |
| `LEO_SwitchEdge` | ESP32C3 Dev Module | USB CDC On Boot Enabled · Partition **Minimal SPIFFS (1.9MB APP with OTA/128KB SPIFFS)** |
| `LEO_TankEdge` | ESP32C3 Dev Module | same as the switch |

The partition scheme matters: it reserves the second app slot that wireless updates need.

From the command line:
```
arduino-cli compile --fqbn "esp32:esp32:esp32s3:FlashSize=8M,PartitionScheme=default_8MB,USBMode=hwcdc,CDCOnBoot=cdc" --output-dir build-hub LEO_Hub
arduino-cli compile --fqbn "esp32:esp32:esp32c3:CDCOnBoot=cdc,PartitionScheme=min_spiffs" --output-dir build-edge LEO_SwitchEdge
arduino-cli compile --fqbn "esp32:esp32:esp32c3:CDCOnBoot=cdc,PartitionScheme=min_spiffs" --output-dir build-tank LEO_TankEdge
```

## First flash (USB, once per board)
Upload normally from the IDE. If the ESP32-S3 refuses large uploads, flash with esptool's `--no-stub`.

## Wireless updates (no cable)
1. In the IDE, choose **Sketch → Export Compiled Binary**. This produces `LEO_Hub.ino.bin`,
   `LEO_SwitchEdge.ino.bin` or `LEO_TankEdge.ino.bin`.
2. Install it from the web app:
   - **Hub:** *Hub → Update hub firmware → Upload & install*. About 10–20 s; the hub restarts.
   - **Switch or tank:** *Devices → (device) → Update firmware*. The hub stores the file, then streams it over
     ESP-NOW in signed 200-byte pieces. About 45 s at a good signal, longer at a weak one.
3. If anything fails, the old firmware keeps running.

A switch update restarts the switch, so every relay goes OFF for about a minute.

## Factory reset
| Device | From the web app | With a button |
|---|---|---|
| Hub | *Hub → Advanced → Factory reset the hub* (type RESET) | hold **BOOT** 10 s |
| Switch | *switch page → Advanced → Factory reset this device* | hold **BOOT** 10 s |
| Tank | *tank page → Advanced → Factory reset this device* | hold the tank's **push button** 10 s |

- **Warning:** after 2 s of holding, the light blinks red fast. Let go before 10 s to cancel.
- **Hub:**
  - It first tells every paired device to forget it.
  - Then it erases WiFi, password, devices, names, logs and history, and restarts with a **setup hotspot that has no
    password** (*LEO-Hub-xxxxxx*). Open `http://192.168.4.1` and set WiFi again; the hotspot locks again after that.
- **Edge:** it erases its pairing key and all settings (names, watts, touch, calibration, alarms, LEDs) and
  restarts unpaired. Pair it again with *Devices → Allow new devices*.

## USB serial commands (115200 baud)
| Device | Command | Effect |
|---|---|---|
| Hub | `SETWIFI<TAB>ssid<TAB>password` | save WiFi and restart |
| Hub | `RESETPASS` | remove the web password and sign out all browsers |
| Hub | `SHOWAP` | print the emergency hotspot name and password |
| Switch, tank | `UNPAIR` | forget the hub and the key |
