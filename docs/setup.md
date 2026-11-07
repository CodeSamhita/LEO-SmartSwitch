# Setting up LEO Smart Home

This covers the first install of the hub, adding a switch or tank, removing one, and starting over.

## 1. Prepare the PC (once)
1. **Install the tools:**
   - [Arduino IDE 2](https://www.arduino.cc/en/software).
   - The board package: *Tools → Board → Boards Manager* → **esp32 by Espressif**, version 3.3.x.
   - The libraries: *Tools → Manage Libraries* → **ESPAsyncWebServer** and **AsyncTCP** (both by ESP32Async), **ArduinoJson** (7.x)
     and **Adafruit NeoPixel**.
2. **Get the project:** clone or download this repository. Each folder (`LEO_Hub`, `LEO_SwitchEdge`, `LEO_TankEdge`) opens as
   its own sketch.

## 2. Set up the hub (once)
1. **Open the sketch:** open `LEO_Hub/LEO_Hub.ino` and choose the board settings from [firmware.md](firmware.md):
   ESP32S3 Dev Module, 8 MB, *8M with spiffs*.
2. **Upload:** connect the hub by USB and press **Upload**.
3. **Join the hub's hotspot:** the hub starts **LEO-Hub-xxxxxx**.
   - **Password:** after a factory reset this hotspot has none. Otherwise send `SHOWAP` over the serial monitor at 115200 baud to see it.
   - Open `http://192.168.4.1` and go to **Hub → WiFi**. Enter your home WiFi and press *Save & reconnect*.
4. **Open the web app:** on a phone or PC on your home WiFi, open **`http://leohub.local`**, or the hub's IP shown in your router.
5. **Set a password:** go to **Hub → Security** and set a password (at least 6 characters).
6. **Optional, a fixed address:** in your router, reserve the hub's IP (DHCP reservation for its MAC). Also give the 2.4 GHz WiFi a
   **fixed channel**, so the devices never have to search for the hub.

The hub's light gives one soft **green** breath every 5 s when everything is fine.

## 3. Add a switch or tank
1. **Flash the device once over USB:**
   - **Which sketch:** `LEO_SwitchEdge` (switch) or `LEO_TankEdge` (tank), with board settings *ESP32C3 Dev Module*, *Minimal SPIFFS*.
   - **A device used with another hub before:** factory-reset it first by holding its **BOOT** button for 15 s.
2. **Start adding:** in the web app, go to **Devices → Start adding (2 minutes)**.
3. **Power the device on** within a few metres of the hub.
   - Its light breathes **blue** while it looks for a hub.
   - Within seconds it appears on the Devices page with *🔒 secured*, the page shows **✅ Added: …**, and its light changes to a
     calm **green** breath.
4. **Name it:**
   - **The device:** tap its card on **Home**, set its name and settings.
   - **A switch:** also name the relays and set their watts, and switch off **In use** for relays with nothing connected.
   - **A tank:** also set **Tank size** (calibration), **Alarm rules** and the **LED display**.
5. **A device that asks to join while adding is closed:** a banner *"A new device is asking to join"* appears, with an **Allow** button.

From now on every update is wireless: go to **Devices → (device) → Update firmware**.

## 4. Remove a device
- **From its page:** on the device page, or under **Devices**, press **Remove device…**.
  - **Online:** it is told to forget the hub and goes back to *looking for a hub* (blue).
  - **Offline:** factory-reset it (hold **BOOT** 15 s) before you use it again.
- **What is deleted:** the hub deletes the device's history and its settings stored on the hub (name, relays marked not in use).
  Settings stored on the device itself (relay names, tank calibration, rules) stay until you factory-reset the device.

## 5. Move a device to another hub, or start over
- **Device:** hold its **BOOT** button for 15 s, or use *its page → Advanced → Factory reset this device*. Then add it as in step 3.
- **Hub:** *Hub → Advanced → Factory reset the hub*, or hold the hub's **BOOT** button for 15 s. Then set it up as in step 2.

## Factory-reset buttons
| Board | Button |
|---|---|
| Hub, ESP32-S3 dev board | **BOOT** (GPIO 0) |
| Switch, ESP32-C3 Super Mini | **BOOT**, small button marked *B* or *BOOT* (GPIO 9) |
| Tank, ESP32-C3 Super Mini | **BOOT** (GPIO 9) |

- **How:** hold the button for **15 seconds**. After 2 s the light blinks **red**: slow and dim at first, faster and brighter the longer you hold. At **15 s** it turns **solid bright red**: the reset is accepted and the board wipes itself and restarts. Let go before 15 s to cancel.
- **Why a loose pin can't trigger it:** the pin has a pull-up, and the button must hold it hard LOW for the full 15 s.
- **The tank's own push button** only silences alarms.
- **A separate reset button added later:** it is disabled until it is enabled in the firmware (tell the developer the pin), so an
  unconnected pin can never reset anything.
