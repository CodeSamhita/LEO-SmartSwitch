# Using the web app

Open **`http://leohub.local`**.
- If you open the hub by its IP address instead, the page moves you to `leohub.local` once it has
  checked that your phone or PC can reach that name. Some Android browsers can't, and then you stay on the IP.
- Add `?ip` to the address to never switch.
- On Android, Chrome may block local addresses; use another browser (for example Brave) or allow local-network access.

**Install it as an app (Android Chrome):** Chrome only installs apps from secure addresses. On the phone, open `chrome://flags/#unsafely-treat-insecure-origin-as-secure`, enter `http://leohub.local,http://192.168.1.115`, set it to **Enabled** and relaunch Chrome. Then open `http://leohub.local` and choose **⋮ → Install app**. It gets the LEO icon and opens full-screen; if the hub can't be reached it shows a short *not reachable* page. Without the flag, **⋮ → Add to home screen → Create shortcut** gives an icon that opens in Chrome.

Every setting has a **?** next to it. Tap it for a short explanation.

**The page stays live:** the hub sends an update at least every 2 seconds. If updates stop (phone asleep, WiFi blip,
hub restarting), the header shows **Reconnecting…** and the page reconnects by itself. It also reconnects the
moment you come back to the tab. The page is cached and only downloads again after a hub firmware update.

## Home
Quick controls for every device. Tap a card (not its buttons) to open the device's page.
- **Switch card:** relay toggles, the total power, and **All on / All off**. Relays marked *not in use* are hidden and skipped by All on.
- **Tank card:** a bar that looks like the real LED strip, with the same number of LEDs and the same colours, plus the level,
  distance, status and room light. The bar is **yellow** when the sensor has a problem.

## Switch page
Tabs: **Overview** (relays, power chart) · **Relays** (names, watts, in use) · **Setup** (touch pads, name, restart, update, remove, Advanced).
- **Controls:** every relay (and how long it has been on), All on / All off, signal, uptime and firmware.
- **Power use:** a chart with **1 h / 6 h / 24 h / Yesterday / 7 days**.
  - **Points:** each point is the average power of 5 minutes (24 h) or of an hour (Yesterday, 7 days).
  - **Scale:** always 0 to the total watts of the relays in use, on every range.
  - **The last point** is the **live** power right now.
  - **Footer:** *Now … W*, the estimated energy (kWh) and the peak.
- **Relays:** name and watts per relay. **In use**: switch it off for a relay with nothing connected.
- **Touch buttons:** turn the touch pads on GPIO 4–7 on or off.
- **Device:** name, Identify, Restart, Update firmware…, **Remove device…**
- **Advanced:** chip temperature, free memory, storage, firmware size, last restart cause, ESP-IDF version, and **Factory reset this device**.

## Tank page
Tabs: **Overview** (live view, actions, chart) · **Alarms** (rules, buzzer, quiet hours) · **Display** (colours, highlight, LEDs, daytime display) · **Setup** (tank size, status labels, name, restart, update, remove, Advanced).
The alarm rules are a short list sorted by level, highest first (switched-off rules last), for example *Rises to 95 % · Long beeps ×8 · Blue*; tap a rule to edit it.
- **Live view:** level, distance, status, room light, signal and firmware.
- **Actions:** **Silence alarm**, **Beep** (a short test beep) and **Identify**.
- **Water level:** a chart with **1 h / 6 h / 24 h / Yesterday / 7 days**, the last point live, plus the lowest and highest level.
- **Tank size (calibration):** the distance when FULL and when EMPTY. **Use now** copies the current reading.
- **Alarm rules:** up to 6. Each rule has:

  | Field | Choices |
  |---|---|
  | On / off | |
  | **When level rises to** / **drops to** | a level in % |
  | **Sound** | Chirp · Short beeps · Long beeps · Triple beep · Siren · LEDs only |
  | **Times** | 1–30 |
  | **Flash colour** | none · green · red · blue · white · amber |

  - **Test:** plays the sound once. **Save:** sends the rule to the tank.
  - **Firing:** a rule fires once, then re-arms when the level has moved 5 % back.
  - **Stopping it:** the tank's push button or **Silence alarm** stops it.
  - **Defaults:** rule 1 = rises to 95 %, long beeps ×10, green. Rule 2 = drops to 10 %, short beeps ×10, red.
  - **Status labels:** at what % the status text says *Full* or *Low*. This does not affect alarms.
  - **Buzzer** on/off. Quiet hours are a global Home setting (shown read-only). The buzzer is also quiet whenever the room is dark; the LEDs still flash.
- **LED display:**
  - **Level colours:** Red → Blue, Red → Green, **Spectrum** (red → orange → yellow → green → cyan → blue, spread over the LEDs in use), or **Custom**. Custom gives one colour picker per LED, listed **top LED first**,
    like the real strip.
  - **Current level highlight** (slider 0–50 %): how much the top lit LED stands out. Half makes it brighter, half makes the LEDs below dimmer.
  - **LEDs used to show the level:** 1–8, counted from the bottom.
  - **Daytime minimum brightness:** during the global daytime hours the level LEDs never go fully dark; they stay at least this bright.
- **After a restart** (power cut or update), a rule does not sound for a level the tank is already at. It fires only when the level actually rises or drops into it.
- **Sensor problem:** when the ultrasonic sensor fails, all level LEDs on the tank **blink yellow rapidly**.
- **While a device is updating,** its page says so. Settings and controls work again once it has restarted.
- **Device and Advanced:** the same as for the switch.

Every tank setting and rule is stored **on the tank itself**, so it keeps working without the hub.

## Devices
- **Add a device:** a step-by-step guide plus **Start adding (2 minutes)**. The page shows *✅ Added: …* when the new device joins.
  If a new device tries to join while adding is closed, a banner offers **Allow**. See [setup.md](setup.md).
- **Device list:** one row per device with status, firmware and signal, plus **Open settings ›** (its page, where all of its settings are), **Remove device**, and **Update firmware…** (choose the `.bin`).
- **Update progress:** shown while the update runs, then *✅ Updated — now running x.y.z* once the device is back. The message clears after 2 minutes.

## Activity
Every ON/OFF, blocked attempt, setting or rule change, pairing, update, password change and device restart,
with the date and time. **Clear log** deletes it.

## Hub
- **Home settings** (global — apply to every device; each device keeps the last values it received):
  - **Quiet hours:** no sounds from any device.
  - **Daytime hours:** displays may stay on dimly; also the day/night fallback when no room light reading is available.
  - **Status light brightness:** in a bright room and in a dark room (1–40).
  - **Room light thresholds:** bright above / dark below (the tank's light sensor reading; the current reading is shown).
  Device pages show these read-only, with a link here. Everything that depends on a device's hardware stays on that device's page.
- **Night lock:** lock now, or every night. While it is active, ON commands are refused and recorded; OFF always works.
- **Security:**
  - Set or change the web password.
  - **Remove password…** needs the current one.
  - The emergency hotspot password.
- **WiFi:** the network the hub joins.
- **Hub:** name, restart, and hub firmware update.
- **Advanced:**
  - Chip details.
  - The **live log**, with a Clear button. Its time stamps read `yy-mm-dd hh:mm:ss`.
  - **Factory reset the hub.**
