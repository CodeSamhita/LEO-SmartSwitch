# Using the web app

Open **`http://leohub.local`**.
- If you open the hub by its IP address instead, the page moves you to `leohub.local` once it has
  checked that your phone or PC can reach that name. Some Android browsers can't, and then you stay on the IP.
- Add `?ip` to the address to never switch.
- On Android, Chrome may block local addresses; use another browser (for example Brave) or allow local-network access.

**Install it as an app (Android Chrome):** Chrome only installs apps from secure addresses. On the phone, open `chrome://flags/#unsafely-treat-insecure-origin-as-secure`, enter `http://leohub.local,http://192.168.1.115`, set it to **Enabled** and relaunch Chrome. Then open `http://leohub.local` and choose **⋮ → Install app**. It gets the LEO icon and opens full-screen; if the hub can't be reached it shows a short *not reachable* page. Without the flag, **⋮ → Add to home screen → Create shortcut** gives an icon that opens in Chrome.

The labels are kept short and there are no help bubbles. Less-used settings sit under **＋ More options** style links.

**Device pages** have two tabs: **Control** (live view, buttons, charts) and **Settings** — a list grouped by part
(e.g. *Sensors · Alarm · Level LEDs · Device*, or one row per relay). Each row opens one screen with a **‹** back button.
Screens explain in plain words what the current choice does and what is happening right now.

**Nothing changes by accident:** moving a slider, picking from a list or typing only shows the new value and brings up
the **Unsaved changes · Cancel · Save** bar; nothing is sent until you press **Save**. Leaving the screen asks first.
Settings that have a low and a high end (tank full/empty distance, Low/Full status text, light sensor OFF/FULL) use
**one slider with two handles** plus a number box for each end; the ends can't cross. *Hub → Home settings* stays greyed
until you tap **✎ Edit home settings**.

**Status lights:** every device flashes rapidly while booting (warm white), while a firmware update runs (cyan) and just
before a restart (white).

**Feedback and motion:** every button that changes something spins while it is sent, then flashes **green** (done) or
shakes **red** (failed). A slider's value turns green once it is saved. Pages and tabs fade in, toggles slide, and the
tank bar changes colour smoothly. If the phone asks for reduced motion, animations are off.

**Refresh keeps your place:** the address remembers the page and tab (for example `#tank/<mac>/display`), so a refresh
brings you back there. Tap **LEO Home Hub** or the logo to go to Home.

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
- **Controls:** every relay (with its colour dot and how long it has been on), All on / All off, signal, uptime and firmware.
- **Per relay (Settings → the relay):** name, watts, *In use*, and (switch 2.9+) **When switched ON**: *Stay ON until
  switched OFF* or *Pulse* (ON for the set milliseconds, then OFF by itself — for bells, gate openers, impulse relays),
  and **ON drives the relay pin LOW or HIGH** (most relay boards: LOW).
- **Touch pads (switch 2.9+):** on/off, and for each pad which relay it controls (or nothing) and whether it
  *toggles on each touch* or is *ON only while touched*. All on / All off were removed.
- **Timers (⏱ next to each relay):** *off in* 15 m / 30 m / 1 h / 2 h / 4 h, or *off at* a time. If the relay is off, the same
  buttons mean *on for*. The row shows *⏱ off in …*. Cancel removes it. Timers are kept by the hub (a hub restart cancels them)
  and each one is recorded in Activity.
- **Power use:** a smooth chart with **1H / 6H / 24H / Yday / 7D**. The big number is the live power; tap or hover the chart and
  it shows the value and time at that point. Peak, average and energy are shown beside it. The scale is always 0 to the total
  watts of the relays in use.
- **By light · cost:** stacked bars coloured per relay (hourly for 1H–Yday, daily for 7D), the estimated cost in ₹ for the
  period, a *per month* projection, and for each light: time on, kWh, ₹ and its share. **＋ Price per unit** sets a day and a
  night price (default ₹6.16 = BESCOM home rate ₹5.80 + 36 p surcharge; household tariffs have no day/night rate, so both are
  the same). This is an **estimate** from each light's watts and on-time, not a meter reading.
- **Relays:** name and watts per relay. **In use**: switch it off for a relay with nothing connected.
- **Touch buttons:** turn the touch pads on GPIO 4–7 on or off.
- **Device:** name, Identify, Restart, Update firmware…, **Remove device…**
- **Advanced:** chip temperature, free memory, storage, firmware size, last restart cause, ESP-IDF version, and **Factory reset this device**.

## Tank page
Tabs: **Overview** (live view, actions, chart) · **Alarms** (rules, buzzer) · **LEDs** (colours, level, brightness) · **Setup** (tank size, status labels, name, restart, update, remove, Advanced).
- **Buzzer → Sound allowed** (tank 1.10+): *Always*, *By time* (not in the night hours), *By room light* (only when the room is lit), or *By time and room light* (default).
- **LEDs → Brightness:** ☀ *Day · at least* (1–60 / 255) and ☾ *Night · at most* (0–255; 0 = level LEDs off at night).
  **＋ Follow room light** holds the sensor range (LEDs off at / full brightness at).
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
  - **Fixed-range settings are sliders** that save when you let go. Next to each % the app shows the real value: brightness out of 255, light sensor out of 4095, water in cm.
  - **Current level highlight** (slider 0–100 %): how much the top lit LED stands out. Half makes it brighter, half makes the LEDs below dimmer.
    Under the slider: the actual brightness of the top LED and of the LEDs below (out of 255), right now and in full daylight. At 100 % the top LED is 1.5× brighter and the others are at half.
  - **LEDs used to show the level:** 1–8, counted from the bottom.
  - **Daytime minimum brightness** (1–60 of 255): during the global daytime hours the level LEDs never go fully dark; they stay at least this bright.
- **Light sensor** (tank 1.9+): the reading now (0–4095), the lowest and highest readings of the last 24 h, and two calibration sliders.
  - **Dark room reading:** at or below this the level LEDs are off.
  - **Full daylight reading:** at or above this they are at full brightness (255). In between they follow the light.
  - **Now is dark / Now is full daylight** copy the current reading.
- **Advanced → LED simulation** (tank 1.9+): sliders for water level and light sensor, plus *Daytime hours* and *Sensor fault* switches. **Start (3 min)** makes the real strip show those values; a preview in the app shows the same. Nothing is saved, no alarm sounds, and the app keeps showing the real level. **Stop** ends it early.
- **Alarm rules** show the level in cm of water next to the %, and the overview shows the water depth.
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
  - **☀ Day:** the daytime hours and the status light brightness (0–255) in a bright room.
  - **☾ Night:** the night hours, the status light brightness in a dark room, and **Mute sounds** (no sounds during the night hours).
  - **◉ Status light:** Breath, Blink, Double blink, Steady or Off, every 1, 2, 2.5, 5 or 10 s, and the colour when all is well. A live preview dot shows the pattern. Warnings keep their own colours (amber = looking for the hub, blue = not paired / hotspot, cyan = updating or pairing, red = sensor fault). All devices stay in step.
- **🎨 LED colour calibration** (its own screen, from the Hub page; hub 2.7, switch 2.11, tank 1.12): while the screen is
  open, **every LED on every device** lights up in a test colour (white, warm white, cyan, yellow, magenta, orange or any
  colour) at the test brightness you choose — also at night. Set **Red / Green / Blue never below** (0–80 of 255): the
  lowest value each colour may drop to while it is lit. At low brightness a colour part can round down to off (warm white
  turns orange, cyan turns green); raise that colour's minimum until it stays — the real LEDs change as you move the
  slider, and the screen shows the R/G/B values sent and which would have dropped out. **Save** keeps the minimums;
  **Cancel**, leaving the screen or closing the app stops the test (it also stops by itself after 90 s without the app).
  - **◐ Room light:** one **Dark below** slider on a meter that shows the current reading. The "bright again" point is set automatically a little higher, so the two can never be set the wrong way round.
  - **Reset to defaults** restores all of the above.
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
  - The **live log**, with a Clear button. Its time stamps read `yy-mm-dd h:mm:ss AM/PM`. All times in the app use the 12-hour clock.
  - **Factory reset the hub.**
