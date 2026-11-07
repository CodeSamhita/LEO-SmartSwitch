# Using the web app

Open **`http://leohub.local`**.
- If you open the hub by its IP address instead, the page moves you to `leohub.local` once it has
  checked that your phone or PC can reach that name. Some Android browsers can't, and then you stay on the IP.
- Add `?ip` to the address to never switch, for example `http://192.168.1.115/?ip`.
- On Android, Chrome may block local addresses; use another browser or allow Chrome's local-network access.

Every setting has a **?** next to it. Tap it for a short explanation.

## Home
Quick controls for every device:
- **Switch card:** relay toggles, the total power, and **All on / All off**. Relays marked *not in use* are hidden and skipped by All on.
- **Tank card:** the level, distance, status and room light.

Tap a card (not its buttons) to open the device page.

## Switch page
- **Controls:** every relay, with how long it has been on, plus All on / All off, signal, uptime and firmware.
- **Power use, last 24 hours:** a chart of the average watts per 5 minutes, the estimated kWh for the day and the peak.
- **Relays:**
  - The name and watts of each relay.
  - **In use:** switch it off for a relay with nothing connected.
- **Touch buttons:** turn the TTP223 pads on GPIO 4–7 on or off.
- **Device:** name, Identify (flashes the LED), Restart, and Update / forget.
- **Advanced:** chip temperature, free memory, storage, firmware size, last restart cause, ESP-IDF version, and **factory reset**.

## Tank page
- **Live:** level, distance, status, room light, signal and firmware.
- **Actions:** **Silence alarm**, **Test buzzer** and **Identify**.
- **Water level, last 24 hours:** a chart, with the current, lowest and highest level.
- **Tank size (calibration):** the distance when FULL and when EMPTY.
  - **Use now** copies the current reading. Fill the tank and press *Use now* next to Full; do the same for Empty.
- **Alarms:**
  - The full % and low % levels.
  - **Buzzer** on/off.
  - **Quiet hours:** no beeping between these times. The buzzer is also quiet whenever the room is dark.
- **LED display:**
  - Level colours: **Red → Blue** or **Red → Green**.
  - **LEDs used to show the level:** 1–8, counted from the bottom.
  - **Daytime display:** between these hours the level LEDs never go fully dark. They stay at least
    at **Minimum brightness** (1–60). At night they follow the room light.
- **Device and Advanced:** the same as for the switch.

Every setting is stored **on the tank itself**, so it keeps working without the hub. The page shows the
new value once the tank confirms it.

## Devices
- **Allow new devices for 2 minutes:** pairing is only accepted while this is open.
- **Per device:** rename, the relays' names, watts and GPIO, touch buttons, Identify, Restart, **Forget**,
  and **Update firmware** (choose the `.bin`).

## Activity
Every ON/OFF, blocked attempt, setting change, pairing, update, password change and device restart,
with the date and time. **Clear log** deletes it.

## Hub
- **Night lock:**
  - Lock now, or lock automatically every night.
  - While it is active, every **ON** command is refused and recorded; OFF always works.
- **Security:** the web password (each browser signs in once and is remembered) and the emergency hotspot password.
- **WiFi:** the network the hub joins.
- **Hub:** name, restart, and hub firmware update.
- **Advanced:**
  - Chip details.
  - The **live log**, with a Clear button. Its time stamps read `yy-mm-dd hh:mm:ss`, or `boot+Ns` before the clock is set.
  - **Factory reset the hub.**
