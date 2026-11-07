# Troubleshooting

| Problem | What to do |
|---|---|
| Phone shows *ERR_TOO_MANY_RETRIES* or *can't be reached*, but a PC works | Android Chrome blocks local addresses. Use another browser, or allow Chrome's local-network permission. Try the IP address instead of `leohub.local`. |
| `leohub.local` doesn't open | Some Android devices can't resolve `.local` names. Use the hub's IP. A DHCP reservation in the router keeps that IP fixed. |
| Live log shows "re-linked" now and then | Look for *"Router moved WiFi from channel X to Y"* lines nearby. Setting a fixed 2.4 GHz channel in the router stops these. A high "lost N/M" count means radio interference or a weak signal; move the boards closer. |
| Edge shows amber breaths (looking for the hub) | Is the hub on? Is it within range? If you factory-reset the hub, factory-reset the edge too (hold its BOOT button for 15 s), then pair it again. |
| "Device has a key this hub doesn't know" in the log | The edge was paired with another hub, or the hub was reset. Factory-reset the edge or send `UNPAIR` over USB, then pair it again. |
| Tank shows "Sensor not connected" | Check the HC-SR04 wiring (TRIG 4, ECHO 3, 5 V or 3.3 V and GND). Fault readings clear by themselves after 3 good readings. |
| Tank % looks wrong | Recalibrate: *tank page → Tank size → Use now* when full and when empty. |
| Tank buzzer is silent | Check that the buzzer is on, the time isn't inside quiet hours, the room isn't dark, and the alarm wasn't already silenced. |
| Wireless update is slow or fails | The signal is weak (see *Advanced → Signal*). Move the board closer; a failed update leaves the old firmware running. |
| Forgot the hub password | Connect the hub by USB and send `RESETPASS` (115200 baud). |
| Nothing else helps | Factory reset (see [firmware.md](firmware.md)). |
