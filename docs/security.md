# Security

| Threat | Protection |
|---|---|
| Someone nearby sends fake radio commands | Every packet is signed with the device's own key (HMAC-SHA256); unsigned or wrongly signed packets are ignored |
| Someone records and replays a command | A per-session random nonce and strictly increasing counters drop replays |
| A stranger's board pairs with your hub | Pairing is accepted only while *Devices → Allow new devices* is open (2 min), or in the first 10 min of a brand-new hub |
| Someone on your WiFi opens the web app | Hub password (salted SHA-256); signed-in browsers keep an HttpOnly cookie; 5 wrong tries pause sign-in for 30 s |
| Another website tries to control the hub from your browser | Requests are accepted only from pages served on your LAN (Origin check), and cookies are SameSite=Strict |
| Lights switched on at night | Night lock refuses every ON command and records it as BLOCKED; OFF always works |
| Not knowing what happened | The activity log records every action, with time and the IP address it came from |
| Lights coming on after a power cut | Relays are never saved; every relay starts OFF |
| Default hotspot password | The emergency hotspot uses a random per-hub password (*Hub → Security*) |

## Known limits
- The device key is sent once, **unencrypted, during pairing**. Keep pairing windows short.
- Radio packets are authenticated, **not encrypted**. Someone in range could see *that* a relay changed,
  but cannot cause it.
- After a **hub factory reset**, the setup hotspot has no password until WiFi is configured. The hub
  logs this, and it only happens after a deliberate reset.
- The web app uses plain HTTP inside your home network.

## Security test — 2026-11-08 (hub 2.4.0 / 2.4.1)
Run from a PC on the home WiFi against the real hub. Nothing was changed on the devices: the command tests used a
made-up device address, so no relay could switch.

| # | Test | Result |
|---|---|---|
| 1 | Read state / chip info without signing in | **Allowed — because no hub password is set.** With a password these return 401. |
| 2 | Send a command from another website (foreign `Origin`) | Blocked (403) ✅ |
| 3 | Send a command from the app's own page / a script on the LAN | Accepted (expected; needs the password once one is set) |
| 4 | Another website reading the hub's data (CORS) | Blocked — no CORS headers ✅ |
| 5 | Another website opening the live-update WebSocket | **Was allowed** (could read live state). **Fixed in hub 2.4.1**: now 401; the app's own page still connects (101) ✅ |
| 6 | Malformed JSON, 3 KB text field, bad MAC, path traversal (`/../../etc/passwd`) | Rejected (400/404); the hub kept running ✅ |
| 7 | Other open network ports (21, 22, 23, 81, 443, 3232, 8080, 8266) | None open — only the web app on port 80 ✅ |
| 8 | Radio packets (code review) | HMAC-SHA256 tag, per-session nonce, strictly increasing counters; unsigned, wrongly signed and replayed packets are dropped ✅ |
| 9 | Pairing (code review) | The key is sent in clear once while *Allow new devices* is open — see Known limits |

**Most important:** with no password, anyone on your WiFi (a guest's phone, a hacked smart TV) can switch your lights,
change every setting and even **install new firmware** on the hub and devices. Set a password in *Hub → Security*.
Other tips: keep the router's WiFi password strong, put guests on a guest network, and open *Allow new devices* only
when you are adding one.
