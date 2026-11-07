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
