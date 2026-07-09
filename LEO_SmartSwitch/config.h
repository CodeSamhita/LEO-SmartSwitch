/* =====================================================================
   LEO Smart Switch  -  config.h
   ESP32-C3  /  Arduino-ESP32 core 3.x
   Compile-time constants and factory defaults only.
   Anything the user can change at runtime lives in NVS/LittleFS, not here.
   ===================================================================== */
#pragma once

#define FW_VERSION         "1.4.1-cluster"
#define DEVICE_MODEL       "LEO-C3"

/* ---- Identity -------------------------------------------------------- */
/* mDNS host is now per-device and user-changeable at runtime. MDNS_PREFIX is
   only the default ("leo-XXXXXX"). Device *detection* never relies on mDNS -
   it uses the stable MAC-derived id (gId) carried in the LAN beacon.       */
#define MDNS_PREFIX        "leo-"                     // (legacy) per-device prefix
#define DEFAULT_MDNS_HOST  "leoswitch"                // default host -> leoswitch.local
#define DHCP_HOSTNAME      "ESP32-c3-smartswitch"     // shown in router page
#define DEFAULT_AP_SSID    "LEO-SmartSwitch"
#define DEFAULT_AP_PASS    "leo12345"                 // >=8 chars, changeable in UI
#define DEFAULT_DEV_NAME   "Smart Switch"             // friendly name, user-editable
#define DEVICE_TYPE        "smartswitch"              // only switches join this cluster
#define DEFAULT_GROUP      "home"                     // logical cluster/group
#define DEFAULT_ROLE       "none"                     // none | master | slave

/* ---- LAN discovery beacon (mDNS-independent) ------------------------- */
#define BEACON_PORT        49497      // UDP broadcast port for peer discovery
#define BEACON_MS          5000       // how often we announce ourselves
#define PEER_TIMEOUT_MS    20000      // drop a peer not heard from in this long
#define MAX_PEERS          24         // max peers tracked

/* ---- Relays (ACTIVE-LOW opto board) ---------------------------------- */
/* 4 fixed physical channels. The UI may re-map which logical button drives
   which GPIO, but the hardware set never changes.                        */
#define RELAY_COUNT        4
#define RELAY_ACTIVE_LOW   1                          // 1 = LOW turns relay ON
static const int  RELAY_GPIO_POOL[RELAY_COUNT] = { 0, 1, 3, 10 };

/* ---- Status LED ------------------------------------------------------ */
#define NEOPIXEL_PIN       2
#define NEOPIXEL_COUNT     1
#define NEOPIXEL_BRIGHT    40                         // 0-255, default brightness
#define DEFAULT_LED_MODE   "status"                   // off | status | always
#define DEFAULT_LED_TIMEOUT 30                        // s of steady ONLINE before LED sleeps (0=never)

/* ---- RF -------------------------------------------------------------- */
/* C3 radio is fussy at full power; keep TX low for AP+STA stability.     */
#define WIFI_TX_POWER      WIFI_POWER_8_5dBm

/* ---- Timing (ms) ----------------------------------------------------- */
#define CPU_MHZ            80       // 80 runs much cooler than 160; WiFi needs >=80
#define TICK_PUSH_MS       1000     // websocket telemetry push cadence
#define ENERGY_FLUSH_MS    60000    // persist energy accumulators
#define CLOCK_PERSIST_MS   120000   // persist last-known epoch
#define STA_RETRY_MS       8000     // re-issue WiFi.begin while disconnected
#define WDT_TIMEOUT_S      10       // task watchdog -> auto reboot if loop hangs

/* ---- Time ------------------------------------------------------------ */
#define DEFAULT_TZ         "IST-5:30"     // POSIX TZ, India, no DST
#define DEFAULT_24H        0              // 0 = 12h AM/PM (default), 1 = 24h
#define NTP_SERVER_1       "pool.ntp.org"
#define NTP_SERVER_2       "time.google.com"

/* ---- Live console (serial mirror over WebSocket) ---------------------- */
#define CONSOLE_LINES      200      // RAM ring buffer; replayed to a client on /console connect
#define CONSOLE_LINE_LEN   110      // fixed-size lines (no String churn/fragmentation over uptime)

/* ---- Storage / logs -------------------------------------------------- */
#define FS_FILL_LIMIT      0.80     // prune logs above 80% LittleFS usage
#define LOG_MAX_AGE_DAYS   90       // ~3 months
#define LOG_MAX_LINES      400      // hard cap regardless of size
#define ENERGY_DAYS        31       // rolling window for the 30-day graph

#define CFG_FILE           "/config.json"
#define ENERGY_FILE        "/energy.json"
#define LOG_FILE           "/logs.jsonl"
#define CLOCK_FILE         "/clock.json"
#define AUTH_FILE          "/auth.json"

/* ---- Auth ------------------------------------------------------------ */
#define MAX_REMEMBERED_DEVICES  8   // remembered browser tokens

/* ---- Defaults applied on first boot / factory reset ------------------ */
struct RelayDefault { const char* name; int gpio; float watts; };
static const RelayDefault RELAY_DEFAULTS[RELAY_COUNT] = {
  { "Relay 1", 0,  60.0f },
  { "Relay 2", 1,  60.0f },
  { "Relay 3", 3,  60.0f },
  { "Relay 4", 10, 60.0f },
};

#define DEFAULT_TARIFF     6.50f    // INR per kWh, editable in UI
