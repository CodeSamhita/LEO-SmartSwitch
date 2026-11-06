/* =====================================================================
   LEO Smart Switch  -  LEO_SmartSwitch.ino
   ESP32-C3  /  Arduino-ESP32 core 3.x   (Phase 1 firmware)

   Libraries (Library Manager / PlatformIO):
     - ESPAsyncWebServer  (ESP32Async org, ESP32 core 3.x compatible)
     - AsyncTCP           (ESP32Async org)
     - ArduinoJson  v7
     - Adafruit_NeoPixel
   Built-in: WiFi, ESPmDNS, LittleFS, esp_task_wdt, esp_sntp, time

   Single-file sketch: config and the web UI are embedded below - just
   upload this sketch. Use a partition scheme that includes a filesystem
   (LittleFS stores settings, energy history and logs).
   ===================================================================== */

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <ESPmDNS.h>
#include <AsyncUDP.h>
#include <LittleFS.h>
#include <ESPAsyncWebServer.h>
#include <AsyncJson.h>
#include <ArduinoJson.h>
#include <Adafruit_NeoPixel.h>
#include <esp_task_wdt.h>
#include <esp_sntp.h>
#include <mbedtls/sha256.h>
#include <time.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
/* ##################### CONFIG (formerly config.h) #####################
   Compile-time constants and factory defaults. Edit here.            */
/* =====================================================================
   LEO Smart Switch  -  config.h
   ESP32-C3  /  Arduino-ESP32 core 3.x
   Compile-time constants and factory defaults only.
   Anything the user can change at runtime lives in NVS/LittleFS, not here.
   ===================================================================== */

#define FW_VERSION         "1.4.3-cluster"
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
#define STA_RETRY_MS       15000    // re-issue WiFi.begin while disconnected. Was 8000: each
                                    // retry does disconnect()+begin(), and a WPA handshake + DHCP
                                    // on a slow router can take >8 s, so retries kept aborting
                                    // attempts that were about to succeed.
#define WDT_TIMEOUT_S      10       // task watchdog -> auto reboot if loop hangs
#define LOG_PRUNE_MS       21600000 // re-run log pruning every 6h (boot-time prune can't
                                     // age-cutoff since the clock isn't synced yet then)

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
/* ################### END CONFIG ################### */


/* ============================ CONCURRENCY ============================
   AsyncWebServer/AsyncTCP callbacks (HTTP + WS handlers) all run
   sequentially on one dedicated AsyncTCP task (pinned via
   CONFIG_ASYNC_TCP_RUNNING_CORE=0), so handler-vs-handler access is
   already serialized. The one real race is that task vs. the separate
   main Arduino loop() task, whenever both touch the same shared array or
   struct field. A real FreeRTOS mutex (not a spinlock/critical section)
   is used - it's safe to hold across String/heap work, unlike
   portENTER_CRITICAL, which must never wrap anything that can block.
   RAII guard so a lock is never left held on an early return. */
SemaphoreHandle_t stateLock = nullptr;
struct LockGuard {
  LockGuard() { xSemaphoreTake(stateLock, portMAX_DELAY); }
  ~LockGuard() { xSemaphoreGive(stateLock); }
};
/* Separate lock for the console ring buffer. dbg() is called from loop(),
   the AsyncTCP task, the WiFi event task, and from inside code that already
   holds stateLock (peerUpsert/peerPrune) - stateLock is non-recursive, so
   reusing it here would deadlock. */
SemaphoreHandle_t consoleLock = nullptr;

/* Work deferred out of callback contexts into loop():
   - restartAt: async handlers used to call delay()+ESP.restart() inline,
     which blocks the AsyncTCP task so the HTTP reply was never actually
     transmitted - the browser/app always saw "failed" on Save WiFi / AP /
     reboot / factory reset even though it worked.
   - netUpPending/netDownPending: the WiFi event callback runs on the WiFi
     event task; it used to do mode switches, MDNS.end/begin, UDP rebinds and
     flash writes right there, racing loop() (the same class of crash the
     mdnsDirty deferral was added to prevent). */
volatile uint32_t restartAt = 0;
volatile bool     restartSaveEnergy = true;
volatile bool     netUpPending = false;
volatile bool     netDownPending = false;
static void scheduleRestart(uint32_t inMs, bool saveEnergy) {
  restartSaveEnergy = saveEnergy;
  uint32_t t = millis() + inMs; restartAt = t ? t : 1;
}

/* ============================== STATE ============================== */
struct RelayCh {
  String  name;
  int     gpio;
  float   watts;
  bool    on;
  uint32_t onSinceMs;
  uint32_t lastAccrueMs;
};

struct Config {
  String   staSsid, staPass;
  String   apSsid, apPass;
  String   tz;
  bool     h24;
  float    tariff;
  RelayCh  relay[RELAY_COUNT];
  // identity / cluster
  String   deviceName;           // friendly name (user editable)
  String   mdnsHost;             // "" = auto (leoswitch election); else explicit override
  String   role;                 // none | master | slave
  String   group;                // logical cluster name
  // status LED
  String   ledMode;              // off | status | always
  uint8_t  ledBright;            // 0-255
  uint16_t ledTimeout;           // s of steady ONLINE before LED sleeps (0=never)
  // auth
  bool     authEnabled;
  String   authUser, authPass;   // pass stored hashed (hex)
} cfg;

enum LedState { LED_BOOT, LED_AP, LED_CONNECTING, LED_ONLINE, LED_ERROR };
volatile LedState ledState = LED_BOOT;

bool   timeSynced     = false;
double clockDriftSec  = 0;        // last measured NTP correction
uint32_t loopMs       = 0;        // last loop duration
uint32_t lastStaTry   = 0;
uint32_t lastHealth   = 0;        // periodic "connected but stuck" check
int      badHealth    = 0;        // consecutive failed health checks
uint32_t staGoodMs    = 0;        // last time STA was verified healthy
uint32_t lastTick     = 0;
uint32_t lastEnergyFlush = 0;
uint32_t lastLogPrune = 0;
uint32_t lastClockPersist = 0;
bool   apActive       = false;

AsyncWebServer server(80);
AsyncWebSocket ws("/ws");
AsyncWebSocket consoleWs("/console");   // live serial-mirror stream (raw text, one line per frame)
Adafruit_NeoPixel pix(NEOPIXEL_COUNT, NEOPIXEL_PIN, NEO_GRB + NEO_KHZ800);

/* live console: RAM ring buffer of recent lines, replayed to a client that
   connects mid-stream, plus a copy always goes out to Serial and to any
   /console WebSocket clients. Not flash-persisted (would wear the flash for
   high-frequency debug lines) - the CRIT/ERR log below still is.
   Fixed-size char lines (not String) - a 200-slot ring buffer reassigned
   forever via Arduino String would fragment the heap over long uptime. */
char     consoleBuf[CONSOLE_LINES][CONSOLE_LINE_LEN];
int      consoleHead  = 0;
int      consoleCount = 0;

/* smart-home network discovery (mDNS + SSDP/UPnP, no cloud) */
AsyncUDP ssdp;
bool     ssdpUp = false;
String   gName, gUUID;            // friendly name + UPnP UDN, derived from MAC
String   gId;                     // STABLE unique id "LEO-XXXXXX" (MAC based)
String   gIdSuffix;               // the 6-hex tag (e.g. 30d7dc)
String   curMdnsHost;             // mDNS host currently advertised
bool     mdnsDirty = false;       // re-advertise mDNS from loop (not async ctx)
bool     beaconDirty = false;     // re-announce beacon from loop
uint32_t lastMdnsEval = 0;        // periodic leoswitch-owner re-evaluation
uint32_t lastNotify = 0;
/* LED runtime */
uint32_t ledOnSince = 0;          // when current visible state started
int      lastLedState = -1;
uint32_t identifyUntil = 0;       // blink-to-identify window
uint32_t staDownSince = 0;        // for the long-down hard reset

/* LAN cluster discovery beacon (mDNS-independent, WiFiUDP for reliable broadcast) */
WiFiUDP  beaconUdp;
bool     beaconUp = false;
uint32_t lastBeacon = 0;
struct Peer {
  String id, name, ip, role, group, type, fw;
  int    port;
  bool   cap;            // canonical-capable (mDNS on auto -> can own leoswitch.local)
  uint32_t lastSeen;
};
Peer  peers[MAX_PEERS];
int   peerCount = 0;

/* energy: rolling daily Wh per relay, keyed by YYYY-MM-DD */
struct DayBucket { String date; double wh[RELAY_COUNT]; };
DayBucket energyDays[ENERGY_DAYS];
int energyCount = 0;

String authTokens[MAX_REMEMBERED_DEVICES];
int    authTokenCount = 0;
int      loginFails     = 0;      // consecutive failed /api/login attempts
uint32_t loginLockUntil = 0;      // millis() until login is locked out

/* ============================ FORWARD ============================== */
void logEvent(const char* lvl, const String& msg);
void dbg(const String& msg);
void pushTelemetry();
String telemetryJson();

/* ============================ HELPERS ============================== */
static uint32_t fnv1a(const String& s) {
  uint32_t h = 2166136261u;
  for (size_t i = 0; i < s.length(); ++i) { h ^= (uint8_t)s[i]; h *= 16777619u; }
  return h;
}
/* Salted SHA-256 (salt = this device's stable MAC-derived id, gId).
   Replaces the old 32-bit FNV1a hash, which was brute-forceable offline. */
static String hashPass(const String& p) {
  String salted = "leo:" + gId + ":" + p;
  unsigned char out[32];
  mbedtls_sha256((const unsigned char*)salted.c_str(), salted.length(), out, 0);
  String s; s.reserve(64);
  for (int i = 0; i < 32; ++i) { char b[3]; snprintf(b, sizeof(b), "%02x", out[i]); s += b; }
  return s;
}
static bool constEq(const String& a, const String& b) {
  if (a.length() != b.length()) return false;
  uint8_t diff = 0;
  for (size_t i = 0; i < a.length(); ++i) diff |= (uint8_t)a[i] ^ (uint8_t)b[i];
  return diff == 0;
}
/* Pre-1.3.1 firmware stored "%08x" of fnv1a("leo:"+pass). Without accepting
   that format once, upgrading a unit that had login enabled locked the owner
   out entirely (and factory reset itself needs auth). */
static String legacyHashPass(const String& p) {
  char b[12]; snprintf(b, sizeof(b), "%08x", fnv1a("leo:" + p)); return String(b);
}
/* Returns true if `p` matches the stored password; transparently upgrades a
   legacy hash to salted SHA-256 on a successful match. */
static bool passMatches(const String& p) {
  if (!cfg.authPass.length()) return false;
  if (cfg.authPass.length() == 64) return constEq(hashPass(p), cfg.authPass);
  if (constEq(legacyHashPass(p), cfg.authPass)) { cfg.authPass = hashPass(p); return true; }
  return false;
}
static String randToken() {
  String t; for (int i = 0; i < 4; ++i) { char b[9]; snprintf(b, sizeof(b), "%08x", esp_random()); t += b; } return t;
}
static String nowDate() {
  time_t n = time(nullptr); struct tm tm; localtime_r(&n, &tm);
  char b[11]; strftime(b, sizeof(b), "%Y-%m-%d", &tm); return String(b);
}
static String nowClock12() {
  time_t n = time(nullptr); struct tm tm; localtime_r(&n, &tm);
  char b[16];
  if (cfg.h24) strftime(b, sizeof(b), "%H:%M:%S", &tm);
  else         strftime(b, sizeof(b), "%I:%M:%S %p", &tm);
  return String(b);
}

/* ============================ RELAYS =============================== */
inline int relayOffLevel() { return RELAY_ACTIVE_LOW ? HIGH : LOW; }
inline int relayOnLevel()  { return RELAY_ACTIVE_LOW ? LOW  : HIGH; }

void relayApplyPin(int gpio, bool on) {
  digitalWrite(gpio, on ? relayOnLevel() : relayOffLevel());
}
void relayInitPins() {
  // Drive OFF first, then enable output. Mechanical relays (>5 ms pull-in)
  // ignore the sub-ms switch window, so no false trigger at boot.
  for (int i = 0; i < RELAY_COUNT; ++i) {
    int g = cfg.relay[i].gpio;
    digitalWrite(g, relayOffLevel());
    pinMode(g, OUTPUT);
    digitalWrite(g, relayOffLevel());
    cfg.relay[i].on = false;
    cfg.relay[i].onSinceMs = 0;
    cfg.relay[i].lastAccrueMs = millis();
  }
}
void energyAccrue(int i);   // fwd
// (no default argument: Arduino IDE's auto-generated prototypes choke on them)
void relaySetEx(int i, bool on, bool push) {
  if (i < 0 || i >= RELAY_COUNT) return;
  if (cfg.relay[i].on == on) { if (push) pushTelemetry(); return; }  // no-op: don't reset its on-timer
  energyAccrue(i);                       // bank energy up to this instant
  cfg.relay[i].on = on;
  cfg.relay[i].onSinceMs = on ? millis() : 0;
  relayApplyPin(cfg.relay[i].gpio, on);
  dbg("Relay " + String(i) + " (" + cfg.relay[i].name + ") -> " + (on ? "ON" : "OFF"));
  if (push) pushTelemetry();
}
void relaySet(int i, bool on) { relaySetEx(i, on, true); }

/* ============================ ENERGY =============================== */
// Only ever called from energyAccrue() below, which already holds stateLock -
// do not call this from anywhere else without taking the lock first.
DayBucket* energyToday() {
  String d = nowDate();
  for (int i = 0; i < energyCount; ++i) if (energyDays[i].date == d) return &energyDays[i];
  // rotate
  if (energyCount < ENERGY_DAYS) {
    DayBucket* b = &energyDays[energyCount++]; b->date = d;
    for (int r = 0; r < RELAY_COUNT; ++r) b->wh[r] = 0; return b;
  }
  // shift out oldest
  for (int i = 1; i < ENERGY_DAYS; ++i) energyDays[i - 1] = energyDays[i];
  DayBucket* b = &energyDays[ENERGY_DAYS - 1]; b->date = d;
  for (int r = 0; r < RELAY_COUNT; ++r) b->wh[r] = 0; return b;
}
void energyAccrue(int i) {
  uint32_t now = millis();
  RelayCh& r = cfg.relay[i];
  if (r.on && r.watts > 0) {
    double hrs = (now - r.lastAccrueMs) / 3600000.0;
    if (hrs > 0) {
      LockGuard g;                                    // energyDays[] is read/written from both loop() and async handlers
      DayBucket* b = energyToday(); b->wh[i] += r.watts * hrs;
    }
  }
  r.lastAccrueMs = now;
}
void energyAccrueAll() { for (int i = 0; i < RELAY_COUNT; ++i) energyAccrue(i); }

void energySave() {
  energyAccrueAll();
  JsonDocument doc; JsonArray a = doc["days"].to<JsonArray>();
  { LockGuard g;
    for (int i = 0; i < energyCount; ++i) {
      JsonObject o = a.add<JsonObject>(); o["d"] = energyDays[i].date;
      JsonArray w = o["wh"].to<JsonArray>();
      for (int r = 0; r < RELAY_COUNT; ++r) w.add(energyDays[i].wh[r]);
    }
  }
  File f = LittleFS.open(ENERGY_FILE, "w"); if (f) { serializeJson(doc, f); f.close(); }
}
void energyLoad() {
  energyCount = 0;
  File f = LittleFS.open(ENERGY_FILE, "r"); if (!f) return;
  JsonDocument doc; if (deserializeJson(doc, f)) { f.close(); return; } f.close();
  for (JsonObject o : doc["days"].as<JsonArray>()) {
    if (energyCount >= ENERGY_DAYS) break;
    DayBucket& b = energyDays[energyCount];
    b.date = o["d"].as<String>(); int r = 0;
    for (JsonVariant v : o["wh"].as<JsonArray>()) { if (r < RELAY_COUNT) b.wh[r++] = v.as<double>(); }
    energyCount++;
  }
}

/* ============================ CONFIG =============================== */
void configDefaults() {
  cfg.staSsid = ""; cfg.staPass = "";
  cfg.apSsid = DEFAULT_AP_SSID; cfg.apPass = DEFAULT_AP_PASS;
  cfg.tz = DEFAULT_TZ; cfg.h24 = DEFAULT_24H; cfg.tariff = DEFAULT_TARIFF;
  cfg.deviceName = DEFAULT_DEV_NAME; cfg.mdnsHost = ""; // mdnsHost "" = auto (leoswitch election)
  cfg.role = DEFAULT_ROLE; cfg.group = DEFAULT_GROUP;
  cfg.ledMode = DEFAULT_LED_MODE; cfg.ledBright = NEOPIXEL_BRIGHT; cfg.ledTimeout = DEFAULT_LED_TIMEOUT;
  cfg.authEnabled = false; cfg.authUser = ""; cfg.authPass = "";
  for (int i = 0; i < RELAY_COUNT; ++i) {
    cfg.relay[i].name  = RELAY_DEFAULTS[i].name;
    cfg.relay[i].gpio  = RELAY_DEFAULTS[i].gpio;
    cfg.relay[i].watts = RELAY_DEFAULTS[i].watts;
    cfg.relay[i].on    = false;
  }
}
void configSave() {
  JsonDocument doc;
  doc["staSsid"] = cfg.staSsid; doc["staPass"] = cfg.staPass;
  doc["apSsid"]  = cfg.apSsid;  doc["apPass"]  = cfg.apPass;
  doc["tz"] = cfg.tz; doc["h24"] = cfg.h24; doc["tariff"] = cfg.tariff;
  doc["deviceName"] = cfg.deviceName; doc["mdnsHost"] = cfg.mdnsHost;
  doc["role"] = cfg.role; doc["group"] = cfg.group;
  doc["ledMode"] = cfg.ledMode; doc["ledBright"] = cfg.ledBright; doc["ledTimeout"] = cfg.ledTimeout;
  doc["authEnabled"] = cfg.authEnabled; doc["authUser"] = cfg.authUser; doc["authPass"] = cfg.authPass;
  JsonArray a = doc["relays"].to<JsonArray>();
  for (int i = 0; i < RELAY_COUNT; ++i) {
    JsonObject o = a.add<JsonObject>();
    o["name"] = cfg.relay[i].name; o["gpio"] = cfg.relay[i].gpio; o["watts"] = cfg.relay[i].watts;
  }
  File f = LittleFS.open(CFG_FILE, "w"); if (f) { serializeJson(doc, f); f.close(); }
}
void configLoad() {
  configDefaults();
  File f = LittleFS.open(CFG_FILE, "r"); if (!f) return;
  JsonDocument doc; if (deserializeJson(doc, f)) { f.close(); return; } f.close();
  cfg.staSsid = doc["staSsid"] | cfg.staSsid; cfg.staPass = doc["staPass"] | cfg.staPass;
  cfg.apSsid  = doc["apSsid"]  | cfg.apSsid;  cfg.apPass  = doc["apPass"]  | cfg.apPass;
  cfg.tz = doc["tz"] | cfg.tz; cfg.h24 = doc["h24"] | cfg.h24; cfg.tariff = doc["tariff"] | cfg.tariff;
  cfg.deviceName = doc["deviceName"] | cfg.deviceName; cfg.mdnsHost = doc["mdnsHost"] | cfg.mdnsHost;
  cfg.role = doc["role"] | cfg.role; cfg.group = doc["group"] | cfg.group;
  cfg.ledMode = doc["ledMode"] | cfg.ledMode;
  cfg.ledBright = doc["ledBright"] | cfg.ledBright;
  cfg.ledTimeout = doc["ledTimeout"] | cfg.ledTimeout;
  cfg.authEnabled = doc["authEnabled"] | false;
  cfg.authUser = doc["authUser"] | ""; cfg.authPass = doc["authPass"] | "";
  JsonArray a = doc["relays"].as<JsonArray>(); int i = 0;
  for (JsonObject o : a) {
    if (i >= RELAY_COUNT) break;
    cfg.relay[i].name  = o["name"]  | cfg.relay[i].name;
    cfg.relay[i].gpio  = o["gpio"]  | cfg.relay[i].gpio;
    cfg.relay[i].watts = o["watts"] | cfg.relay[i].watts;
    i++;
  }
}

/* ============================ AUTH ================================= */
void authLoad() {
  authTokenCount = 0;
  File f = LittleFS.open(AUTH_FILE, "r"); if (!f) return;
  JsonDocument doc; if (deserializeJson(doc, f)) { f.close(); return; } f.close();
  for (JsonVariant v : doc["tokens"].as<JsonArray>()) {
    if (authTokenCount < MAX_REMEMBERED_DEVICES) authTokens[authTokenCount++] = v.as<String>();
  }
}
void authSave() {
  JsonDocument doc; JsonArray a = doc["tokens"].to<JsonArray>();
  for (int i = 0; i < authTokenCount; ++i) a.add(authTokens[i]);
  File f = LittleFS.open(AUTH_FILE, "w"); if (f) { serializeJson(doc, f); f.close(); }
}
String authIssue() {
  String t = randToken();
  if (authTokenCount >= MAX_REMEMBERED_DEVICES) {            // drop oldest
    for (int i = 1; i < MAX_REMEMBERED_DEVICES; ++i) authTokens[i - 1] = authTokens[i];
    authTokenCount = MAX_REMEMBERED_DEVICES - 1;
  }
  authTokens[authTokenCount++] = t; authSave(); return t;
}
bool tokenValid(const String& t) {
  if (!t.length()) return false;
  for (int i = 0; i < authTokenCount; ++i) if (constEq(authTokens[i], t)) return true;
  return false;
}

/* ---- CSRF / DNS-rebinding guard ----
   The API uses wildcard CORS so any LEO device's dashboard can control its
   peers cross-origin. That also means, with login disabled (the default),
   any webpage the user's browser visits could otherwise POST to a guessed
   LAN IP and flip relays. Since a browser always sends an Origin header on
   a cross-origin fetch, reject anything whose Origin isn't a private LAN
   address (RFC1918) or an *.local mDNS host - a public/internet page can
   never satisfy that, while other LEO devices on the LAN always will. */
static bool ipIsPrivate(const IPAddress& ip) {
  if (ip[0] == 10) return true;
  if (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) return true;
  if (ip[0] == 192 && ip[1] == 168) return true;
  if (ip[0] == 127) return true;
  return false;
}
static bool originIsLocal(AsyncWebServerRequest* req) {
  if (!req->hasHeader("Origin")) return true;      // same-origin nav / non-browser client
  String o = req->header("Origin"); o.toLowerCase();
  int p = o.indexOf("://"); if (p < 0) return false;
  String host = o.substring(p + 3);
  int slash = host.indexOf('/'); if (slash >= 0) host = host.substring(0, slash);
  int colon = host.indexOf(':'); if (colon >= 0) host = host.substring(0, colon);
  // mDNS-addressed LEO device. Must be the host's *suffix* - the old
  // indexOf(".local") check also let e.g. "http://x.local.evil.com" through.
  if (host.endsWith(".local")) return true;
  IPAddress ip;
  if (!ip.fromString(host)) return false;           // not a bare IP and not *.local -> reject
  return ipIsPrivate(ip);
}

bool checkAuth(AsyncWebServerRequest* req) {
  if (!originIsLocal(req)) return false;
  if (!cfg.authEnabled) return true;
  return req->hasHeader("X-Auth-Token") && tokenValid(req->header("X-Auth-Token"));
}

/* ============================ CONSOLE =============================== */
/* Serial mirror: prints to USB serial as before, and fans the same line out
   to the RAM ring buffer + any live /console WebSocket clients so WiFi/mDNS
   issues (like the AP-stuck bug) can be diagnosed without a USB cable.
   `if (Serial)` matters here: on boards with USB-CDC serial (this project's
   README enables it for Arduino IDE builds), Serial.print() BLOCKS once the
   TX buffer fills if no USB host is actually attached and reading - which is
   the normal case once you unplug the programming cable. dbg() now runs on
   every relay toggle and WiFi retry, so without this guard the device stalls
   on every one of those the moment it's running untethered. */
void dbg(const String& msg) {
  char line[CONSOLE_LINE_LEN];
  snprintf(line, sizeof(line), "[%lus] %s", (unsigned long)(millis() / 1000), msg.c_str());
  if (consoleLock) xSemaphoreTake(consoleLock, portMAX_DELAY);
  memcpy(consoleBuf[consoleHead], line, sizeof(line));
  consoleHead = (consoleHead + 1) % CONSOLE_LINES;
  if (consoleCount < CONSOLE_LINES) consoleCount++;
  if (consoleLock) xSemaphoreGive(consoleLock);
  if (Serial) Serial.println(line);
  if (consoleWs.count()) consoleWs.textAll(line);
}
/* Whole ring buffer as ONE newline-joined frame. Replaying it as up to 200
   separate c->text() frames overflowed AsyncWebSocket's per-client queue
   (WS_MAX_QUEUED_MESSAGES, 32 by default), which makes the library close the
   client - so the console disconnected immediately on every connect and the
   web UI / app sat in a reconnect loop once the buffer had filled up. */
String consoleHistory() {
  String out;
  if (consoleLock) xSemaphoreTake(consoleLock, portMAX_DELAY);
  out.reserve(consoleCount * 48);
  int start = (consoleCount < CONSOLE_LINES) ? 0 : consoleHead;
  for (int i = 0; i < consoleCount; ++i) {
    if (i) out += '\n';
    out += consoleBuf[(start + i) % CONSOLE_LINES];
  }
  if (consoleLock) xSemaphoreGive(consoleLock);
  return out;
}

/* ============================ LOGS ================================= */
void logEvent(const char* lvl, const String& msg) {
  dbg(String("[") + lvl + "] " + msg);
  // only critical / error are persisted to flash
  if (strcmp(lvl, "CRIT") != 0 && strcmp(lvl, "ERR") != 0) return;
  JsonDocument d; d["t"] = (long)time(nullptr); d["s"] = timeSynced; d["lvl"] = lvl; d["msg"] = msg;
  File f = LittleFS.open(LOG_FILE, "a"); if (!f) return; serializeJson(d, f); f.print("\n"); f.close();
}
void logPrune() {
  File f = LittleFS.open(LOG_FILE, "r"); if (!f) return;
  std::vector<String> lines; while (f.available()) { String l = f.readStringUntil('\n'); if (l.length()) lines.push_back(l); } f.close();
  time_t now = time(nullptr); long cutoff = (long)now - (long)LOG_MAX_AGE_DAYS * 86400L;
  std::vector<String> keep;
  for (auto& l : lines) {
    JsonDocument d; if (deserializeJson(d, l)) continue;
    bool synced = d["s"] | false; long t = d["t"] | 0L;
    if (timeSynced && synced && t < cutoff) continue;   // too old
    keep.push_back(l);
  }
  // hard cap by count
  while ((int)keep.size() > LOG_MAX_LINES) keep.erase(keep.begin());
  // Storage pressure: drop oldest lines until the bytes we'd free bring usage
  // under the limit. The old loop re-checked LittleFS usage after each erase
  // from an in-memory vector - usage never changed, so whenever the FS was
  // over 80% for any reason it silently wiped the log down to one line.
  size_t total = LittleFS.totalBytes(), used = LittleFS.usedBytes();
  if (total && (double)used / total > FS_FILL_LIMIT) {
    size_t excess = used - (size_t)(total * FS_FILL_LIMIT);
    size_t freed = 0;
    while (freed < excess && keep.size() > 1) { freed += keep.front().length() + 1; keep.erase(keep.begin()); }
  }
  File w = LittleFS.open(LOG_FILE, "w"); if (!w) return;
  for (auto& l : keep) { w.print(l); w.print("\n"); } w.close();
}

/* ============================ CLOCK ================================ */
void clockPersist() {
  JsonDocument d; d["epoch"] = (long)time(nullptr);
  File f = LittleFS.open(CLOCK_FILE, "w"); if (f) { serializeJson(d, f); f.close(); }
}
void clockSeedFromLast() {
  File f = LittleFS.open(CLOCK_FILE, "r"); if (!f) return;
  JsonDocument d; if (deserializeJson(d, f)) { f.close(); return; } f.close();
  long e = d["epoch"] | 0L;
  if (e > 1700000000L) { struct timeval tv = { e, 0 }; settimeofday(&tv, nullptr); } // seed offline clock
}
void onNtpSync(struct timeval* tv) {
  // measure drift vs our running clock before it was corrected
  static bool first = true;
  time_t before = time(nullptr);
  clockDriftSec = (double)tv->tv_sec - (double)before;
  timeSynced = true;
  // INFO, not ERR: a normal sync was being written to the persisted error log
  if (first) { logEvent("INFO", String("NTP first sync, drift ") + (long)clockDriftSec + "s"); first = false; }
  clockPersist();
}
void clockBegin() {
  setenv("TZ", cfg.tz.c_str(), 1); tzset();
  clockSeedFromLast();                          // run own clock immediately
  sntp_set_time_sync_notification_cb(onNtpSync);
  configTzTime(cfg.tz.c_str(), NTP_SERVER_1, NTP_SERVER_2);
}

/* ============================ NEOPIXEL ============================= */
void ledShow(uint8_t r, uint8_t g, uint8_t b) { pix.setPixelColor(0, pix.Color(r, g, b)); pix.show(); }
void ledOff() { pix.setPixelColor(0, 0); pix.show(); }
void ledTick() {
  static uint32_t last = 0; if (millis() - last < 30) return; last = millis();

  // reset the on-timer whenever the visible state changes
  if ((int)ledState != lastLedState) { lastLedState = (int)ledState; ledOnSince = millis(); }

  pix.setBrightness(cfg.ledBright ? cfg.ledBright : 1);

  // identify: blink white briefly regardless of mode (find the physical box)
  if (millis() < identifyUntil) {
    bool on = ((millis() / 150) % 2) == 0;
    if (on) ledShow(255, 255, 255); else ledOff();
    return;
  }

  if (cfg.ledMode == "off") { ledOff(); return; }

  // status mode: once steady-online, sleep the LED after the timeout (saves power)
  bool steadyOnline = (ledState == LED_ONLINE);
  if (cfg.ledMode == "status" && steadyOnline && cfg.ledTimeout > 0 &&
      (millis() - ledOnSince > (uint32_t)cfg.ledTimeout * 1000UL)) { ledOff(); return; }

  float ph = (sinf(millis() / 500.0f) + 1) / 2;           // 0..1 slow pulse
  switch (ledState) {
    case LED_BOOT:       ledShow(20, 20, 20); break;
    case LED_AP:         ledShow(0, 0, (uint8_t)(40 + ph * 120)); break;   // pulsing blue
    case LED_CONNECTING: ledShow((uint8_t)(60 + ph * 100), (uint8_t)(30 + ph * 50), 0); break; // amber
    case LED_ONLINE:     ledShow(0, 30, 0); break;        // solid dim green
    case LED_ERROR:      ledShow(120, 0, 0); break;
  }
}

/* ========================= DISCOVERY ============================== */
/* Makes the device appear as a smart-home device on the LAN, with no cloud
   and no voice ecosystem: rich mDNS (your app + any Bonjour/NSD browser) plus
   a tiny SSDP/UPnP responder (generic network / UPnP device lists).        */
void buildIdentity() {
  if (gId.length()) return;
  String m = WiFi.macAddress(); m.replace(":", ""); m.toLowerCase();   // 12 hex
  if (m.length() < 12) m = "000000000000";
  String id6 = m.substring(6);                       // last 6 hex = unique tag
  gIdSuffix = id6;
  gId   = "LEO-" + id6;                               // STABLE id (mDNS-independent)
  gName = cfg.deviceName.length() ? cfg.deviceName : String(DEFAULT_DEV_NAME);
  gUUID = "uuid:4c454f53-" + m.substring(0, 4) + "-" + m.substring(4, 8) + "-8a2e-" + m;
  // cfg.mdnsHost stays "" = auto: the leoswitch.local owner is elected at runtime.
  // same firmware on every unit -> AP name == device id so they always correspond
  if (!cfg.apSsid.length() || cfg.apSsid == DEFAULT_AP_SSID) cfg.apSsid = gId;
}

/* ---- leoswitch.local ownership election (mDNS-independent detection) ----
   Goal: leoswitch.local is reachable at all times even with many devices.
   Rule: the MASTER owns "leoswitch"; if no master is present, the lowest-id
   online device owns it; everyone else uses their unique "leo-<id>". A device
   with an explicit mDNS override opts out (cap=false) and keeps its own name. */
bool canonicalOwner() {
  if (cfg.mdnsHost.length()) return false;            // explicit override -> not in election
  bool selfMaster = (cfg.role == "master");
  String bestMaster = selfMaster ? gId : "";
  LockGuard g;                                        // peers[] is also touched from loop()
  for (int i = 0; i < peerCount; ++i) {
    if (!peers[i].cap) continue;
    if (peers[i].role == "master" && (bestMaster == "" || peers[i].id < bestMaster))
      bestMaster = peers[i].id;
  }
  if (bestMaster.length()) return selfMaster && gId == bestMaster;
  String lowest = gId;                                // no master -> lowest id wins
  for (int i = 0; i < peerCount; ++i)
    if (peers[i].cap && peers[i].id < lowest) lowest = peers[i].id;
  return gId == lowest;
}
String effectiveMdnsHost() {
  if (cfg.mdnsHost.length()) return cfg.mdnsHost;     // user override
  return canonicalOwner() ? String(DEFAULT_MDNS_HOST) : (String(MDNS_PREFIX) + gIdSuffix);
}

void discoveryMdns() {
  MDNS.end();
  String host = effectiveMdnsHost();
  bool ok = MDNS.begin(host.c_str());
  if (!ok) { delay(50); ok = MDNS.begin(host.c_str()); }   // one retry
  if (!ok) { logEvent("ERR", "mDNS begin failed for " + host); return; }
  dbg("mDNS advertising as " + host + ".local");
  curMdnsHost = host;
  gName = cfg.deviceName.length() ? cfg.deviceName : String(DEFAULT_DEV_NAME);
  MDNS.setInstanceName(gName);
  MDNS.addService("http", "tcp", 80);
  MDNS.addServiceTxt("http", "tcp", "id",     gId);
  MDNS.addServiceTxt("http", "tcp", "model",  DEVICE_MODEL);
  MDNS.addServiceTxt("http", "tcp", "fw",     FW_VERSION);
  MDNS.addServiceTxt("http", "tcp", "type",   DEVICE_TYPE);
  MDNS.addServiceTxt("http", "tcp", "path",   "/");
  // dedicated service type so a controller can browse only LEO switches
  MDNS.addService("leoswitch", "tcp", 80);
  MDNS.addServiceTxt("leoswitch", "tcp", "id",    gId);
  MDNS.addServiceTxt("leoswitch", "tcp", "name",  gName);
  MDNS.addServiceTxt("leoswitch", "tcp", "model", DEVICE_MODEL);
  MDNS.addServiceTxt("leoswitch", "tcp", "role",  cfg.role);
  MDNS.addServiceTxt("leoswitch", "tcp", "group", cfg.group);
  MDNS.addServiceTxt("leoswitch", "tcp", "type",  DEVICE_TYPE);
}

/* ---------- LAN cluster beacon: detection without relying on mDNS ------- */
String beaconPacket() {
  JsonDocument d;
  d["leo"] = 1; d["id"] = gId; d["name"] = gName;
  d["ip"] = WiFi.localIP().toString(); d["port"] = 80;
  d["role"] = cfg.role; d["group"] = cfg.group; d["type"] = DEVICE_TYPE; d["fw"] = FW_VERSION;
  d["cap"] = (cfg.mdnsHost.length() == 0);     // auto -> eligible to own leoswitch.local
  d["mdns"] = curMdnsHost;
  String s; serializeJson(d, s); return s;
}
void peerUpsert(JsonDocument& d, const String& fromIp) {
  String id = d["id"] | "";
  if (!id.length() || id == gId) return;               // ignore self / junk
  if (String(d["type"] | "") != DEVICE_TYPE) return;   // only smart switches
  LockGuard g;                                         // peers[] is also read/written from loop()
  for (int i = 0; i < peerCount; ++i) {
    if (peers[i].id == id) {                            // refresh existing
      peers[i].name = d["name"] | peers[i].name;
      peers[i].ip   = d["ip"]   | fromIp;
      peers[i].role = d["role"] | ""; peers[i].group = d["group"] | "";
      peers[i].fw   = d["fw"] | ""; peers[i].port = d["port"] | 80;
      peers[i].cap  = d["cap"] | true;
      peers[i].lastSeen = millis(); return;
    }
  }
  int slot;
  if (peerCount < MAX_PEERS) {
    slot = peerCount++;
  } else {
    // full: evict the least-recently-seen peer rather than silently
    // dropping a newly-discovered one forever.
    slot = 0;
    for (int i = 1; i < peerCount; ++i) if (peers[i].lastSeen < peers[slot].lastSeen) slot = i;
  }
  Peer& p = peers[slot];
  p.id = id; p.name = d["name"] | id; p.ip = d["ip"] | fromIp;
  p.role = d["role"] | ""; p.group = d["group"] | ""; p.type = DEVICE_TYPE;
  p.fw = d["fw"] | ""; p.port = d["port"] | 80; p.cap = d["cap"] | true; p.lastSeen = millis();
  dbg("Peer discovered: " + p.id + " (" + p.name + ") at " + p.ip);
}
void peerPrune() {
  uint32_t now = millis();
  LockGuard g;                                         // peers[] is also read/written from async handlers
  for (int i = peerCount - 1; i >= 0; --i) {
    if (now - peers[i].lastSeen > PEER_TIMEOUT_MS) {
      dbg("Peer timed out: " + peers[i].id);
      for (int j = i; j < peerCount - 1; ++j) peers[j] = peers[j + 1];
      peerCount--;
    }
  }
}
void beaconStart() {
  beaconUdp.stop();
  beaconUp = beaconUdp.begin(BEACON_PORT);   // (re)bind on the active interface
}
void beaconAnnounce() {
  if (!beaconUp) return;
  String s = beaconPacket();
  // subnet-directed broadcast is the most reliable; fall back to global broadcast
  IPAddress bc(255, 255, 255, 255);
  if (WiFi.status() == WL_CONNECTED) {
    IPAddress ip = WiFi.localIP(), m = WiFi.subnetMask();
    bc = IPAddress(ip[0] | ~m[0], ip[1] | ~m[1], ip[2] | ~m[2], ip[3] | ~m[3]);
  } else if (apActive) {
    bc = IPAddress(192, 168, 4, 255);
  }
  beaconUdp.beginPacket(bc, BEACON_PORT);
  beaconUdp.write((const uint8_t*)s.c_str(), s.length());
  beaconUdp.endPacket();
  // also hit the global broadcast in case the router prefers it
  beaconUdp.beginPacket(IPAddress(255, 255, 255, 255), BEACON_PORT);
  beaconUdp.write((const uint8_t*)s.c_str(), s.length());
  beaconUdp.endPacket();
}
void beaconPoll() {
  if (!beaconUp) return;
  for (int guard = 0; guard < 6; ++guard) {            // bounded per loop
    int sz = beaconUdp.parsePacket();
    if (sz <= 0) return;
    char buf[600];
    int n = beaconUdp.read(buf, sz < 599 ? sz : 599);
    if (n <= 0) return;
    buf[n] = 0;
    JsonDocument d;
    if (deserializeJson(d, buf, n)) continue;
    if ((int)(d["leo"] | 0) != 1) continue;
    peerUpsert(d, beaconUdp.remoteIP().toString());
  }
}

void ssdpReply(AsyncUDPPacket& p, const String& st, const String& usnSuffix) {
  String ip = WiFi.localIP().toString();
  String r  = "HTTP/1.1 200 OK\r\n";
  r += "CACHE-CONTROL: max-age=1800\r\n";
  r += "EXT:\r\n";
  r += "LOCATION: http://" + ip + "/description.xml\r\n";
  r += "SERVER: ESP32/1.0 UPnP/1.1 LEO/1.0\r\n";
  r += "ST: " + st + "\r\n";
  r += "USN: " + gUUID + usnSuffix + "\r\n\r\n";
  p.printf("%s", r.c_str());
}
void ssdpStart() {
  if (ssdpUp) return;
  if (!ssdp.listenMulticast(IPAddress(239, 255, 255, 250), 1900)) return;
  ssdp.onPacket([](AsyncUDPPacket p) {
    if (p.length() < 8) return;
    String req; req.reserve(p.length());
    for (size_t i = 0; i < p.length(); ++i) req += (char)p.data()[i];
    if (req.indexOf("M-SEARCH") < 0) return;
    String st = "upnp:rootdevice";
    int i = req.indexOf("ST:"); if (i < 0) i = req.indexOf("st:");
    if (i >= 0) { int e = req.indexOf("\r\n", i); st = req.substring(i + 3, e); st.trim(); }
    if (st.indexOf("ssdp:all") >= 0) {
      ssdpReply(p, "upnp:rootdevice", "::upnp:rootdevice");
      ssdpReply(p, gUUID, "");
      ssdpReply(p, "urn:schemas-upnp-org:device:Basic:1", "::urn:schemas-upnp-org:device:Basic:1");
    } else if (st.indexOf("rootdevice") >= 0) {
      ssdpReply(p, "upnp:rootdevice", "::upnp:rootdevice");
    } else if (st.indexOf("Basic") >= 0) {
      ssdpReply(p, "urn:schemas-upnp-org:device:Basic:1", "::urn:schemas-upnp-org:device:Basic:1");
    } else if (st.indexOf("4c454f53") >= 0) {
      ssdpReply(p, gUUID, "");
    }
  });
  ssdpUp = true;
}
void ssdpStop() { if (!ssdpUp) return; ssdp.close(); ssdpUp = false; }
void ssdpNotify() {
  if (WiFi.status() != WL_CONNECTED) return;
  String ip = WiFi.localIP().toString();
  const char* nts[3] = { "upnp:rootdevice", "", "urn:schemas-upnp-org:device:Basic:1" };
  const char* sfx[3] = { "::upnp:rootdevice", "", "::urn:schemas-upnp-org:device:Basic:1" };
  for (int k = 0; k < 3; ++k) {
    String nt = nts[k][0] ? String(nts[k]) : gUUID;
    String m  = "NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n";
    m += "CACHE-CONTROL: max-age=1800\r\n";
    m += "LOCATION: http://" + ip + "/description.xml\r\n";
    m += "SERVER: ESP32/1.0 UPnP/1.1 LEO/1.0\r\n";
    m += "NT: " + nt + "\r\nNTS: ssdp:alive\r\nUSN: " + gUUID + sfx[k] + "\r\n\r\n";
    ssdp.writeTo((uint8_t*)m.c_str(), m.length(), IPAddress(239, 255, 255, 250), 1900);
  }
}

/* ============================ WIFI ================================= */
void apStart() {
  if (apActive) return;
  WiFi.softAP(cfg.apSsid.c_str(), cfg.apPass.c_str());
  apActive = true;
}
void apStop() { if (!apActive) return; WiFi.softAPdisconnect(true); apActive = false; }

/* Runs on the WiFi event task: only set flags here, the real work happens
   in wifiHandlePending() from loop(). */
void wifiEvent(WiFiEvent_t e) {
  switch (e) {
    case ARDUINO_EVENT_WIFI_STA_GOT_IP:
      ledState = LED_ONLINE;
      netUpPending = true;
      break;
    case ARDUINO_EVENT_WIFI_STA_DISCONNECTED:
      ledState = cfg.staSsid.length() ? LED_CONNECTING : LED_AP;
      netDownPending = true;
      break;
    default: break;
  }
}
void wifiHandlePending() {
  if (netDownPending) {
    netDownPending = false;
    if (WiFi.status() != WL_CONNECTED) {
      dbg("WiFi STA disconnected");
      ssdpStop();
      if (WiFi.getMode() != WIFI_AP_STA) WiFi.mode(WIFI_AP_STA);
      apStart();                      // bring AP back fast
    }
  }
  if (netUpPending) {
    netUpPending = false;
    if (WiFi.status() == WL_CONNECTED) {
      apStop();                       // drop AP the instant we are online
      WiFi.mode(WIFI_STA);
      discoveryMdns();                // refresh mDNS on the STA interface
      ssdpStart(); ssdpNotify();      // announce as a smart-home device
      beaconStart(); beaconAnnounce();// join the LAN cluster
      staDownSince = 0; badHealth = 0; staGoodMs = millis(); lastHealth = millis();
      // INFO, not ERR: every normal (re)connect was landing in the error log
      logEvent("INFO", "WiFi connected " + WiFi.localIP().toString());
    }
  }
}
void wifiBegin() {
  WiFi.persistent(false);
  WiFi.onEvent(wifiEvent);
  buildIdentity();                    // derive unique id / AP / mDNS from MAC FIRST
  WiFi.setHostname(gId.c_str());      // unique per-device name in the router's client list
  WiFi.setSleep(true);                // modem sleep in STA -> big reduction in heat/power
  WiFi.setAutoReconnect(true);        // let the SDK also retry under us
  if (cfg.staSsid.length()) {
    WiFi.mode(WIFI_AP_STA);
    apStart();                        // AP available immediately at boot
    ledState = LED_CONNECTING;
    WiFi.setTxPower(WIFI_TX_POWER);
    WiFi.begin(cfg.staSsid.c_str(), cfg.staPass.c_str());
  } else {
    WiFi.mode(WIFI_AP);
    apStart();
    ledState = LED_AP;
    WiFi.setTxPower(WIFI_TX_POWER);
  }
  discoveryMdns();                    // advertise on AP immediately too
  beaconStart();                      // listen for peers (also works on AP subnet)
}
void wifiForceReconnect(const char* why) {
  logEvent("ERR", String("WiFi recovery: ") + why);
  // Snapshot into locals under the lock rather than reading cfg.staSsid's
  // buffer directly at the WiFi.begin() call sites below: an async handler
  // (/api/network) can reassign that String concurrently, which frees its
  // old heap buffer - reading through a stale .c_str() pointer at that
  // moment is a use-after-free, not just a stale value.
  String ssid, pass;
  { LockGuard g; ssid = cfg.staSsid; pass = cfg.staPass; }
  if (WiFi.getMode() != WIFI_AP_STA) WiFi.mode(WIFI_AP_STA);
  apStart();                                   // make sure user still has the AP
  WiFi.disconnect();                           // drop the wedged association
  WiFi.setTxPower(WIFI_TX_POWER);
  WiFi.begin(ssid.c_str(), pass.c_str());
  lastStaTry = millis();
  ledState = LED_CONNECTING;
}

void wifiTick() {
  if (!cfg.staSsid.length()) return;           // AP-only, nothing to manage

  if (WiFi.status() == WL_CONNECTED) {
    // Detect "shows connected but is actually stuck": no IP, or RSSI flatlined.
    if (millis() - lastHealth >= 15000) {
      lastHealth = millis();
      bool healthy = (WiFi.localIP() != IPAddress(0, 0, 0, 0)) && ((int)WiFi.RSSI() != 0);
      if (healthy) { badHealth = 0; staGoodMs = millis(); staDownSince = 0; }
      else if (++badHealth >= 2) { badHealth = 0; wifiForceReconnect("link stale"); }
    }
    return;
  }

  // Not connected -> keep retrying every STA_RETRY_MS (5-10 s window).
  if (millis() - lastStaTry > STA_RETRY_MS) {
    lastStaTry = millis();
    if (WiFi.getMode() != WIFI_AP_STA) WiFi.mode(WIFI_AP_STA);
    apStart();                                 // AP stays up while we retry
    // Snapshot once, under the lock (see wifiForceReconnect for why), and
    // reuse the same copy for both begin() calls below.
    String ssid, pass;
    { LockGuard g; ssid = cfg.staSsid; pass = cfg.staPass; }
    // A bare repeat WiFi.begin() after a failed/absent-AP attempt is silently
    // ignored by the IDF driver (it needs its connect state machine reset).
    // Without this disconnect, a device that boots before its router is up
    // (or briefly loses the AP) never actually retries and is stuck on AP
    // forever even once the SSID is broadcasting again.
    WiFi.disconnect();
    WiFi.setTxPower(WIFI_TX_POWER);
    WiFi.begin(ssid.c_str(), pass.c_str());
    dbg("WiFi retry: joining " + ssid);
    // If we've been down a long time, a full radio reset clears deeper wedges.
    if (staDownSince == 0) staDownSince = millis();
    if (millis() - staDownSince > 120000) {    // 2 min of failure -> hard reset radio
      staDownSince = millis();
      dbg("WiFi hard reset: 2 min without a connection");
      WiFi.disconnect(true); delay(20); WiFi.mode(WIFI_AP_STA); apStart();
      WiFi.begin(ssid.c_str(), pass.c_str());
    }
  }
}

/* ============================ TELEMETRY ============================ */
/* LittleFS.usedBytes() walks the whole filesystem block map - tens of ms at
   80 MHz. It used to run inside telemetryJson(), i.e. every second AND on
   every relay toggle (4x for All On/Off), on whichever task was serving the
   request. That was a big part of the sluggish toggles. Cached instead. */
uint32_t fsUsedKB = 0, fsTotalKB = 0, lastFsStat = 0;
void fsStatRefresh() {
  fsUsedKB  = (uint32_t)(LittleFS.usedBytes() / 1024);
  fsTotalKB = (uint32_t)(LittleFS.totalBytes() / 1024);
  lastFsStat = millis();
}
String connStateStr() {
  if (WiFi.status() == WL_CONNECTED) return "WIFI";
  if (cfg.staSsid.length()) return "RECONNECTING";
  return "AP";
}
String telemetryJson() {
  JsonDocument d;
  d["clock"]   = nowClock12();
  d["date"]    = nowDate();
  d["synced"]  = timeSynced;
  d["conn"]    = connStateStr();
  d["ssid"]    = WiFi.status() == WL_CONNECTED ? WiFi.SSID() : cfg.apSsid;
  d["rssi"]    = WiFi.status() == WL_CONNECTED ? WiFi.RSSI() : 0;
  d["ip"]      = WiFi.status() == WL_CONNECTED ? WiFi.localIP().toString() : WiFi.softAPIP().toString();
  d["mac"]     = WiFi.macAddress();
  d["temp"]    = temperatureRead();
  d["uptime"]  = (uint32_t)(millis() / 1000);
  d["loopms"]  = loopMs;
  d["heapFree"] = ESP.getFreeHeap() / 1024;
  d["heapTotal"] = ESP.getHeapSize() / 1024;
  d["fsUsed"]  = fsUsedKB;
  d["fsTotal"] = fsTotalKB;
  d["mdns"]    = (curMdnsHost.length() ? curMdnsHost : String(DEFAULT_MDNS_HOST)) + ".local";
  d["id"]      = gId;
  d["name"]    = gName;
  d["role"]    = cfg.role;
  d["group"]   = cfg.group;
  d["model"]   = DEVICE_MODEL;
  d["version"] = FW_VERSION;
  d["tariff"]  = cfg.tariff;
  float totalW = 0;
  for (int i = 0; i < RELAY_COUNT; ++i) if (cfg.relay[i].on) totalW += cfg.relay[i].watts;
  d["total_watts"] = totalW;
  JsonArray a = d["relays"].to<JsonArray>();
  for (int i = 0; i < RELAY_COUNT; ++i) {
    JsonObject o = a.add<JsonObject>();
    o["name"] = cfg.relay[i].name; o["gpio"] = cfg.relay[i].gpio;
    o["watts"] = cfg.relay[i].watts; o["on"] = cfg.relay[i].on;
    o["onSecs"] = cfg.relay[i].on ? (uint32_t)((millis() - cfg.relay[i].onSinceMs) / 1000) : 0;
  }
  String out; serializeJson(d, out); return out;
}
void pushTelemetry() { if (ws.count()) ws.textAll(telemetryJson()); }


/* ===================== WEB UI (formerly data/index.html) =====================
   Embedded in flash, so there is no separate LittleFS upload step any more.
   LittleFS now only holds config/energy/logs, and those files are no longer
   web-reachable (serveStatic used to expose /config.json with the WiFi
   password and /auth.json with login tokens to anyone on the LAN). */
static const char INDEX_HTML[] PROGMEM = R"LEOHTML(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>LEO Smart Switch</title>
<style>
:root{
  --bg:#0c0f12;--surface:#14191e;--surface2:#1b222a;--line:#26303a;
  --txt:#e7edf2;--muted:#8aa0b2;--accent:#34d3b0;--on:#34d3b0;--off:#3a4651;
  --warn:#f0a93b;--bad:#e2564b;--good:#46c46a;--pwr:#f0a93b;--navh:62px;--r:14px}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(1200px 600px at 70% -10%,#13202022,transparent),var(--bg);
  color:var(--txt);font:14px/1.45 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  -webkit-tap-highlight-color:transparent}
button{font:inherit;color:inherit;cursor:pointer}
.wrap{max-width:560px;margin:0 auto;padding:14px 14px calc(var(--navh) + 24px)}
@media(min-width:760px){.wrap{max-width:1000px;padding:22px 24px calc(var(--navh) + 28px)}}
@media(min-width:1200px){.wrap{max-width:1140px}}

/* header */
header{display:flex;align-items:center;gap:11px;padding:2px 2px 0}
.logo{width:40px;height:40px;border-radius:11px;flex:0 0 auto;background:linear-gradient(150deg,#1d2730,#10161b);
  border:1px solid var(--line);display:grid;place-items:center;cursor:pointer}
.logo svg{width:22px;height:22px}
.htitle{flex:1;min-width:0;cursor:pointer}
.htitle h1{margin:0;font-size:16px;font-weight:650;letter-spacing:.2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sub{display:flex;gap:8px;align-items:center;font-size:11.5px;color:var(--muted);margin-top:1px}
.pill{display:inline-flex;align-items:center;gap:5px;padding:2px 8px;border-radius:20px;background:var(--surface2);
  border:1px solid var(--line);font-weight:600;font-size:10.5px;letter-spacing:.4px}
.dot{width:7px;height:7px;border-radius:50%;background:var(--muted)}
.pill.wifi .dot{background:var(--good)}.pill.ap .dot{background:var(--accent)}
.pill.reconnecting .dot{background:var(--warn);animation:bl 1s infinite}
.rolebadge{font-size:9.5px;font-weight:700;letter-spacing:.5px;padding:2px 7px;border-radius:20px;border:1px solid var(--line)}
.rolebadge.master{color:var(--accent);border-color:#2a4a44}.rolebadge.slave{color:var(--muted)}
@keyframes bl{50%{opacity:.25}}

.clockrow{display:flex;justify-content:space-between;align-items:baseline;margin:12px 2px 10px}
.clock{font-size:30px;font-weight:300;letter-spacing:1px;font-variant-numeric:tabular-nums}
@media(min-width:760px){.clock{font-size:38px}}
.clock small{font-size:13px;color:var(--muted);margin-left:6px}
.ipv{font-size:12px;color:var(--muted);font-variant-numeric:tabular-nums}

.statsbar{background:var(--surface);border:1px solid var(--line);border-radius:var(--r);margin-bottom:14px;overflow:hidden}
.statshead{display:flex;gap:14px;align-items:center;padding:11px 14px;cursor:pointer}
.statshead .s{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--muted)}
.statshead .s b{color:var(--txt);font-weight:600}
.statshead .chev{margin-left:auto;transition:.15s;stroke:var(--muted);width:16px;height:16px}
.statsbar.open .chev{transform:rotate(180deg)}
.statsdetail{display:none;border-top:1px solid var(--line);padding:6px 14px 12px}
.statsbar.open .statsdetail{display:block}
.kv{display:flex;justify-content:space-between;padding:5px 0;font-size:12.5px;border-bottom:1px dashed #1e2731}
.kv:last-child{border:0}.kv span{color:var(--muted)}.kv b{font-weight:600;font-variant-numeric:tabular-nums}

.master{display:flex;gap:10px;margin-bottom:14px}
.master button{flex:1;padding:13px;border-radius:var(--r);border:1px solid var(--line);background:var(--surface);
  font-weight:650;letter-spacing:.3px;transition:.15s}
.master .allon{color:var(--on)}.master .alloff{color:var(--muted)}
.master button:active{transform:scale(.98)}

#peers{display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));gap:11px}
#relays{display:block}
.card{background:var(--surface);border:1px solid var(--line);border-radius:var(--r);padding:13px 14px}
.card.on{border-color:#2a4a44;background:linear-gradient(180deg,#16201d,var(--surface))}
.relayrow{display:flex;align-items:center;gap:12px;padding:7px 0;border-bottom:1px dashed #1e2731}
.relayrow:last-child{border:0}
.cmeta{flex:1;min-width:0}
.cname{font-size:14px;font-weight:600}
.cline{font-size:11px;color:var(--muted);margin-top:2px;font-variant-numeric:tabular-nums}
.cline .pw{color:var(--pwr)}
.tgl{width:58px;height:32px;border-radius:20px;border:1px solid var(--line);background:var(--off);position:relative;flex:0 0 auto;transition:.15s}
.tgl:after{content:"";position:absolute;top:3px;left:3px;width:24px;height:24px;border-radius:50%;background:#cfd8df;transition:.15s}
.tgl.on{background:var(--on)}.tgl.on:after{left:29px;background:#06231e}

/* device (peer) cards */
.devcard{background:var(--surface);border:1px solid var(--line);border-radius:var(--r);padding:14px}
.devhead{display:flex;align-items:center;gap:10px;margin-bottom:8px}
.devhead .nm{flex:1;min-width:0;font-size:15px;font-weight:650;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.devhead .self{font-size:10px;color:var(--accent);margin-left:6px}
.devmeta{font-size:11.5px;color:var(--muted);margin-bottom:10px;font-variant-numeric:tabular-nums}
.minigrid{display:flex;gap:6px}
.minibtn{flex:1;height:38px;border-radius:9px;border:1px solid var(--line);background:var(--off);color:var(--txt);font-weight:700;font-size:11px}
.minibtn.on{background:var(--on);color:#06231e;border-color:#2a4a44}
.devactions{display:flex;gap:8px;margin-top:10px}
.linkbtn{flex:1;padding:9px;border-radius:9px;border:1px solid var(--line);background:transparent;color:var(--txt);font-size:12px;text-align:center;text-decoration:none}

h3{font-size:13px;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);margin:18px 0 10px}
.page>h3:first-child{margin-top:4px}
.field{margin-bottom:13px}.field label{display:block;font-size:12px;color:var(--muted);margin-bottom:5px}
input,select{width:100%;padding:10px 11px;border-radius:10px;border:1px solid var(--line);background:var(--surface);color:var(--txt);font:inherit}
.cardbox{background:var(--surface);border:1px solid var(--line);border-radius:var(--r);padding:14px;margin-bottom:14px}
.btn{width:100%;padding:11px;border-radius:11px;border:1px solid var(--accent);background:var(--accent);color:#06231e;font-weight:700;margin-top:4px}
.btn.ghost{background:transparent;color:var(--txt);border-color:var(--line)}
.btn.danger{background:transparent;color:var(--bad);border-color:#5a2a26}
.row2{display:flex;gap:8px}.row2>*{flex:1}
.note{font-size:11.5px;color:var(--muted);margin:8px 0}
.seg{display:flex;gap:6px}
.seg button{flex:1;padding:10px;border-radius:10px;border:1px solid var(--line);background:var(--surface);color:var(--muted);font-weight:600;font-size:12px}
.seg button.sel{background:var(--accent);color:#06231e;border-color:var(--accent)}
.netitem{display:flex;justify-content:space-between;align-items:center;padding:9px 11px;border:1px solid var(--line);border-radius:10px;margin-bottom:7px;background:var(--surface);cursor:pointer}
canvas{width:100%;height:170px;display:block;background:var(--surface);border:1px solid var(--line);border-radius:11px}
.energytot{display:flex;gap:10px;margin:12px 0}
.energytot div{flex:1;background:var(--surface);border:1px solid var(--line);border-radius:11px;padding:11px;text-align:center}
.energytot b{display:block;font-size:20px;font-weight:600;margin-top:2px}
.logbox{background:#0a0d10;border:1px solid var(--line);border-radius:11px;padding:10px;font:11px ui-monospace,monospace;color:#a9b7c2;max-height:240px;overflow:auto;white-space:pre-wrap}
.subtabs{display:flex;gap:6px;overflow-x:auto;margin-bottom:14px}
.subtabs button{white-space:nowrap;padding:7px 11px;border-radius:9px;border:1px solid var(--line);background:var(--surface);color:var(--muted);font-size:12px;font-weight:600}
.subtabs button.sel{color:#06231e;background:var(--accent);border-color:var(--accent)}
.page{display:none}.page.active{display:block}
.tg{display:flex;align-items:center;gap:9px;font-size:13px}
.err{color:var(--bad);font-size:12px;min-height:16px}

/* footer nav */
nav{position:fixed;left:0;right:0;bottom:0;height:var(--navh);background:#0e1318ee;backdrop-filter:blur(8px);
  border-top:1px solid var(--line);display:flex;z-index:20;padding-bottom:env(safe-area-inset-bottom)}
nav button{flex:1;background:none;border:0;display:flex;flex-direction:column;align-items:center;justify-content:center;
  gap:3px;color:var(--muted);font-size:10px;font-weight:600}
nav button svg{width:21px;height:21px;stroke:var(--muted);fill:none;stroke-width:1.7}
nav button.sel{color:var(--accent)}nav button.sel svg{stroke:var(--accent)}
@media(min-width:760px){nav{max-width:560px;left:50%;transform:translateX(-50%);border-radius:16px 16px 0 0;border:1px solid var(--line);border-bottom:0}}

/* modals / login */
.modal{position:fixed;inset:0;background:#000a;backdrop-filter:blur(2px);display:none;place-items:center;z-index:40;padding:24px}
.modal.show{display:grid}
.modalbox{width:min(360px,100%);background:var(--surface);border:1px solid var(--line);border-radius:16px;padding:20px;text-align:center}
.modalbox h2{margin:0 0 8px;font-size:17px}
.modalbox p{color:var(--muted);font-size:13px;margin:0 0 16px}
.login{position:fixed;inset:0;background:var(--bg);display:none;place-items:center;z-index:50;padding:24px}
.login.show{display:grid}
</style>
</head>
<body>

<!-- login overlay -->
<div class="login" id="login"><div style="width:min(340px,100%);text-align:center">
  <div class="logo" style="margin:0 auto 14px;width:54px;height:54px"><svg viewBox="0 0 24 24" fill="none" stroke="#34d3b0" stroke-width="1.7"><path d="M9 18h6M10 21h4M12 2a7 7 0 00-4 12.7V17h8v-2.3A7 7 0 0012 2z"/></svg></div>
  <h2 style="margin:0 0 14px">Sign in</h2>
  <div class="field"><input id="lu" placeholder="Username"></div>
  <div class="field"><input id="lp" type="password" placeholder="Password"></div>
  <button class="btn" onclick="doLogin()">Sign in</button>
  <div class="err" id="lerr"></div>
</div></div>

<!-- unsaved-changes guard -->
<div class="modal" id="dirtyModal"><div class="modalbox">
  <h2>Unsaved changes</h2>
  <p>You were editing settings. Finish saving first, or discard your changes?</p>
  <button class="btn ghost" onclick="closeDirty()">Continue setup</button>
  <button class="btn danger" style="margin-top:8px" onclick="discardAndGo()">Discard &amp; leave</button>
</div></div>

<div class="wrap">
  <header>
    <div class="logo" onclick="goHome()"><svg viewBox="0 0 24 24" fill="none" stroke="#34d3b0" stroke-width="1.6"><path d="M9 18h6M10 21h4M12 2a7 7 0 00-4 12.7V17h8v-2.3A7 7 0 0012 2z"/></svg></div>
    <div class="htitle" onclick="goHome()">
      <h1 id="hname">Smart Switch</h1>
      <div class="sub">
        <span class="pill" id="conn"><span class="dot"></span><span id="connt">…</span></span>
        <span class="rolebadge" id="roleBadge" style="display:none"></span>
      </div>
    </div>
  </header>

  <!-- HOME -->
  <section class="page active" id="p-home">
    <div class="clockrow"><div class="clock" id="clock">--:--<small id="ampm"></small></div><div class="ipv" id="ipv">—</div></div>
    <div class="statsbar" id="statsbar">
      <div class="statshead" onclick="document.getElementById('statsbar').classList.toggle('open')">
        <div class="s"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#f0a93b" stroke-width="1.8"><path d="M14 4v6l5 9H5l5-9V4M9 4h6"/></svg><b id="temp">—</b></div>
        <div class="s"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#46c46a" stroke-width="1.8"><path d="M2 9a15 15 0 0120 0M5 12.5a10 10 0 0114 0M8.5 16a5 5 0 017 0M12 19.5h.01"/></svg><b id="rssi">—</b></div>
        <div class="s"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#8aa0b2" stroke-width="1.8"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg><b id="uptime">—</b></div>
        <svg class="chev" viewBox="0 0 24 24" fill="none" stroke-width="2"><path d="M6 9l6 6 6-6"/></svg>
      </div>
      <div class="statsdetail" id="statsdetail"></div>
    </div>
    <div class="master"><button class="allon" onclick="setAll(true)">All On</button><button class="alloff" onclick="setAll(false)">All Off</button></div>
    <div id="relays"></div>
  </section>

  <!-- DEVICES -->
  <section class="page" id="p-devices">
    <h3>This device</h3>
    <div class="cardbox">
      <div class="field" style="margin:0"><label>Role — who is in charge of the group</label>
        <div class="seg" id="roleSeg">
          <button data-r="none" onclick="setRole('none')">None</button>
          <button data-r="master" onclick="setRole('master')">Master</button>
          <button data-r="slave" onclick="setRole('slave')">Slave</button>
        </div></div>
      <div class="err" id="roleErr"></div>
    </div>
    <h3 id="devCount">Smart switches on your network</h3>
    <p class="note">Detected by a stable device ID broadcast on the LAN — independent of mDNS. Controlling any one here reaches them all.</p>
    <div class="row2" style="margin-bottom:12px">
      <input id="manualIp" placeholder="Add a device by IP (e.g. 192.168.1.50)">
      <button class="btn" style="margin:0;max-width:120px" onclick="addManual()">Add</button>
    </div>
    <div id="peers"></div>
  </section>

  <!-- ENERGY -->
  <section class="page" id="p-energy">
    <h3>Last 30 days</h3>
    <canvas id="chart" width="500" height="170"></canvas>
    <div class="energytot"><div>kWh (30d)<b id="e-kwh">—</b></div><div>Cost (30d)<b id="e-cost">—</b></div></div>
    <div class="cardbox track">
      <div class="field" style="margin:0"><label>Tariff (₹ / kWh)</label><input id="tariff" type="number" step="0.01"></div>
    </div>
    <button class="btn" onclick="saveTariff()">Save tariff</button>
    <p class="note">Estimated from wattage × on-time, not metered.</p>
  </section>

  <!-- NETWORK -->
  <section class="page" id="p-network">
    <h3>Identity</h3>
    <div class="cardbox" id="idSummary" style="font-variant-numeric:tabular-nums"></div>
    <div class="cardbox track">
      <div class="field"><label>Device name</label><input id="devName" placeholder="e.g. Living Room Switch"></div>
      <button class="btn ghost" onclick="saveName()">Save name</button>
      <div class="field" style="margin-top:14px"><label>mDNS hostname (recovery address, no spaces)</label>
        <div class="row2"><input id="mdnsHost" placeholder="leoswitch"><button class="btn" style="margin:0;max-width:120px" onclick="saveMdns()">Apply</button></div></div>
      <p class="note" id="mdnsNote">Default is automatic: one unit owns <b>leoswitch.local</b> (the master, or the lowest-ID device, with automatic failover) and the rest use <b>leo-&lt;id&gt;.local</b>. Set a fixed name here to pin this unit, or type <b>auto</b> to hand it back to the election. Detection itself never depends on mDNS.</p>
    </div>

    <h3>Connection</h3>
    <p class="note" id="netcur">—</p>
    <button class="btn ghost" onclick="scan()">Scan for networks</button>
    <div id="netlist" style="margin-top:10px"></div>
    <div class="cardbox track" style="margin-top:12px">
      <div class="field"><label>Join WiFi — SSID</label><input id="sta-ssid"></div>
      <div class="field"><label>Password</label><input id="sta-pass" type="password"></div>
      <button class="btn" onclick="saveSta()">Save &amp; reconnect</button>
    </div>

    <h3>Access Point</h3>
    <div class="cardbox track">
      <div class="field"><label>AP name</label><input id="ap-ssid"></div>
      <div class="field"><label>AP password (min 8)</label><input id="ap-pass" type="password" placeholder="leave blank to keep"></div>
      <button class="btn ghost" onclick="saveAp()">Save AP &amp; reboot</button>
    </div>
  </section>

  <!-- SYSTEM -->
  <section class="page" id="p-system">
    <div class="subtabs" id="sysTabs">
      <button data-s="time" class="sel" onclick="sysTab('time')">Time</button>
      <button data-s="relays" onclick="sysTab('relays')">Relays</button>
      <button data-s="led" onclick="sysTab('led')">LED</button>
      <button data-s="security" onclick="sysTab('security')">Security</button>
      <button data-s="logs" onclick="sysTab('logs')">Logs</button>
      <button data-s="console" onclick="sysTab('console')">Console</button>
      <button data-s="device" onclick="sysTab('device')">Device</button>
    </div>

    <div class="syspane track" id="s-time">
      <p class="note" id="syncnote">—</p>
      <div class="field"><label>Time format</label><select id="fmt"><option value="0">12-hour (AM/PM)</option><option value="1">24-hour</option></select></div>
      <div class="field"><label>Time zone</label>
        <select id="tz">
          <option value="IST-5:30">India — IST (UTC+5:30)</option>
          <option value="GMT0">UTC / GMT</option>
          <option value="GST-4">Gulf — GST (UTC+4)</option>
          <option value="CET-1CEST,M3.5.0,M10.5.0/3">Central Europe</option>
          <option value="GMT0BST,M3.5.0/1,M10.5.0">UK</option>
          <option value="EST5EDT,M3.2.0,M11.1.0">US Eastern</option>
          <option value="PST8PDT,M3.2.0,M11.1.0">US Pacific</option>
          <option value="JST-9">Japan (UTC+9)</option>
        </select></div>
      <button class="btn" onclick="saveTime()">Apply</button>
    </div>

    <div class="syspane track" id="s-relays" style="display:none">
      <p class="note">Each GPIO (0,1,3,10) maps to exactly one relay.</p>
      <div id="maprows"></div><div class="err" id="maperr"></div>
      <button class="btn" onclick="saveMap()">Save mapping</button>
    </div>

    <div class="syspane track" id="s-led" style="display:none">
      <p class="note">The status LED shows boot/AP/connecting/online/error. In <b>Auto-off</b> it lights on changes then sleeps once steady online, so it isn't drawing power 24/7.</p>
      <div class="field"><label>Behaviour</label>
        <div class="seg" id="ledModeSeg">
          <button data-m="off" onclick="setLedMode('off')">Off</button>
          <button data-m="status" onclick="setLedMode('status')">Auto-off</button>
          <button data-m="always" onclick="setLedMode('always')">Always</button>
        </div></div>
      <div class="field"><label>Brightness — <span id="ledBrightVal">40</span>/255</label>
        <input id="ledBright" type="range" min="0" max="255" step="1" oninput="$('#ledBrightVal').textContent=this.value"></div>
      <div class="field" id="ledTimeoutField"><label>Auto-off after (seconds, 0 = never)</label>
        <input id="ledTimeout" type="number" min="0" max="3600" step="5"></div>
      <div class="row2"><button class="btn" onclick="saveLed()">Save</button><button class="btn ghost" onclick="identify()">Identify (blink)</button></div>
    </div>

    <div class="syspane track" id="s-security" style="display:none">
      <div class="field tg"><input type="checkbox" id="authon" style="width:auto" onchange="document.getElementById('authfields').style.display=this.checked?'block':'none'"><label style="margin:0">Require login (remembers known devices)</label></div>
      <div id="authfields" style="display:none">
        <div class="field"><label>Username</label><input id="au"></div>
        <div class="field"><label>Password</label><input id="ap2" type="password" placeholder="set / change"></div>
      </div>
      <button class="btn ghost" onclick="saveAuth()">Save security</button>
    </div>

    <div class="syspane" id="s-logs" style="display:none">
      <div class="logbox" id="logbox">—</div>
      <div class="row2" style="margin-top:8px"><button class="btn ghost" onclick="loadLogs()">Refresh</button><button class="btn ghost" onclick="clearLogs()">Clear</button></div>
    </div>

    <div class="syspane" id="s-console" style="display:none">
      <p class="note">Live mirror of the device's debug output (the same lines it prints over USB serial). Connects only while this tab is open.</p>
      <div class="logbox" id="consoleBox" style="max-height:320px">—</div>
      <div class="row2" style="margin-top:8px"><button class="btn ghost" onclick="clearConsole()">Clear</button><button class="btn ghost" onclick="connectConsole()">Reconnect</button></div>
    </div>

    <div class="syspane" id="s-device" style="display:none">
      <div id="sysinfo"></div>
      <button class="btn ghost" style="margin-top:14px" onclick="reboot()">Soft reboot</button>
      <div class="field" style="margin-top:12px"><label>Type RESET to factory reset</label><input id="rstxt" placeholder="RESET"></div>
      <button class="btn danger" onclick="doReset()">Factory reset</button>
    </div>
  </section>
</div>

<nav id="tabbar">
  <button data-p="home" class="sel" onclick="nav('home')"><svg viewBox="0 0 24 24"><path d="M3 11l9-8 9 8M5 10v10h14V10"/></svg>Home</button>
  <button data-p="devices" onclick="nav('devices')"><svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="6" rx="2"/><path d="M7 7.5h.01M7 17h.01"/></svg>Devices</button>
  <button data-p="energy" onclick="nav('energy')"><svg viewBox="0 0 24 24"><path d="M13 2L4 14h6l-1 8 9-12h-6z"/></svg>Energy</button>
  <button data-p="network" onclick="nav('network')"><svg viewBox="0 0 24 24"><path d="M2 9a15 15 0 0120 0M5 12.5a10 10 0 0114 0M8.5 16a5 5 0 017 0M12 19.5h.01"/></svg>Network</button>
  <button data-p="system" onclick="nav('system')"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a8 8 0 000-6l1.5-2.6-2.8-2.8L15.5 4a8 8 0 00-7 0L5.9 2.5 3.1 5.3 4.6 9a8 8 0 000 6l-1.5 2.6 2.8 2.8L8.5 20a8 8 0 007 0l2.6 1.4 2.8-2.8z"/></svg>System</button>
</nav>

<script>
const $=s=>document.querySelector(s),$$=s=>document.querySelectorAll(s);
let TOKEN=localStorage.getItem('leo_token')||'',last=null,page='home',sys='time',dirty=false,pendingNav=null,peerTimer=null;
const SELF=location.origin;

function H(){return TOKEN?{'X-Auth-Token':TOKEN}:{}}
async function api(p,m='GET',b){const o={method:m,headers:{...H()}};if(b){o.headers['Content-Type']='application/json';o.body=JSON.stringify(b)}
  const r=await fetch(p,o);if(r.status===401){$('#login').classList.add('show');throw new Error('auth')}return r}
// retry wrapper: try/catch + N retries with backoff; returns Response or null
async function apiR(p,m='GET',b,tries=2){for(let i=0;i<=tries;i++){try{const r=await api(p,m,b);if(r.ok||r.status===401)return r}catch(e){if(e.message==='auth')return null}await new Promise(z=>setTimeout(z,250*(i+1)))}return null}
// safe JSON GET with retry; returns parsed object or null (never throws)
async function jget(p,tries=2){const r=await apiR(p,'GET',null,tries);if(!r)return null;try{return await r.json()}catch(e){return null}}
async function doLogin(){$('#lerr').textContent='';
  const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user:$('#lu').value,pass:$('#lp').value})});
  if(r.ok){TOKEN=(await r.json()).token;localStorage.setItem('leo_token',TOKEN);$('#login').classList.remove('show');connectWS()}
  else $('#lerr').textContent=r.status===429?'Too many attempts — wait 30 s':'Wrong username or password'}

/* ---- dirty-change guard ---- */
document.addEventListener('input',e=>{if(e.target.closest('.track'))dirty=true});
document.addEventListener('change',e=>{if(e.target.closest('.track'))dirty=true});
function clearDirty(){dirty=false}
function guard(go){if(dirty){pendingNav=go;$('#dirtyModal').classList.add('show')}else go()}
function closeDirty(){$('#dirtyModal').classList.remove('show');pendingNav=null}
function discardAndGo(){dirty=false;$('#dirtyModal').classList.remove('show');const g=pendingNav;pendingNav=null;if(g)g()}
function goHome(){guard(()=>switchPage('home'))}

/* ---- navigation ---- */
function nav(p){guard(()=>switchPage(p))}
function switchPage(p){
  page=p;
  $$('.page').forEach(s=>s.classList.toggle('active',s.id==='p-'+p));
  $$('#tabbar button').forEach(b=>b.classList.toggle('sel',b.dataset.p===p));
  clearInterval(peerTimer);
  disconnectConsole();
  if(p==='energy')loadEnergy();
  if(p==='network')loadNetwork();
  if(p==='system')loadSystem();
  if(p==='devices'){loadPeers();peerTimer=setInterval(loadPeers,5000)}
  window.scrollTo(0,0);
}
function sysTab(s){sys=s;$$('#sysTabs button').forEach(b=>b.classList.toggle('sel',b.dataset.s===s));
  $$('.syspane').forEach(p=>p.style.display=p.id==='s-'+s?'block':'none');
  if(s==='relays')loadMap();if(s==='led')loadLed();if(s==='security')loadAuthCfg();if(s==='logs')loadLogs();if(s==='device')loadDeviceInfo();if(s==='time')loadTime();
  if(s==='console')connectConsole();else disconnectConsole();
}

/* ---- live console (serial mirror) ---- */
let consoleWs=null,consoleLines=[],consoleWant=false;
function connectConsole(){
  consoleWant=true;
  if(consoleWs){consoleWs.onclose=null;consoleWs.close()}
  $('#consoleBox').textContent='Connecting…';
  consoleWs=new WebSocket((location.protocol==='https:'?'wss':'ws')+'://'+location.host+'/console');
  consoleWs.onopen=()=>{consoleLines=[];$('#consoleBox').textContent=''};
  consoleWs.onmessage=e=>{
    // history arrives as one newline-joined frame, live lines one per frame
    consoleLines.push(...String(e.data).split('\n'));if(consoleLines.length>500)consoleLines.splice(0,consoleLines.length-500);
    const box=$('#consoleBox');const atBottom=box.scrollTop+box.clientHeight>=box.scrollHeight-24;
    box.textContent=consoleLines.join('\n');if(atBottom)box.scrollTop=box.scrollHeight;
  };
  consoleWs.onclose=()=>{if(consoleWant)setTimeout(()=>{if(consoleWant)connectConsole()},2000)};
}
function disconnectConsole(){consoleWant=false;if(consoleWs){consoleWs.onclose=null;consoleWs.close();consoleWs=null}}
function clearConsole(){consoleLines=[];$('#consoleBox').textContent=''}

/* ---- live telemetry (this device) ---- */
// Single telemetry socket. doLogin() calls connectWS() again; previously that
// opened a second socket (each with its own reconnect chain) on every login.
let telWs=null,telTimer=null;
function connectWS(){clearTimeout(telTimer);
  if(telWs){telWs.onclose=null;try{telWs.close()}catch(e){}}
  const ws=new WebSocket((location.protocol==='https:'?'wss':'ws')+'://'+location.host+'/ws');telWs=ws;
  ws.onmessage=e=>{try{renderHome(JSON.parse(e.data))}catch(err){}};
  ws.onclose=()=>{if(telWs===ws)telTimer=setTimeout(connectWS,1500)}}
function fmtUp(s){const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);return d?`${d}d ${h}h`:h?`${h}h ${m}m`:`${m}m`}
function esc(s){return(s+'').replace(/[<>&"']/g,m=>({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;',"'":'&#39;'}[m]))}
// for values placed inside a JS string inside an onclick="..." attribute (e.g. an SSID with an apostrophe)
function jsq(s){return esc((s+'').replace(/\\/g,'\\\\').replace(/'/g,"\\'"))}

function renderHome(d){
  last=d;
  $('#hname').textContent=d.name||'Smart Switch';
  const t=(d.clock||'').split(' ');$('#clock').firstChild.nodeValue=t[0]||'--:--';
  $('#ampm').textContent=(t[1]||'')+(d.synced?'':' ~');
  $('#ipv').textContent=d.ip;
  const cs=(d.conn||'AP').toLowerCase();$('#conn').className='pill '+cs;$('#connt').textContent=d.conn;
  const rb=$('#roleBadge');if(d.role&&d.role!=='none'){rb.style.display='';rb.textContent=d.role.toUpperCase();rb.className='rolebadge '+d.role}else rb.style.display='none';
  $('#temp').textContent=(d.temp??0).toFixed(1)+' °C';
  $('#rssi').textContent=d.conn==='WIFI'?d.rssi+' dBm':'AP';
  $('#uptime').textContent=fmtUp(d.uptime);
  $('#statsdetail').innerHTML=[['Device ID',d.id],['Internal Temp',(d.temp??0).toFixed(1)+' °C'],['MAC',d.mac],['Loop',d.loopms+' ms'],
    ['Heap (free/total)',d.heapFree+' / '+d.heapTotal+' KB'],['mDNS',d.mdns],['Storage',d.fsUsed+' / '+d.fsTotal+' KB'],
    ['IP',d.ip],['SSID',d.ssid+(d.conn==='WIFI'?' ('+d.rssi+' dBm)':'')]].map(([k,v])=>`<div class="kv"><span>${k}</span><b>${esc(v)}</b></div>`).join('');
  $('#relays').innerHTML=`<div class="card">`+d.relays.map((r,i)=>{
    const on=r.on,onTime=on?`On ${Math.floor(r.onSecs/3600)?Math.floor(r.onSecs/3600)+'h ':''}${Math.floor(r.onSecs%3600/60)}m`:'Off';
    return `<div class="relayrow"><div class="cmeta"><div class="cname">${esc(r.name)}</div>
      <div class="cline">GPIO ${r.gpio} · ${onTime} · <span class="pw">≈ ${r.watts} W</span></div></div>
      <button class="tgl ${on?'on':''}" onclick="toggle(${i},${!on},this)"></button></div>`}).join('')+`</div>`;
}
// optimistic, but revert if the device rejected/failed the request
async function toggle(i,on,el){el.classList.toggle('on',on);let ok=false;try{ok=(await api('/api/relay','POST',{i,on})).ok}catch(e){}if(!ok)el.classList.toggle('on',!on)}
async function setAll(on){try{await api('/api/all','POST',{on})}catch(e){}}

/* ---- devices / cluster ---- */
function getManual(){try{return JSON.parse(localStorage.getItem('leo_manual')||'[]')}catch(e){return[]}}
function setManual(a){localStorage.setItem('leo_manual',JSON.stringify([...new Set(a)]))}
function addManual(){let ip=($('#manualIp').value||'').trim().replace(/^https?:\/\//,'').replace(/\/.*$/,'');
  if(!ip){return}setManual([...getManual(),ip]);$('#manualIp').value='';loadPeers()}
function removeManual(ip){setManual(getManual().filter(x=>x!==ip));loadPeers()}

async function loadPeers(){
  let data={peers:[]};try{data=await(await api('/api/peers')).json()}catch(e){}
  const discovered=data.peers||[];
  const seenIp=new Set(discovered.map(p=>p.ip)), seenId=new Set(discovered.map(p=>p.id));
  // resolve manually-added IPs (fallback when a router blocks broadcast)
  const extra=[];
  for(const ip of getManual()){
    if(seenIp.has(ip))continue;
    let idj=null;try{idj=await(await fetch(`http://${ip}/api/identity`,{headers:H()})).json()}catch(e){}
    if(idj&&seenId.has(idj.id))continue;
    extra.push(idj?{id:idj.id,name:idj.name,ip,port:80,role:idj.role,manual:true}
                  :{id:'ip:'+ip,name:ip,ip,port:80,role:'',manual:true,offline:true});
  }
  const list=[...discovered,...extra];
  $('#devCount').textContent=`Smart switches on your network (${list.length})`;
  const selfRole=(list.find(p=>p.self)||{}).role||(last&&last.role)||'none';
  $$('#roleSeg button').forEach(b=>b.classList.toggle('sel',b.dataset.r===selfRole));
  const box=$('#peers');
  box.innerHTML=list.map(p=>{
    const base=p.self?SELF:`http://${p.ip}:${p.port||80}`;
    const role=p.role&&p.role!=='none'?`<span class="rolebadge ${p.role}">${p.role.toUpperCase()}</span>`:'';
    const rm=p.manual?`<button class="linkbtn" style="max-width:44px;color:var(--bad)" onclick="removeManual('${jsq(p.ip)}')">✕</button>`:'';
    return `<div class="devcard" data-base="${base}" data-id="${esc(p.id)}">
      <div class="devhead"><span class="nm">${esc(p.name||p.id)}${p.self?'<span class="self">(this)</span>':''}${p.manual?'<span class="self">(manual)</span>':''}</span>${role}
        <span class="dot" style="background:var(--muted)"></span></div>
      <div class="devmeta">${esc(p.id)} · ${esc(p.ip)}</div>
      <div class="minigrid" data-relays>${[0,1,2,3].map(i=>`<button class="minibtn" disabled>—</button>`).join('')}</div>
      <div class="devactions">
        <button class="linkbtn" onclick="peerAll('${base}',true,this)">All On</button>
        <button class="linkbtn" onclick="peerAll('${base}',false,this)">All Off</button>
        <a class="linkbtn" href="${base}" target="_blank" rel="noopener">Open</a>${rm}
      </div></div>`}).join('')||'<p class="note">No switches found yet — add one by IP above if your router blocks broadcasts.</p>';
  list.forEach(async p=>{
    const base=p.self?SELF:`http://${p.ip}:${p.port||80}`;
    const card=box.querySelector(`[data-id="${cssEsc(p.id)}"]`);if(!card)return;
    let s;try{s=await(await fetch(base+'/api/state',{headers:H()})).json()}catch(e){card.querySelector('.dot').style.background='var(--bad)';return}
    card.querySelector('.dot').style.background='var(--accent)';
    const g=card.querySelector('[data-relays]');
    g.innerHTML=s.relays.map((r,i)=>`<button class="minibtn ${r.on?'on':''}" title="${esc(r.name)}" onclick="peerToggle('${base}',${i},${!r.on},this)">${esc(r.name.slice(0,1).toUpperCase())+(i+1)}</button>`).join('');
  });
}
function cssEsc(s){return(s+'').replace(/["\\]/g,'\\$&')}
async function peerToggle(base,i,on,el){el.classList.toggle('on',on);try{await fetch(base+'/api/relay',{method:'POST',headers:{'Content-Type':'application/json',...H()},body:JSON.stringify({i,on})})}catch(e){}}
async function peerAll(base,on,el){try{await fetch(base+'/api/all',{method:'POST',headers:{'Content-Type':'application/json',...H()},body:JSON.stringify({on})})}catch(e){}setTimeout(loadPeers,400)}
async function setRole(r){$('#roleErr').textContent='';try{await api('/api/role','POST',{role:r});$$('#roleSeg button').forEach(b=>b.classList.toggle('sel',b.dataset.r===r))}catch(e){$('#roleErr').textContent='Could not set role'}}

/* ---- energy ---- */
async function loadEnergy(){const d=await jget('/api/energy');if(!d)return;$('#tariff').value=d.tariff;
  let k=0,c=0;d.days.forEach(x=>{k+=x.kwh;c+=x.cost});$('#e-kwh').textContent=k.toFixed(2);$('#e-cost').textContent='₹ '+c.toFixed(2);drawChart(d.days);clearDirty()}
function drawChart(days){const cv=$('#chart');cv.width=Math.max(320,cv.clientWidth||500);cv.height=170;
  const ct=cv.getContext('2d'),W=cv.width,Hh=cv.height,pad=22;ct.clearRect(0,0,W,Hh);
  const vals=days.map(d=>d.kwh),max=Math.max(0.001,...vals);ct.strokeStyle='#26303a';ct.lineWidth=1;
  for(let g=0;g<=3;g++){const y=pad+(Hh-2*pad)*g/3;ct.beginPath();ct.moveTo(pad,y);ct.lineTo(W-6,y);ct.stroke()}
  if(!days.length){ct.fillStyle='#8aa0b2';ct.font='12px sans-serif';ct.fillText('No data yet',pad,Hh/2);return}
  const n=days.length,x=i=>pad+(W-pad-6)*(n<2?.5:i/(n-1)),y=v=>Hh-pad-(Hh-2*pad)*(v/max);
  const gr=ct.createLinearGradient(0,pad,0,Hh-pad);gr.addColorStop(0,'#34d3b055');gr.addColorStop(1,'#34d3b000');
  ct.beginPath();ct.moveTo(x(0),Hh-pad);days.forEach((d,i)=>ct.lineTo(x(i),y(d.kwh)));ct.lineTo(x(n-1),Hh-pad);ct.closePath();ct.fillStyle=gr;ct.fill();
  ct.beginPath();days.forEach((d,i)=>i?ct.lineTo(x(i),y(d.kwh)):ct.moveTo(x(i),y(d.kwh)));ct.strokeStyle='#34d3b0';ct.lineWidth=2;ct.stroke()}
async function saveTariff(){await api('/api/tariff','POST',{tariff:parseFloat($('#tariff').value)||0});clearDirty();loadEnergy()}

/* ---- network ---- */
async function loadNetwork(){
  const id=await jget('/api/identity');if(!id)return;
  $('#devName').value=id.name||'';
  $('#mdnsHost').value=(id.mdns||'').replace('.local','');
  $('#ap-ssid').value=id.ap||'';     // AP name is the device's own AP, not the joined WiFi
  const code=(id.id||'').replace('LEO-','');
  let own = id.mdnsAuto ? (id.ownsCanonical
        ? 'Automatic — this unit currently owns <b>leoswitch.local</b>'
        : 'Automatic — <b>leoswitch.local</b> is held by another unit; this one answers to <b>'+esc(id.mdns)+'</b>')
      : 'Manual override';
  $('#idSummary').innerHTML=[['Device ID',id.id],['AP name',id.ap],['mDNS',id.mdns],['IP',id.ip||(last&&last.ip)||'—']]
    .map(([k,v])=>`<div class="kv"><span>${k}</span><b>${esc(v||'—')}</b></div>`).join('')
    +`<p class="note" style="margin:8px 0 0">${own}. Device ID and AP share tag <b>${esc(code)}</b>. Type <b>auto</b> to rejoin the leoswitch.local election.</p>`
    +(id.apPassDefault?`<p class="note" style="margin:8px 0 0;color:var(--warn)">⚠ This device still uses the default AP password — set a new one below.</p>`:'');
  if(last)$('#netcur').textContent=last.conn==='WIFI'?`Connected to ${last.ssid} (${last.rssi} dBm)`:`Not on WiFi — hosting AP ${id.ap}`;
  clearDirty();
}
async function scan(){$('#netlist').innerHTML='<p class="note">Scanning…</p>';
  const poll=async()=>{const r=await api('/api/scan');if(r.status===202){setTimeout(poll,1200);return}
    const d=await r.json();$('#netlist').innerHTML=d.nets.sort((a,b)=>b.rssi-a.rssi).map(n=>`<div class="netitem" onclick="$('#sta-ssid').value='${jsq(n.ssid)}'"><b>${esc(n.ssid)}${n.ssid===d.connected?' ✓':''}</b><small>${n.lock?'🔒 ':''}${n.rssi} dBm</small></div>`).join('')||'<p class="note">Nothing found</p>'};poll()}
function netMsg(t){$('#netlist').innerHTML=`<p class="note">${esc(t)}</p>`}
async function saveSta(){const ssid=$('#sta-ssid').value.trim();if(!ssid){netMsg('Enter a network name first.');return}
  let r=null;try{r=await api('/api/network','POST',{ssid,pass:$('#sta-pass').value})}catch(e){}
  if(r&&r.ok){clearDirty();netMsg('Saved. Rebooting to join '+ssid+'…')}else netMsg('Could not save — try again.')}
async function saveAp(){const pass=$('#ap-pass').value;if(pass&&pass.length<8){netMsg('AP password must be at least 8 characters.');return}
  let r=null;try{r=await api('/api/ap','POST',{ssid:$('#ap-ssid').value.trim(),pass})}catch(e){}
  if(r&&r.ok){clearDirty();netMsg('AP saved. Rebooting…')}else netMsg('Could not save AP settings.')}
async function saveName(){await api('/api/devicename','POST',{name:$('#devName').value});clearDirty()}
async function saveMdns(){const v=($('#mdnsHost').value||'').trim();
  const r=await apiR('/api/mdns','POST',{mdns:v});if(!r){return}
  let d={};try{d=await r.json()}catch(e){}
  setTimeout(loadNetwork,400);   // reflect new ownership/effective host
}

/* ---- system: time ---- */
async function loadTime(){const d=await jget('/api/timecfg');if(!d)return;$('#fmt').value=d.h24?'1':'0';$('#tz').value=d.tz;
  $('#syncnote').textContent=d.synced?('Synced via NTP. Last drift: '+(d.drift||0).toFixed(0)+' s'):'Running on internal clock — NTP not yet reached.';clearDirty()}
async function saveTime(){await api('/api/time','POST',{tz:$('#tz').value,h24:$('#fmt').value==='1'});clearDirty()}

/* ---- system: relay map ---- */
let MAP=[],POOL=[];
async function loadMap(){const d=await jget('/api/relaymap');if(!d)return;MAP=d.relays;POOL=d.pool;$('#maperr').textContent='';
  $('#maprows').innerHTML=MAP.map((r,i)=>`<div class="cardbox"><div class="field" style="margin-bottom:9px"><label>Name</label><input value="${esc(r.name)}" oninput="MAP[${i}].name=this.value"></div>
    <div class="row2"><div class="field" style="margin:0"><label>GPIO</label><select onchange="MAP[${i}].gpio=+this.value">${POOL.map(g=>`<option value="${g}" ${g===r.gpio?'selected':''}>GPIO ${g}</option>`).join('')}</select></div>
    <div class="field" style="margin:0"><label>Wattage</label><input type="number" value="${r.watts}" oninput="MAP[${i}].watts=+this.value"></div></div></div>`).join('');clearDirty()}
async function saveMap(){const seen={};if(MAP.some(r=>seen[r.gpio]?true:(seen[r.gpio]=1,false))){$('#maperr').textContent='Each GPIO maps to one relay only.';return}
  let r=null;try{r=await api('/api/relaymap/set','POST',{relays:MAP})}catch(e){}
  $('#maperr').textContent=r&&r.ok?'Saved.':'Save failed.';if(r&&r.ok)clearDirty()}

/* ---- system: security ---- */
async function loadAuthCfg(){const a=await jget('/api/authcfg');if(!a)return;$('#authon').checked=a.enabled;$('#authfields').style.display=a.enabled?'block':'none';$('#au').value=a.user||'';clearDirty()}
async function saveAuth(){const enabled=$('#authon').checked,user=$('#au').value.trim(),pass=$('#ap2').value;
  if(enabled&&!user){alert('Enter a username to enable login.');return}
  let r=null;try{r=await api('/api/auth','POST',{enabled,user,pass})}catch(e){return}
  if(!r.ok){alert(r.status===400?'Set a username and password before enabling login.':'Could not save security settings.');return}
  try{const d=await r.json();if(d.token){TOKEN=d.token;localStorage.setItem('leo_token',TOKEN)}}catch(e){}
  $('#ap2').value='';clearDirty()}

/* ---- status LED ---- */
async function loadLed(){const d=await jget('/api/led');if(!d)return;
  $$('#ledModeSeg button').forEach(b=>b.classList.toggle('sel',b.dataset.m===d.mode));
  $('#ledBright').value=d.brightness;$('#ledBrightVal').textContent=d.brightness;
  $('#ledTimeout').value=d.timeout;
  $('#ledTimeoutField').style.display=d.mode==='status'?'block':'none';clearDirty()}
function setLedMode(m){$$('#ledModeSeg button').forEach(b=>b.classList.toggle('sel',b.dataset.m===m));
  $('#ledTimeoutField').style.display=m==='status'?'block':'none';dirty=true}
async function saveLed(){const mode=($('#ledModeSeg button.sel')||{}).dataset?.m||'status';
  const r=await apiR('/api/led','POST',{mode,brightness:+$('#ledBright').value,timeout:+$('#ledTimeout').value});
  if(r)clearDirty()}
async function identify(){await apiR('/api/led/identify','POST',{})}

/* ---- system: logs / device ---- */
async function loadLogs(){try{const d=await(await api('/api/logs')).json();$('#logbox').textContent=d.logs.length?d.logs.map(l=>`[${l.lvl}] ${l.s?new Date(l.t*1000).toLocaleString():'(uptime)'}  ${l.msg}`).reverse().join('\n'):'No log entries.'}catch(e){}}
async function clearLogs(){await api('/api/logs/clear','POST');loadLogs()}
function loadDeviceInfo(){if(!last)return;$('#sysinfo').innerHTML=[['Device ID',last.id],['Name',last.name],['Model',last.model],['Firmware',last.version],
  ['Role',last.role],['mDNS',last.mdns],['IP',last.ip],['MAC',last.mac],['Storage',last.fsUsed+' / '+last.fsTotal+' KB']].map(([k,v])=>`<div class="kv"><span>${k}</span><b>${esc(v)}</b></div>`).join('')}
async function reboot(){if(confirm('Soft reboot now? Relays switch off.'))await api('/api/reboot','POST')}
async function doReset(){if($('#rstxt').value!=='RESET'){alert('Type RESET to confirm.');return}await api('/api/reset','POST',{confirm:'RESET'})}

function loadSystem(){sysTab(sys)}
connectWS();
setInterval(()=>{if(last&&page==='home')renderHome(last)},1000);
</script>
</body>
</html>
)LEOHTML";

/* ============================ WEB ================================= */
void sendUnauth(AsyncWebServerRequest* r) { r->send(401, "application/json", "{\"err\":\"auth\"}"); }

void onJsonRelay(AsyncWebServerRequest* req, JsonVariant& json) {
  if (!checkAuth(req)) return sendUnauth(req);
  int i = json["i"] | -1; bool on = json["on"] | false;
  relaySet(i, on); req->send(200, "application/json", "{\"ok\":1}");
}
void onJsonAll(AsyncWebServerRequest* req, JsonVariant& json) {
  if (!checkAuth(req)) return sendUnauth(req);
  bool on = json["on"] | false;
  for (int i = 0; i < RELAY_COUNT; ++i) relaySetEx(i, on, false);
  pushTelemetry();                                   // one push, not four
  req->send(200, "application/json", "{\"ok\":1}");
}
void onJsonNetwork(AsyncWebServerRequest* req, JsonVariant& json) {
  if (!checkAuth(req)) return sendUnauth(req);
  String ssid = json["ssid"] | "";
  if (!ssid.length()) { req->send(400, "application/json", "{\"err\":\"ssid\"}"); return; }
  { LockGuard g; cfg.staSsid = ssid; cfg.staPass = json["pass"] | ""; }
  configSave(); req->send(200, "application/json", "{\"ok\":1}");
  scheduleRestart(800, true);                        // from loop(), after the reply is out
}
void onJsonAp(AsyncWebServerRequest* req, JsonVariant& json) {
  if (!checkAuth(req)) return sendUnauth(req);
  String s = json["ssid"] | ""; String p = json["pass"] | "";
  if (p.length() && p.length() < 8) { req->send(400, "application/json", "{\"err\":\"pass\"}"); return; }
  if (s.length()) cfg.apSsid = s;
  if (p.length() >= 8) cfg.apPass = p;
  configSave(); req->send(200, "application/json", "{\"ok\":1}");
  scheduleRestart(800, true);
}
void onJsonTime(AsyncWebServerRequest* req, JsonVariant& json) {
  if (!checkAuth(req)) return sendUnauth(req);
  cfg.tz = json["tz"] | cfg.tz; cfg.h24 = json["h24"] | cfg.h24;
  configSave(); setenv("TZ", cfg.tz.c_str(), 1); tzset();
  configTzTime(cfg.tz.c_str(), NTP_SERVER_1, NTP_SERVER_2);
  req->send(200, "application/json", "{\"ok\":1}");
}
void onJsonMap(AsyncWebServerRequest* req, JsonVariant& json) {
  if (!checkAuth(req)) return sendUnauth(req);
  // validate: gpios must be unique and from the pool
  bool used[64] = {false}; bool ok = true; JsonArray a = json["relays"].as<JsonArray>();
  int idx = 0; int gp[RELAY_COUNT];
  for (JsonObject o : a) {
    if (idx >= RELAY_COUNT) break;
    int g = o["gpio"] | -1; bool inPool = false;
    for (int k = 0; k < RELAY_COUNT; ++k) if (RELAY_GPIO_POOL[k] == g) inPool = true;
    if (!inPool || g < 0 || used[g]) { ok = false; break; }
    used[g] = true; gp[idx++] = g;
  }
  if (!ok || idx != RELAY_COUNT) { req->send(400, "application/json", "{\"err\":\"gpio\"}"); return; }
  idx = 0;
  for (JsonObject o : a) {
    if (idx >= RELAY_COUNT) break;
    relaySetEx(idx, false, false);                   // safe-off before remap
    cfg.relay[idx].name  = o["name"]  | cfg.relay[idx].name;
    cfg.relay[idx].gpio  = o["gpio"]  | cfg.relay[idx].gpio;
    cfg.relay[idx].watts = o["watts"] | cfg.relay[idx].watts;
    idx++;
  }
  relayInitPins(); configSave(); pushTelemetry();
  req->send(200, "application/json", "{\"ok\":1}");
}
void onJsonTariff(AsyncWebServerRequest* req, JsonVariant& json) {
  if (!checkAuth(req)) return sendUnauth(req);
  cfg.tariff = json["tariff"] | cfg.tariff; configSave();
  req->send(200, "application/json", "{\"ok\":1}");
}
void onJsonAuth(AsyncWebServerRequest* req, JsonVariant& json) {
  if (!checkAuth(req)) return sendUnauth(req);
  bool enable = json["enabled"] | false;
  String user = json["user"].is<const char*>() ? json["user"].as<String>() : cfg.authUser;
  String pass = json["pass"].is<const char*>() ? json["pass"].as<String>() : String("");
  user.trim();
  // Enabling login with no username/password used to succeed and lock
  // everyone out for good (no password could ever match an empty hash, and
  // factory reset itself requires auth).
  if (enable && (!user.length() || (!pass.length() && !cfg.authPass.length()))) {
    req->send(400, "application/json", "{\"err\":\"need user and password\"}"); return;
  }
  bool wasEnabled = cfg.authEnabled;
  cfg.authEnabled = enable;
  cfg.authUser = user;
  if (pass.length()) cfg.authPass = hashPass(pass);
  configSave();
  // Hand the browser/app that just turned login on a token, so it isn't
  // immediately kicked to a login prompt by its own change.
  if (enable && !wasEnabled) {
    String t = authIssue();
    req->send(200, "application/json", String("{\"ok\":1,\"token\":\"") + t + "\"}");
  } else req->send(200, "application/json", "{\"ok\":1}");
}
void onJsonRole(AsyncWebServerRequest* req, JsonVariant& json) {
  if (!checkAuth(req)) return sendUnauth(req);
  String role = json["role"] | cfg.role;
  if (role == "master" || role == "slave" || role == "none") cfg.role = role;
  if (json["group"].is<const char*>()) cfg.group = json["group"].as<String>();
  configSave(); mdnsDirty = true; beaconDirty = true;   // role affects leoswitch ownership
  req->send(200, "application/json", "{\"ok\":1}");
}
void onJsonDeviceName(AsyncWebServerRequest* req, JsonVariant& json) {
  if (!checkAuth(req)) return sendUnauth(req);
  String n = json["name"] | "";
  if (n.length()) { cfg.deviceName = n; gName = n; configSave(); mdnsDirty = true; beaconDirty = true; }
  req->send(200, "application/json", "{\"ok\":1}");
}
void onJsonMdns(AsyncWebServerRequest* req, JsonVariant& json) {
  if (!checkAuth(req)) return sendUnauth(req);
  String h = json["mdns"] | "";
  h.toLowerCase(); h.trim();
  if (h == "auto" || h == "") {                       // back to automatic leoswitch election
    cfg.mdnsHost = ""; configSave(); mdnsDirty = true; beaconDirty = true;
    req->send(200, "application/json", "{\"ok\":1,\"mdns\":\"auto\"}");
    return;
  }
  String clean; for (size_t i = 0; i < h.length(); ++i) {
    char c = h[i]; if ((c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='-') clean += c;
  }
  if (clean.length() >= 2) {
    cfg.mdnsHost = clean; configSave();
    mdnsDirty = true; beaconDirty = true;             // apply from loop (not async ctx)
    req->send(200, "application/json", String("{\"ok\":1,\"mdns\":\"") + clean + ".local\"}");
  } else req->send(400, "application/json", "{\"err\":\"name\"}");
}
void onJsonLed(AsyncWebServerRequest* req, JsonVariant& json) {
  if (!checkAuth(req)) return sendUnauth(req);
  String m = json["mode"] | cfg.ledMode;
  if (m == "off" || m == "status" || m == "always") cfg.ledMode = m;
  if (json["brightness"].is<int>()) { int b = json["brightness"].as<int>(); cfg.ledBright = b < 0 ? 0 : (b > 255 ? 255 : b); }
  if (json["timeout"].is<int>())    { int t = json["timeout"].as<int>();    cfg.ledTimeout = t < 0 ? 0 : (t > 3600 ? 3600 : t); }
  lastLedState = -1;                                   // force re-eval of on-timer
  configSave();
  req->send(200, "application/json", "{\"ok\":1}");
}
void onJsonLogin(AsyncWebServerRequest* req, JsonVariant& json) {
  if (!originIsLocal(req)) return sendUnauth(req);
  if (millis() < loginLockUntil) { req->send(429, "application/json", "{\"err\":\"locked\"}"); return; }
  String u = json["user"] | ""; String p = json["pass"] | "";
  size_t oldLen = cfg.authPass.length();
  if (cfg.authEnabled && u == cfg.authUser && passMatches(p)) {
    loginFails = 0;
    if (cfg.authPass.length() != oldLen) { configSave(); logEvent("INFO", "Password hash upgraded to SHA-256"); }
    String t = authIssue();
    req->send(200, "application/json", String("{\"token\":\"") + t + "\"}");
  } else {
    if (++loginFails >= 5) { loginLockUntil = millis() + 30000; loginFails = 0; }  // slow brute force
    req->send(401, "application/json", "{\"err\":\"bad\"}");
  }
}
void onJsonReset(AsyncWebServerRequest* req, JsonVariant& json) {
  if (!checkAuth(req)) return sendUnauth(req);
  if (String(json["confirm"] | "") != "RESET") { req->send(400, "application/json", "{\"err\":\"confirm\"}"); return; }
  LittleFS.remove(CFG_FILE); LittleFS.remove(ENERGY_FILE);
  LittleFS.remove(LOG_FILE); LittleFS.remove(AUTH_FILE); LittleFS.remove(CLOCK_FILE);
  req->send(200, "application/json", "{\"ok\":1}");
  scheduleRestart(800, false);                       // don't re-write energy.json we just wiped
}

void webBegin() {
  // CORS so any LEO device's page can read peers' state cross-origin (LAN only)
  DefaultHeaders::Instance().addHeader("Access-Control-Allow-Origin", "*");
  DefaultHeaders::Instance().addHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  DefaultHeaders::Instance().addHeader("Access-Control-Allow-Headers", "Content-Type, X-Auth-Token");

  // websocket (telemetry push only)
  ws.onEvent([](AsyncWebSocket*, AsyncWebSocketClient* c, AwsEventType t, void*, uint8_t*, size_t) {
    if (t == WS_EVT_CONNECT) c->text(telemetryJson());
  });
  server.addHandler(&ws);

  // live console / serial mirror: replay the ring buffer, then stream new lines
  consoleWs.onEvent([](AsyncWebSocket*, AsyncWebSocketClient* c, AwsEventType t, void*, uint8_t*, size_t) {
    if (t != WS_EVT_CONNECT) return;
    String h = consoleHistory();
    if (h.length()) c->text(h);                     // one frame (see consoleHistory)
  });
  server.addHandler(&consoleWs);

  // static UI from LittleFS
  auto sendIndex = [](AsyncWebServerRequest* r) {
    r->send(200, "text/html", (const uint8_t*)INDEX_HTML, strlen_P(INDEX_HTML));
  };
  server.on("/", HTTP_GET, sendIndex);
  server.on("/index.html", HTTP_GET, sendIndex);

  // identity: who am I (stable id, never tied to mDNS)
  server.on("/api/identity", HTTP_GET, [](AsyncWebServerRequest* r) {
    JsonDocument d;
    d["id"] = gId; d["name"] = gName; d["role"] = cfg.role; d["group"] = cfg.group;
    d["mdns"] = (curMdnsHost.length() ? curMdnsHost : String(DEFAULT_MDNS_HOST)) + ".local"; d["ip"] = WiFi.localIP().toString();
    d["mdnsAuto"] = (cfg.mdnsHost.length() == 0); d["ownsCanonical"] = canonicalOwner();
    d["ap"] = cfg.apSsid; d["apip"] = WiFi.softAPIP().toString();
    d["apPassDefault"] = (cfg.apPass == String(DEFAULT_AP_PASS));
    d["type"] = DEVICE_TYPE; d["model"] = DEVICE_MODEL; d["fw"] = FW_VERSION;
    String out; serializeJson(d, out); r->send(200, "application/json", out);
  });

  // peers: every LEO switch this device has heard on the LAN (self first)
  server.on("/api/peers", HTTP_GET, [](AsyncWebServerRequest* r) {
    peerPrune();
    JsonDocument d; JsonArray a = d["peers"].to<JsonArray>();
    JsonObject me = a.add<JsonObject>();
    me["id"] = gId; me["name"] = gName; me["ip"] = WiFi.localIP().toString();
    me["port"] = 80; me["role"] = cfg.role; me["group"] = cfg.group;
    me["type"] = DEVICE_TYPE; me["fw"] = FW_VERSION; me["self"] = true;
    { LockGuard g;                                    // peers[] is also written from loop()
      for (int i = 0; i < peerCount; ++i) {
        JsonObject o = a.add<JsonObject>();
        o["id"] = peers[i].id; o["name"] = peers[i].name; o["ip"] = peers[i].ip;
        o["port"] = peers[i].port; o["role"] = peers[i].role; o["group"] = peers[i].group;
        o["type"] = peers[i].type; o["fw"] = peers[i].fw; o["self"] = false;
      }
    }
    String out; serializeJson(d, out); r->send(200, "application/json", out);
  });

  server.on("/api/state", HTTP_GET, [](AsyncWebServerRequest* r) {
    r->send(200, "application/json", telemetryJson());
  });

  server.on("/api/led", HTTP_GET, [](AsyncWebServerRequest* r) {
    JsonDocument d; d["mode"] = cfg.ledMode; d["brightness"] = cfg.ledBright; d["timeout"] = cfg.ledTimeout;
    String out; serializeJson(d, out); r->send(200, "application/json", out);
  });
  server.on("/api/led/identify", HTTP_POST, [](AsyncWebServerRequest* r) {
    if (!originIsLocal(r)) return sendUnauth(r);
    identifyUntil = millis() + 4000; lastLedState = -1;
    r->send(200, "application/json", "{\"ok\":1}");
  });

  // UPnP device description (referenced by the SSDP LOCATION header)
  server.on("/description.xml", HTTP_GET, [](AsyncWebServerRequest* r) {
    String ip = WiFi.localIP().toString();
    String x = "<?xml version=\"1.0\"?>"
      "<root xmlns=\"urn:schemas-upnp-org:device-1-0\">"
      "<specVersion><major>1</major><minor>0</minor></specVersion><device>"
      "<deviceType>urn:schemas-upnp-org:device:Basic:1</deviceType>"
      "<friendlyName>" + gName + "</friendlyName>"
      "<manufacturer>LEO</manufacturer>"
      "<modelName>" + String(DEVICE_MODEL) + "</modelName>"
      "<modelNumber>" + String(FW_VERSION) + "</modelNumber>"
      "<serialNumber>" + WiFi.macAddress() + "</serialNumber>"
      "<UDN>" + gUUID + "</UDN>"
      "<presentationURL>http://" + ip + "/</presentationURL>"
      "</device></root>";
    r->send(200, "text/xml", x);
  });
  server.on("/api/relaymap", HTTP_GET, [](AsyncWebServerRequest* r) {
    JsonDocument d; JsonArray pool = d["pool"].to<JsonArray>();
    for (int i = 0; i < RELAY_COUNT; ++i) pool.add(RELAY_GPIO_POOL[i]);
    JsonArray a = d["relays"].to<JsonArray>();
    for (int i = 0; i < RELAY_COUNT; ++i) { JsonObject o = a.add<JsonObject>(); o["name"] = cfg.relay[i].name; o["gpio"] = cfg.relay[i].gpio; o["watts"] = cfg.relay[i].watts; }
    String out; serializeJson(d, out); r->send(200, "application/json", out);
  });
  server.on("/api/timecfg", HTTP_GET, [](AsyncWebServerRequest* r) {
    JsonDocument d; d["tz"] = cfg.tz; d["h24"] = cfg.h24; d["synced"] = timeSynced; d["drift"] = clockDriftSec;
    String out; serializeJson(d, out); r->send(200, "application/json", out);
  });
  server.on("/api/authcfg", HTTP_GET, [](AsyncWebServerRequest* r) {
    JsonDocument d; d["enabled"] = cfg.authEnabled; d["user"] = cfg.authUser;
    String out; serializeJson(d, out); r->send(200, "application/json", out);
  });
  server.on("/api/scan", HTTP_GET, [](AsyncWebServerRequest* r) {
    if (!checkAuth(r)) return sendUnauth(r);
    int n = WiFi.scanComplete();
    if (n == -2) { WiFi.scanNetworks(true); r->send(202, "application/json", "{\"scanning\":1}"); return; }
    if (n == -1) { r->send(202, "application/json", "{\"scanning\":1}"); return; }
    JsonDocument d; d["connected"] = WiFi.status() == WL_CONNECTED ? WiFi.SSID() : "";
    JsonArray a = d["nets"].to<JsonArray>();
    for (int i = 0; i < n && i < 20; ++i) { JsonObject o = a.add<JsonObject>(); o["ssid"] = WiFi.SSID(i); o["rssi"] = WiFi.RSSI(i); o["lock"] = WiFi.encryptionType(i) != WIFI_AUTH_OPEN; }
    String out; serializeJson(d, out); WiFi.scanDelete(); r->send(200, "application/json", out);
  });
  server.on("/api/energy", HTTP_GET, [](AsyncWebServerRequest* r) {
    energyAccrueAll();
    JsonDocument d; d["tariff"] = cfg.tariff;
    JsonArray names = d["names"].to<JsonArray>(); for (int i = 0; i < RELAY_COUNT; ++i) names.add(cfg.relay[i].name);
    JsonArray a = d["days"].to<JsonArray>();
    { LockGuard g;                                    // energyDays[] is also written from loop()
      for (int i = 0; i < energyCount; ++i) {
        JsonObject o = a.add<JsonObject>(); o["d"] = energyDays[i].date;
        double tot = 0; JsonArray w = o["wh"].to<JsonArray>();
        for (int rr = 0; rr < RELAY_COUNT; ++rr) { w.add(energyDays[i].wh[rr]); tot += energyDays[i].wh[rr]; }
        o["kwh"] = tot / 1000.0; o["cost"] = (tot / 1000.0) * cfg.tariff;
      }
    }
    String out; serializeJson(d, out); r->send(200, "application/json", out);
  });
  server.on("/api/logs", HTTP_GET, [](AsyncWebServerRequest* r) {
    if (!checkAuth(r)) return sendUnauth(r);
    File f = LittleFS.open(LOG_FILE, "r");
    String body = "{\"logs\":[";
    if (f) { bool first = true; while (f.available()) { String l = f.readStringUntil('\n'); if (!l.length()) continue; if (!first) body += ","; body += l; first = false; } f.close(); }
    body += "]}"; r->send(200, "application/json", body);
  });
  server.on("/api/logs/clear", HTTP_POST, [](AsyncWebServerRequest* r) {
    if (!checkAuth(r)) return sendUnauth(r);
    LittleFS.remove(LOG_FILE); r->send(200, "application/json", "{\"ok\":1}");
  });
  server.on("/api/reboot", HTTP_POST, [](AsyncWebServerRequest* r) {
    if (!checkAuth(r)) return sendUnauth(r);
    r->send(200, "application/json", "{\"ok\":1}");
    scheduleRestart(800, true);
  });

  // JSON body handlers
  server.addHandler(new AsyncCallbackJsonWebHandler("/api/relay",   onJsonRelay));
  server.addHandler(new AsyncCallbackJsonWebHandler("/api/all",     onJsonAll));
  server.addHandler(new AsyncCallbackJsonWebHandler("/api/network", onJsonNetwork));
  server.addHandler(new AsyncCallbackJsonWebHandler("/api/ap",      onJsonAp));
  server.addHandler(new AsyncCallbackJsonWebHandler("/api/time",    onJsonTime));
  server.addHandler(new AsyncCallbackJsonWebHandler("/api/relaymap/set", onJsonMap));
  server.addHandler(new AsyncCallbackJsonWebHandler("/api/tariff",  onJsonTariff));
  server.addHandler(new AsyncCallbackJsonWebHandler("/api/auth",    onJsonAuth));
  server.addHandler(new AsyncCallbackJsonWebHandler("/api/role",    onJsonRole));
  server.addHandler(new AsyncCallbackJsonWebHandler("/api/devicename", onJsonDeviceName));
  server.addHandler(new AsyncCallbackJsonWebHandler("/api/mdns",    onJsonMdns));
  server.addHandler(new AsyncCallbackJsonWebHandler("/api/led",     onJsonLed));
  server.addHandler(new AsyncCallbackJsonWebHandler("/api/login",   onJsonLogin));
  server.addHandler(new AsyncCallbackJsonWebHandler("/api/reset",   onJsonReset));

  server.onNotFound([](AsyncWebServerRequest* r) {
    if (r->method() == HTTP_OPTIONS) { r->send(200); return; }   // CORS preflight
    r->send(404, "text/plain", "404");
  });
  server.begin();
}

/* ============================ SETUP =============================== */
void setup() {
  stateLock = xSemaphoreCreateMutex();  // before anything else can touch shared state
  consoleLock = xSemaphoreCreateMutex();
  Serial.begin(115200);
  setCpuFrequencyMhz(CPU_MHZ);        // run cooler; 80 MHz is ample for the web server
  pix.begin(); pix.setBrightness(NEOPIXEL_BRIGHT); ledState = LED_BOOT; ledTick();

  // Mount FS with retry; only format as a last resort so logs/config survive.
  bool fs = LittleFS.begin(false);
  if (!fs) { delay(100); fs = LittleFS.begin(false); }
  if (!fs) { fs = LittleFS.begin(true); }          // last resort: format
  if (!fs) { ledState = LED_ERROR; }

  configLoad();
  authLoad();
  energyLoad();
  relayInitPins();              // all OFF, glitch-safe
  logPrune();

  if (cfg.apPass == String(DEFAULT_AP_PASS))
    logEvent("ERR", "Default AP password in use - change it in Network settings");
  if (cfg.authEnabled && cfg.authPass.length() && cfg.authPass.length() != 64)
    logEvent("INFO", "Stored password uses the old hash format - it upgrades automatically on next login");
  fsStatRefresh();

  clockBegin();                 // own clock now, NTP drift correction later
  wifiBegin();
  webBegin();

  // watchdog: if loop() stalls, reboot -> relays come up OFF (intended)
  // Arduino core 3.x already initialises the task WDT at boot, so a bare
  // esp_task_wdt_init() returns ESP_ERR_INVALID_STATE and our timeout was
  // silently ignored. Reconfigure in that case.
  esp_task_wdt_config_t wdt = { .timeout_ms = WDT_TIMEOUT_S * 1000, .idle_core_mask = 0, .trigger_panic = true };
  if (esp_task_wdt_init(&wdt) == ESP_ERR_INVALID_STATE) esp_task_wdt_reconfigure(&wdt);
  esp_task_wdt_add(NULL);

  logEvent("ERR", String("Boot ") + FW_VERSION);
}

/* ============================ LOOP ================================ */
void loop() {
  uint32_t t0 = millis();
  esp_task_wdt_reset();
  ws.cleanupClients();
  consoleWs.cleanupClients();
  ledTick();
  wifiHandlePending();                 // connect/disconnect work deferred from the event task
  wifiTick();
  beaconPoll();                        // receive peer announcements (non-blocking)

  // deferred reboot requested by an HTTP handler (reply has been sent by now)
  if (restartAt && (int32_t)(millis() - restartAt) >= 0) {
    if (restartSaveEnergy) energySave();
    ESP.restart();
  }
  if (millis() - lastFsStat >= 30000) fsStatRefresh();

  if (millis() - lastTick >= TICK_PUSH_MS) { lastTick = millis(); pushTelemetry(); }
  if (millis() - lastEnergyFlush >= ENERGY_FLUSH_MS) { lastEnergyFlush = millis(); energySave(); }
  // logPrune() also runs once at boot, but the clock isn't synced yet at that
  // point so its age-based cutoff is a no-op there; this periodic call is
  // what actually enforces the 90-day retention once NTP has synced.
  if (millis() - lastLogPrune >= LOG_PRUNE_MS) { lastLogPrune = millis(); logPrune(); }
  if (millis() - lastClockPersist >= CLOCK_PERSIST_MS) { lastClockPersist = millis(); if (timeSynced) clockPersist(); }
  if (ssdpUp && millis() - lastNotify >= 300000) { lastNotify = millis(); ssdpNotify(); }
  if (beaconUp && millis() - lastBeacon >= BEACON_MS) { lastBeacon = millis(); beaconAnnounce(); peerPrune(); }

  // deferred re-advertise (kept out of async handler context for stability)
  if (mdnsDirty)   { mdnsDirty = false;   discoveryMdns(); }
  if (beaconDirty) { beaconDirty = false; beaconAnnounce(); }
  // re-evaluate leoswitch.local ownership; re-advertise if it changed (failover)
  if (millis() - lastMdnsEval >= 3000) {
    lastMdnsEval = millis();
    if (effectiveMdnsHost() != curMdnsHost) mdnsDirty = true;
  }

  loopMs = millis() - t0;
  delay(5);                            // yield to idle (cooler than a tight spin)
}
