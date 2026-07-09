/* =====================================================================
   LEO Smart Switch  -  LEO_SmartSwitch.ino
   ESP32-C3  /  Arduino-ESP32 core 3.x   (Phase 1 firmware)

   Libraries (Library Manager / PlatformIO):
     - ESPAsyncWebServer  (ESP32Async org, ESP32 core 3.x compatible)
     - AsyncTCP           (ESP32Async org)
     - ArduinoJson  v7
     - Adafruit_NeoPixel
   Built-in: WiFi, ESPmDNS, LittleFS, esp_task_wdt, esp_sntp, time

   Flash an FS image too: index.html lives in /data and is served from
   LittleFS. (Arduino: "ESP32 LittleFS Data Upload"  |  PlatformIO: run -t
   uploadfs). Choose a partition scheme that includes a filesystem.
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
#include <time.h>
#include "config.h"

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
uint32_t lastClockPersist = 0;
bool   apActive       = false;

AsyncWebServer server(80);
AsyncWebSocket ws("/ws");
Adafruit_NeoPixel pix(NEOPIXEL_COUNT, NEOPIXEL_PIN, NEO_GRB + NEO_KHZ800);

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

/* ============================ FORWARD ============================== */
void logEvent(const char* lvl, const String& msg);
void pushTelemetry();
String telemetryJson();

/* ============================ HELPERS ============================== */
static uint32_t fnv1a(const String& s) {
  uint32_t h = 2166136261u;
  for (size_t i = 0; i < s.length(); ++i) { h ^= (uint8_t)s[i]; h *= 16777619u; }
  return h;
}
static String hashPass(const String& p) {
  char b[12]; snprintf(b, sizeof(b), "%08x", fnv1a("leo:" + p)); return String(b);
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
void relaySet(int i, bool on) {
  if (i < 0 || i >= RELAY_COUNT) return;
  energyAccrue(i);                       // bank energy up to this instant
  cfg.relay[i].on = on;
  cfg.relay[i].onSinceMs = on ? millis() : 0;
  relayApplyPin(cfg.relay[i].gpio, on);
  pushTelemetry();
}

/* ============================ ENERGY =============================== */
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
    if (hrs > 0) { DayBucket* b = energyToday(); b->wh[i] += r.watts * hrs; }
  }
  r.lastAccrueMs = now;
}
void energyAccrueAll() { for (int i = 0; i < RELAY_COUNT; ++i) energyAccrue(i); }

void energySave() {
  energyAccrueAll();
  JsonDocument doc; JsonArray a = doc["days"].to<JsonArray>();
  for (int i = 0; i < energyCount; ++i) {
    JsonObject o = a.add<JsonObject>(); o["d"] = energyDays[i].date;
    JsonArray w = o["wh"].to<JsonArray>();
    for (int r = 0; r < RELAY_COUNT; ++r) w.add(energyDays[i].wh[r]);
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
  for (int i = 0; i < authTokenCount; ++i) if (authTokens[i] == t && t.length()) return true;
  return false;
}
bool checkAuth(AsyncWebServerRequest* req) {
  if (!cfg.authEnabled) return true;
  if (req->hasHeader("X-Auth-Token") && tokenValid(req->header("X-Auth-Token"))) return true;
  return false;
}

/* ============================ LOGS ================================= */
void logEvent(const char* lvl, const String& msg) {
  // only critical / error are persisted
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
  // storage pressure: drop oldest while above fill limit
  auto over = []() { size_t t = LittleFS.totalBytes(), u = LittleFS.usedBytes(); return t && ((double)u / t) > FS_FILL_LIMIT; };
  while (over() && keep.size() > 1) keep.erase(keep.begin());
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
  if (first) { logEvent("ERR", String("NTP first sync, drift ") + (long)clockDriftSec + "s"); first = false; }
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
  if (peerCount >= MAX_PEERS) return;
  Peer& p = peers[peerCount++];
  p.id = id; p.name = d["name"] | id; p.ip = d["ip"] | fromIp;
  p.role = d["role"] | ""; p.group = d["group"] | ""; p.type = DEVICE_TYPE;
  p.fw = d["fw"] | ""; p.port = d["port"] | 80; p.cap = d["cap"] | true; p.lastSeen = millis();
}
void peerPrune() {
  uint32_t now = millis();
  for (int i = peerCount - 1; i >= 0; --i) {
    if (now - peers[i].lastSeen > PEER_TIMEOUT_MS) {
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

void wifiEvent(WiFiEvent_t e) {
  switch (e) {
    case ARDUINO_EVENT_WIFI_STA_GOT_IP:
      ledState = LED_ONLINE;
      apStop();                       // drop AP the instant we are online
      WiFi.mode(WIFI_STA);
      discoveryMdns();                // refresh mDNS on the STA interface
      ssdpStart(); ssdpNotify();      // announce as a smart-home device
      beaconStart(); beaconAnnounce();// join the LAN cluster
      staDownSince = 0; badHealth = 0; staGoodMs = millis();
      logEvent("ERR", "WiFi connected " + WiFi.localIP().toString());
      break;
    case ARDUINO_EVENT_WIFI_STA_DISCONNECTED:
      ssdpStop();
      if (WiFi.getMode() != WIFI_AP_STA) WiFi.mode(WIFI_AP_STA);
      apStart();                      // bring AP back fast
      ledState = cfg.staSsid.length() ? LED_CONNECTING : LED_AP;
      break;
    default: break;
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
  if (WiFi.getMode() != WIFI_AP_STA) WiFi.mode(WIFI_AP_STA);
  apStart();                                   // make sure user still has the AP
  WiFi.disconnect();                           // drop the wedged association
  WiFi.setTxPower(WIFI_TX_POWER);
  WiFi.begin(cfg.staSsid.c_str(), cfg.staPass.c_str());
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
    WiFi.setTxPower(WIFI_TX_POWER);
    WiFi.begin(cfg.staSsid.c_str(), cfg.staPass.c_str());
    // If we've been down a long time, a full radio reset clears deeper wedges.
    if (staDownSince == 0) staDownSince = millis();
    if (millis() - staDownSince > 120000) {    // 2 min of failure -> hard reset radio
      staDownSince = millis();
      WiFi.disconnect(true); delay(20); WiFi.mode(WIFI_AP_STA); apStart();
      WiFi.begin(cfg.staSsid.c_str(), cfg.staPass.c_str());
    }
  }
}

/* ============================ TELEMETRY ============================ */
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
  d["fsUsed"]  = (uint32_t)(LittleFS.usedBytes() / 1024);
  d["fsTotal"] = (uint32_t)(LittleFS.totalBytes() / 1024);
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
  for (int i = 0; i < RELAY_COUNT; ++i) relaySet(i, on);
  req->send(200, "application/json", "{\"ok\":1}");
}
void onJsonNetwork(AsyncWebServerRequest* req, JsonVariant& json) {
  if (!checkAuth(req)) return sendUnauth(req);
  cfg.staSsid = json["ssid"] | ""; cfg.staPass = json["pass"] | "";
  configSave(); req->send(200, "application/json", "{\"ok\":1}");
  delay(200); ESP.restart();
}
void onJsonAp(AsyncWebServerRequest* req, JsonVariant& json) {
  if (!checkAuth(req)) return sendUnauth(req);
  String s = json["ssid"] | ""; String p = json["pass"] | "";
  if (s.length()) cfg.apSsid = s; if (p.length() >= 8) cfg.apPass = p;
  configSave(); req->send(200, "application/json", "{\"ok\":1}");
  delay(200); ESP.restart();
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
    relaySet(idx, false);                            // safe-off before remap
    cfg.relay[idx].name  = o["name"]  | cfg.relay[idx].name;
    cfg.relay[idx].gpio  = o["gpio"]  | cfg.relay[idx].gpio;
    cfg.relay[idx].watts = o["watts"] | cfg.relay[idx].watts;
    idx++;
  }
  relayInitPins(); configSave();
  req->send(200, "application/json", "{\"ok\":1}");
}
void onJsonTariff(AsyncWebServerRequest* req, JsonVariant& json) {
  if (!checkAuth(req)) return sendUnauth(req);
  cfg.tariff = json["tariff"] | cfg.tariff; configSave();
  req->send(200, "application/json", "{\"ok\":1}");
}
void onJsonAuth(AsyncWebServerRequest* req, JsonVariant& json) {
  if (!checkAuth(req)) return sendUnauth(req);
  cfg.authEnabled = json["enabled"] | false;
  if (json["user"].is<const char*>()) cfg.authUser = json["user"].as<String>();
  if (json["pass"].is<const char*>() && String(json["pass"].as<String>()).length())
    cfg.authPass = hashPass(json["pass"].as<String>());
  configSave(); req->send(200, "application/json", "{\"ok\":1}");
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
  String u = json["user"] | ""; String p = json["pass"] | "";
  if (cfg.authEnabled && u == cfg.authUser && hashPass(p) == cfg.authPass) {
    String t = authIssue();
    req->send(200, "application/json", String("{\"token\":\"") + t + "\"}");
  } else req->send(401, "application/json", "{\"err\":\"bad\"}");
}
void onJsonReset(AsyncWebServerRequest* req, JsonVariant& json) {
  if (!checkAuth(req)) return sendUnauth(req);
  if (String(json["confirm"] | "") != "RESET") { req->send(400, "application/json", "{\"err\":\"confirm\"}"); return; }
  LittleFS.remove(CFG_FILE); LittleFS.remove(ENERGY_FILE);
  LittleFS.remove(LOG_FILE); LittleFS.remove(AUTH_FILE); LittleFS.remove(CLOCK_FILE);
  req->send(200, "application/json", "{\"ok\":1}"); delay(300); ESP.restart();
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

  // static UI from LittleFS
  server.serveStatic("/", LittleFS, "/").setDefaultFile("index.html");

  // identity: who am I (stable id, never tied to mDNS)
  server.on("/api/identity", HTTP_GET, [](AsyncWebServerRequest* r) {
    JsonDocument d;
    d["id"] = gId; d["name"] = gName; d["role"] = cfg.role; d["group"] = cfg.group;
    d["mdns"] = (curMdnsHost.length() ? curMdnsHost : String(DEFAULT_MDNS_HOST)) + ".local"; d["ip"] = WiFi.localIP().toString();
    d["mdnsAuto"] = (cfg.mdnsHost.length() == 0); d["ownsCanonical"] = canonicalOwner();
    d["ap"] = cfg.apSsid; d["apip"] = WiFi.softAPIP().toString();
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
    for (int i = 0; i < peerCount; ++i) {
      JsonObject o = a.add<JsonObject>();
      o["id"] = peers[i].id; o["name"] = peers[i].name; o["ip"] = peers[i].ip;
      o["port"] = peers[i].port; o["role"] = peers[i].role; o["group"] = peers[i].group;
      o["type"] = peers[i].type; o["fw"] = peers[i].fw; o["self"] = false;
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
    for (int i = 0; i < energyCount; ++i) {
      JsonObject o = a.add<JsonObject>(); o["d"] = energyDays[i].date;
      double tot = 0; JsonArray w = o["wh"].to<JsonArray>();
      for (int rr = 0; rr < RELAY_COUNT; ++rr) { w.add(energyDays[i].wh[rr]); tot += energyDays[i].wh[rr]; }
      o["kwh"] = tot / 1000.0; o["cost"] = (tot / 1000.0) * cfg.tariff;
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
    r->send(200, "application/json", "{\"ok\":1}"); delay(300); ESP.restart();
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

  clockBegin();                 // own clock now, NTP drift correction later
  wifiBegin();
  webBegin();

  // watchdog: if loop() stalls, reboot -> relays come up OFF (intended)
  esp_task_wdt_config_t wdt = { .timeout_ms = WDT_TIMEOUT_S * 1000, .idle_core_mask = 0, .trigger_panic = true };
  esp_task_wdt_init(&wdt);
  esp_task_wdt_add(NULL);

  logEvent("ERR", String("Boot ") + FW_VERSION);
}

/* ============================ LOOP ================================ */
void loop() {
  uint32_t t0 = millis();
  esp_task_wdt_reset();
  ws.cleanupClients();
  ledTick();
  wifiTick();
  beaconPoll();                        // receive peer announcements (non-blocking)

  if (millis() - lastTick >= TICK_PUSH_MS) { lastTick = millis(); pushTelemetry(); }
  if (millis() - lastEnergyFlush >= ENERGY_FLUSH_MS) { lastEnergyFlush = millis(); energySave(); }
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
