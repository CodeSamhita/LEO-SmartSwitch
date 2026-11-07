/* =====================================================================
   LEO Home Hub  -  LEO_Hub.ino            (ESP32-S3, Arduino-ESP32 core 3.x)

   The ONE device on your home WiFi. Edge devices (LEO switches, AquaNode
   tank) talk to this hub over ESP-NOW - they need no WiFi password, run no
   web server and make no hotspot. This hub serves a single web app for all
   of them, relays commands, and pushes firmware updates to them.

   Security (v1.1):
   - Every hub<->edge packet is signed (HMAC-SHA256, per-device 128-bit key,
     per-session nonce + counter => no forging, no replay). Keys are handed
     out once, when a device pairs, and pairing only happens while the user
     has pressed "Allow new devices" (or for a device the hub already knew).
   - Web app password (salted SHA-256), remembered browsers via cookie,
     5-try lockout. Forgotten password: send RESETPASS over USB.
   - Emergency hotspot uses a random per-hub password (changeable).
   - Night lock: refuses every ON command (manual or on a schedule).
   - Activity log: every ON/OFF with time and who/what caused it.

   Board settings (Arduino IDE / arduino-cli):
     Board            : ESP32S3 Dev Module
     Flash Size       : 8MB (64Mb)
     Partition Scheme : 8M with spiffs (3MB APP/1.5MB SPIFFS)   <- OTA needs this
     USB Mode         : Hardware CDC and JTAG,  USB CDC On Boot: Enabled
   Libraries: ESPAsyncWebServer + AsyncTCP (ESP32Async), ArduinoJson 7
   USB serial commands (115200): SETWIFI<TAB>ssid<TAB>pass | RESETPASS | SHOWAP
   ===================================================================== */
#include <Arduino.h>
#include <WiFi.h>
#include <esp_now.h>
#include <esp_wifi.h>
#include <esp_mac.h>
#include <ESPmDNS.h>
#include <LittleFS.h>
#include <Preferences.h>
#include <Update.h>
#include <ESPAsyncWebServer.h>
#include <AsyncJson.h>
#include <ArduinoJson.h>
#include <esp_task_wdt.h>
#include <Adafruit_NeoPixel.h>
#include <mbedtls/md.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <time.h>
#include <vector>

#define HUB_FW            "2.0.3"
#define HUB_MDNS          "leohub"
#define MAX_DEV           16
#define OFFLINE_MS        9000      // edge counted offline after this long without a verified packet
#define PING_MS           3000      // signed keep-alive to each edge (edges re-link after ~10 s silence)
#define STA_RETRY_MS      15000
#define AP_FALLBACK_MS    30000     // open the emergency hotspot if WiFi isn't up within this
#define CONSOLE_LINES     150
#define CONSOLE_LINE_LEN  128
#define DEV_FILE          "/devices.json"
#define EDGE_BIN          "/edge.bin"
#define ACT_FILE          "/activity.log"
#define ACT_MAX_BYTES     48000
#define MAX_TOKENS        10

/* ===================== LEO EDGE PROTOCOL v2 ==========================
   Keep IDENTICAL in the hub and every edge sketch. Packed, little-endian.
   Every packet except HELLO ends with a LeoAuth trailer:
     tag = HMAC-SHA256(key, session || body || ctr)[0..7]
   session = the edge's random nonce from its latest HELLO; ctr strictly
   increases per direction within a session (replays are dropped).       */
#define LEO_MAGIC  0x4C45
#define LEO_PROTO  2
enum : uint8_t { M_HELLO = 1, M_WELCOME = 2, M_SW_STATE = 3, M_SW_INFO = 4, M_TANK_STATE = 5, M_TANK_INFO = 6,
                 M_CMD = 7, M_OTA_BEGIN = 10, M_OTA_DATA = 11, M_OTA_END = 12, M_OTA_ACK = 13, M_PING = 14, M_DIAG = 15, M_TANK_RULES = 16 };
enum : uint8_t { DEV_SWITCH = 1, DEV_TANK = 2 };
enum : uint8_t { C_RELAY = 1, C_ALL = 2, C_IDENTIFY = 3, C_RENAME = 4, C_RELAY_META = 5, C_REBOOT = 6, C_INFO = 7, C_UNPAIR = 8, C_TOUCH = 9,
                 C_TANK_SET = 10, C_SILENCE = 11, C_BEEP = 12, C_FACTORY = 13, C_TANK_RULE = 14 };   // C_FACTORY: wipe all settings + pairing, restart; C_TANK_RULE: idx = rule 0..5, text[0..5] = on,level,dir,pattern,repeats,color; C_BEEP idx>0 = play sound pattern idx-1 once   // C_TANK_SET: idx 1 fullCm 2 emptyCm 3 fullPct 4 lowPct 5 buzzer 6 quietFrom 7 quietTo 8 palette 9 ledCount 10 showFrom 11 showTo 12 minBright 13..20 custom colour of LED 1..8 (0xRRGGBB) 21 current-level highlight 0..50 % 22..29 colour-matching brightness of LED 1..8 (10..100 %) 30 light all level LEDs for f seconds (0 = stop), value in f
struct __attribute__((packed)) LeoHdr      { uint16_t magic; uint8_t proto; uint8_t type; uint8_t dev; uint8_t seq; };
struct __attribute__((packed)) LeoAuth     { uint32_t ctr; uint8_t tag[8]; };
struct __attribute__((packed)) MsgHello    { LeoHdr h; uint32_t nonce; uint8_t hasKey; char fw[16]; char name[24]; };
struct __attribute__((packed)) MsgWelcome  { LeoHdr h; uint8_t channel; uint8_t keyIncluded; uint8_t key[16]; char hubName[24]; };
struct __attribute__((packed)) MsgPing     { LeoHdr h; int16_t mins; uint8_t room; uint16_t beat;
                                              uint8_t g; uint8_t quietFrom, quietTo, dayFrom, dayTo, ledDay, ledNight; uint16_t litOn, litOff; };   // g = 1: global home settings follow (hub 2.0+)   // beat: hub millis() % 10000 when sent (LED breathing sync)   // mins: hub local time (-1 unknown); room: 1 lit, 0 dark, 255 unknown (from the tank's LDR)
struct __attribute__((packed)) MsgSwState  { LeoHdr h; uint8_t n; uint8_t onMask; uint32_t uptime; uint32_t onSecs[4]; };
struct __attribute__((packed)) MsgSwInfo   { LeoHdr h; char name[24]; char fw[16]; uint8_t n; char rname[4][20]; float watts[4]; uint8_t gpio[4]; uint8_t touch; };   // touch: 1 = touch buttons enabled (switch 2.2+)
struct __attribute__((packed)) MsgTankState{ LeoHdr h; float levelPct; float distCm; uint8_t leds; uint8_t state; uint8_t sensorOk; uint8_t flags; uint32_t uptime; char stateTxt[24]; uint16_t ldr; };   // ldr: room light 0..4095 (tank 1.1+)
struct __attribute__((packed)) MsgTankInfo { LeoHdr h; float fullCm; float emptyCm; uint8_t fullPct; uint8_t lowPct; uint8_t buzzer; uint8_t quietFrom; uint8_t quietTo; uint8_t palette; uint8_t ledCount; uint8_t showFrom; uint8_t showTo; uint8_t minBright; uint8_t colors[24]; uint8_t highlight; uint8_t gain[8]; };   // tank settings (palette 0 red-blue, 1 red-green, 2 custom = colors[] RGB x8, bottom first)
struct __attribute__((packed)) MsgTankRules { LeoHdr h; uint8_t count; uint8_t r[6][6]; };   // alarm rules: on, level %, dir (0 rises to, 1 drops to), pattern, repeats, colour
struct __attribute__((packed)) MsgDiag     { LeoHdr h; int16_t tempC10; uint32_t heapFree; uint32_t heapMin; uint32_t fsUsed; uint32_t fsTotal; uint32_t flashSize; uint32_t sketchSize; uint32_t sketchMax; uint8_t resetReason; uint8_t cpuMHz; char sdk[16]; };   // chip details for the Advanced view
struct __attribute__((packed)) MsgCmd      { LeoHdr h; uint8_t cmd; uint8_t idx; uint8_t val; float f; char text[24]; };
struct __attribute__((packed)) MsgOtaBegin { LeoHdr h; uint32_t size; };
struct __attribute__((packed)) MsgOtaData  { LeoHdr h; uint32_t off; uint16_t len; uint8_t data[200]; };
struct __attribute__((packed)) MsgOtaAck   { LeoHdr h; uint8_t phase; uint32_t off; uint8_t ok; char err[24]; };

/* types used by functions must precede the first function (Arduino auto-prototypes) */
struct RxItem { uint8_t mac[6]; int8_t rssi; uint8_t len; uint8_t data[250]; };

/* ===================================================================== */

/* ------------------------------ state ------------------------------ */
struct Dev {
  bool     used;
  uint8_t  mac[6];
  uint8_t  type;
  char     name[24];
  char     fw[16];
  bool     hasKey;
  uint8_t  key[16];
  uint32_t session;      // edge's nonce from its latest HELLO (0 = unknown since hub boot)
  uint32_t txCtr, rxCtr;
  uint32_t lastSeen;     // millis of last VERIFIED packet
  uint32_t lastPing;
  bool     pingRetry;                     // last packet to it was not acknowledged: ping again soon
  uint8_t  failRun;                       // unacknowledged packets in a row
  uint16_t txSent, txFail;                // radio delivery stats for the current session
  int8_t   rssi;
  uint32_t uptime;
  // switch
  uint8_t  n, onMask;
  bool     maskKnown;
  uint8_t  confMask;                    // last mask the EDGE confirmed (onMask may be optimistic)
  uint8_t  expectMask, expectValid;     // what the last hub command should produce (to tell "changed at device")
  uint32_t expectAt;
  uint32_t onSecs[4];
  char     rname[4][20];
  float    watts[4];
  uint8_t  gpio[4];
  bool     infoKnown;
  uint8_t  touch;                         // 0 off, 1 on, 255 = switch firmware without touch support
  // tank
  float    levelPct, distCm;
  uint8_t  leds, tstate, sensorOk;
  char     stateTxt[24];
  uint16_t ldr;                           // room light from the tank's LDR, 0xFFFF unknown
  uint8_t  tflags;                        // tank flags: 1 alarm active, 2 silenced, 4 room dark
  bool     tcfgKnown;                     // tank settings (from M_TANK_INFO)
  float    tFullCm, tEmptyCm;
  uint8_t  tFullPct, tLowPct, tBuzzer, tQuietFrom, tQuietTo, tPalette, tLedCount, tShowFrom, tShowTo, tMinBright;
  uint8_t  tColors[24]; bool tColorsKnown;  // custom level colours (tank 1.6+)
  uint8_t  tHighlight, tGain[8]; bool tGainKnown;   // current-level highlight %, colour-matching brightness per LED (tank 1.7.3+)
  uint8_t  tRules[36]; bool tRulesKnown;    // alarm rules (tank 1.7+): 6 x {on, level, dir, pattern, repeats, color}
  uint8_t  hideMask;                      // switch relays marked "not in use" (hidden, skipped by All on) - saved in devices.json
  bool     diagKnown;                     // chip details from M_DIAG (Advanced view)
  int16_t  dTemp; uint32_t dHeap, dHeapMin, dFsUsed, dFsTotal, dFlash, dSketch, dSketchMax; uint8_t dReset, dCpu; char dSdk[16];
};
Dev devs[MAX_DEV];
SemaphoreHandle_t devLock;
struct DevGuard { DevGuard() { xSemaphoreTake(devLock, portMAX_DELAY); } ~DevGuard() { xSemaphoreGive(devLock); } };

struct TxItem { uint8_t mac[6]; MsgCmd cmd; };
struct TxResult { uint8_t mac[6]; bool ok; };
/* 24 h trend per device: one value per 5-minute slot (switch: average watts, tank: level x10); 0xFFFF = no data */
#define HIST_SLOTS 288
#define HIST_STEP  300
#define HIST_FILE  "/hist.bin"
#define HIST_HOURS 168                  // plus hourly averages for 7 days
#define FINE_SLOTS 360                  // plus one reading every 10 s for the last hour (RAM only, for the 1 h chart)
struct Fine { uint8_t mac[6]; bool used; uint32_t lastTick; uint16_t v[FINE_SLOTS]; };
Fine fine[4];
struct Hist { bool used; uint8_t mac[6]; uint32_t lastSlot; uint32_t accSum; uint16_t accN; uint16_t v[HIST_SLOTS];
              uint32_t lastHour; uint32_t hAccSum; uint16_t hAccN; uint16_t h[HIST_HOURS]; };
Hist hist[4];
QueueHandle_t rxq, txq, txres;

Preferences prefs;
String cfgSsid, cfgPass, hubName, apPass, pwHash;
String hubId;                       // "HUB-XXXXXX"
String tokens[MAX_TOKENS]; int tokenCount = 0;
int    loginFails = 0; uint32_t loginLockUntil = 0;
uint32_t pairingUntil = 0;
uint8_t  pendingMac[6]; uint32_t pendingAt = 0;   // an unknown device asking to join while adding is closed (shown in the app)
bool lockManual = false, lockSched = false; int lockFrom = 23 * 60, lockTo = 6 * 60;   // night lock

AsyncWebServer server(80);
AsyncWebSocket ws("/ws");
AsyncWebSocket consoleWs("/console");

volatile bool netUpPending = false, netDownPending = false;
bool     staUp = false, apUp = false;
// onboard RGB LED: GPIO48 on most ESP32-S3 DevKitC boards, GPIO38 on DevKitC v1.1 - drive both (nothing else uses them)
Adafruit_NeoPixel ledA(1, 48, NEO_GRB + NEO_KHZ800), ledB(1, 38, NEO_GRB + NEO_KHZ800);
// room light for every device, taken from the tank's LDR: 1 lit, 0 dark, 255 unknown (no tank online -> clock)
uint8_t roomLight = 255;
uint8_t savedRoom = 0;                    // last known room light, kept in flash for the power-on glow
/* Power-on glow: soft warm white the instant the hub gets power, gone after ~1.5 s.
   Peak 14/255 if the room was lit last time, 3/255 if it was dark (or never known). */
#define BOOT_GLOW_MS  1500
uint8_t bootGlowLevel() {
  uint32_t t = millis(); if (t >= BOOT_GLOW_MS) return 0;
  uint8_t peak = savedRoom == 1 ? 14 : 3;
  if (t < BOOT_GLOW_MS - 300) return peak;
  return (uint8_t)(peak * (BOOT_GLOW_MS - t) / 300);
}
/* GLOBAL home settings (Hub -> Home settings): stored on the hub and sent to every device in each keep-alive;
   devices save the last values so they keep following them when the hub is off. Device-specific settings
   (tank calibration, rules, colours, relays, touch pads...) stay on each device. */
uint8_t  gQuietFrom = 22, gQuietTo = 7;  // no sounds between these hours (from == to: none)
uint8_t  gDayFrom = 7, gDayTo = 18;      // daytime: displays may stay on dimly; clock fallback for day/night
uint8_t  gLedDay = 5, gLedNight = 2;     // status light peak brightness (/255) in a bright / dark room
uint16_t gLitOn = 120, gLitOff = 80;     // room counts as bright above gLitOn, dark again below gLitOff (tank LDR)
bool     gInit = false;                  // copied once from the tank's own values when upgrading
void globalsSave() {
  prefs.putUChar("gqf", gQuietFrom); prefs.putUChar("gqt", gQuietTo); prefs.putUChar("gdf", gDayFrom); prefs.putUChar("gdt", gDayTo);
  prefs.putUChar("gld", gLedDay); prefs.putUChar("gln", gLedNight); prefs.putUShort("glon", gLitOn); prefs.putUShort("gloff", gLitOff);
  prefs.putBool("ginit", true); gInit = true;
}
uint32_t staDownSince = 0, lastStaTry = 0, lastPush = 0, restartAt = 0;
bool     stateDirty = true;
uint8_t  txSeq = 0;
bool     otaFailed = false; String otaErr;     // hub's own OTA

struct {                                       // edge OTA (hub -> edge over ESP-NOW, stop-and-wait)
  bool active; uint8_t mac[6]; File f; uint32_t size, off; uint16_t lastLen;
  uint8_t phase;                               // 1 begin, 2 data, 3 end
  uint32_t lastSend; uint8_t retries; int pct; String msg; bool uploadOk; String upErr;
  uint32_t doneAt;                             // when the last update finished (the page clears its message after a while)
} eota;

char consoleBuf[CONSOLE_LINES][CONSOLE_LINE_LEN];
int  consoleHead = 0, consoleCount = 0;
SemaphoreHandle_t consoleLock, actLock;

/* ---------------- protocol signing (after all type definitions) ---------------- */
void leoTag(const uint8_t* key, uint32_t session, const uint8_t* body, size_t len, uint32_t ctr, uint8_t* out8) {
  uint8_t buf[264]; size_t n = 0;
  memcpy(buf, &session, 4); n += 4;
  if (len > sizeof(buf) - 8) len = sizeof(buf) - 8;
  memcpy(buf + n, body, len); n += len;
  memcpy(buf + n, &ctr, 4); n += 4;
  uint8_t full[32];
  mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), key, 16, buf, n, full);
  memcpy(out8, full, 8);
}
/* returns total length (body + trailer) written into out */
size_t leoSign(uint8_t* out, const void* body, size_t len, const uint8_t* key, uint32_t session, uint32_t ctr) {
  memcpy(out, body, len);
  LeoAuth a; a.ctr = ctr; leoTag(key, session, out, len, ctr, a.tag);
  memcpy(out + len, &a, sizeof(a));
  return len + sizeof(a);
}
/* checks the trailer; on success *ctr = its counter and returns body length, else 0 */
size_t leoVerify(const uint8_t* pkt, size_t total, const uint8_t* key, uint32_t session, uint32_t* ctr) {
  if (total < sizeof(LeoHdr) + sizeof(LeoAuth)) return 0;
  size_t len = total - sizeof(LeoAuth);
  LeoAuth a; memcpy(&a, pkt + len, sizeof(a));
  uint8_t t[8]; leoTag(key, session, pkt, len, a.ctr, t);
  uint8_t diff = 0; for (int i = 0; i < 8; ++i) diff |= t[i] ^ a.tag[i];
  if (diff) return 0;
  *ctr = a.ctr; return len;
}

/* ------------------------------ helpers ---------------------------- */
void dbg(const String& msg) {
  char line[CONSOLE_LINE_LEN], stamp[24];
  time_t now = time(nullptr);
  if (now > 1700000000) {                       // clock set by NTP: "26-11-07 08:44:12"
    struct tm tm; localtime_r(&now, &tm); strftime(stamp, sizeof(stamp), "%y-%m-%d %I:%M:%S %p", &tm);
  } else {                                      // before NTP: seconds since boot
    snprintf(stamp, sizeof(stamp), "boot+%lus", (unsigned long)(millis() / 1000));
  }
  snprintf(line, sizeof(line), "[%s] %s", stamp, msg.c_str());
  xSemaphoreTake(consoleLock, portMAX_DELAY);
  memcpy(consoleBuf[consoleHead], line, sizeof(line));
  consoleHead = (consoleHead + 1) % CONSOLE_LINES;
  if (consoleCount < CONSOLE_LINES) consoleCount++;
  xSemaphoreGive(consoleLock);
  if (Serial && Serial.availableForWrite() >= (int)strlen(line) + 2) Serial.println(line);   // never block
  if (consoleWs.count()) consoleWs.textAll(line);
}
String consoleHistory() {
  String out; xSemaphoreTake(consoleLock, portMAX_DELAY);
  int start = consoleCount < CONSOLE_LINES ? 0 : consoleHead;
  for (int i = 0; i < consoleCount; ++i) { if (i) out += '\n'; out += consoleBuf[(start + i) % CONSOLE_LINES]; }
  xSemaphoreGive(consoleLock); return out;
}
String macStr(const uint8_t* m) {
  char b[18]; snprintf(b, sizeof(b), "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]); return String(b);
}
bool parseMac(const String& s, uint8_t* out) {
  unsigned v[6];
  if (sscanf(s.c_str(), "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6) return false;
  for (int i = 0; i < 6; ++i) out[i] = (uint8_t)v[i]; return true;
}
String hexStr(const uint8_t* b, size_t n) { String s; char x[3]; for (size_t i = 0; i < n; ++i) { snprintf(x, 3, "%02x", b[i]); s += x; } return s; }
bool parseHex(const String& s, uint8_t* out, size_t n) {
  if (s.length() != n * 2) return false;
  for (size_t i = 0; i < n; ++i) { unsigned v; if (sscanf(s.c_str() + i * 2, "%2x", &v) != 1) return false; out[i] = (uint8_t)v; }
  return true;
}
void copyStr(char* dst, size_t n, const char* src) { strncpy(dst, src, n - 1); dst[n - 1] = 0; }
void fillHdr(LeoHdr& h, uint8_t type) { h.magic = LEO_MAGIC; h.proto = LEO_PROTO; h.type = type; h.dev = 0; h.seq = ++txSeq; }
const char* typeName(uint8_t t) { return t == DEV_SWITCH ? "switch" : t == DEV_TANK ? "tank" : "unknown"; }
String randomText(int n) {
  const char* cs = "abcdefghjkmnpqrstuvwxyz23456789";      // no look-alikes (l/1, o/0)
  String s; for (int i = 0; i < n; ++i) s += cs[esp_random() % 31]; return s;
}
String newToken() { uint8_t rb[16]; esp_fill_random(rb, 16); return hexStr(rb, 16); }
String sha256Hex(const String& s) {
  uint8_t out[32];
  mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (const uint8_t*)s.c_str(), s.length(), out);
  return hexStr(out, 32);
}
String hashPass(const String& p) { return sha256Hex("leohub:" + hubId + ":" + p); }
bool constEq(const String& a, const String& b) {
  if (a.length() != b.length()) return false; uint8_t d = 0;
  for (size_t i = 0; i < a.length(); ++i) d |= a[i] ^ b[i]; return d == 0;
}
bool timeValid() { return time(nullptr) > 1700000000; }

/* ------------------------- activity log ---------------------------- */
void activity(const String& msg, bool blocked) {
  dbg("ACTIVITY: " + msg);
  JsonDocument d; d["t"] = timeValid() ? (long)time(nullptr) : 0; d["msg"] = msg; if (blocked) d["blocked"] = true;
  String line; serializeJson(d, line);
  xSemaphoreTake(actLock, portMAX_DELAY);
  File f = LittleFS.open(ACT_FILE, "a"); if (f) { f.println(line); f.close(); }
  f = LittleFS.open(ACT_FILE, "r");
  if (f && f.size() > ACT_MAX_BYTES) {                      // keep the newest half
    size_t sz = f.size(); f.seek(sz / 2); f.readStringUntil('\n');
    String rest = f.readString(); f.close();
    File w = LittleFS.open(ACT_FILE, "w"); if (w) { w.print(rest); w.close(); }
  } else if (f) f.close();
  xSemaphoreGive(actLock);
}

/* --------------------------- 24 h trends ---------------------------- */
Hist* histFor(const uint8_t* mac, uint32_t createAtSlot) {     // createAtSlot 0 = don't create
  for (int k = 0; k < 4; ++k) if (hist[k].used && !memcmp(hist[k].mac, mac, 6)) return &hist[k];
  if (!createAtSlot) return nullptr;
  for (int k = 0; k < 4; ++k) if (!hist[k].used) {
    Hist& h = hist[k]; memset(&h, 0, sizeof(h)); h.used = true; memcpy(h.mac, mac, 6); h.lastSlot = createAtSlot;
    h.lastHour = createAtSlot * HIST_STEP / 3600;
    for (int s = 0; s < HIST_SLOTS; ++s) h.v[s] = 0xFFFF;
    for (int s = 0; s < HIST_HOURS; ++s) h.h[s] = 0xFFFF;
    return &h;
  }
  return nullptr;
}
/* the 10-second readings are kept in RAM; they are written to flash only just before a planned restart
   (update, restart button) and read back at boot, so the 1 h chart survives updates */
#define FINE_FILE "/fine.bin"
void fineSave() {
  File f = LittleFS.open(FINE_FILE, "w"); if (!f) return;
  uint32_t magic = 0x4C464E31; f.write((uint8_t*)&magic, 4); f.write((uint8_t*)fine, sizeof(fine)); f.close();
}
void fineLoad() {
  File f = LittleFS.open(FINE_FILE, "r"); if (!f) return;
  uint32_t magic = 0;
  if (f.size() == 4 + sizeof(fine) && f.read((uint8_t*)&magic, 4) == 4 && magic == 0x4C464E31) f.read((uint8_t*)fine, sizeof(fine));
  f.close(); LittleFS.remove(FINE_FILE);                     // one-shot: a stale copy is never reused after a power cut
}
void histDrop(const uint8_t* mac) {
  Hist* h = histFor(mac, 0); if (h) h->used = false;
  for (int j = 0; j < 4; ++j) if (fine[j].used && !memcmp(fine[j].mac, mac, 6)) fine[j].used = false;
}
void histSave() {
  File f = LittleFS.open(HIST_FILE, "w"); if (!f) return;
  uint32_t magic = 0x4C484932; f.write((uint8_t*)&magic, 4); f.write((uint8_t*)hist, sizeof(hist)); f.close();
}
void histLoad() {
  File f = LittleFS.open(HIST_FILE, "r"); if (!f) return;
  uint32_t magic = 0;
  if (f.size() == 4 + sizeof(hist) && f.read((uint8_t*)&magic, 4) == 4 && magic == 0x4C484932) f.read((uint8_t*)hist, sizeof(hist));
  else memset(hist, 0, sizeof(hist));
  f.close();
}
void histTick() {                       // once a second from loop(): advance slots, then add the current values
  if (!timeValid()) return;
  uint32_t slot = (uint32_t)time(nullptr) / HIST_STEP; bool save = false;
  uint32_t hour = (uint32_t)time(nullptr) / 3600;
  for (int k = 0; k < 4; ++k) {                                // hourly averages (7 days)
    Hist& h = hist[k]; if (!h.used || hour == h.lastHour) continue;
    if (!h.lastHour) { h.lastHour = hour; continue; }
    h.h[h.lastHour % HIST_HOURS] = h.hAccN ? (uint16_t)(h.hAccSum / h.hAccN) : 0xFFFF;
    uint32_t gap = hour > h.lastHour ? hour - h.lastHour : HIST_HOURS;
    for (uint32_t s = 1; s < gap && s <= HIST_HOURS; ++s) h.h[(h.lastHour + s) % HIST_HOURS] = 0xFFFF;
    h.lastHour = hour; h.hAccSum = 0; h.hAccN = 0; h.h[hour % HIST_HOURS] = 0xFFFF;
  }
  for (int k = 0; k < 4; ++k) {
    Hist& h = hist[k]; if (!h.used || slot == h.lastSlot) continue;
    h.v[h.lastSlot % HIST_SLOTS] = h.accN ? (uint16_t)(h.accSum / h.accN) : 0xFFFF;
    uint32_t gap = slot > h.lastSlot ? slot - h.lastSlot : HIST_SLOTS;        // clock jumped back -> start over
    for (uint32_t s = 1; s < gap && s <= HIST_SLOTS; ++s) h.v[(h.lastSlot + s) % HIST_SLOTS] = 0xFFFF;
    h.lastSlot = slot; h.accSum = 0; h.accN = 0; h.v[slot % HIST_SLOTS] = 0xFFFF;
    if (slot % 2 == 0) save = true;                                           // write to flash every 10 min
  }
  struct { uint8_t mac[6]; uint16_t v; } now[MAX_DEV]; int n = 0;
  { DevGuard g;
    for (int i = 0; i < MAX_DEV; ++i) {
      Dev& d = devs[i]; if (!d.used || !d.lastSeen || millis() - d.lastSeen >= OFFLINE_MS) continue;
      if (d.type == DEV_SWITCH && d.infoKnown) {
        float w = 0; for (int r = 0; r < 4; ++r) if (d.onMask & (1 << r)) w += d.watts[r];
        memcpy(now[n].mac, d.mac, 6); now[n].v = (uint16_t)constrain(w + 0.5f, 0.0f, 65000.0f); n++;
      } else if (d.type == DEV_TANK && d.sensorOk) {
        memcpy(now[n].mac, d.mac, 6); now[n].v = (uint16_t)constrain(d.levelPct * 10 + 0.5f, 0.0f, 1000.0f); n++;
      }
    } }
  for (int k = 0; k < n; ++k) { Hist* h = histFor(now[k].mac, slot); if (h) { h->accSum += now[k].v; h->accN++; h->hAccSum += now[k].v; h->hAccN++; } }
  // 10-second readings for the last hour (gaps stay 0xFFFF)
  uint32_t tick = (uint32_t)time(nullptr) / 10;
  for (int f = 0; f < 4; ++f) if (fine[f].used && tick != fine[f].lastTick) {
    uint32_t gap = tick > fine[f].lastTick ? tick - fine[f].lastTick : FINE_SLOTS;
    for (uint32_t s = 1; s <= gap && s <= FINE_SLOTS; ++s) fine[f].v[(fine[f].lastTick + s) % FINE_SLOTS] = 0xFFFF;
    fine[f].lastTick = tick;
  }
  for (int k = 0; k < n; ++k) {
    int f = -1; for (int j = 0; j < 4; ++j) if (fine[j].used && !memcmp(fine[j].mac, now[k].mac, 6)) f = j;
    if (f < 0) for (int j = 0; j < 4; ++j) if (!fine[j].used) { f = j; fine[j].used = true; memcpy(fine[j].mac, now[k].mac, 6); fine[j].lastTick = tick;
                                                                for (int s = 0; s < FINE_SLOTS; ++s) fine[j].v[s] = 0xFFFF; break; }
    if (f >= 0) fine[f].v[tick % FINE_SLOTS] = now[k].v;
  }
  if (save) histSave();
}

/* ---------------------------- night lock --------------------------- */
bool lockActive() {
  if (lockManual) return true;
  if (!lockSched || !timeValid()) return false;
  time_t now = time(nullptr); struct tm tm; localtime_r(&now, &tm);
  int m = tm.tm_hour * 60 + tm.tm_min;
  return lockFrom <= lockTo ? (m >= lockFrom && m < lockTo) : (m >= lockFrom || m < lockTo);
}
String hhmm(int m) { char b[6]; snprintf(b, sizeof(b), "%02d:%02d", m / 60, m % 60); return String(b); }   // for the API / time inputs
String hm12(int m) { char b[10]; int h = m / 60 % 24; snprintf(b, sizeof(b), "%d:%02d %s", h % 12 ? h % 12 : 12, m % 60, h < 12 ? "AM" : "PM"); return String(b); }   // for log text
int parseHHMM(const String& s, int dflt) { int h, m; if (sscanf(s.c_str(), "%d:%d", &h, &m) == 2 && h >= 0 && h < 24 && m >= 0 && m < 60) return h * 60 + m; return dflt; }

/* ------------------------------- auth ------------------------------ */
void tokensLoad() {
  tokenCount = 0; String all = prefs.getString("tokens", "");
  int s = 0; while (s < (int)all.length() && tokenCount < MAX_TOKENS) {
    int e = all.indexOf(',', s); if (e < 0) e = all.length();
    if (e - s == 32) tokens[tokenCount++] = all.substring(s, e); s = e + 1;
  }
}
void tokensSave() { String all; for (int i = 0; i < tokenCount; ++i) { if (i) all += ','; all += tokens[i]; } prefs.putString("tokens", all); }
String cookieToken(AsyncWebServerRequest* r) {
  if (!r->hasHeader("Cookie")) return "";
  String c = r->header("Cookie"); int p = c.indexOf("leo_t=");
  if (p < 0) return "";
  int e = c.indexOf(';', p); return c.substring(p + 6, e < 0 ? c.length() : e);
}
bool authOk(AsyncWebServerRequest* r) {
  if (!pwHash.length()) return true;                       // no password set yet (UI warns)
  String t = cookieToken(r); if (t.length() != 32) return false;
  for (int i = 0; i < tokenCount; ++i) if (constEq(tokens[i], t)) return true;
  return false;
}
/* only accept control requests from pages served on the LAN */
bool originOk(AsyncWebServerRequest* r) {
  if (!r->hasHeader("Origin")) return true;
  String o = r->header("Origin"); o.toLowerCase();
  int p = o.indexOf("://"); if (p < 0) return false;
  String host = o.substring(p + 3); int c = host.indexOf(':'); if (c >= 0) host = host.substring(0, c);
  int sl = host.indexOf('/'); if (sl >= 0) host = host.substring(0, sl);
  if (host.endsWith(".local")) return true;
  IPAddress ip; if (!ip.fromString(host)) return false;
  return ip[0] == 10 || (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) || (ip[0] == 192 && ip[1] == 168) || ip[0] == 127;
}
bool guard(AsyncWebServerRequest* r) {                    // true = allowed; otherwise a response was sent
  if (!originOk(r)) { r->send(403, "application/json", "{\"err\":\"origin\"}"); return false; }
  if (!authOk(r))   { r->send(401, "application/json", "{\"err\":\"login\"}"); return false; }
  return true;
}
String who(AsyncWebServerRequest* r) { return r->client() ? r->client()->remoteIP().toString() : String("?"); }
void jsonOk(AsyncWebServerRequest* r) { r->send(200, "application/json", "{\"ok\":1}"); }
void setTokenCookie(AsyncWebServerRequest* r, const String& t) {
  AsyncWebServerResponse* res = r->beginResponse(200, "application/json", "{\"ok\":1}");
  res->addHeader("Set-Cookie", "leo_t=" + t + "; Path=/; Max-Age=31536000; SameSite=Strict; HttpOnly");
  r->send(res);
}

/* ------------------------------ devices ---------------------------- */
int findDev(const uint8_t* mac) {
  for (int i = 0; i < MAX_DEV; ++i) if (devs[i].used && !memcmp(devs[i].mac, mac, 6)) return i;
  return -1;
}
void devsSave() {
  JsonDocument d; JsonArray a = d.to<JsonArray>();
  { DevGuard g;
    for (int i = 0; i < MAX_DEV; ++i) if (devs[i].used) {
      JsonObject o = a.add<JsonObject>(); o["mac"] = macStr(devs[i].mac); o["type"] = devs[i].type; o["name"] = devs[i].name;
      if (devs[i].hasKey) o["key"] = hexStr(devs[i].key, 16);
      if (devs[i].hideMask) o["hide"] = devs[i].hideMask;
    } }
  File f = LittleFS.open(DEV_FILE, "w"); if (f) { serializeJson(d, f); f.close(); }
}
void devsLoad() {
  File f = LittleFS.open(DEV_FILE, "r"); if (!f) return;
  JsonDocument d; if (deserializeJson(d, f)) { f.close(); return; } f.close();
  int i = 0;
  for (JsonObject o : d.as<JsonArray>()) {
    if (i >= MAX_DEV) break;
    if (!parseMac(o["mac"] | "", devs[i].mac)) continue;
    devs[i].used = true; devs[i].type = o["type"] | 0;
    copyStr(devs[i].name, sizeof(devs[i].name), o["name"] | "Device");
    devs[i].hasKey = parseHex(o["key"] | "", devs[i].key, 16);
    devs[i].hideMask = o["hide"] | 0;
    i++;
  }
}
void ensurePeer(const uint8_t* mac) {
  if (esp_now_is_peer_exist(mac)) return;
  esp_now_peer_info_t p = {}; memcpy(p.peer_addr, mac, 6);
  p.channel = 0; p.ifidx = WIFI_IF_STA; p.encrypt = false;   // authenticity comes from our HMAC trailer
  esp_now_add_peer(&p);
}
/* sign with the device's key + session and send */
bool sendSigned(int i, const void* body, size_t len) {
  uint8_t mac[6], key[16]; uint32_t session, ctr;
  { DevGuard g; Dev& d = devs[i];
    if (!d.used || !d.hasKey || !d.session) return false;
    memcpy(mac, d.mac, 6); memcpy(key, d.key, 16); session = d.session; ctr = ++d.txCtr; }
  uint8_t buf[250]; size_t n = leoSign(buf, body, len, key, session, ctr);
  ensurePeer(mac);
  return esp_now_send(mac, buf, n) == ESP_OK;
}
void queueCmd(const uint8_t* mac, uint8_t cmd, uint8_t idx, uint8_t val, float f, const char* text) {
  TxItem t; memcpy(t.mac, mac, 6); memset(&t.cmd, 0, sizeof(t.cmd));
  fillHdr(t.cmd.h, M_CMD); t.cmd.cmd = cmd; t.cmd.idx = idx; t.cmd.val = val; t.cmd.f = f;
  copyStr(t.cmd.text, sizeof(t.cmd.text), text);
  xQueueSend(txq, &t, 0);
}

/* ESP-NOW callbacks run on the WiFi task: copy and hand to loop() */
void onRecv(const esp_now_recv_info_t* info, const uint8_t* data, int len) {
  if (len < (int)sizeof(LeoHdr) || len > 250) return;
  RxItem it; memcpy(it.mac, info->src_addr, 6);
  it.rssi = info->rx_ctrl ? info->rx_ctrl->rssi : 0; it.len = (uint8_t)len; memcpy(it.data, data, len);
  xQueueSend(rxq, &it, 0);
}
void onSent(const esp_now_send_info_t* info, esp_now_send_status_t st) {   // radio-level ACK from the edge
  if (!info || !info->des_addr) return;
  TxResult r; memcpy(r.mac, info->des_addr, 6); r.ok = (st == ESP_NOW_SEND_SUCCESS);
  xQueueSend(txres, &r, 0);
}

String relayName(const Dev& d, int r) { return (r >= 0 && r < 4 && d.rname[r][0]) ? String(d.rname[r]) : ("Relay " + String(r + 1)); }

/* ------------------------- edge OTA streaming ----------------------- */
void edgeOtaFinish(bool ok, const String& msg) {
  eota.doneAt = millis();
  if (eota.f) eota.f.close();
  LittleFS.remove(EDGE_BIN);
  eota.active = false; eota.pct = ok ? 100 : eota.pct; eota.msg = msg;
  dbg("Edge OTA " + macStr(eota.mac) + ": " + msg); stateDirty = true;
}
void edgeOtaSendCurrent() {
  eota.lastSend = millis();
  int i; { DevGuard g; i = findDev(eota.mac); }
  if (i < 0) return;
  if (eota.phase == 1) {
    MsgOtaBegin b = {}; fillHdr(b.h, M_OTA_BEGIN); b.size = eota.size; sendSigned(i, &b, sizeof(b));
  } else if (eota.phase == 2) {
    MsgOtaData d = {}; fillHdr(d.h, M_OTA_DATA); d.off = eota.off;
    eota.f.seek(eota.off);
    uint8_t chunk[200]; size_t want = min<uint32_t>(sizeof(chunk), eota.size - eota.off);
    size_t got = eota.f.read(chunk, want); memcpy(d.data, chunk, got); d.len = (uint16_t)got;
    eota.lastLen = d.len;
    sendSigned(i, &d, sizeof(LeoHdr) + 6 + d.len);
  } else if (eota.phase == 3) {
    MsgOtaBegin e = {}; fillHdr(e.h, M_OTA_END); e.size = eota.size; sendSigned(i, &e, sizeof(e));
  }
}
void edgeOtaOnAck(const uint8_t* mac, const MsgOtaAck& a) {
  if (!eota.active || memcmp(mac, eota.mac, 6)) return;
  if (!a.ok) { edgeOtaFinish(false, String("device rejected update: ") + a.err); return; }
  if (a.phase != eota.phase) return;                        // stale/duplicate ack
  if (eota.phase == 1) { eota.phase = 2; eota.off = 0; }
  else if (eota.phase == 2) {
    if (a.off != eota.off + eota.lastLen) return;           // ack for an older chunk
    eota.off += eota.lastLen;
    int pct = (int)((uint64_t)eota.off * 100 / eota.size);
    if (pct != eota.pct) { eota.pct = pct; eota.msg = "Sending to device… " + String(pct) + "%"; stateDirty = true; }
    if (eota.off >= eota.size) eota.phase = 3;
  } else if (eota.phase == 3) { edgeOtaFinish(true, "Installed — the device is restarting."); activity("Firmware updated on " + macStr(mac), false); return; }
  eota.retries = 0; edgeOtaSendCurrent();
}
void edgeOtaTick() {
  if (!eota.active) return;
  if (millis() - eota.lastSend < 350) return;
  if (++eota.retries > 12) { edgeOtaFinish(false, "device stopped answering (out of range or offline?)"); return; }
  edgeOtaSendCurrent();
}
bool edgeOtaStart(const uint8_t* mac) {
  if (eota.active) return false;
  eota.f = LittleFS.open(EDGE_BIN, "r");
  if (!eota.f) return false;
  eota.size = eota.f.size();
  memcpy(eota.mac, mac, 6); eota.active = true; eota.phase = 1; eota.off = 0; eota.retries = 0; eota.pct = 0;
  eota.msg = "Starting…"; dbg("Edge OTA start " + macStr(mac) + " " + String(eota.size) + " bytes");
  edgeOtaSendCurrent(); return true;
}

/* --------------------------- packet handling ------------------------ */
void handleHello(const RxItem& it) {
  if (it.len < sizeof(MsgHello)) return;
  MsgHello m; memcpy(&m, it.data, sizeof(m));
  const uint8_t devType = m.h.dev;
  bool pairingOpen = millis() < pairingUntil;
  int i; bool giveKey = false; bool added = false; uint8_t key[16]; String relinkNote;
  {
    DevGuard g;
    i = findDev(it.mac);
    if (i < 0) {
      if (!pairingOpen) {
        if (!pendingAt || memcmp(pendingMac, it.mac, 6)) stateDirty = true;
        memcpy(pendingMac, it.mac, 6); pendingAt = millis();
        static uint32_t lastNag = 0; if (millis() - lastNag > 10000) { lastNag = millis(); dbg("New device " + macStr(it.mac) + " wants to join - press 'Start adding' (Devices) to accept"); }
        return;
      }
      for (int k = 0; k < MAX_DEV; ++k) if (!devs[k].used) { i = k; break; }
      if (i < 0) { dbg("Device table full - ignoring " + macStr(it.mac)); return; }
      memset(&devs[i], 0, sizeof(Dev)); devs[i].used = true; memcpy(devs[i].mac, it.mac, 6);
      copyStr(devs[i].name, sizeof(devs[i].name), m.name[0] ? m.name : (devType == DEV_TANK ? "Water tank" : "Smart switch"));
      added = true;
    }
    Dev& d = devs[i];
    if (!m.hasKey) {
      // a key is handed out only to a new device while pairing is open, to a device the hub
      // already knew from before keys existed (one-time migration), or to a known device the
      // user is deliberately re-pairing (pairing open)
      if (!d.hasKey || pairingOpen) { esp_fill_random(d.key, 16); d.hasKey = true; giveKey = true; }
      else { dbg("Device " + macStr(it.mac) + " has no key - press 'Allow new devices' to re-pair it"); return; }
    }
    if (!d.hasKey) { dbg("Device " + macStr(it.mac) + " has a key this hub doesn't know - unpair it (USB: UNPAIR)"); return; }
    if (d.session && d.session != m.nonce && !added) {           // a re-link: say what the link looked like
      relinkNote = String(d.name) + " re-linked: heard " +
        (d.lastSeen ? String((millis() - d.lastSeen) / 1000) + "s ago" : String("never")) +
        ", lost " + String(d.txFail) + "/" + String(d.txSent) +
        ", " + String(it.rssi) + "dBm, ch " + String(WiFi.channel());
    }
    d.type = devType; copyStr(d.fw, sizeof(d.fw), m.fw);
    d.session = m.nonce; d.txCtr = 0; d.rxCtr = 0; d.rssi = it.rssi;
    d.txSent = 0; d.txFail = 0; d.pingRetry = false; d.failRun = 0;
    memcpy(key, d.key, 16);
  }
  MsgWelcome w = {}; fillHdr(w.h, M_WELCOME); w.channel = WiFi.channel();
  copyStr(w.hubName, sizeof(w.hubName), hubName.c_str());
  if (giveKey) { w.keyIncluded = 1; memcpy(w.key, key, 16); }
  sendSigned(i, &w, sizeof(w));
  if (added) activity("Paired new " + String(typeName(devType)) + " '" + String(m.name) + "'", false);
  if (giveKey) { devsSave(); dbg("Issued security key to " + macStr(it.mac)); }
  dbg(relinkNote.length() ? relinkNote : "Edge " + macStr(it.mac) + " session started");
  stateDirty = true;
}

void handlePacket(const RxItem& it) {
  const LeoHdr* h = (const LeoHdr*)it.data;
  if (h->magic != LEO_MAGIC) return;
  if (h->proto != LEO_PROTO) { static uint32_t lastWarn = 0; if (millis() - lastWarn > 30000) { lastWarn = millis(); dbg("Edge " + macStr(it.mac) + " speaks old protocol v" + String(h->proto) + " - update its firmware"); } return; }
  if (h->type == M_HELLO) { handleHello(it); return; }

  // everything else must be signed by a known device in its current session
  int i; uint8_t key[16]; uint32_t session, lastCtr;
  { DevGuard g; i = findDev(it.mac); if (i < 0 || !devs[i].hasKey || !devs[i].session) return;
    memcpy(key, devs[i].key, 16); session = devs[i].session; lastCtr = devs[i].rxCtr; }
  uint32_t ctr; size_t blen = leoVerify(it.data, it.len, key, session, &ctr);
  if (!blen || ctr <= lastCtr) return;                       // forged, wrong session or replay
  { DevGuard g; devs[i].rxCtr = ctr; devs[i].lastSeen = millis(); devs[i].rssi = it.rssi; }

  if (h->type == M_SW_STATE && blen >= sizeof(MsgSwState)) {
    MsgSwState m; memcpy(&m, it.data, sizeof(m));
    String note; bool changed = false; bool needInfo = false; uint8_t mac[6];
    { DevGuard g; Dev& d = devs[i]; memcpy(mac, d.mac, 6);
      bool restarted = d.maskKnown && m.uptime + 5 < d.uptime;
      if (restarted) note = String(d.name) + " restarted (power cut?) - all relays start OFF";
      // a report sent just before our command landed is stale: don't let it flicker the UI or the log
      bool pending = d.expectValid && millis() - d.expectAt < 3000 && m.onMask != d.expectMask && !restarted;
      if (!pending) {
        if (d.maskKnown && !restarted && m.onMask != d.confMask && !(d.expectValid && m.onMask == d.expectMask)) {
          for (int r = 0; r < 4; ++r) if ((d.confMask ^ m.onMask) & (1 << r))
            note += (note.length() ? ", " : "") + String(d.name) + ": " + relayName(d, r) + ((m.onMask & (1 << r)) ? " ON" : " OFF");
          note += " (changed at the device, not by the hub)";
        }
        if (d.onMask != m.onMask) changed = true;
        d.expectValid = 0; d.confMask = m.onMask; d.onMask = m.onMask;
      }
      d.n = m.n > 4 ? 4 : m.n; d.uptime = m.uptime; d.maskKnown = true;
      memcpy(d.onSecs, m.onSecs, sizeof(d.onSecs));
      needInfo = !d.infoKnown;
    }
    if (needInfo) queueCmd(mac, C_INFO, 0, 0, 0, "");
    if (note.length()) activity(note, false);
    if (changed) stateDirty = true;
  } else if (h->type == M_SW_INFO && blen >= sizeof(MsgSwInfo) - 1) {       // older switches omit 'touch'
    MsgSwInfo m = {}; memcpy(&m, it.data, min(blen, sizeof(m)));
    DevGuard g; Dev& d = devs[i];
    d.touch = blen >= sizeof(MsgSwInfo) ? (m.touch ? 1 : 0) : 255;
    d.n = m.n > 4 ? 4 : m.n; copyStr(d.fw, sizeof(d.fw), m.fw);
    for (int r = 0; r < 4; ++r) { copyStr(d.rname[r], sizeof(d.rname[r]), m.rname[r]); d.watts[r] = m.watts[r]; d.gpio[r] = m.gpio[r]; }
    d.infoKnown = true; stateDirty = true;
  } else if (h->type == M_TANK_STATE && blen >= sizeof(MsgTankState) - 2) {   // tank 1.0 has no 'ldr'
    MsgTankState m = {}; memcpy(&m, it.data, min(blen, sizeof(m)));
    DevGuard g; Dev& d = devs[i];
    d.ldr = blen >= sizeof(MsgTankState) ? m.ldr : 0xFFFF;
    if (d.tflags != m.flags) stateDirty = true;
    d.tflags = m.flags;
    if (!d.tcfgKnown) { static uint32_t lastAsk = 0; if (millis() - lastAsk > 5000) { lastAsk = millis(); queueCmd(d.mac, C_INFO, 0, 0, 0, ""); } }   // older link: ask for settings
    if ((int)d.levelPct != (int)m.levelPct || d.leds != m.leds || d.sensorOk != m.sensorOk || strncmp(d.stateTxt, m.stateTxt, sizeof(d.stateTxt))) stateDirty = true;
    d.levelPct = m.levelPct; d.distCm = m.distCm; d.leds = m.leds; d.tstate = m.state;
    d.sensorOk = m.sensorOk; d.uptime = m.uptime; copyStr(d.stateTxt, sizeof(d.stateTxt), m.stateTxt);
  } else if (h->type == M_TANK_INFO && blen >= offsetof(MsgTankInfo, palette)) {   // older tanks send fewer fields
    MsgTankInfo m = {}; m.ledCount = 7; m.showFrom = 7; m.showTo = 22; m.minBright = 6; m.highlight = 10;
    for (int k = 0; k < 8; ++k) m.gain[k] = 100;
    memcpy(&m, it.data, min(blen, sizeof(m)));
    DevGuard g; Dev& d = devs[i];
    d.tFullCm = m.fullCm; d.tEmptyCm = m.emptyCm; d.tFullPct = m.fullPct; d.tLowPct = m.lowPct;
    d.tBuzzer = m.buzzer; d.tQuietFrom = m.quietFrom; d.tQuietTo = m.quietTo; d.tPalette = m.palette; d.tLedCount = m.ledCount;
    d.tShowFrom = m.showFrom; d.tShowTo = m.showTo; d.tMinBright = m.minBright;
    d.tColorsKnown = blen >= offsetof(MsgTankInfo, highlight); memcpy(d.tColors, m.colors, sizeof(d.tColors));
    d.tGainKnown = blen >= sizeof(MsgTankInfo); d.tHighlight = m.highlight; memcpy(d.tGain, m.gain, sizeof(d.tGain));
    d.tcfgKnown = true; stateDirty = true;
  } else if (h->type == M_TANK_RULES && blen >= sizeof(MsgTankRules)) {
    MsgTankRules m; memcpy(&m, it.data, sizeof(m));
    DevGuard g; Dev& d = devs[i]; memcpy(d.tRules, m.r, sizeof(d.tRules)); d.tRulesKnown = true; stateDirty = true;
  } else if (h->type == M_DIAG && blen >= sizeof(MsgDiag)) {
    MsgDiag m; memcpy(&m, it.data, sizeof(m));
    DevGuard g; Dev& d = devs[i];
    d.dTemp = m.tempC10; d.dHeap = m.heapFree; d.dHeapMin = m.heapMin; d.dFsUsed = m.fsUsed; d.dFsTotal = m.fsTotal;
    d.dFlash = m.flashSize; d.dSketch = m.sketchSize; d.dSketchMax = m.sketchMax; d.dReset = m.resetReason; d.dCpu = m.cpuMHz;
    copyStr(d.dSdk, sizeof(d.dSdk), m.sdk); d.diagKnown = true;
  } else if (h->type == M_OTA_ACK && blen >= sizeof(MsgOtaAck)) {
    MsgOtaAck a; memcpy(&a, it.data, sizeof(a));
    edgeOtaOnAck(it.mac, a);
  }
}

/* ------------------------------- WiFi ------------------------------ */
void wifiEvent(WiFiEvent_t e) {           // WiFi event task: flags only
  if (e == ARDUINO_EVENT_WIFI_STA_GOT_IP) netUpPending = true;
  if (e == ARDUINO_EVENT_WIFI_STA_DISCONNECTED) netDownPending = true;
}
/* factory reset of the hub: tell every paired edge to forget us, wipe settings + files, restart.
   Afterwards the setup hotspot has NO password until WiFi is configured again (else you'd be locked out). */
bool factoryPending = false; bool setupMode = false;
void hubFactoryReset() {
  uint32_t red = ledA.Color(160, 0, 0);                  // solid bright red = accepted, wiping now
  ledA.setPixelColor(0, red); ledA.show(); ledB.setPixelColor(0, red); ledB.show();
  dbg("FACTORY RESET - telling paired devices to forget this hub");
  for (int i = 0; i < MAX_DEV; ++i) {
    bool ok; { DevGuard g; ok = devs[i].used && devs[i].hasKey && devs[i].session; }
    if (ok) { MsgCmd c = {}; fillHdr(c.h, M_CMD); c.cmd = C_UNPAIR; sendSigned(i, &c, sizeof(c)); delay(30); sendSigned(i, &c, sizeof(c)); delay(30); }
  }
  prefs.clear(); prefs.putBool("setup", true);
  LittleFS.format();
  delay(1500); ESP.restart();
}
/* BOOT button on the ESP32-S3 board held 15 s = factory reset. From 2 s the light blinks red, slow and dim at first,
   faster and brighter the longer you hold; at 15 s it turns solid bright red (accepted). Let go before 15 s to cancel. */
#define HUB_RESET_PIN 0
#define RESET_HOLD_MS 15000
uint32_t resetHeldSince = 0;
bool resetArmed() { return resetHeldSince && millis() - resetHeldSince > 2000; }
uint8_t resetLevel() {
  float p = constrain((float)(millis() - resetHeldSince - 2000) / (RESET_HOLD_MS - 2000), 0.0f, 1.0f);
  uint32_t period = 1000 - (uint32_t)(p * 880);          // 1 s -> 0.12 s
  return (millis() % period) < period / 2 ? (uint8_t)(6 + p * 144) : 0;
}
void resetBtnTick() {
  if (digitalRead(HUB_RESET_PIN) != LOW) { resetHeldSince = 0; return; }
  if (!resetHeldSince) resetHeldSince = millis();
  if (millis() - resetHeldSince >= RESET_HOLD_MS) { resetHeldSince = 0; factoryPending = true; }
}
String apSsid() { return "LEO-Hub-" + hubId.substring(4); }
void apStart() {
  if (apUp) return;
  WiFi.mode(WIFI_AP_STA);
  if (setupMode) WiFi.softAP(apSsid().c_str()); else WiFi.softAP(apSsid().c_str(), apPass.c_str());   // setup after a factory reset: open
  apUp = true; dbg("Emergency hotspot " + apSsid() + " at 192.168.4.1");
}
void apStop() { if (!apUp) return; WiFi.softAPdisconnect(true); WiFi.mode(WIFI_STA); apUp = false; dbg("Emergency hotspot off"); }
void staBegin() {
  if (!cfgSsid.length()) return;
  WiFi.disconnect(); WiFi.begin(cfgSsid.c_str(), cfgPass.c_str());
  lastStaTry = millis(); dbg("WiFi: joining " + cfgSsid);
}
void wifiTick() {
  if (netUpPending) {
    netUpPending = false;
    if (WiFi.status() == WL_CONNECTED) {
      staUp = true; staDownSince = 0;
      dbg("WiFi connected " + WiFi.localIP().toString() + " ch " + String(WiFi.channel()) + " rssi " + String(WiFi.RSSI()));
      apStop();
      MDNS.end(); if (MDNS.begin(HUB_MDNS)) { MDNS.addService("http", "tcp", 80); MDNS.addService("leohub", "tcp", 80); }
      configTzTime("IST-5:30", "pool.ntp.org", "time.google.com");
      stateDirty = true;
    }
  }
  if (netDownPending) {
    netDownPending = false;
    if (WiFi.status() != WL_CONNECTED && staUp) { staUp = false; staDownSince = millis(); dbg("WiFi lost"); stateDirty = true; }
  }
  if (WiFi.status() == WL_CONNECTED) return;
  if (!staDownSince) staDownSince = millis();
  if (!cfgSsid.length() || millis() - staDownSince > AP_FALLBACK_MS) apStart();
  if (cfgSsid.length() && millis() - lastStaTry > STA_RETRY_MS) staBegin();
}

/* ------------------------------ JSON ------------------------------- */
String stateJson() {
  JsonDocument d;
  JsonObject h = d["hub"].to<JsonObject>();
  h["name"] = hubName; h["id"] = hubId; h["fw"] = HUB_FW;
  h["room"] = roomLight == 1 ? "bright" : roomLight == 0 ? "dark" : "unknown";
  { JsonObject g = h["global"].to<JsonObject>(); g["quietFrom"] = gQuietFrom; g["quietTo"] = gQuietTo; g["dayFrom"] = gDayFrom; g["dayTo"] = gDayTo;
    g["ledDay"] = gLedDay; g["ledNight"] = gLedNight; g["litOn"] = gLitOn; g["litOff"] = gLitOff; }
  if (pendingAt && millis() - pendingAt < 30000) h["pending"] = macStr(pendingMac);   // asking to join in the last 30 s
  h["wifi"] = (WiFi.status() == WL_CONNECTED); h["ip"] = WiFi.localIP().toString();
  h["ap"] = apUp ? apSsid() : String("");
  h["passwordSet"] = pwHash.length() > 0;
  h["pairing"] = millis() < pairingUntil ? (int)((pairingUntil - millis()) / 1000) : 0;
  JsonObject l = h["lock"].to<JsonObject>();
  l["active"] = lockActive(); l["manual"] = lockManual; l["sched"] = lockSched; l["from"] = hhmm(lockFrom); l["to"] = hhmm(lockTo);
  JsonArray a = d["devices"].to<JsonArray>();
  uint32_t now = millis();
  { DevGuard g;
    for (int i = 0; i < MAX_DEV; ++i) {
      Dev& v = devs[i]; if (!v.used) continue;
      JsonObject o = a.add<JsonObject>();
      o["mac"] = macStr(v.mac); o["type"] = typeName(v.type); o["name"] = v.name; o["fw"] = v.fw;
      bool online = v.lastSeen && (now - v.lastSeen < OFFLINE_MS);
      o["online"] = online; o["rssi"] = v.rssi; o["uptime"] = v.uptime; o["secure"] = v.hasKey;
      o["seenAgo"] = v.lastSeen ? (now - v.lastSeen) : 0;
      if (v.type == DEV_SWITCH && v.infoKnown) {
        if (v.touch != 255) o["touch"] = (bool)v.touch;
        JsonArray rl = o["relays"].to<JsonArray>();
        for (int r = 0; r < v.n; ++r) {
          JsonObject x = rl.add<JsonObject>();
          x["name"] = v.rname[r]; x["watts"] = v.watts[r]; x["gpio"] = v.gpio[r];
          x["on"] = (bool)(v.onMask & (1 << r)); x["onSecs"] = v.onSecs[r]; x["used"] = !(v.hideMask & (1 << r));
        }
      } else if (v.type == DEV_TANK) {
        JsonObject t = o["tank"].to<JsonObject>();
        t["level"] = v.levelPct; t["dist"] = v.distCm; t["leds"] = v.leds;
        t["sensorOk"] = (bool)v.sensorOk; t["stateTxt"] = v.stateTxt;
        if (v.ldr != 0xFFFF) t["ldr"] = v.ldr;
        t["alert"] = (bool)(v.tflags & 1);
        if (v.tcfgKnown) {
          JsonObject c = t["cfg"].to<JsonObject>();
          c["fullCm"] = v.tFullCm; c["emptyCm"] = v.tEmptyCm; c["fullPct"] = v.tFullPct; c["lowPct"] = v.tLowPct;
          c["buzzer"] = (bool)v.tBuzzer; c["quietFrom"] = v.tQuietFrom; c["quietTo"] = v.tQuietTo;
          c["palette"] = v.tPalette; c["ledCount"] = v.tLedCount;
          c["showFrom"] = v.tShowFrom; c["showTo"] = v.tShowTo; c["minBright"] = v.tMinBright;
          if (v.tGainKnown) { c["highlight"] = v.tHighlight; JsonArray ga = c["gain"].to<JsonArray>(); for (int k = 0; k < 8; ++k) ga.add(v.tGain[k]); }
          if (v.tRulesKnown) { JsonArray ra = c["rules"].to<JsonArray>();
            for (int k = 0; k < 6; ++k) { JsonArray x = ra.add<JsonArray>(); for (int b = 0; b < 6; ++b) x.add(v.tRules[k * 6 + b]); } }
          if (v.tColorsKnown) { JsonArray ca = c["colors"].to<JsonArray>();
            for (int k = 0; k < 8; ++k) { char hx[8]; snprintf(hx, sizeof(hx), "#%02x%02x%02x", v.tColors[k * 3], v.tColors[k * 3 + 1], v.tColors[k * 3 + 2]); ca.add(hx); } }
        }
      }
    } }
  if (eota.active || eota.msg.length()) {
    JsonObject o = d["ota"].to<JsonObject>();
    o["mac"] = macStr(eota.mac); o["pct"] = eota.pct; o["msg"] = eota.msg; o["active"] = eota.active;
    o["ago"] = eota.active || !eota.doneAt ? 0 : (millis() - eota.doneAt) / 1000;          // seconds since it finished
  }
  String s; serializeJson(d, s); return s;
}

/* -------------------------------- web ------------------------------ */
// Web UI (generated from hub_ui.html): plain C string lines.
// PNG app icons for installing the web app (generated by make_icons.py)
static const uint8_t ICON_192_PNG[] PROGMEM = {
  0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a,0x00,0x00,0x00,0x0d,0x49,0x48,0x44,0x52,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0xc0,
  0x08,0x02,0x00,0x00,0x00,0xdd,0xbe,0xfb,0x50,0x00,0x00,0x02,0xbf,0x49,0x44,0x41,0x54,0x78,0xda,0xed,0xdd,0xcb,0x69,0x2b,
  0x41,0x10,0x40,0xd1,0x56,0xa1,0xa5,0xc1,0xe0,0x28,0x1c,0x84,0xa2,0x71,0x60,0x8e,0xc6,0x41,0x38,0x1c,0xef,0x8c,0x40,0x16,
  0x98,0xf9,0x76,0x55,0x9d,0xbb,0xf3,0x5b,0x08,0x66,0xe6,0xa8,0xba,0xf5,0x46,0x9f,0xcb,0xcb,0xeb,0xdb,0x90,0x96,0x16,0x4e,
  0x81,0x00,0x12,0x40,0x02,0x48,0x00,0x49,0x00,0x09,0x20,0x01,0x24,0x80,0x24,0x80,0x04,0x90,0x00,0x12,0x40,0x12,0x40,0x02,
  0x48,0x00,0x09,0x20,0x09,0x20,0x01,0x24,0x80,0x04,0x90,0x00,0x92,0x00,0x12,0x40,0x02,0x48,0x00,0x49,0x00,0x09,0x20,0x01,
  0x24,0x80,0x24,0x80,0x04,0x90,0x00,0x12,0x40,0x12,0x40,0x02,0x48,0x00,0x09,0x20,0x01,0x24,0x01,0x24,0x80,0x04,0x90,0x00,
  0x92,0x00,0x12,0x40,0x02,0x48,0x00,0x49,0x00,0x09,0x20,0x01,0xa4,0x82,0x5d,0x9d,0x82,0x67,0xbd,0x7f,0x7d,0xde,0xff,0xf9,
  0x7d,0xfb,0x70,0x4e,0x4c,0xa0,0x85,0x7a,0xfe,0xfc,0x17,0x01,0xf4,0x5f,0x3d,0x0c,0x01,0xb4,0x56,0x0f,0x43,0x00,0xad,0xd5,
  0xc3,0xd0,0x63,0x17,0xbf,0x1b,0xbf,0x98,0x85,0x6d,0xb5,0x09,0xb4,0x6a,0xa8,0x18,0x45,0x00,0xad,0x75,0xc0,0x50,0xd0,0x73,
  0xfa,0x23,0x00,0xd4,0x57,0x0f,0x43,0x4d,0x37,0xd1,0x7b,0x5c,0xf2,0x9e,0x7b,0xea,0x8e,0x80,0x76,0x1d,0x18,0xdd,0x18,0x05,
  0x3d,0xb9,0x1e,0x1f,0xa0,0xca,0x7a,0x1a,0x1a,0x0a,0x7a,0xf6,0x58,0x92,0xfa,0x18,0x6a,0xb1,0x07,0x5a,0x7c,0x39,0x7f,0xf5,
  0x1c,0x89,0xcf,0x04,0xaa,0xa6,0xc7,0x1c,0xea,0x3b,0x81,0x36,0xd1,0xb3,0xd3,0xa3,0x99,0x40,0xbd,0xf4,0xac,0x71,0x50,0x78,
  0x14,0x95,0x9d,0x40,0xfb,0xed,0x5a,0xcc,0xa1,0xe2,0x80,0x8e,0xb9,0xc0,0xb6,0xd5,0x35,0x97,0xb0,0xc3,0xc6,0x83,0x6d,0x75,
  0x41,0x40,0x07,0x2f,0x2e,0x0c,0x95,0x5a,0xc2,0xce,0xda,0x9a,0x34,0xdf,0x12,0x15,0x01,0x74,0xee,0x8e,0xa4,0xb3,0xa1,0xf4,
  0x80,0x26,0xb9,0x78,0x6d,0x0d,0xe5,0x06,0x34,0xdb,0x65,0x6b,0xf8,0xd2,0x2c,0xe8,0x19,0x67,0xbf,0x19,0x28,0xf5,0xb6,0x3a,
  0xe8,0x61,0xa8,0xdd,0x12,0x36,0xff,0x4a,0xd1,0x67,0x4b,0x94,0x0c,0x50,0xa2,0x0b,0xd3,0xc4,0x50,0xd0,0x33,0xdb,0x9b,0xa3,
  0x73,0x2d,0x67,0x69,0x26,0x50,0xde,0x27,0x74,0xed,0x97,0x66,0x41,0xcf,0x9c,0xa3,0x28,0xcb,0x1c,0x4a,0x30,0x81,0x6a,0x3c,
  0x83,0xab,0xce,0xa1,0xa9,0x01,0x15,0xdb,0x87,0x96,0xdc,0x56,0x47,0xf3,0x8f,0xe0,0xd8,0x56,0xd7,0x04,0xe4,0x5b,0x2f,0xb2,
  0x9c,0x90,0x70,0xb2,0x18,0x2a,0x05,0x88,0x9e,0x5c,0x27,0xc7,0x17,0x4c,0x09,0x20,0x01,0x24,0x80,0x04,0xd0,0x48,0xfc,0x9f,
  0x25,0x1d,0x9a,0xf0,0xe4,0x84,0xd3,0x44,0x4f,0xc1,0x25,0x6c,0xf3,0x4f,0xa7,0xd3,0xd3,0x6e,0x0f,0xf4,0x78,0xca,0x9a,0xe8,
  0xc9,0x75,0xe0,0x57,0x4f,0x3b,0x07,0xee,0x55,0x98,0x00,0x12,0x40,0x1a,0x7e,0x33,0x75,0xb8,0x37,0x69,0xaf,0x66,0x02,0x1d,
  0x7c,0x67,0xbb,0xf3,0x3b,0x08,0x82,0x1e,0x86,0x00,0x9a,0xe2,0x62,0xf7,0x34,0x64,0x13,0x2d,0x80,0xa6,0x99,0x13,0x0d,0x87,
  0x90,0x09,0x24,0x80,0x04,0x90,0x00,0x12,0x40,0x12,0x40,0x1a,0xee,0x85,0x8d,0x29,0xdf,0x8e,0xe3,0x43,0x8f,0x26,0x90,0x00,
  0x12,0x40,0x02,0x48,0x02,0x48,0x00,0x09,0x20,0x01,0x24,0x80,0x24,0x80,0x04,0x90,0x00,0x12,0x40,0xd2,0xa8,0xf9,0x83,0x73,
  0xe5,0x6f,0x89,0xfb,0xbd,0x30,0x59,0xc2,0x24,0x80,0x04,0x90,0x00,0x12,0x40,0x12,0x40,0x02,0x68,0x8c,0x51,0xfd,0xeb,0xc0,
  0xd2,0x1d,0x5d,0x38,0xcb,0x8e,0xab,0xe3,0x12,0x56,0xcf,0x50,0xd2,0x23,0xca,0x77,0x2b,0x63,0x94,0xbb,0xb3,0x91,0xfa,0xc9,
  0x90,0x1e,0x90,0x2c,0x61,0x02,0x48,0x00,0x49,0x00,0x09,0x20,0x01,0x24,0x80,0x24,0x80,0x04,0x90,0x00,0x12,0x40,0x12,0x40,
  0x02,0x48,0x00,0x09,0x20,0x09,0x20,0x01,0x24,0x80,0x04,0x90,0x00,0x92,0x00,0x12,0x40,0x02,0x48,0x00,0x49,0x00,0x09,0x20,
  0x01,0x24,0x80,0x24,0x80,0x04,0x90,0x00,0x12,0x40,0x12,0x40,0x02,0x48,0x00,0x09,0x20,0x09,0x20,0x01,0x24,0x80,0x04,0x90,
  0x00,0x92,0x00,0x12,0x40,0x02,0x48,0x00,0x49,0x00,0x09,0x20,0x01,0x24,0x80,0x24,0x80,0xb4,0x75,0x3f,0xcb,0x1f,0xf4,0x23,
  0xbe,0xd9,0x45,0x0b,0x00,0x00,0x00,0x00,0x49,0x45,0x4e,0x44,0xae,0x42,0x60,0x82,
};
static const uint8_t ICON_512_PNG[] PROGMEM = {
  0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a,0x00,0x00,0x00,0x0d,0x49,0x48,0x44,0x52,0x00,0x00,0x02,0x00,0x00,0x00,0x02,0x00,
  0x08,0x02,0x00,0x00,0x00,0x7b,0x1a,0x43,0xad,0x00,0x00,0x08,0x7a,0x49,0x44,0x41,0x54,0x78,0xda,0xed,0xdd,0xc1,0x8d,0xab,
  0x48,0x18,0x85,0xd1,0x4b,0x8b,0x25,0x12,0x12,0x51,0x38,0x08,0x47,0xe3,0xc0,0x1c,0x8d,0x83,0x70,0x38,0x1d,0x80,0x2d,0x2f,
  0x2c,0x19,0x15,0xdc,0x73,0x96,0x23,0x8d,0x34,0x0d,0xc5,0xff,0x51,0xc5,0x9b,0x7e,0xd3,0xb2,0x6e,0x01,0xa0,0xcf,0x9f,0x4b,
  0x00,0x20,0x00,0x00,0x08,0x00,0x00,0x02,0x00,0x80,0x00,0x00,0x20,0x00,0x00,0x08,0x00,0x00,0x02,0x00,0x80,0x00,0x00,0x20,
  0x00,0x00,0x08,0x00,0x00,0x02,0x00,0x80,0x00,0x00,0x20,0x00,0x00,0x08,0x00,0x00,0x02,0x00,0x80,0x00,0x00,0x20,0x00,0x00,
  0x08,0x00,0x00,0x02,0x00,0x80,0x00,0x00,0x20,0x00,0x00,0x08,0x00,0x00,0x02,0x00,0x20,0x00,0x00,0x08,0x00,0x00,0x02,0x00,
  0x80,0x00,0x00,0x20,0x00,0x00,0x08,0x00,0x00,0x02,0x00,0x80,0x00,0x00,0x20,0x00,0x00,0x08,0x00,0x00,0x02,0x00,0x80,0x00,
  0x00,0x20,0x00,0x00,0x08,0x00,0x00,0x02,0x00,0x80,0x00,0x00,0x20,0x00,0x00,0x08,0x00,0x00,0x02,0x00,0x80,0x00,0x00,0x20,
  0x00,0x00,0x08,0x00,0x00,0x02,0x00,0x20,0x00,0x00,0x08,0x00,0x00,0x02,0x00,0x80,0x00,0x00,0x20,0x00,0x00,0x08,0x00,0x00,
  0x02,0x00,0x80,0x00,0x00,0x20,0x00,0x00,0x08,0x00,0x00,0x02,0x00,0x80,0x00,0x00,0x20,0x00,0x00,0x08,0x00,0x00,0x02,0x00,
  0x80,0x00,0x00,0x20,0x00,0x00,0x08,0x00,0x00,0x02,0x00,0x80,0x00,0x00,0x20,0x00,0x00,0x08,0x00,0x00,0x02,0x00,0x80,0x00,
  0x00,0x08,0x00,0x00,0x02,0x00,0x80,0x00,0x00,0x20,0x00,0x00,0x08,0x00,0x00,0x02,0x00,0x80,0x00,0x00,0x20,0x00,0x00,0x08,
  0x00,0x00,0x02,0x00,0x80,0x00,0x00,0x20,0x00,0x00,0x08,0x00,0x00,0x02,0x00,0x80,0x00,0x00,0x20,0x00,0x00,0x08,0x00,0x00,
  0x02,0x00,0x80,0x00,0x00,0x20,0x00,0x00,0x08,0x00,0x00,0x02,0x00,0x80,0x00,0x00,0x08,0x00,0x00,0x02,0x00,0x80,0x00,0x00,
  0x20,0x00,0x00,0x08,0x00,0x00,0x02,0x00,0x80,0x00,0x00,0x20,0x00,0x00,0x08,0x00,0x00,0x02,0x00,0x80,0x00,0x00,0x20,0x00,
  0x00,0x08,0x00,0x00,0x02,0x00,0x80,0x00,0x00,0x20,0x00,0x00,0x08,0x00,0x00,0x02,0x00,0x80,0x00,0x00,0x20,0x00,0x00,0x08,
  0x00,0x00,0x02,0x00,0x80,0x00,0x00,0x20,0x00,0x00,0x02,0x00,0x80,0x00,0x00,0x20,0x00,0x00,0x08,0x00,0x00,0x02,0x00,0x80,
  0x00,0x00,0x20,0x00,0x00,0x08,0x00,0x00,0x02,0x00,0x80,0x00,0x00,0x20,0x00,0x00,0x08,0x00,0x00,0x02,0x00,0x80,0x00,0x00,
  0x20,0x00,0x00,0x08,0x00,0x00,0x02,0x00,0x80,0x00,0x00,0xf0,0x85,0xd9,0x25,0xa0,0xd0,0xe5,0x71,0x7f,0xfd,0x87,0xcf,0xeb,
  0xcd,0x95,0xa1,0xca,0xb4,0xac,0x9b,0xab,0x40,0xf3,0xdc,0x57,0x02,0x04,0x00,0x8c,0x7e,0x19,0x20,0xbe,0x01,0x40,0xfb,0xf4,
  0xff,0xfa,0xdf,0x02,0x3b,0x00,0x38,0xf0,0xe8,0xb7,0x15,0xc0,0x0e,0x00,0x4c,0x7f,0x5b,0x01,0x04,0x00,0x00,0x01,0x80,0xaa,
  0xd7,0x7f,0x9b,0x00,0x04,0x00,0x7a,0xa7,0xbf,0x06,0x20,0x00,0xd0,0x3b,0xfd,0x35,0x00,0x01,0x80,0xde,0xe9,0xaf,0x01,0x08,
  0x00,0xf4,0x4e,0x7f,0x0d,0x40,0x00,0xa0,0x77,0xfa,0x6b,0x00,0x02,0x00,0xbd,0xd3,0x5f,0x03,0x88,0xff,0x13,0x18,0x3a,0x47,
  0x7f,0xfc,0x7f,0xc2,0xd8,0x01,0x80,0xe9,0x6f,0x2b,0x80,0x00,0x40,0xf5,0xe4,0xd5,0x00,0x04,0x00,0x7a,0x67,0xae,0x06,0x20,
  0x00,0xd0,0x3b,0x6d,0x35,0x80,0xf8,0x08,0x0c,0xcd,0x43,0xd6,0x37,0x61,0x04,0x00,0xaa,0x5f,0xb1,0x65,0x80,0x38,0x02,0x82,
  0xce,0x03,0x16,0xc7,0x41,0x08,0x00,0xf4,0xce,0x53,0x0d,0x40,0x00,0xa0,0x77,0x92,0x6a,0x00,0x02,0x00,0xbd,0x33,0x54,0x03,
  0x88,0x8f,0xc0,0xd0,0x3c,0x3a,0x7d,0x13,0x46,0x00,0xa0,0xfa,0xc5,0x59,0x06,0x88,0x23,0x20,0xe8,0x3c,0x36,0x71,0x1c,0x84,
  0x00,0x40,0xef,0x94,0xd4,0x00,0x04,0x00,0x7a,0xe7,0xa3,0x06,0x10,0xdf,0x00,0xa0,0x79,0x2c,0xfa,0x1e,0x80,0x1d,0x00,0x94,
  0xbe,0x14,0xdb,0x07,0x60,0x07,0x00,0xed,0xa3,0xd0,0x56,0x00,0x3b,0x00,0x4c,0x7f,0x57,0x00,0x04,0x00,0xb3,0xcf,0x75,0x00,
  0x01,0xc0,0xd4,0x73,0x35,0x20,0xbe,0x01,0x60,0xd8,0xc5,0xf7,0x00,0xb0,0x03,0xc0,0xf4,0x3f,0xe5,0xcc,0x95,0x46,0xec,0x00,
  0x30,0xfd,0xf7,0x9e,0xfe,0xb2,0x84,0x1d,0x00,0x94,0xbe,0xfb,0x8f,0x36,0x70,0x6d,0x05,0x10,0x00,0x4c,0xff,0xfd,0x5e,0xb1,
  0x35,0x80,0x38,0x02,0x82,0xd3,0x0f,0xb2,0x0f,0xb3,0xde,0x59,0x10,0x02,0x00,0xbd,0x9f,0x7c,0x35,0x00,0x01,0x80,0xea,0x3f,
  0xf0,0x33,0xd4,0x7f,0xbc,0x06,0x20,0x00,0x98,0xfe,0xbb,0xce,0x50,0x5b,0x01,0xe2,0x23,0x30,0x74,0x8e,0x4e,0x9f,0x85,0x11,
  0x00,0xe8,0x7d,0x71,0xd6,0x00,0xe2,0x08,0x08,0xce,0xf7,0x07,0x7e,0x9c,0x05,0x81,0x00,0xe0,0xc5,0x5f,0x03,0x10,0x00,0x30,
  0x1f,0xfd,0xd1,0x20,0x04,0x00,0x4c,0x7f,0x3f,0x2c,0xf1,0x11,0x18,0x0c,0x44,0x9f,0x85,0x11,0x00,0xf0,0x3a,0xac,0x01,0xc4,
  0x11,0x10,0x46,0x7f,0xf5,0x49,0x88,0x2b,0x80,0x1d,0x00,0xa6,0x7f,0xe9,0xec,0xb3,0x0f,0xc0,0x0e,0x00,0xd3,0xbf,0xfd,0xcd,
  0xd7,0x05,0xc1,0x0e,0x00,0xd3,0xbf,0x74,0xd8,0xd9,0x0a,0x20,0x00,0x98,0xfe,0xbd,0x93,0x57,0x03,0x88,0x23,0x20,0x8c,0xfe,
  0xe6,0x83,0x0e,0x81,0x44,0x00,0x30,0xfd,0x7b,0xe7,0x9a,0x6b,0x45,0x1c,0x01,0x61,0xfa,0x77,0x4e,0x34,0x67,0x41,0xd8,0x01,
  0x60,0xfa,0xb7,0xbf,0xcf,0xba,0x74,0xd8,0x01,0x60,0xfa,0x97,0x8e,0x30,0x5b,0x01,0x04,0x00,0xd3,0xbf,0xf7,0x05,0x56,0x03,
  0x88,0x23,0x20,0x8c,0xfe,0xe6,0xb3,0x0b,0xd7,0x13,0x3b,0x00,0x4c,0xab,0xd2,0x69,0x65,0x1f,0x80,0x00,0x60,0xfa,0xf7,0xbe,
  0xab,0x6a,0x00,0x71,0x04,0x84,0xe9,0x5f,0x7e,0x52,0xe1,0x22,0x63,0x07,0x80,0xc1,0x54,0x3a,0x98,0x6c,0x05,0xb0,0x03,0xc0,
  0x08,0xa8,0x7e,0x2d,0x95,0x5b,0x04,0x00,0x93,0xa8,0x77,0x12,0xb9,0xf2,0xc4,0x11,0x10,0x66,0x50,0xe7,0x0c,0x72,0x16,0x84,
  0x00,0xe0,0x81,0xef,0x7d,0x03,0xd5,0x00,0xe2,0x08,0x08,0x8f,0x7a,0xf9,0xf9,0x83,0xdb,0x81,0x1d,0x00,0xc6,0x4d,0x29,0x5b,
  0x01,0xec,0x00,0x30,0xfa,0xdd,0x1d,0x77,0x07,0x3b,0x00,0xcc,0x17,0xfb,0x00,0x0b,0x06,0x01,0xc0,0xf4,0xd7,0x00,0xcb,0x86,
  0x38,0x02,0xc2,0xf4,0x77,0xcb,0xdc,0x2f,0x04,0x00,0xd3,0xdf,0x8d,0x73,0xe3,0x10,0x00,0xfc,0x8e,0x07,0x77,0xd0,0xed,0x43,
  0x00,0x30,0x3b,0xdc,0x47,0xf7,0x91,0xf8,0x08,0x6c,0x6a,0x98,0x1a,0xf1,0x59,0xd8,0x67,0x61,0x04,0xc0,0xf4,0x37,0xc2,0x34,
  0x40,0x03,0x88,0x23,0x20,0xd3,0xdf,0xf4,0x77,0x73,0xdd,0x59,0x04,0xc0,0x80,0x30,0x23,0xdc,0x62,0xb7,0x58,0x00,0x04,0xc0,
  0x5c,0x30,0x1a,0xdc,0x6b,0x37,0x5a,0x00,0x30,0x11,0x4c,0x04,0x77,0xdc,0x1d,0x8f,0x8f,0xc0,0x98,0x05,0x66,0x41,0x7c,0x16,
  0xf6,0x59,0x58,0x00,0x30,0xfd,0x4d,0x7f,0x97,0x5a,0x03,0xe2,0x08,0x08,0x8f,0x9c,0xe9,0x6f,0x19,0x58,0x03,0x02,0x80,0xd1,
  0xef,0xc9,0xb7,0x1e,0x2c,0x06,0x01,0xc0,0xd3,0x8e,0x55,0x61,0x55,0xc4,0x37,0x00,0x3c,0xe7,0xf8,0x24,0x80,0x00,0x60,0xfa,
  0xa3,0x01,0xc4,0x11,0x10,0x0e,0xfd,0xb1,0x54,0x10,0x00,0x0e,0xfc,0x1a,0xe5,0x91,0xb6,0x66,0xac,0x99,0x38,0x02,0xc2,0x26,
  0x1a,0x2c,0xe6,0x43,0x9b,0x5d,0x02,0x4f,0x0b,0xec,0xb3,0xaa,0x6d,0x05,0xec,0x00,0x30,0xfd,0xb1,0xbc,0x11,0x00,0x00,0x04,
  0x00,0xef,0x47,0x58,0xe4,0x08,0x80,0x07,0x03,0x2c,0x75,0x04,0x00,0x00,0x01,0xf0,0x4e,0x04,0x16,0x3c,0x02,0x00,0x80,0x00,
  0x00,0x20,0x00,0xb6,0xc3,0x60,0xd9,0x23,0x00,0x00,0x08,0x00,0x00,0x02,0x00,0x80,0x00,0x00,0x20,0x00,0x00,0x02,0x00,0x80,
  0x00,0x10,0x7f,0x5f,0x12,0x58,0xf6,0x02,0x00,0x80,0x00,0x00,0x20,0x00,0xd8,0x0e,0x83,0x05,0x2f,0x00,0x00,0x08,0x00,0xde,
  0x89,0xc0,0x52,0x17,0x00,0x3c,0x18,0x60,0x91,0x0b,0x00,0x00,0x02,0x80,0xf7,0x23,0x2c,0x6f,0x86,0x31,0xbb,0x04,0x63,0x3e,
  0x24,0x7e,0x5b,0x3a,0x46,0x3f,0x76,0x00,0x1e,0x18,0x8f,0x19,0x96,0x25,0x76,0x00,0xb6,0x02,0x9e,0x31,0x2c,0x4b,0x04,0xa0,
  0xf0,0x9d,0xeb,0xed,0x23,0xe7,0x01,0xc3,0xb2,0x44,0x00,0xec,0xbe,0xc1,0xb2,0x24,0xbe,0x01,0x00,0x20,0x00,0x00,0x08,0x00,
  0x00,0x02,0x00,0x80,0x00,0x00,0x08,0x00,0x00,0x02,0x00,0x80,0x00,0x00,0x20,0x00,0x00,0x08,0x00,0x00,0xf1,0xab,0x20,0x60,
  0x0f,0xc7,0xfa,0xfd,0xd8,0x7e,0x41,0x02,0x02,0x00,0x5d,0x73,0xff,0xf5,0x3f,0x5b,0x09,0x10,0x00,0x68,0x19,0xfd,0x6f,0x7f,
  0x0a,0x19,0x20,0xbe,0x01,0x40,0xd5,0xf4,0x3f,0xeb,0x8f,0x83,0x00,0x80,0x71,0xa9,0x01,0x08,0x00,0x18,0x94,0x1a,0x80,0x00,
  0x80,0x11,0xa9,0x01,0x08,0x00,0x18,0x8e,0x1a,0x80,0x00,0x00,0x20,0x00,0xe0,0xbd,0xd8,0x26,0x00,0x01,0x00,0x40,0x00,0x00,
  0x10,0x00,0xe2,0xfc,0xc7,0x8f,0x0c,0x02,0x00,0x80,0x00,0x00,0x20,0x00,0xc4,0x61,0x88,0x1f,0x1c,0x04,0x00,0x00,0x01,0x00,
  0x40,0x00,0x00,0x10,0x00,0x00,0x04,0x00,0x00,0x01,0x00,0x40,0x00,0x00,0x04,0x00,0x00,0x01,0x00,0x40,0x00,0x00,0x10,0x00,
  0x00,0x04,0x00,0x00,0x01,0x00,0x40,0x00,0x00,0x10,0x00,0x00,0x04,0x00,0x80,0x21,0xcd,0x2e,0x01,0xe7,0xf6,0xbc,0xde,0xe2,
  0xef,0x6c,0x01,0x3b,0x00,0x00,0x04,0x00,0x40,0x00,0x00,0x10,0x00,0x00,0x04,0x00,0x00,0x01,0x00,0x40,0x00,0x00,0x10,0x00,
  0x00,0x04,0x00,0x00,0x01,0x00,0x40,0x00,0x00,0x10,0x00,0x00,0x04,0x00,0x00,0x01,0x00,0x40,0x00,0x00,0x10,0x00,0x00,0x04,
  0x00,0x00,0x01,0x00,0x40,0x00,0x00,0x10,0x00,0x00,0x04,0x00,0x00,0x01,0x00,0x40,0x00,0x00,0x10,0x00,0x00,0x04,0x00,0x00,
  0x01,0x00,0x10,0x00,0x00,0x04,0x00,0x00,0x01,0x00,0x40,0x00,0x00,0x10,0x00,0x00,0x04,0x00,0x00,0x01,0x00,0x40,0x00,0x00,
  0x10,0x00,0x00,0x06,0x35,0x2d,0xeb,0xe6,0x2a,0x9c,0xc9,0xe5,0x71,0x77,0x11,0xf8,0x91,0xe7,0xf5,0xe6,0x22,0xd8,0x01,0x00,
  0x20,0x00,0x00,0x08,0x00,0x00,0x02,0x00,0x80,0x00,0x00,0x20,0x00,0x00,0x08,0x00,0x00,0x02,0x00,0x80,0x00,0x00,0x20,0x00,
  0x00,0x08,0x00,0x00,0x02,0x00,0x80,0x00,0x00,0x20,0x00,0x00,0x08,0x00,0x00,0x02,0x00,0x80,0x00,0x00,0x20,0x00,0x00,0x08,
  0x40,0xfc,0xa5,0x7d,0x60,0x69,0x09,0x00,0x00,0x02,0x00,0x80,0x00,0x60,0xab,0x0e,0x16,0x95,0x00,0x00,0x20,0x00,0x78,0x5f,
  0xc3,0x72,0x42,0x00,0xf0,0xd0,0x62,0x21,0x21,0x00,0x78,0x74,0xb1,0x84,0x10,0x00,0x3c,0xc0,0x58,0x3c,0x08,0x00,0x1e,0x63,
  0x2c,0x1b,0x86,0x35,0x2d,0xeb,0xe6,0x2a,0x94,0xb8,0x3c,0xee,0x2e,0x02,0x46,0x3f,0x02,0xa0,0x04,0x60,0xee,0x0b,0x80,0x00,
  0x28,0x01,0xe6,0x3e,0x02,0x00,0x40,0x7c,0x04,0x06,0x40,0x00,0x00,0x10,0x00,0x00,0x04,0x00,0x00,0x01,0x00,0x40,0x00,0x00,
  0x10,0x00,0x00,0x04,0x00,0x00,0x01,0x00,0x40,0x00,0x00,0x10,0x00,0x00,0x04,0x00,0x00,0x01,0x00,0x40,0x00,0x00,0x10,0x00,
  0x00,0x04,0x00,0x00,0x01,0x00,0x40,0x00,0x00,0x10,0x00,0x00,0x04,0x00,0x00,0x01,0x00,0x40,0x00,0x00,0x04,0x00,0x00,0x01,
  0x00,0x40,0x00,0x00,0x10,0x00,0x00,0x04,0x00,0x00,0x01,0x00,0x40,0x00,0x00,0x10,0x00,0x00,0x04,0x00,0x00,0x01,0x00,0x40,
  0x00,0x00,0x10,0x00,0x00,0x04,0x00,0x00,0x01,0x00,0x40,0x00,0x00,0x10,0x00,0x00,0x04,0x00,0x00,0x01,0x00,0x40,0x00,0x00,
  0x10,0x00,0x00,0x04,0x00,0x00,0x01,0x00,0x40,0x00,0x00,0x04,0x00,0x00,0x01,0x00,0x40,0x00,0x00,0x10,0x00,0x00,0x04,0x00,
  0x00,0x01,0x00,0x40,0x00,0x00,0x10,0x00,0x00,0x04,0x00,0x00,0x01,0x00,0x40,0x00,0x00,0x10,0x00,0x00,0x04,0x00,0x00,0x01,
  0x00,0x40,0x00,0x00,0x10,0x00,0x00,0x04,0x00,0x00,0x01,0x00,0x40,0x00,0x00,0x10,0x00,0x00,0x04,0x00,0x00,0x01,0x00,0x40,
  0x00,0x00,0x10,0x00,0x00,0x01,0x00,0x40,0x00,0x00,0x10,0x00,0x00,0x04,0x00,0x00,0x01,0x00,0x40,0x00,0x00,0x10,0x00,0x00,
  0x04,0x00,0x00,0x01,0x00,0x40,0x00,0x00,0x10,0x00,0x00,0x04,0x00,0x00,0x01,0x00,0x40,0x00,0x00,0x10,0x00,0x00,0x04,0x00,
  0x00,0x01,0x00,0x40,0x00,0x00,0x10,0x00,0x00,0x04,0x00,0x00,0x01,0x00,0x40,0x00,0x00,0x10,0x00,0x00,0x01,0x00,0x40,0x00,
  0x00,0x10,0x00,0x00,0x04,0x00,0x00,0x01,0x00,0x40,0x00,0x00,0x10,0x00,0x00,0x04,0x00,0x00,0x01,0x00,0x40,0x00,0x00,0x10,
  0x00,0x00,0x04,0x00,0x00,0x01,0x00,0x40,0x00,0x00,0x10,0x00,0x00,0x04,0x00,0x00,0x01,0x00,0x40,0x00,0x00,0x10,0x00,0x00,
  0x04,0x00,0x00,0x01,0x00,0x40,0x00,0x00,0x10,0x00,0x00,0x04,0x00,0x40,0x00,0x00,0x10,0x00,0x00,0x04,0x00,0x00,0x01,0x00,
  0x40,0x00,0x00,0x10,0x00,0x00,0x04,0x00,0x00,0x01,0x00,0x40,0x00,0x00,0x10,0x00,0x00,0x04,0x00,0x00,0x01,0x00,0x40,0x00,
  0x00,0x10,0x00,0x00,0x04,0x00,0x00,0x01,0x00,0x40,0x00,0x00,0x10,0x00,0x00,0x04,0x00,0x00,0x01,0x00,0xe0,0x83,0x7f,0x1c,
  0x2f,0x6e,0x0d,0xa5,0x49,0xaa,0xb9,0x00,0x00,0x00,0x00,0x49,0x45,0x4e,0x44,0xae,0x42,0x60,0x82,
};

static const char INDEX_HTML[] PROGMEM =
  "<!DOCTYPE html>\n"
  "<html lang=\"en\">\n"
  "<head>\n"
  "<meta charset=\"utf-8\">\n"
  "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1,viewport-fit=cover\">\n"
  "<title>LEO Home Hub</title>\n"
  "<link rel=\"manifest\" href=\"/manifest.json\">\n"
  "<link rel=\"icon\" href=\"/icon.svg\" type=\"image/svg+xml\">\n"
  "<link rel=\"apple-touch-icon\" href=\"/icon-192.png\">\n"
  "<meta name=\"theme-color\" content=\"#0c0f12\">\n"
  "<meta name=\"mobile-web-app-capable\" content=\"yes\">\n"
  "<meta name=\"apple-mobile-web-app-capable\" content=\"yes\">\n"
  "<style>\n"
  ":root{--bg:#0c0f12;--s1:#14191e;--s2:#1b222a;--line:#26303a;--txt:#e7edf2;--mut:#8aa0b2;--acc:#34d3b0;--off:#3a4651;\n"
  "  --warn:#f0a93b;--bad:#e2564b;--good:#46c46a;--water:#3aa0ff;--r:14px;--navh:62px}\n"
  "*{box-sizing:border-box}\n"
  "body{margin:0;background:var(--bg);color:var(--txt);font:14px/1.45 ui-sans-serif,system-ui,-apple-system,\"Segoe UI\",Roboto,sans-serif;-webkit-tap-highlight-color:transparent}\n"
  "button{font:inherit;color:inherit;cursor:pointer}\n"
  ".wrap{max-width:1040px;margin:0 auto;padding:14px 14px calc(var(--navh) + 24px)}\n"
  "header{display:flex;align-items:center;gap:11px;margin-bottom:14px}\n"
  ".logo{width:40px;height:40px;border-radius:11px;background:var(--s2);border:1px solid var(--line);display:grid;place-items:center}\n"
  "header h1{margin:0;font-size:16px}\n"
  ".sub{font-size:11.5px;color:var(--mut)}\n"
  ".pill{display:inline-flex;align-items:center;gap:5px;padding:2px 8px;border-radius:20px;background:var(--s2);border:1px solid var(--line);font-size:10.5px;font-weight:600}\n"
  ".dot{width:8px;height:8px;border-radius:50%;background:var(--mut);display:inline-block}\n"
  ".dot.on{background:var(--good)}.dot.off{background:var(--bad)}\n"
  ".grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:12px}\n"
  ".card{background:var(--s1);border:1px solid var(--line);border-radius:var(--r);padding:14px}\n"
  ".card.offline{opacity:.55}\n"
  ".chead{display:flex;align-items:center;gap:8px;margin-bottom:10px}\n"
  ".chead .nm{flex:1;font-weight:650;font-size:15px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}\n"
  ".chead .w{font-size:12px;font-weight:650;color:var(--warn)}\n"
  ".meta{font-size:11px;color:var(--mut)}\n"
  ".rel{display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px dashed #1e2731}\n"
  ".rel:last-of-type{border:0}\n"
  ".rel .n{flex:1;min-width:0}.rel .n b{display:block;font-weight:600;font-size:13.5px}\n"
  ".tgl{width:56px;height:31px;border-radius:20px;border:1px solid var(--line);background:var(--off);position:relative;flex:0 0 auto;transition:.15s}\n"
  ".tgl:after{content:\"\";position:absolute;top:3px;left:3px;width:23px;height:23px;border-radius:50%;background:#cfd8df;transition:.15s}\n"
  ".tgl.on{background:var(--acc)}.tgl.on:after{left:28px;background:#06231e}\n"
  ".row{display:flex;gap:8px;margin-top:10px}.row>*{flex:1}\n"
  ".btn{padding:10px;border-radius:11px;border:1px solid var(--line);background:var(--s2);color:var(--txt);font-weight:650}\n"
  ".btn.p{background:var(--acc);border-color:var(--acc);color:#06231e}\n"
  ".btn.d{color:var(--bad);border-color:#5a2a26;background:transparent}\n"
  ".tank{display:flex;gap:16px;align-items:center}\n"
  ".tankbar{width:46px;height:150px;border:2px solid var(--line);border-radius:10px;display:flex;flex-direction:column-reverse;gap:3px;padding:4px;flex:0 0 auto}\n"
  ".seg{flex:1;border-radius:3px;background:#1d2630}\n"
  ".seg.on{background:var(--water)}\n"
  ".big{font-size:38px;font-weight:300;line-height:1}\n"
  ".big small{font-size:15px;color:var(--mut)}\n"
  "h3{font-size:12.5px;text-transform:uppercase;letter-spacing:.6px;color:var(--mut);margin:18px 0 10px}\n"
  "input,select{width:100%;padding:10px 11px;border-radius:10px;border:1px solid var(--line);background:var(--s1);color:var(--txt);font:inherit}\n"
  "label{display:block;font-size:12px;color:var(--mut);margin:8px 0 4px}\n"
  ".note{font-size:11.5px;color:var(--mut)}\n"
  ".err{color:var(--bad);font-size:12px}\n"
  ".page{display:none}.page.active{display:block}\n"
  ".logbox{background:#0a0d10;border:1px solid var(--line);border-radius:11px;padding:10px;font:11px ui-monospace,monospace;color:#a9b7c2;max-height:300px;overflow:auto;white-space:pre-wrap}\n"
  ".empty{text-align:center;padding:28px 14px;color:var(--mut)}\n"
  ".bar{height:6px;background:var(--s2);border-radius:4px;overflow:hidden;margin-top:6px}.bar i{display:block;height:100%;background:var(--acc);width:0}\n"
  "nav{position:fixed;left:0;right:0;bottom:0;height:var(--navh);background:#0e1318ee;backdrop-filter:blur(8px);border-top:1px solid var(--line);display:flex;padding-bottom:env(safe-area-inset-bottom)}\n"
  "nav button{flex:1;background:none;border:0;color:var(--mut);font-size:11px;font-weight:650}\n"
  "nav button.sel{color:var(--acc)}\n"
  "@media(min-width:760px){nav{max-width:520px;left:50%;transform:translateX(-50%);border-radius:16px 16px 0 0;border:1px solid var(--line)}}\n"
  ".banner{background:#2a1f10;border:1px solid #5a4320;color:#f3c77a;border-radius:12px;padding:10px 12px;margin-bottom:12px;font-size:13px;display:flex;gap:10px;align-items:center}\n"
  ".banner.info{background:#122028;border-color:#22465a;color:#9fd3f0}\n"
  ".banner b{flex:1}\n"
  ".login{position:fixed;inset:0;background:var(--bg);display:none;place-items:center;z-index:50;padding:24px}\n"
  ".login.show{display:grid}\n"
  ".act{display:flex;gap:10px;padding:8px 0;border-bottom:1px dashed #1e2731;font-size:13px}\n"
  ".act time{color:var(--mut);font-variant-numeric:tabular-nums;flex:0 0 auto;min-width:118px}\n"
  ".act.blocked{color:var(--warn)}\n"
  ".toast{position:fixed;left:50%;bottom:calc(var(--navh) + 14px);transform:translateX(-50%);background:var(--s2);border:1px solid var(--line);padding:9px 14px;border-radius:12px;font-size:13px;display:none;z-index:60}\n"
  ".switchrow{display:flex;align-items:center;gap:10px;margin-top:6px}\n"
  ".switchrow span{flex:1}\n"
  ".card.click{cursor:pointer}.card.click:active{transform:scale(.99)}\n"
  ".chev{color:var(--mut);font-size:20px;line-height:1}\n"
  ".kv{display:flex;justify-content:space-between;gap:10px;padding:6px 0;border-bottom:1px dashed #1e2731;font-size:13px}.kv:last-child{border:0}.kv span{color:var(--mut)}\n"
  ".btn:disabled{opacity:.45}\n"
  ".subtabs{display:flex;gap:6px;position:sticky;top:0;z-index:5;background:var(--bg);padding:6px 0 10px;margin-top:-4px}\n"
  ".subtabs button{flex:1;padding:9px 4px;border-radius:10px;border:1px solid var(--line);background:var(--s2);color:var(--mut);font-weight:650;font-size:13px}\n"
  ".subtabs button.on{background:var(--acc);border-color:var(--acc);color:#06231e}.subtabs button.back{flex:0 0 40px;font-size:18px;color:var(--txt)}\n"
  "details.rule{border-bottom:1px dashed #1e2731;padding:2px 0}details.rule>summary{list-style:none;cursor:pointer;display:flex;align-items:center;gap:8px;padding:10px 0}\n"
  "details.rule>summary::-webkit-details-marker{display:none}details.rule>summary .rd{flex:1;font-size:13px}details.rule[open]>summary .chev{transform:rotate(90deg)}\n"
  ".pill.off{opacity:.5}\n"
  "details.adv summary{cursor:pointer;font-weight:650;color:var(--mut);list-style:none}details.adv summary:before{content:\"▸ \"}details.adv[open] summary:before{content:\"▾ \"}\n"
  ".hlp{display:inline-grid;place-items:center;width:17px;height:17px;border:1px solid var(--mut);border-radius:50%;font-size:10.5px;font-weight:700;color:var(--mut);margin-left:6px;cursor:pointer;vertical-align:1px;text-transform:none}\n"
  ".hlpt{display:none;background:var(--s2);border:1px solid var(--line);border-radius:9px;padding:8px 10px;margin:6px 0;font-size:12px;color:var(--txt);text-transform:none;letter-spacing:0;font-weight:400}.hlpt.show{display:block}\n"
  "</style>\n"
  "</head>\n"
  "<body>\n"
  "<div class=\"login\" id=\"login\"><div style=\"width:min(340px,100%);text-align:center\">\n"
  "  <h2 style=\"margin:0 0 6px\">LEO Home Hub</h2><p class=\"note\" style=\"margin:0 0 14px\">Enter the hub password</p>\n"
  "  <input id=\"lpass\" type=\"password\" placeholder=\"Password\" onkeydown=\"if(event.key==='Enter')doLogin()\">\n"
  "  <div class=\"row\"><button class=\"btn p\" onclick=\"doLogin()\">Sign in</button></div>\n"
  "  <div class=\"err\" id=\"lerr\" style=\"margin-top:8px\"></div>\n"
  "  <p class=\"note\" style=\"margin-top:16px\">Forgot it? Connect the hub by USB and send <b>RESETPASS</b>.</p>\n"
  "</div></div>\n"
  "<div class=\"toast\" id=\"toast\"></div>\n"
  "\n"
  "<div class=\"wrap\">\n"
  "  <header>\n"
  "    <div class=\"logo\"><svg width=\"22\" height=\"22\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"#34d3b0\" stroke-width=\"1.7\"><path d=\"M3 11l9-8 9 8M5 10v10h14V10M10 20v-6h4v6\"/></svg></div>\n"
  "    <div style=\"flex:1;min-width:0\"><h1 id=\"hubName\">LEO Home Hub</h1>\n"
  "      <div class=\"sub\"><span class=\"pill\"><span class=\"dot\" id=\"wifiDot\"></span><span id=\"wifiTxt\">…</span></span> <span id=\"devSum\"></span></div></div>\n"
  "  </header>\n"
  "  <div id=\"banners\"></div>\n"
  "\n"
  "  <section class=\"page active\" id=\"p-home\">\n"
  "    <div class=\"grid\" id=\"cards\"></div>\n"
  "  </section>\n"
  "\n"
  "  <section class=\"page\" id=\"p-devices\">\n"
  "    <div class=\"card\" style=\"margin-bottom:12px\">\n"
  "      <b>Add a device</b>\n"
  "      <ol class=\"note\" style=\"padding-left:18px;margin:8px 0\">\n"
  "        <li>The device needs LEO firmware once, over USB (<b>LEO_SwitchEdge</b> or <b>LEO_TankEdge</b> — see the setup guide in docs/setup.md). A device that was used before: factory-reset it first (hold its BOOT button 15 s).</li>\n"
  "        <li>Press <b>Start adding</b> below — the hub accepts new devices for 2 minutes.</li>\n"
  "        <li>Power the device on within a few metres of the hub. Its light breathes <b>blue</b> while it looks for a hub.</li>\n"
  "        <li>Within seconds it appears in the list below with 🔒 secured, and its light turns to a calm <b>green</b> breath. Give it a name.</li>\n"
  "      </ol>\n"
  "      <div class=\"row\"><button class=\"btn p\" id=\"pairbtn\" onclick=\"openPairing()\">Start adding (2 minutes)</button></div>\n"
  "      <div class=\"note\" id=\"pairmsg\" style=\"margin-top:6px\"></div>\n"
  "    </div>\n"
  "    <div id=\"devlist\"></div>\n"
  "  </section>\n"
  "\n"
  "  <section class=\"page\" id=\"p-activity\">\n"
  "    <div class=\"row\" style=\"margin:0 0 10px\"><button class=\"btn\" onclick=\"loadActivity()\">Refresh</button><button class=\"btn d\" onclick=\"clearActivity()\">Clear log</button></div>\n"
  "    <div class=\"card\" id=\"actlist\"><div class=\"meta\">Loading…</div></div>\n"
  "  </section>\n"
  "\n"
  "  <section class=\"page\" id=\"p-hub\">\n"
  "    <h3>Home settings</h3>\n"
  "    <div class=\"card\" id=\"homeset\"><div class=\"meta\">Loading…</div></div>\n"
  "    <h3>Night lock</h3>\n"
  "    <div class=\"card\">\n"
  "      <p class=\"note\" style=\"margin-top:0\">While the lock is active the hub refuses every <b>ON</b> command (turning things OFF still works). Every blocked attempt is recorded in Activity.</p>\n"
  "      <div class=\"switchrow\"><span>Lock now (until I turn it off)</span><button class=\"tgl\" id=\"lockManual\" onclick=\"setLock({manual:!this.classList.contains('on')})\"></button></div>\n"
  "      <div class=\"switchrow\"><span>Lock automatically every night</span><button class=\"tgl\" id=\"lockSched\" onclick=\"setLock({sched:!this.classList.contains('on')})\"></button></div>\n"
  "      <div class=\"row\"><div><label>From</label><input type=\"time\" id=\"lockFrom\"></div><div><label>Until</label><input type=\"time\" id=\"lockTo\"></div></div>\n"
  "      <div class=\"row\"><button class=\"btn\" onclick=\"setLock({from:$('#lockFrom').value,to:$('#lockTo').value})\">Save schedule</button></div>\n"
  "      <div class=\"note\" id=\"lockmsg\"></div>\n"
  "    </div>\n"
  "    <h3>Security</h3>\n"
  "    <div class=\"card\">\n"
  "      <div class=\"meta\" id=\"pwstate\">—</div>\n"
  "      <label id=\"oldlbl\">Current password</label><input id=\"oldpw\" type=\"password\" autocomplete=\"current-password\">\n"
  "      <label>New password (at least 6 characters)</label><input id=\"newpw\" type=\"password\" autocomplete=\"new-password\">\n"
  "      <div class=\"row\"><button class=\"btn p\" onclick=\"setPassword()\">Save password</button><button class=\"btn\" onclick=\"logout()\">Sign out</button></div>\n"
  "      <div class=\"row\" id=\"rmpwrow\"><button class=\"btn d\" onclick=\"removePassword()\">Remove password…</button></div>\n"
  "      <div class=\"note\" id=\"pwmsg\"></div>\n"
  "      <label style=\"margin-top:14px\">Emergency hotspot password (used only if WiFi is down for 30 s)</label>\n"
  "      <div class=\"row\" style=\"margin:0\"><input id=\"appw\" type=\"text\" autocomplete=\"off\"><button class=\"btn\" style=\"flex:0 0 90px\" onclick=\"saveApPass()\">Save</button></div>\n"
  "      <div class=\"note\" id=\"apmsg\"></div>\n"
  "    </div>\n"
  "    <h3>WiFi</h3>\n"
  "    <div class=\"card\">\n"
  "      <div class=\"meta\" id=\"netinfo\">—</div>\n"
  "      <label>Network name (SSID)</label><input id=\"ssid\">\n"
  "      <label>Password</label><input id=\"pass\" type=\"password\" placeholder=\"unchanged if empty\">\n"
  "      <div class=\"row\"><button class=\"btn p\" onclick=\"saveWifi()\">Save &amp; reconnect</button></div>\n"
  "      <div class=\"note\" id=\"wifimsg\"></div>\n"
  "    </div>\n"
  "    <h3>Hub</h3>\n"
  "    <div class=\"card\">\n"
  "      <label>Hub name</label><input id=\"hname\">\n"
  "      <div class=\"row\"><button class=\"btn\" onclick=\"saveHubName()\">Save name</button><button class=\"btn\" onclick=\"if(confirm('Restart the hub?'))post('/api/reboot')\">Restart hub</button></div>\n"
  "      <label style=\"margin-top:14px\">Update hub firmware (OTA) — LEO_Hub.ino.bin</label><input id=\"hubbin\" type=\"file\" accept=\".bin\">\n"
  "      <div class=\"row\"><button class=\"btn p\" onclick=\"hubOta()\">Upload &amp; install</button></div>\n"
  "      <div class=\"bar\"><i id=\"hubbar\"></i></div><div class=\"note\" id=\"hubotamsg\"></div>\n"
  "    </div>\n"
  "    <details class=\"card adv\" style=\"margin-top:18px\" ontoggle=\"if(this.open)loadHubAdv()\"><summary>Advanced</summary>\n"
  "      <div id=\"hubadv\" class=\"meta\">Loading…</div>\n"
  "      <div class=\"switchrow\" style=\"margin-top:14px\"><span><b>Live log</b></span><button class=\"btn\" style=\"flex:0 0 auto\" onclick=\"clearConsole()\">Clear</button></div>\n"
  "      <div class=\"logbox\" id=\"log\" style=\"margin-top:8px\">Connecting…</div>\n"
  "      <div class=\"row\" style=\"margin-top:16px\"><button class=\"btn d\" onclick=\"hubFactory()\">Factory reset the hub…</button></div>\n"
  "      <p class=\"note\">Erases WiFi, password, devices, names and logs. Paired devices are told to forget the hub. Afterwards join the hotspot <b>LEO-Hub-…</b> (no password) and open 192.168.4.1 to set WiFi again. Also possible by holding the hub's <b>BOOT</b> button for 15 seconds (from 2 s its light blinks red, faster and brighter; solid red = accepted).</p>\n"
  "    </details>\n"
  "  </section>\n"
  "\n"
  "  <section class=\"page\" id=\"p-sw\">\n"
  "    <div class=\"subtabs\"><button class=\"back\" onclick=\"nav('home')\">‹</button><button data-t=\"ov\" onclick=\"subTab('sw','ov')\">Overview</button><button data-t=\"relays\" onclick=\"subTab('sw','relays')\">Relays</button><button data-t=\"setup\" onclick=\"subTab('sw','setup')\">Setup</button></div>\n"
  "    <div data-tab=\"ov\"><div id=\"swlive\"></div>\n"
  "    <h3>Power use</h3><div class=\"card\" id=\"swchart\"><div class=\"meta\">Loading…</div></div></div>\n"
  "    <div id=\"swset\"></div>\n"
  "    <details class=\"card adv\" data-tab=\"setup\" id=\"swadvd\" style=\"margin-top:14px\" ontoggle=\"if(this.open)loadAdv(swMac,'#swadv')\"><summary>Advanced</summary><div id=\"swadv\" class=\"meta\">Loading…</div></details>\n"
  "  </section>\n"
  "\n"
  "  <section class=\"page\" id=\"p-tank\">\n"
  "    <div class=\"subtabs\"><button class=\"back\" onclick=\"nav('home')\">‹</button><button data-t=\"ov\" onclick=\"subTab('tank','ov')\">Overview</button><button data-t=\"alarms\" onclick=\"subTab('tank','alarms')\">Alarms</button><button data-t=\"display\" onclick=\"subTab('tank','display')\">Display</button><button data-t=\"setup\" onclick=\"subTab('tank','setup')\">Setup</button></div>\n"
  "    <div data-tab=\"ov\"><div id=\"tlive\"></div>\n"
  "    <h3>Water level</h3><div class=\"card\" id=\"tchart\"><div class=\"meta\">Loading…</div></div></div>\n"
  "    <div id=\"tset\"></div>\n"
  "    <details class=\"card adv\" data-tab=\"setup\" id=\"tadvd\" style=\"margin-top:14px\" ontoggle=\"if(this.open)loadAdv(tankMac,'#tadv')\"><summary>Advanced</summary><div id=\"tadv\" class=\"meta\">Loading…</div></details>\n"
  "  </section>\n"
  "</div>\n"
  "\n"
  "<nav>\n"
  "  <button data-p=\"home\" class=\"sel\" onclick=\"nav('home')\">Home</button>\n"
  "  <button data-p=\"devices\" onclick=\"nav('devices')\">Devices</button>\n"
  "  <button data-p=\"activity\" onclick=\"nav('activity')\">Activity</button>\n"
  "  <button data-p=\"hub\" onclick=\"nav('hub')\">Hub</button>\n"
  "</nav>\n"
  "\n"
  "<script>\n"
  "const $=s=>document.querySelector(s),$$=s=>document.querySelectorAll(s);\n"
  "let S={hub:{},devices:[],ota:{}},page='home',devKeys='',sock=null;\n"
  "function esc(s){return(s==null?'':s+'').replace(/[<>&\"']/g,m=>({'<':'&lt;','>':'&gt;','&':'&amp;','\"':'&quot;',\"'\":'&#39;'}[m]))}\n"
  "function ago(ms){const s=Math.round(ms/1000);return s<60?s+'s':s<3600?Math.round(s/60)+'m':Math.round(s/3600)+'h'}\n"
  "function up(s){const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);return d?d+'d '+h+'h':h?h+'h '+m+'m':m+'m'}\n"
  "function toast(t){const e=$('#toast');e.textContent=t;e.style.display='block';clearTimeout(e._t);e._t=setTimeout(()=>e.style.display='none',3500)}\n"
  "function needLogin(){$('#login').classList.add('show');$('#lpass').focus()}\n"
  "/* every API call goes through here: 401 -> login screen */\n"
  "async function call(p,b,m){try{const r=await fetch(p,{method:m||(b===undefined?'GET':'POST'),headers:{'Content-Type':'application/json'},body:b===undefined?undefined:JSON.stringify(b)});\n"
  "  if(r.status===401){needLogin();return null}return r}catch(e){return null}}\n"
  "async function post(p,b){const r=await call(p,b||{});return r&&r.ok}\n"
  "async function jget(p){const r=await call(p);if(!r||!r.ok)return null;try{return await r.json()}catch(e){return null}}\n"
  "async function cmd(mac,c,x){const r=await call('/api/cmd',Object.assign({mac:mac,cmd:c},x||{}));\n"
  "  if(r&&r.status===423){toast('Night lock is on — ON commands are blocked');return false}return !!(r&&r.ok)}\n"
  "\n"
  "async function doLogin(){$('#lerr').textContent='';\n"
  "  let r;try{r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pass:$('#lpass').value})})}catch(e){$('#lerr').textContent='Hub not reachable';return}\n"
  "  if(r.ok){$('#lpass').value='';$('#login').classList.remove('show');connect()}\n"
  "  else $('#lerr').textContent=r.status===429?'Too many attempts — wait 30 seconds':'Wrong password'}\n"
  "async function logout(){await post('/api/logout');location.reload()}\n"
  "\n"
  "/* live state */\n"
  "/* stays live: retries until the hub answers, reconnects when updates stop (hub pushes at least every 2 s)\n"
  "   or when you come back to the page, and skips redraws when nothing changed (no lost taps) */\n"
  "let lastMsg=0,lastData='',connecting=false,retryT=null;\n"
  "function liveState(ok){const w=$('#wifiTxt');if(w&&!ok)w.textContent='Reconnecting…';$('#wifiDot').className='dot '+(ok?((S.hub||{}).wifi?'on':'off'):'off')}\n"
  "async function connect(){\n"
  "  if(connecting)return;connecting=true;clearTimeout(retryT);\n"
  "  try{\n"
  "    const st=await call('/api/state');\n"
  "    if(!st){if(!$('#login').classList.contains('show'))retryT=setTimeout(connect,2000);liveState(false);return}   // 401 shows the login screen\n"
  "    try{const txt=await st.text();lastData=txt;S=JSON.parse(txt);render()}catch(e){}\n"
  "    if(sock){sock.onclose=null;try{sock.close()}catch(_){}}\n"
  "    const ws=new WebSocket('ws://'+location.host+'/ws');sock=ws;lastMsg=Date.now();\n"
  "    ws.onmessage=e=>{lastMsg=Date.now();if(e.data===lastData)return;lastData=e.data;try{S=JSON.parse(e.data);render()}catch(_){}};\n"
  "    ws.onclose=()=>{if(sock===ws){liveState(false);retryT=setTimeout(connect,1500)}};\n"
  "  }finally{connecting=false}}\n"
  "setInterval(()=>{if(sock&&Date.now()-lastMsg>7000&&!connecting){liveState(false);connect()}},2000);\n"
  "document.addEventListener('visibilitychange',()=>{if(!document.hidden&&Date.now()-lastMsg>3000)connect()});\n"
  "window.addEventListener('online',()=>connect());\n"
  "function nav(p){page=p;$$('.page').forEach(s=>s.classList.toggle('active',s.id==='p-'+p));\n"
  "  $$('nav button').forEach(b=>b.classList.toggle('sel',b.dataset.p===p));\n"
  "  if(p==='devices'){devKeys='';render()} if(p==='hub'){loadHub();logOn()}else logOff(); if(p==='activity')loadActivity();\n"
  "  if(p==='tank'){tsetKey='';renderTank();pageExtras('tank')} if(p==='sw'){swKey='';renderSw();pageExtras('sw')} window.scrollTo(0,0)}\n"
  "\n"
  "function render(){\n"
  "  const h=S.hub||{};$('#hubName').textContent=h.name||'LEO Home Hub';\n"
  "  $('#wifiDot').className='dot '+(h.wifi?'on':'off');$('#wifiTxt').textContent=h.wifi?('WiFi · '+h.ip):(h.ap?'Hotspot '+h.ap:'Connecting…');\n"
  "  const on=S.devices.filter(d=>d.online).length;$('#devSum').textContent=S.devices.length?(on+'/'+S.devices.length+' devices online'):'';\n"
  "  let b='';const L=h.lock||{};\n"
  "  if(L.active)b+=`<div class=\"banner\"><b>🌙 Night lock is on — lights can't be switched ON${L.manual?'':(' until '+esc(L.to))}.</b>${L.manual?'<button class=\"btn\" onclick=\"setLock({manual:false})\">Unlock</button>':''}</div>`;\n"
  "  if(h.passwordSet===false)b+=`<div class=\"banner\"><b>⚠ No hub password yet — anyone on your WiFi can control your devices.</b><button class=\"btn\" onclick=\"nav('hub')\">Set one</button></div>`;\n"
  "  if(h.pairing>0)b+=`<div class=\"banner info\"><b>Adding devices for ${h.pairing}s more — power on the new device near the hub.</b><button class=\"btn\" onclick=\"post('/api/pairing',{secs:0})\">Stop</button></div>`;\n"
  "  else if(h.pending)b+=`<div class=\"banner info\"><b>A new device (${esc(h.pending)}) is asking to join.</b><button class=\"btn p\" onclick=\"openPairing()\">Allow</button></div>`;\n"
  "  $('#banners').innerHTML=b;\n"
  "  const pb=$('#pairbtn');if(pb)pb.textContent=h.pairing>0?('Waiting for the new device… '+h.pairing+'s'):'Start adding (2 minutes)';\n"
  "  const pm=$('#pairmsg');if(pm){if(h.pairing>0&&pairBase){const nw=S.devices.filter(d=>!pairBase.includes(d.mac));pm.innerHTML=nw.length?('✅ Added: '+nw.map(d=>'<b>'+esc(d.name)+'</b>').join(', ')):'Looking for new devices…'}else if(!h.pairing)pairBase=null}\n"
  "  if(page==='home')renderHome();\n"
  "  if(page==='devices')renderDevices();\n"
  "  if(page==='hub'){renderLock();renderHomeSet()}\n"
  "  if(page==='tank')renderTank();\n"
  "  if(page==='sw')renderSw();\n"
  "}\n"
  "function totalW(d){return (d.relays||[]).reduce((a,r)=>a+(r.on?r.watts:0),0)}\n"
  "function renderHome(){\n"
  "  const box=$('#cards');\n"
  "  if(!S.devices.length){box.innerHTML='<div class=\"card empty\" style=\"grid-column:1/-1\">No devices yet.<br>Go to <b>Devices → Allow new devices</b>, then power on a LEO switch or tank near the hub.</div>';return}\n"
  "  box.innerHTML=S.devices.map(d=>{\n"
  "    const st=d.online?'<span class=\"dot on\"></span>':'<span class=\"dot off\"></span>';\n"
  "    const meta=d.online?('signal '+d.rssi+' dBm · up '+up(d.uptime||0)+(d.secure?' · 🔒 secured':' · ⚠ not secured')):('offline · last seen '+ago(d.seenAgo)+' ago');\n"
  "    if(d.type==='switch'){\n"
  "      const rel=(d.relays||[]).map((r,i)=>r.used===false?'':`<div class=\"rel\"><div class=\"n\"><b>${esc(r.name)}</b><span class=\"meta\">${r.on?('On · '+r.watts+' W'):'Off'}</span></div>\n"
  "        <button class=\"tgl ${r.on?'on':''}\" ${d.online?'':'disabled'} onclick=\"tog(this,'${d.mac}',${i},${!r.on})\"></button></div>`).join('');\n"
  "      return `<div class=\"card click ${d.online?'':'offline'}\" onclick=\"cardOpen(event,'sw','${d.mac}')\"><div class=\"chead\">${st}<span class=\"nm\">${esc(d.name)}</span><span class=\"w\">${totalW(d).toFixed(0)} W</span><span class=\"chev\">›</span></div>\n"
  "        ${rel||'<div class=\"meta\">Waiting for relay info…</div>'}\n"
  "        <div class=\"row\"><button class=\"btn\" ${d.online?'':'disabled'} onclick=\"cmd('${d.mac}',2,{val:1})\">All on</button><button class=\"btn\" ${d.online?'':'disabled'} onclick=\"cmd('${d.mac}',2,{val:0})\">All off</button></div>\n"
  "        <div class=\"meta\" style=\"margin-top:8px\">${meta}</div></div>`}\n"
  "    if(d.type==='tank'){const t=d.tank||{};\n"
  "      return `<div class=\"card click ${d.online?'':'offline'}\" onclick=\"openTank('${d.mac}')\"><div class=\"chead\">${st}<span class=\"nm\">${esc(d.name)}</span><span class=\"chev\">›</span></div>\n"
  "        <div class=\"tank\">${tankBar(d)}<div><div class=\"big\">${t.sensorOk===false?'—':Math.round(t.level||0)}<small>%</small></div>\n"
  "        <div class=\"meta\" style=\"margin-top:6px\">${t.sensorOk===false?'<span class=\"err\">Sensor error</span>':('Water distance '+(t.dist||0).toFixed(1)+' cm')}</div>\n"
  "        <div class=\"meta\">${esc(t.stateTxt||'')}</div>${t.ldr!==undefined?`<div class=\"meta\">Room light: ${esc(S.hub.room||'')} (${t.ldr})</div>`:''}</div></div>\n"
  "        <div class=\"meta\" style=\"margin-top:8px\">${meta}</div></div>`}\n"
  "    return `<div class=\"card\"><div class=\"chead\">${st}<span class=\"nm\">${esc(d.name)}</span></div><div class=\"meta\">Unknown device type</div></div>`}).join('');\n"
  "}\n"
  "async function tog(el,mac,i,on){el.classList.toggle('on',on);if(!await cmd(mac,1,{idx:i,val:on?1:0}))el.classList.toggle('on',!on)}\n"
  "async function everything(on){for(const d of S.devices)if(d.type==='switch'&&d.online)await cmd(d.mac,2,{val:on?1:0})}\n"
  "let pairBase=null;\n"
  "async function openPairing(){pairBase=S.devices.map(d=>d.mac);if(await post('/api/pairing',{secs:120}))toast('Adding devices for 2 minutes — power the new one on now')}\n"
  "\n"
  "/* devices page: rebuilt only when the device set changes, so typing isn't clobbered */\n"
  "function renderDevices(){\n"
  "/* Devices = a simple list: status, open its settings page, update firmware, remove. All settings live on the device pages. */\n"
  "  const keys=S.devices.map(d=>d.mac+d.type+d.name).join(',');\n"
  "  if(keys!==devKeys){devKeys=keys;\n"
  "    $('#devlist').innerHTML=S.devices.length?S.devices.map(d=>`<div class=\"card\" style=\"margin-bottom:12px\" id=\"dv-${d.mac.replace(/:/g,'')}\">\n"
  "      <div class=\"chead\"><span class=\"dot\" data-k=\"dot\"></span><span class=\"nm\">${esc(d.name)}</span><span class=\"pill\">${esc(d.type)}</span></div>\n"
  "      <div class=\"meta\" data-k=\"meta\"></div>\n"
  "      <div class=\"row\"><button class=\"btn p\" onclick=\"${d.type==='tank'?'openTank':'openSw'}('${d.mac}')\">Open settings ›</button><button class=\"btn d\" onclick=\"forget('${d.mac}')\">Remove device</button></div>\n"
  "      <details style=\"margin-top:10px\"><summary class=\"meta\" style=\"cursor:pointer\">Update firmware…</summary>\n"
  "        <label>Choose the device's .bin (${d.type==='tank'?'LEO_TankEdge':'LEO_SwitchEdge'}.ino.bin)</label><input type=\"file\" accept=\".bin\" data-k=\"bin\">\n"
  "        <div class=\"row\"><button class=\"btn p\" onclick=\"edgeOta('${d.mac}',this)\">Upload &amp; install</button></div></details>\n"
  "      <div class=\"bar\" data-k=\"barw\" style=\"display:none\"><i data-k=\"bar\"></i></div><div class=\"note\" data-k=\"otamsg\"></div>\n"
  "    </div>`).join(''):'<div class=\"card empty\">No devices yet — use <b>Add a device</b> above.</div>'}\n"
  "  for(const d of S.devices){const c=$('#dv-'+d.mac.replace(/:/g,''));if(!c)continue;\n"
  "    c.querySelector('[data-k=dot]').className='dot '+(d.online?'on':'off');\n"
  "    c.querySelector('[data-k=meta]').textContent='fw '+(d.fw||'?')+' · '+(d.secure?'🔒 secured':'⚠ not secured')+' · '+(d.online?('signal '+d.rssi+' dBm · up '+up(d.uptime||0)):('offline, last seen '+ago(d.seenAgo)+' ago'));\n"
  "    // update progress: shown while running, then '✅ Updated' once the device is back, cleared after 2 minutes\n"
  "    const o=S.ota||{},bw=c.querySelector('[data-k=barw]'),m=c.querySelector('[data-k=otamsg]');\n"
  "    if(o.mac===d.mac&&(o.active||(o.ago||0)<120)&&o.msg){bw.style.display='';c.querySelector('[data-k=bar]').style.width=(o.pct||0)+'%';\n"
  "      m.textContent=o.active?o.msg:(/^Installed/.test(o.msg)?(d.online&&(d.uptime||0)<180?'✅ Updated — now running '+(d.fw||''):'Installed — waiting for the device to restart…'):o.msg)}\n"
  "    else if(!c.dataset.uploading){bw.style.display='none';m.textContent=''}}\n"
  "}\n"
  "async function rename(mac,btn){const v=btn.parentElement.querySelector('input').value.trim();if(v)await cmd(mac,4,{text:v})}\n"
  "async function relMeta(mac,i,btn){const p=btn.parentElement;await cmd(mac,5,{idx:i,text:p.querySelector('[data-r=\"'+i+'n\"]').value.trim(),f:parseFloat(p.querySelector('[data-r=\"'+i+'w\"]').value)||0})}\n"
  "async function forget(mac){const d=S.devices.find(x=>x.mac===mac)||{};\n"
  "  if(!confirm('Remove \"'+(d.name||mac)+'\" from the hub?\\n\\n'+(d.online?'It is online, so it is also told to forget this hub and goes back to \"looking for a hub\" (blue light).':'It is OFFLINE: before adding it again later, factory-reset it (hold its BOOT button 15 s).')+'\\n\\nIts history and settings on the hub are deleted; settings stored on the device itself are kept.'))return;\n"
  "  if(await post('/api/forget',{mac})){devKeys='';toast('Device removed');if(page!=='devices')nav('devices')}}\n"
  "function upload(url,file,bar,msg,done){\n"
  "  const fd=new FormData();fd.append('firmware',file,file.name);const x=new XMLHttpRequest();x.open('POST',url);\n"
  "  x.upload.onprogress=e=>{if(e.lengthComputable){bar.style.width=Math.round(e.loaded*100/e.total)+'%';msg.textContent='Uploading to hub… '+Math.round(e.loaded*100/e.total)+'%'}};\n"
  "  x.onload=()=>{if(x.status===401){needLogin();done(false,'sign in first');return}let e='';try{e=JSON.parse(x.responseText).err}catch(_){}done(x.status===200,e)};\n"
  "  x.onerror=()=>done(false,'upload interrupted');x.send(fd)}\n"
  "function edgeOta(mac,btn){const c=btn.closest('.card'),f=c.querySelector('[data-k=bin]').files[0],bar=c.querySelector('[data-k=bar]'),msg=c.querySelector('[data-k=otamsg]');\n"
  "  if(!f||!/\\.bin$/i.test(f.name)){msg.textContent='Choose the device\\'s .bin file first.';return}\n"
  "  if(!confirm('Send '+f.name+' to this device? It restarts when done.'))return;\n"
  "  c.dataset.uploading='1';c.querySelector('[data-k=barw]').style.display='';\n"
  "  upload('/api/edge-ota?mac='+encodeURIComponent(mac),f,bar,msg,(ok,e)=>{delete c.dataset.uploading;msg.textContent=ok?'Sending to device over ESP-NOW…':('Failed: '+(e||'error'))})}\n"
  "\n"
  "/* activity */\n"
  "async function loadActivity(){const a=await jget('/api/activity');if(!a)return;\n"
  "  $('#actlist').innerHTML=a.items.length?a.items.map(x=>`<div class=\"act ${x.blocked?'blocked':''}\"><time>${x.t?((d,p)=>`${p(d.getFullYear()%100)}-${p(d.getMonth()+1)}-${p(d.getDate())} ${hm(d,1)}`)(new Date(x.t*1000),n=>String(n).padStart(2,'0')):'(clock not set)'}</time><span>${esc(x.msg)}</span></div>`).join(''):'<div class=\"meta\">Nothing recorded yet.</div>'}\n"
  "\n"
  "/* hub page */\n"
  "function renderLock(){const L=(S.hub||{}).lock||{};$('#lockManual').classList.toggle('on',!!L.manual);$('#lockSched').classList.toggle('on',!!L.sched);\n"
  "  if(document.activeElement!==$('#lockFrom'))$('#lockFrom').value=L.from||'23:00';if(document.activeElement!==$('#lockTo'))$('#lockTo').value=L.to||'06:00';\n"
  "  $('#lockmsg').textContent=L.active?'Lock is ACTIVE now.':'Lock is not active now.'}\n"
  "async function setLock(x){if(!await post('/api/lock',x))toast('Could not change the lock')}\n"
  "async function loadHub(){const h=await jget('/api/hub');if(!h)return;$('#ssid').value=h.ssid||'';$('#hname').value=h.name||'';$('#appw').value=h.apPass||'';\n"
  "  $('#netinfo').textContent=(h.wifi?('Connected to '+h.ssid+' · '+h.ip+' · channel '+h.channel+' · '+h.rssi+' dBm'):'Not connected to WiFi')+' · hub fw '+h.fw+' · leohub.local';\n"
  "  $('#pwstate').textContent=h.passwordSet?'A hub password is set. Phones that signed in are remembered.':'No password set yet — set one so only you can control your devices.';\n"
  "  $('#oldlbl').style.display=$('#oldpw').style.display=$('#rmpwrow').style.display=h.passwordSet?'':'none';renderLock()}\n"
  "async function removePassword(){if(!$('#oldpw').value){$('#pwmsg').textContent='Type the current password first.';return}\n"
  "  if(!confirm('Remove the hub password? Anyone on your WiFi can then control your devices.'))return;\n"
  "  const r=await call('/api/password',{old:$('#oldpw').value,remove:true});\n"
  "  if(r&&r.ok){$('#pwmsg').textContent='Password removed.';$('#oldpw').value='';loadHub()}\n"
  "  else $('#pwmsg').textContent=r&&r.status===403?'Current password is wrong.':'Could not remove.'}\n"
  "async function setPassword(){const n=$('#newpw').value;if(n.length<6){$('#pwmsg').textContent='Use at least 6 characters.';return}\n"
  "  const r=await call('/api/password',{old:$('#oldpw').value,new:n});\n"
  "  if(r&&r.ok){$('#pwmsg').textContent='Password saved. This browser stays signed in.';$('#oldpw').value=$('#newpw').value='';loadHub()}\n"
  "  else $('#pwmsg').textContent=r&&r.status===403?'Current password is wrong.':'Could not save.'}\n"
  "async function saveApPass(){const p=$('#appw').value;if(p.length<8){$('#apmsg').textContent='At least 8 characters.';return}\n"
  "  $('#apmsg').textContent=await post('/api/appass',{pass:p})?'Saved.':'Could not save.'}\n"
  "async function saveWifi(){const ssid=$('#ssid').value.trim();if(!ssid){$('#wifimsg').textContent='Enter the network name.';return}\n"
  "  $('#wifimsg').textContent=await post('/api/wifi',{ssid,pass:$('#pass').value})?'Saved — the hub is reconnecting.':'Could not save.'}\n"
  "async function saveHubName(){await post('/api/hubname',{name:$('#hname').value.trim()})}\n"
  "function hubOta(){const f=$('#hubbin').files[0];if(!f||!/\\.bin$/i.test(f.name)){$('#hubotamsg').textContent='Choose LEO_Hub.ino.bin first.';return}\n"
  "  if(!confirm('Install '+f.name+' on the hub? It restarts when done.'))return;\n"
  "  upload('/api/ota',f,$('#hubbar'),$('#hubotamsg'),(ok,e)=>{$('#hubotamsg').textContent=ok?'Installed — restarting, this page reconnects by itself.':('Failed: '+(e||'error')+'. The current firmware is still running.');if(ok)setTimeout(()=>location.reload(),15000)})}\n"
  "let lws=null,lines=[];\n"
  "function logOn(){if(lws)return;lws=new WebSocket('ws://'+location.host+'/console');lws.onopen=()=>{lines=[];$('#log').textContent=''};\n"
  "  lws.onmessage=e=>{lines.push(...String(e.data).split('\\n'));if(lines.length>400)lines.splice(0,lines.length-400);const b=$('#log');b.textContent=lines.join('\\n');b.scrollTop=b.scrollHeight};\n"
  "  lws.onclose=()=>{lws=null;if(page==='hub')setTimeout(logOn,2000)}}\n"
  "function logOff(){if(lws){lws.onclose=null;lws.close();lws=null}}\n"
  "/* opened by IP address? switch to http://leohub.local - but only if this phone/PC can actually reach that\n"
  "   name (some Android browsers can't resolve .local), otherwise stay on the IP. ?ip in the URL = never switch. */\n"
  "(function(){const h=location.hostname;if(!/^\\d+\\.\\d+\\.\\d+\\.\\d+$/.test(h)||h==='192.168.4.1'||location.search.includes('ip'))return;\n"
  "  const ac=new AbortController();setTimeout(()=>ac.abort(),2500);\n"
  "  fetch('http://leohub.local/api/ping?'+Date.now(),{mode:'no-cors',cache:'no-store',signal:ac.signal})\n"
  "    .then(()=>location.replace('http://leohub.local'+location.pathname+location.hash)).catch(()=>{})})();\n"
  "/* installable web app: register the service worker (only possible on a secure origin, e.g. with Chrome's\n"
  "   'insecure origins treated as secure' flag for http://leohub.local) */\n"
  "if('serviceWorker' in navigator&&window.isSecureContext)navigator.serviceWorker.register('/sw.js').catch(()=>{});\n"
  "connect();\n"
  "setInterval(()=>{if(page==='home')renderHome()},5000);\n"
  "/* tank detail page: live view + actions + settings (settings are stored on the tank itself) */\n"
  "/* settings areas are not redrawn while you are TYPING in them (text/number fields, drop-downs, colour pickers);\n"
  "   buttons and toggles never block a redraw - after any tap the focus is released so live values always come through */\n"
  "function typing(sel){const a=document.activeElement,box=$(sel);if(!a||!box||!box.contains(a))return false;\n"
  "  return a.tagName==='SELECT'||a.tagName==='TEXTAREA'||(a.tagName==='INPUT'&&!['button','checkbox','radio','submit'].includes(a.type))}\n"
  "document.addEventListener('click',e=>{const b=e.target.closest('button');if(b)setTimeout(()=>b.blur(),0)},true);\n"
  "/* q(text): a circled ? that shows/hides an explanation right below it */\n"
  "function q(t){return `<span class=\"hlp\" onclick=\"event.stopPropagation();this.nextElementSibling.classList.toggle('show')\">?</span><span class=\"hlpt\">${t}</span>`}\n"
  "/* device pages are split into tabs (Overview / Alarms / Display / Setup, or Overview / Relays / Setup) */\n"
  "const subSel={tank:'ov',sw:'ov'};\n"
  "function subTab(k,t){subSel[k]=t;applySub(k);window.scrollTo(0,0);if(t==='ov')pageExtras(k)}\n"
  "function applySub(k){const sec=$(k==='tank'?'#p-tank':'#p-sw');if(!sec)return;const t=subSel[k];\n"
  "  sec.querySelectorAll('[data-tab]').forEach(e=>e.style.display=e.dataset.tab===t?'':'none');\n"
  "  sec.querySelectorAll('.subtabs [data-t]').forEach(b=>b.classList.toggle('on',b.dataset.t===t))}\n"
  "function ruleDesc(r){return r[0]?`${r[2]?'Drops to':'Rises to'} ${r[1]} % · ${SNDS[r[3]]} ×${r[4]||1} · ${FLCOL[r[5]]}`:'<span class=\"meta\">Off</span>'}\n"
  "let tankMac='',tsetKey='';\n"
  "function openTank(m){tankMac=m;subSel.tank='ov';nav('tank')}\n"
  "/* while a device is being updated it does not answer setting changes - say so instead of looking stuck */\n"
  "function otaNote(mac){const o=S.ota||{};return o.active&&o.mac===mac?`<div class=\"banner info\"><b>Updating firmware… ${o.pct||0}% — settings and controls work again when it has restarted.</b></div>`:''}\n"
  "function tankDev(){return S.devices.find(x=>x.mac===tankMac)}\n"
  "function tset(idx,v){return cmd(tankMac,10,{idx:idx,f:+v})}\n"
  "function hrs(v){return [...Array(24)].map((_,h)=>`<option value=\"${h}\" ${h==v?'selected':''}>${h12(h)}</option>`).join('')}\n"
  "/* the tank bar in the app looks like the real strip: same number of level LEDs, same colours, yellow when the sensor fails */\n"
  "function ledCol(c,i,n){if(c&&c.palette==2&&c.colors&&c.colors[i])return c.colors[i];if(c&&c.palette==3)return 'hsl('+Math.round((n>1?i/(n-1):1)*240)+',100%,50%)';const t=n>1?i/(n-1):1,r=Math.round(255*(1-t)),v=Math.round(255*t);\n"
  "  return c&&c.palette==1?`rgb(${r},${v},0)`:`rgb(${r},0,${v})`}\n"
  "function tankBar(d,h){const t=d.tank||{},c=t.cfg,n=c?(c.ledCount||7):9,ok=t.sensorOk!==false,lit=ok?Math.round((t.level||0)*n/100):0;\n"
  "  return `<div class=\"tankbar\" style=\"${h?'height:'+h+'px':''}\">${[...Array(n)].map((_,i)=>`<div class=\"seg\" style=\"${!ok?'background:#d9a400;opacity:.85':i<lit?'background:'+ledCol(c,i,n)+segLook(c,i,lit):''}\"></div>`).join('')}</div>`}\n"
  "/* app bar mirrors the strip: colour-matching brightness per LED, current level highlighted (shown a bit stronger so it reads on a phone) */\n"
  "function segLook(c,i,lit){const g=c&&c.gain?c.gain[i]/100:1,hl=c&&c.highlight!=null?c.highlight:10;\n"
  "  return i===lit-1?`;filter:brightness(${(g*(1+hl/50)).toFixed(2)});box-shadow:0 0 ${hl?6:0}px ${ledCol(c,i,lit)}`:`;filter:brightness(${(g*(1-hl/200)).toFixed(2)})`}\n"
  "const SNDS=['Chirp','Short beeps','Long beeps','Triple beep','Siren','LEDs only'],FLCOL=['No flash','Green','Red','Blue','White','Amber'];\n"
  "function opts(list,v){return list.map((x,i)=>`<option value=\"${i}\" ${i==v?'selected':''}>${x}</option>`).join('')}\n"
  "function renderTank(){  const d=tankDev();if(!d){nav('home');return}\n"
  "  const t=d.tank||{},c=t.cfg,ok=t.sensorOk!==false,on=d.online;\n"
  "  $('#tlive').innerHTML=otaNote(d.mac)+`<div class=\"card ${on?'':'offline'}\">\n"
  "    <div class=\"chead\"><span class=\"dot ${on?'on':'off'}\"></span><span class=\"nm\">${esc(d.name)}</span></div>\n"
  "    <div class=\"tank\">${tankBar(d,190)}<div style=\"flex:1;min-width:0\">\n"
  "      <div class=\"big\">${ok?Math.round(t.level||0):'—'}<small>%</small></div>\n"
  "      <div class=\"kv\"><span>Water distance</span><b>${ok?(t.dist||0).toFixed(1)+' cm':'no reading'}</b></div>\n"
  "      <div class=\"kv\"><span>Status</span><b class=\"${t.alert?'err':''}\">${esc(t.stateTxt||'')}</b></div>\n"
  "      ${t.ldr!==undefined?`<div class=\"kv\"><span>Room light</span><b>${esc(S.hub.room||'')} (${t.ldr})</b></div>`:''}\n"
  "      <div class=\"kv\"><span>Signal</span><b>${on?d.rssi+' dBm':'offline'}</b></div>\n"
  "      <div class=\"kv\"><span>Firmware</span><b>${esc(d.fw||'')}</b></div></div></div>\n"
  "    <div class=\"row\"><button class=\"btn ${t.alert?'p':''}\" ${on&&t.alert?'':'disabled'} onclick=\"tankSilence()\">Silence alarm</button>\n"
  "      <button class=\"btn\" ${on?'':'disabled'} onclick=\"tankBeep()\">Beep</button>\n"
  "      <button class=\"btn\" ${on?'':'disabled'} onclick=\"cmd(tankMac,3)\">Identify</button></div></div>`;\n"
  "  // settings form: rebuilt only when the tank reports new values and you are not typing in it\n"
  "  const key=JSON.stringify(c||{})+d.name+JSON.stringify((S.hub||{}).global||{});\n"
  "  if(key===tsetKey||typing('#tset'))return;\n"
  "  tsetKey=key;\n"
  "  if(!c){$('#tset').innerHTML=`<div class=\"card\" style=\"margin-top:12px\"><div class=\"meta\">Waiting for the tank's settings… (tank firmware 1.4 or newer)</div></div>`;return}\n"
  "  const G=(S.hub||{}).global||{quietFrom:c.quietFrom,quietTo:c.quietTo,dayFrom:c.showFrom,dayTo:c.showTo};   // global home settings\n"
  "  $('#tset').innerHTML=`\n"
  "  <div data-tab=\"setup\">\n"
  "  <h3>Tank size (calibration)${q('How the tank turns the sensor distance into a percentage. The sensor sits at the top and measures down to the water: a SHORT distance means a FULL tank, a LONG distance means EMPTY. Fill the tank, wait a minute and press <b>Use now</b> next to Full; do the same for Empty when it is nearly empty. Then press Save.')}</h3>\n"
  "  <div class=\"card\">\n"
  "    <label>Distance when FULL (cm)${q('Distance from the sensor to the water surface when the tank is full. Readings this close or closer show 100 %.')}</label>\n"
  "    <div class=\"row\" style=\"margin:0\"><input id=\"tFull\" type=\"number\" step=\"0.5\" value=\"${c.fullCm.toFixed(1)}\"><button class=\"btn\" style=\"flex:0 0 auto\" onclick=\"useNow('#tFull')\">Use now</button></div>\n"
  "    <label>Distance when EMPTY (cm)${q('Distance from the sensor to the water (or the tank floor) when the tank is empty. Readings this far or farther show 0 %. Must be at least 10 cm more than Full.')}</label>\n"
  "    <div class=\"row\" style=\"margin:0\"><input id=\"tEmpty\" type=\"number\" step=\"0.5\" value=\"${c.emptyCm.toFixed(1)}\"><button class=\"btn\" style=\"flex:0 0 auto\" onclick=\"useNow('#tEmpty')\">Use now</button></div>\n"
  "    <div class=\"row\"><button class=\"btn p\" onclick=\"saveCal()\">Save tank size</button></div>\n"
  "    <div class=\"note\" id=\"calmsg\"></div>\n"
  "  </div>\n"
  "  </div><div data-tab=\"alarms\">\n"
  "  <h3>Alarm rules${q('Each rule watches the water level. When the level RISES TO or DROPS TO its %, the tank plays the chosen sound the chosen number of times and flashes its level LEDs in the chosen colour. A rule fires once, then waits until the level has moved 5 % back before it can fire again. A press on the tank\\'s button or Silence alarm stops it. Rules run on the tank itself, so they work without the hub.')}</h3>\n"
  "  <div class=\"card\">\n"
  "    ${c.rules?c.rules.map((r,i)=>[r,i]).sort((a,b)=>(b[0][0]-a[0][0])||(b[0][1]-a[0][1])).map(([r,i],n)=>`<details class=\"rule\" data-rule=\"${i}\"><summary><span class=\"pill ${r[0]?'':'off'}\">${n+1}</span><span class=\"rd\">${ruleDesc(r)}</span><span class=\"chev\">›</span></summary>\n"
  "      <div class=\"switchrow\" style=\"margin:2px 0 0\"><span>Rule on</span><button class=\"tgl ${r[0]?'on':''}\" data-k=\"on\" onclick=\"this.classList.toggle('on')\"></button></div>\n"
  "      <div class=\"row\" style=\"margin-top:6px\"><select data-k=\"dir\">${opts(['When level rises to','When level drops to'],r[2])}</select><input data-k=\"level\" type=\"number\" min=\"0\" max=\"100\" value=\"${r[1]}\" style=\"flex:0 0 74px\"><span class=\"meta\" style=\"flex:0 0 auto;align-self:center\">%</span></div>\n"
  "      <div class=\"row\" style=\"margin-top:6px\"><select data-k=\"pattern\">${opts(SNDS,r[3])}</select><input data-k=\"repeats\" type=\"number\" min=\"1\" max=\"30\" value=\"${r[4]||1}\" style=\"flex:0 0 64px\" title=\"Times\"><span class=\"meta\" style=\"flex:0 0 auto;align-self:center\">times</span></div>\n"
  "      <div class=\"row\" style=\"margin-top:6px\"><select data-k=\"color\">${opts(FLCOL,r[5])}</select><button class=\"btn\" style=\"flex:0 0 70px\" onclick=\"testRule(${i})\">Test</button><button class=\"btn p\" style=\"flex:0 0 70px\" onclick=\"saveRule(${i})\">Save</button></div><div style=\"height:10px\"></div></details>`).join('')\n"
  "      :'<div class=\"meta\">Alarm rules need tank firmware 1.7 or newer.</div>'}\n"
  "  </div>\n"
  "  <h3>Buzzer</h3>\n"
  "  <div class=\"card\">\n"
  "    <div class=\"switchrow\" style=\"margin-top:0\"><span>Buzzer${q('Turn the beeping off completely. The LEDs still flash for alarms and the app still shows them.')}</span><button class=\"tgl ${c.buzzer?'on':''}\" onclick=\"tankBuzzer(this)\"></button></div>\n"
  "    ${globalNote(`Quiet hours ${h12(G.quietFrom)}–${h12(G.quietTo)} (no sounds)`)}\n"
  "  </div>\n"
  "  </div><div data-tab=\"display\">\n"
  "  <h3>LED display</h3>\n"
  "  <div class=\"card\">\n"
  "    <label>Level colours${q('Colour of the level LEDs from the bottom to the top: red fading to blue, red fading to green, Spectrum (red, orange, yellow, green, cyan, blue), or Custom — pick your own colour for every LED.')}</label>\n"
  "    <div class=\"row\" style=\"margin:0\"><button class=\"btn ${c.palette==0?'p':''}\" onclick=\"tset(8,0)\">Red → Blue</button><button class=\"btn ${c.palette==1?'p':''}\" onclick=\"tset(8,1)\">Red → Green</button><button class=\"btn ${c.palette==3?'p':''}\" onclick=\"tset(8,3)\">Spectrum</button>${c.colors?`<button class=\"btn ${c.palette==2?'p':''}\" onclick=\"tset(8,2)\">Custom</button>`:''}</div>\n"
  "    ${c.palette==2&&c.colors?`<div style=\"margin-top:10px\">${c.colors.slice(0,c.ledCount||7).map((col,i)=>`<div class=\"switchrow\" style=\"margin:4px 0\"><span>LED ${i+1}${i==0?' (bottom)':i==(c.ledCount||7)-1?' (top)':''}</span>\n"
  "      <input type=\"color\" value=\"${col}\" data-led=\"${i}\" data-was=\"${col}\" style=\"flex:0 0 64px;height:34px;padding:2px\"></div>`).reverse().join('')}\n"
  "      <div class=\"row\"><button class=\"btn\" onclick=\"presetColors()\">Preset: Red · greens · Blue</button><button class=\"btn p\" onclick=\"saveColors()\">Save colours</button></div>\n"
  "      <p class=\"note\">LED 1 is the bottom of the strip. Only LEDs that are lit for the current level show their colour.</p></div>`:''}\n"
  "    ${c.gain?`<label>Current level highlight${q('How much the top lit LED (the current water level) stands out from the LEDs below it: 0 % = all equal, 50 % = very clear. Half of it makes the top LED brighter, half makes the others dimmer.')}</label>\n"
  "    <div class=\"row\" style=\"margin:0;align-items:center\"><input type=\"range\" min=\"0\" max=\"50\" value=\"${c.highlight}\" oninput=\"this.nextElementSibling.textContent=this.value+' %'\" onchange=\"tset(21,this.value);this.blur()\"><span class=\"meta\" style=\"flex:0 0 44px;text-align:right\">${c.highlight} %</span></div>`:''}\n"
  "    <label>LEDs used to show the level${q('How many LEDs, counted from the bottom of the strip, show the water level (1 to 8). A full tank lights all of them. The top LED is always the small status light.')}</label>\n"
  "    <div class=\"row\" style=\"margin:0\"><input id=\"tLeds\" type=\"number\" min=\"1\" max=\"8\" value=\"${c.ledCount||7}\"><button class=\"btn\" style=\"flex:0 0 90px\" onclick=\"saveLeds()\">Save</button></div>\n"
  "    <label style=\"margin-top:12px\">Daytime minimum brightness (1–60)${q('During the daytime hours (a global setting) the level LEDs never go fully dark: they stay at least this bright, even in a dark room. 1 is barely visible, 60 is clearly visible.')}</label>\n"
  "    <div class=\"row\" style=\"margin:0\"><input id=\"tMb\" type=\"number\" min=\"1\" max=\"60\" value=\"${c.minBright||6}\"><button class=\"btn\" style=\"flex:0 0 90px\" onclick=\"saveShow()\">Save</button></div>\n"
  "    ${globalNote(`Daytime hours ${h12(G.dayFrom)}–${h12(G.dayTo)}`)}\n"
  "  </div>\n"
  "  </div><div data-tab=\"setup\">\n"
  "  <h3>Status labels</h3>\n"
  "  <div class=\"card\">\n"
  "    <label style=\"margin-top:0\">Show \"Full\" at / \"Low\" at (%)${q('Only for the status text: the tank is shown as \"Full\" at or above the first value and \"Low\" at or below the second. Alarms come from the rules above.')}</label>\n"
  "    <div class=\"row\" style=\"margin:0\"><div><input id=\"tFp\" type=\"number\" min=\"20\" max=\"100\" value=\"${c.fullPct}\" title=\"Full at %\"></div><div><input id=\"tLp\" type=\"number\" min=\"0\" max=\"80\" value=\"${c.lowPct}\" title=\"Low at %\"></div><button class=\"btn\" style=\"flex:0 0 90px\" onclick=\"saveAlarms()\">Save</button></div>\n"
  "    <div class=\"note\" id=\"almsg\"></div>\n"
  "  </div>\n"
  "  <h3>Device</h3>\n"
  "  <div class=\"card\">\n"
  "    <label>Name${q('The name shown in the app and in the Activity log.')}</label>\n"
  "    <div class=\"row\" style=\"margin:0\"><input id=\"tName\" value=\"${esc(d.name)}\"><button class=\"btn\" style=\"flex:0 0 90px\" onclick=\"tankRename()\">Save</button></div>\n"
  "    <div class=\"row\"><button class=\"btn\" onclick=\"if(confirm('Restart the tank monitor?'))cmd(tankMac,6)\">Restart</button><button class=\"btn\" onclick=\"nav('devices')\">Update firmware…</button></div>\n"
  "    <div class=\"row\"><button class=\"btn d\" onclick=\"forget(tankMac)\">Remove device…</button></div>\n"
  "  </div></div>`;\n"
  "  applySub('tank');\n"
  "}\n"
  "function useNow(sel){const t=(tankDev()||{}).tank||{};if(t.sensorOk===false){toast('No sensor reading right now');return}$(sel).value=(t.dist||0).toFixed(1)}\n"
  "async function saveCal(){const d=tankDev(),c=d.tank.cfg,f=+$('#tFull').value,e=+$('#tEmpty').value,m=$('#calmsg');\n"
  "  if(!(f>=2&&e<=400&&e-f>=10)){m.textContent='Full must be at least 10 cm less than empty (and empty at most 400 cm).';return}\n"
  "  m.textContent='Saving…';\n"
  "  // send in an order the tank accepts (it always keeps full < empty - 10)\n"
  "  const ok=e>c.emptyCm?(await tset(2,e)&&await tset(1,f)):(await tset(1,f)&&await tset(2,e));\n"
  "  m.textContent=ok?'Sent — the tank confirms by showing the new values.':'Could not reach the hub.'}\n"
  "function ruleVals(i){const b=$(`[data-rule=\"${i}\"]`),g=k=>b.querySelector(`[data-k=\"${k}\"]`);\n"
  "  return {on:g('on').classList.contains('on'),dir:+g('dir').value,level:Math.round(+g('level').value),pattern:+g('pattern').value,repeats:Math.round(+g('repeats').value),color:+g('color').value}}\n"
  "async function saveRule(i){const v=ruleVals(i);if(!(v.level>=0&&v.level<=100)){toast('Level must be 0–100 %');return}if(!(v.repeats>=1&&v.repeats<=30)){toast('Times must be 1–30');return}\n"
  "  if(await post('/api/tankrule',Object.assign({mac:tankMac,idx:i},v)))toast('Rule '+(i+1)+' sent')}\n"
  "async function testRule(i){const v=ruleVals(i);if(await cmd(tankMac,12,{idx:v.pattern+1,val:v.color}))toast('Playing '+SNDS[v.pattern])}\n"
  "async function saveAlarms(){const d=tankDev(),c=d.tank.cfg,fp=Math.round(+$('#tFp').value),lp=Math.round(+$('#tLp').value),m=$('#almsg');\n"
  "  if(!(fp<=100&&lp>=0&&fp-lp>10)){m.textContent='\"Full\" must be more than 10 % above \"Low\".';return}\n"
  "  m.textContent='Saving…';\n"
  "  const ok=fp>c.fullPct?(await tset(3,fp)&&await tset(4,lp)):(await tset(4,lp)&&await tset(3,fp));\n"
  "  m.textContent=ok?'Sent — the tank confirms by showing the new values.':'Could not reach the hub.'}\n"
  "/* preset: bottom LED red (low), top LED blue (high), the ones between fade amber -> greens (fills the pickers; press Save) */\n"
  "function presetColors(){const els=[...document.querySelectorAll('#tset input[data-led]')].sort((a,b)=>a.dataset.led-b.dataset.led),n=els.length;\n"
  "  const stops=[[212,167,44],[150,190,60],[85,150,45],[110,220,120]],mix=(a,b,f)=>a.map((x,k)=>Math.round(x+(b[k]-x)*f)),hex=c=>'#'+c.map(x=>x.toString(16).padStart(2,'0')).join('');\n"
  "  els.forEach((el,i)=>{let c;if(i===0)c=[229,57,53];else if(i===n-1&&n>1)c=[47,59,255];else{const f=n>3?(i-1)/(n-3):0,p=f*(stops.length-1),k=Math.min(Math.floor(p),stops.length-2);c=mix(stops[k],stops[k+1],p-k)}el.value=hex(c)});\n"
  "  toast('Preset filled in — press Save colours')}\n"
  "async function saveColors(){let n=0;for(const el of document.querySelectorAll('#tset input[data-led]')){if(el.value===el.dataset.was)continue;\n"
  "    if(!await tset(13+(+el.dataset.led),parseInt(el.value.slice(1),16)))return toast('Could not reach the hub');n++}\n"
  "  toast(n?n+' colour'+(n>1?'s':'')+' sent':'Nothing changed')}\n"
  "async function saveLeds(){const n=Math.round(+$('#tLeds').value);if(!(n>=1&&n<=8)){toast('Choose 1 to 8 LEDs');return}if(await tset(9,n))toast('Sent')}\n"
  "async function saveShow(){const b=Math.round(+$('#tMb').value);if(!(b>=1&&b<=60)){toast('Brightness must be 1 to 60');return}\n"
  "  if(await tset(12,b))toast('Minimum brightness sent')}\n"
  "async function tankBuzzer(el){const on=!el.classList.contains('on');el.classList.toggle('on',on);if(!await tset(5,on?1:0))el.classList.toggle('on',!on)}\n"
  "async function tankSilence(){if(await cmd(tankMac,11))toast('Alarm silenced')}\n"
  "async function tankBeep(){if(await cmd(tankMac,12))toast('Beep!')}\n"
  "async function tankRename(){const n=$('#tName').value.trim();if(!n)return;if(await cmd(tankMac,4,{text:n}))toast('Name saved')}\n"
  "\n"
  "/* tap a home card (but not its buttons) to open the device page */\n"
  "function cardOpen(ev,kind,mac){if(ev.target.closest('button'))return;if(kind==='tank')openTank(mac);else openSw(mac)}\n"
  "\n"
  "/* switch detail page */\n"
  "let swMac='',swKey='';\n"
  "function openSw(m){swMac=m;subSel.sw='ov';nav('sw')}\n"
  "function swDev(){return S.devices.find(x=>x.mac===swMac)}\n"
  "function renderSw(){\n"
  "  const d=swDev();if(!d){nav('home');return}\n"
  "  const on=d.online,rl=d.relays||[];\n"
  "  $('#swlive').innerHTML=otaNote(d.mac)+`<div class=\"card ${on?'':'offline'}\">\n"
  "    <div class=\"chead\"><span class=\"dot ${on?'on':'off'}\"></span><span class=\"nm\">${esc(d.name)}</span><span class=\"w\">${totalW(d).toFixed(0)} W</span></div>\n"
  "    ${rl.map((r,i)=>`<div class=\"rel\"><div class=\"n\"><b>${esc(r.name)}${r.used===false?' <span class=\"meta\">(not in use)</span>':''}</b><span class=\"meta\">${r.on?('On · '+r.watts+' W'+(r.onSecs?' · '+up(r.onSecs):'')):'Off'}</span></div>\n"
  "      <button class=\"tgl ${r.on?'on':''}\" ${on?'':'disabled'} onclick=\"tog(this,'${d.mac}',${i},${!r.on})\"></button></div>`).join('')||'<div class=\"meta\">Waiting for relay info…</div>'}\n"
  "    <div class=\"row\"><button class=\"btn\" ${on?'':'disabled'} onclick=\"cmd(swMac,2,{val:1})\">All on</button><button class=\"btn\" ${on?'':'disabled'} onclick=\"cmd(swMac,2,{val:0})\">All off</button></div>\n"
  "    <div class=\"kv\" style=\"margin-top:8px\"><span>Signal</span><b>${on?d.rssi+' dBm':'offline'}</b></div>\n"
  "    <div class=\"kv\"><span>Up</span><b>${up(d.uptime||0)}</b></div>\n"
  "    <div class=\"kv\"><span>Firmware</span><b>${esc(d.fw||'')}</b></div></div>`;\n"
  "  const key=JSON.stringify(rl.map(r=>[r.name,r.watts,r.used,r.gpio]))+d.touch+d.name+JSON.stringify((S.hub||{}).global||{});\n"
  "  if(key===swKey||typing('#swset'))return;\n"
  "  swKey=key;\n"
  "  $('#swset').innerHTML=`\n"
  "  <div data-tab=\"relays\">\n"
  "  <h3>Relays${q('Each relay is one output of the switch. Give it the name of what it powers and its watts (used for the power total on Home).')}</h3>\n"
  "  <div class=\"card\">\n"
  "    ${rl.map((r,i)=>`<div style=\"padding:8px 0;border-bottom:1px dashed #1e2731\">\n"
  "      <div class=\"switchrow\" style=\"margin:0\"><span><b>Relay ${i+1}</b> <span class=\"meta\">GPIO ${r.gpio}</span></span><span class=\"meta\" style=\"flex:0 0 auto\">In use${q('Switch this off for a relay with nothing connected: it is hidden on the Home page and skipped by All on. You can still switch it here.')}</span>\n"
  "        <button class=\"tgl ${r.used===false?'':'on'}\" onclick=\"relUse(this,${i})\"></button></div>\n"
  "      <div class=\"row\" style=\"margin-top:6px\"><input value=\"${esc(r.name)}\" data-r=\"${i}n\" placeholder=\"Name\"><input type=\"number\" value=\"${r.watts}\" style=\"flex:0 0 80px\" data-r=\"${i}w\" title=\"Watts\">\n"
  "        <button class=\"btn\" style=\"flex:0 0 64px\" onclick=\"relMeta(swMac,${i},this).then(()=>toast('Saved'))\">Save</button></div></div>`).join('')}\n"
  "  </div>\n"
  "  </div><div data-tab=\"setup\">\n"
  "  ${d.touch!==undefined?`<h3>Touch buttons${q('Touch pads wired to GPIO 4–7 of the switch. When on, touching pad 1–4 toggles relay 1–4 directly on the switch, even if the hub is off. Leave off until the pads are connected.')}</h3><div class=\"card\"><div class=\"switchrow\" style=\"margin:0\"><span>Touch pads on the switch</span>\n"
  "    <button class=\"tgl ${d.touch?'on':''}\" onclick=\"cmd(swMac,9,{val:${d.touch?0:1}})\"></button></div></div>`:''}\n"
  "  <h3>Device</h3>\n"
  "  <div class=\"card\">\n"
  "    <label>Name${q('The name shown in the app and in the Activity log.')}</label>\n"
  "    <div class=\"row\" style=\"margin:0\"><input id=\"swName\" value=\"${esc(d.name)}\"><button class=\"btn\" style=\"flex:0 0 90px\" onclick=\"swRename()\">Save</button></div>\n"
  "    <div class=\"row\"><button class=\"btn\" onclick=\"cmd(swMac,3)\">Identify</button><button class=\"btn\" onclick=\"if(confirm('Restart the switch? All relays turn OFF.'))cmd(swMac,6)\">Restart</button></div>\n"
  "    <div class=\"row\"><button class=\"btn\" onclick=\"nav('devices')\">Update firmware…</button><button class=\"btn d\" onclick=\"forget(swMac)\">Remove device…</button></div>\n"
  "    <p class=\"note\">Identify flashes the switch's LED so you can find it. Restart turns every relay off.</p>\n"
  "    ${(S.hub||{}).global?globalNote(`Status light brightness ${S.hub.global.ledDay} (bright room) / ${S.hub.global.ledNight} (dark room)`):''}\n"
  "  </div></div>`;\n"
  "  applySub('sw');\n"
  "}\n"
  "async function relUse(el,i){const u=!el.classList.contains('on');el.classList.toggle('on',u);if(!await post('/api/relayuse',{mac:swMac,idx:i,used:u}))el.classList.toggle('on',!u)}\n"
  "async function swRename(){const n=$('#swName').value.trim();if(!n)return;if(await cmd(swMac,4,{text:n}))toast('Name saved')}\n"
  "\n"
  "/* 24 h trend chart (one point per 5 minutes, gaps where the device was offline) */\n"
  "let chartTimer=null;\n"
  "function pageExtras(kind){\n"
  "  const mac=kind==='tank'?tankMac:swMac,box=kind==='tank'?'#tchart':'#swchart',det=kind==='tank'?'#tadvd':'#swadvd';\n"
  "  const go=()=>{if(page===kind)loadChart(mac,box,kind==='tank'?'%':'W')};\n"
  "  go();clearInterval(chartTimer);chartTimer=setInterval(go,20000);\n"
  "  const d=$(det);if(d)d.open=false;\n"
  "}\n"
  "function h12(h){h=+h;return (h%12||12)+' '+(h<12?'AM':'PM')}\n"
  "function hm(t,s){const h=t.getHours();return (h%12||12)+':'+String(t.getMinutes()).padStart(2,'0')+(s?':'+String(t.getSeconds()).padStart(2,'0'):'')+' '+(h<12?'AM':'PM')}\n"
  "let chartRange='day';\n"
  "function setRange(r){chartRange=r;pageExtras(page)}\n"
  "function hms(t){return hm(t,1)}\n"
  "async function loadChart(mac,box,unit){\n"
  "  const el=$(box);if(!el)return;\n"
  "  const week=chartRange==='yday'||chartRange==='week',fineR=chartRange==='h1',mq='/api/history?mac='+encodeURIComponent(mac);\n"
  "  const [h,h5]=await Promise.all([jget(mq+(week?'&range=week':fineR?'&range=fine':'')),fineR?jget(mq):null]);\n"
  "  const btns=`<div class=\"row\" style=\"margin:0 0 8px;gap:6px\">${[['h1','1 h'],['h6','6 h'],['day','24 h'],['yday','Yesterday'],['week','7 days']].map(([k,l])=>`<button class=\"btn ${chartRange===k?'p':''}\" style=\"padding:6px\" onclick=\"setRange('${k}')\">${l}</button>`).join('')}</div>`;\n"
  "  if(!h||!h.end){el.innerHTML=btns+'<div class=\"meta\">No history yet — the hub records a reading every 10 s (1 h), every 5 minutes (24 h) and every hour (7 days).</div>';return}\n"
  "  const sc=x=>x==null?null:(unit==='%'?x/10:x);\n"
  "  const step=h.step*1000,endMs=h.end*1000;let v=h.v.map(sc),t0=endMs-(v.length-1)*step;\n"
  "  // 1 h: where 10-second readings are missing (e.g. after a hub restart), fill in from the 5-minute values\n"
  "  if(fineR&&h5&&h5.end){const s5=h5.step*1000,e5=h5.end*1000,v5=h5.v.map(sc);\n"
  "    v=v.map((x,i)=>{if(x!=null)return x;const k=v5.length-1-Math.floor((e5+s5-1-(t0+i*step))/s5);return k>=0&&k<v5.length?v5[k]:null})}\n"
  "  if(chartRange==='yday'){const d=new Date();d.setHours(0,0,0,0);const a=d.getTime()-864e5,b=d.getTime();\n"
  "    const out=[];for(let i=0;i<v.length;i++){const ts=t0+i*step;if(ts>=a&&ts<b)out.push(v[i])}\n"
  "    if(!out.length||out.every(x=>x==null)){el.innerHTML=btns+'<div class=\"meta\">No readings for yesterday yet — the history only goes back to '+hm(new Date(t0+Math.max(0,h.v.findIndex(x=>x!=null))*step))+' today.</div>';return}\n"
  "    v=out;t0=a;while(v.length<24)v.push(null)}\n"
  "  if(chartRange==='h6'){v=v.slice(-72);t0=endMs-(v.length-1)*step}\n"
  "  if(!week){const dv=S.devices.find(x=>x.mac===mac);if(dv&&dv.online){const live=unit==='%'?((dv.tank||{}).sensorOk!==false?(dv.tank||{}).level:null):totalW(dv);if(live!=null)v[v.length-1]=live}}   // last point = live value\n"
  "  // start where the data starts, so a young history fills the chart instead of hugging the right edge\n"
  "  let note='';const first=v.findIndex(x=>x!=null);\n"
  "  if(first>0&&chartRange!=='yday'){v=v.slice(first);t0+=first*step;note=' · history starts '+(week?new Date(t0).toLocaleDateString([], {weekday:'short'})+' ':'')+hm(new Date(t0))}\n"
  "  const pts=v.filter(x=>x!=null),n=v.length;\n"
  "  if(!pts.length){el.innerHTML=btns+'<div class=\"meta\">No readings for this period yet.</div>';return}\n"
  "  // y-axis: water level always 0-100 %; power always 0 to the switch's total watts\n"
  "  // power: 0 to the total watts of the relays in use, the same on every range (stretches only if a reading is higher)\n"
  "  const dvc=S.devices.find(x=>x.mac===mac)||{},capW=(dvc.relays||[]).filter(r=>r.used!==false).reduce((a,r)=>a+(+r.watts||0),0);\n"
  "  let lo=0,hi=unit==='%'?100:Math.max(capW||10,...pts);\n"
  "  const W=320,H=140,pl=34,pr=8,pt=8,pb=18;\n"
  "  const X=i=>pl+(W-pl-pr)*i/Math.max(1,n-1),Y=y=>pt+(H-pt-pb)*(1-(y-lo)/(hi-lo||1));\n"
  "  let path='',dots='',pen=false;v.forEach((y,i)=>{if(y==null){pen=false;return}path+=(pen?'L':'M')+X(i).toFixed(1)+' '+Y(y).toFixed(1)+' ';pen=true;\n"
  "    if((i===0||v[i-1]==null)&&(i===n-1||v[i+1]==null))dots+=`<circle cx=\"${X(i).toFixed(1)}\" cy=\"${Y(y).toFixed(1)}\" r=\"2.2\"/>`});   // lone readings get a dot\n"
  "  const dec=(hi-lo)<10?1:0,fmt=x=>x.toFixed(dec);\n"
  "  let g='';[0,.5,1].forEach(f=>{const val=lo+(hi-lo)*f,y=Y(val);g+=`<line x1=\"${pl}\" x2=\"${W-pr}\" y1=\"${y}\" y2=\"${y}\" stroke=\"#25303a\"/><text x=\"${pl-4}\" y=\"${y+3}\" fill=\"#7d8b97\" font-size=\"9\" text-anchor=\"end\">${fmt(val)}</text>`});\n"
  "  const lbl=(i,txt,anc)=>`<text x=\"${X(i)}\" y=\"${H-4}\" fill=\"#7d8b97\" font-size=\"9\" text-anchor=\"${anc||'middle'}\">${txt}</text>`;\n"
  "  if(chartRange==='yday')[0,6,12,18].forEach(hh=>{g+=lbl(hh,h12(hh),hh?'middle':'start')});\n"
  "  else{const parts=n>8?4:Math.max(1,n-1);for(let k=parts;k>=0;k--){const i=Math.round((n-1)*(parts-k)/parts),t=new Date(t0+i*step);\n"
  "    g+=lbl(i,!k&&!week?'now':(chartRange==='week'?t.toLocaleDateString([], {weekday:'short'})+' '+hm(t):hm(t)),k===parts?'start':k?'middle':'end')}}\n"
  "  const last=pts[pts.length-1],col=unit==='%'?'var(--water)':'var(--warn)',hrsPer=h.step/3600,u=unit==='%'?' %':' W';\n"
  "  const foot=unit==='%'?`${!week?'Now '+last.toFixed(1)+' % · ':''}lowest ${Math.min(...pts).toFixed(1)} % · highest ${Math.max(...pts).toFixed(1)} %`\n"
  "    :`${!week?'Now '+Math.round(last)+' W · ':''}energy ${(v.reduce((a,x)=>a+(x||0),0)*hrsPer/1000).toFixed(3)} kWh · peak ${Math.round(Math.max(...pts))} W`;\n"
  "  const res=(fineR?'every 10 s':week?'hourly averages':'5-minute averages')+note;\n"
  "  el.innerHTML=btns+`<svg viewBox=\"0 0 ${W} ${H}\" width=\"100%\" style=\"display:block;touch-action:pan-y\">${g}<path d=\"${path}\" fill=\"none\" stroke=\"${col}\" stroke-width=\"1.8\" stroke-linejoin=\"round\" stroke-linecap=\"round\"/><g fill=\"${col}\">${dots}</g>\n"
  "    <line class=\"cx\" y1=\"${pt}\" y2=\"${H-pb}\" stroke=\"#7d8b97\" stroke-dasharray=\"2 2\" visibility=\"hidden\"/><circle class=\"cd\" r=\"3\" fill=\"${col}\" visibility=\"hidden\"/></svg>\n"
  "    <div class=\"meta\" data-k=\"tip\" style=\"min-height:15px;margin-top:2px;color:var(--txt)\">Tap or hover the chart for exact values · ${res}</div>\n"
  "    <div class=\"meta\" style=\"margin-top:2px\">${foot}${q(unit==='%'?'Water level: a reading every 10 s for 1 h, 5-minute averages for 6 h and 24 h, hourly averages for Yesterday and 7 days. The chart starts where the history starts. The scale is always 0-100 %. Gaps mean the tank was offline or had no sensor reading.':'Power from the watts you set for each relay, on a fixed scale up to the total watts of the relays in use: every 10 s for 1 h, 5-minute averages for 6 h and 24 h, hourly averages for Yesterday and 7 days. Energy is an estimate, not a meter reading.')}</div>`;\n"
  "  // tap / hover: exact value and time at that point\n"
  "  const svg=el.querySelector('svg'),cx=svg.querySelector('.cx'),cd=svg.querySelector('.cd'),tip=el.querySelector('[data-k=tip]');\n"
  "  const show=e=>{const r=svg.getBoundingClientRect(),x=(e.clientX-r.left)*W/r.width;let i=Math.round((x-pl)/((W-pl-pr)/Math.max(1,n-1)));i=Math.max(0,Math.min(n-1,i));\n"
  "    let j=i;for(let d=0;d<n&&v[j]==null;d++){if(i+d<n&&v[i+d]!=null){j=i+d;break}if(i-d>=0&&v[i-d]!=null){j=i-d;break}}\n"
  "    if(v[j]==null)return;const t=new Date(t0+j*step);\n"
  "    cx.setAttribute('x1',X(j));cx.setAttribute('x2',X(j));cx.setAttribute('visibility','visible');cd.setAttribute('cx',X(j));cd.setAttribute('cy',Y(v[j]));cd.setAttribute('visibility','visible');\n"
  "    tip.textContent=(week?t.toLocaleDateString([], {weekday:'short',day:'numeric'})+' '+hm(t):fineR?hms(t):hm(t))+' · '+(unit==='%'?v[j].toFixed(1):Math.round(v[j]))+u+(j===n-1&&!week?' (now)':'')};\n"
  "  svg.addEventListener('pointermove',show);svg.addEventListener('pointerdown',show);\n"
  "}\n"
  "\n"
  "/* Advanced: chip details + factory reset */\n"
  "const RST=['unknown','power on','reset pin','software restart','crash','interrupt watchdog','task watchdog','watchdog','deep sleep','brownout (low power)','SDIO','USB','JTAG','eFuse','power glitch','CPU lockup'];\n"
  "function fmtB(b){return b>=1048576?(b/1048576).toFixed(2)+' MB':Math.round(b/1024)+' KB'}\n"
  "function advRows(a){const r=[];\n"
  "  if(a.temp!==undefined)r.push(['Chip temperature',a.temp.toFixed(1)+' °C','The processor\\'s own sensor; it runs warmer than the room. Above ~80 °C is too hot.']);\n"
  "  if(a.heap!==undefined)r.push(['Free memory',fmtB(a.heap)+' (lowest '+fmtB(a.heapMin)+')','Working memory (RAM) left. If the lowest value gets very small (under ~20 KB) the device may restart.']);\n"
  "  if(a.fsTotal)r.push(['Storage used',fmtB(a.fsUsed)+' of '+fmtB(a.fsTotal),'Space for saved files (settings, logs, history).']);\n"
  "  if(a.sketch)r.push(['Firmware size',fmtB(a.sketch)+' of '+fmtB(a.sketchMax),'Size of the program; it must fit in the update space for wireless updates to work.']);\n"
  "  if(a.flash)r.push(['Flash chip',fmtB(a.flash),'Total flash memory on the board.']);\n"
  "  if(a.psram)r.push(['PSRAM',fmtB(a.psram),'Extra memory chip on the board.']);\n"
  "  if(a.cpu)r.push(['CPU speed',a.cpu+' MHz','']);\n"
  "  if(a.reset!==undefined)r.push(['Last restart cause',RST[a.reset]||a.reset,'Why the chip last started. \"brownout\" means the power supply dipped; \"crash\" or \"watchdog\" means the program had a problem.']);\n"
  "  if(a.uptime!==undefined)r.push(['Running for',up(a.uptime),'']);\n"
  "  if(a.rssi!==undefined)r.push(['Signal',a.rssi+' dBm','Radio signal strength: -50 excellent, -70 good, -85 weak, below -90 unreliable.']);\n"
  "  if(a.channel)r.push(['WiFi channel',a.channel,'The router\\'s channel. All LEO devices follow it automatically.']);\n"
  "  if(a.mac)r.push(['MAC address',a.mac,'']);if(a.ip)r.push(['IP address',a.ip,'']);\n"
  "  if(a.fw)r.push(['Firmware',a.fw,'']);if(a.sdk)r.push(['ESP-IDF',a.sdk,'Version of Espressif\\'s system software inside the firmware.']);\n"
  "  return r.map(([k,v,h])=>`<div class=\"kv\"><span>${k}${h?q(h):''}</span><b>${esc(v)}</b></div>`).join('')}\n"
  "async function loadAdv(mac,box){const el=$(box);el.innerHTML='Loading…';\n"
  "  const a=await jget('/api/diag?mac='+encodeURIComponent(mac));if(!a){el.textContent='Not available.';return}\n"
  "  el.innerHTML=(a.known?advRows(a):'<div class=\"meta\">Chip details arrive within a minute (device firmware: switch 2.6 / tank 1.6 or newer).</div>')+\n"
  "    `<div class=\"row\" style=\"margin-top:14px\"><button class=\"btn d\" onclick=\"devFactory('${a.mac}')\">Factory reset this device…</button></div>\n"
  "     <p class=\"note\">Erases this device's settings and pairing, removes it from the hub and restarts it. Pair it again with Devices → Allow new devices. Also possible by holding the board's <b>BOOT</b> button for 15 seconds — from 2 s the light blinks red, faster and brighter the longer you hold; solid red = accepted; let go before 15 s to cancel.</p>`}\n"
  "async function devFactory(mac){const d=S.devices.find(x=>x.mac===mac);if(!d)return;\n"
  "  if(!confirm('Factory reset \"'+d.name+'\"? All its settings are erased and it must be paired again.'))return;\n"
  "  if(!confirm('Really erase \"'+d.name+'\"?'))return;\n"
  "  if(await cmd(mac,13)){toast('Factory reset sent');nav('home')}}\n"
  "async function loadHubAdv(){const a=await jget('/api/hub');$('#hubadv').innerHTML=a?advRows(a):'Not available.'}\n"
  "async function hubFactory(){if(!confirm('Factory reset the HUB? WiFi, password, all devices, names and logs are erased.'))return;\n"
  "  if(prompt('Type RESET to confirm')!=='RESET')return;\n"
  "  if(await post('/api/factory',{confirm:'RESET'}))alert('The hub is resetting. Join the WiFi hotspot \"LEO-Hub-…\" (no password), then open http://192.168.4.1 to set it up again.')}\n"
  "async function clearActivity(){if(!confirm('Delete the whole activity log?'))return;if(await post('/api/clearactivity'))loadActivity()}\n"
  "async function clearConsole(){if(await post('/api/clearconsole'))$('#log').textContent=''}\n"
  "\n"
  "/* Hub -> Home settings: GLOBAL settings that apply to every device (each device keeps the last values it got) */\n"
  "let homeKey='';\n"
  "function renderHomeSet(){const box=$('#homeset'),g=(S.hub||{}).global;if(!box||!g)return;\n"
  "  const key=JSON.stringify(g);if(key===homeKey||typing('#homeset'))return;homeKey=key;\n"
  "  const tk=S.devices.find(d=>d.type==='tank'),ldr=tk&&tk.tank&&tk.tank.ldr!==undefined?tk.tank.ldr:null;\n"
  "  box.innerHTML=`<p class=\"note\" style=\"margin-top:0\">These apply to <b>every</b> LEO device. Settings that depend on a device's hardware (tank size, alarm rules, colours, relays…) are on that device's page.</p>\n"
  "    <label>Quiet hours — no sounds${q('No device makes a sound between these times (the tank\\'s alarm buzzer, for example). Sounds are also off whenever the room is dark. Set both the same for no quiet hours. Lights still show alarms.')}</label>\n"
  "    <div class=\"row\" style=\"margin:0\"><select id=\"gQf\">${hrs(g.quietFrom)}</select><select id=\"gQt\">${hrs(g.quietTo)}</select></div>\n"
  "    <label>Daytime hours${q('The daytime part of the day for every device: the tank keeps its level LEDs on (dimly) during these hours even in a dark room, and when no room light reading is available the status lights use these hours to decide between day and night brightness.')}</label>\n"
  "    <div class=\"row\" style=\"margin:0\"><select id=\"gDf\">${hrs(g.dayFrom)}</select><select id=\"gDt\">${hrs(g.dayTo)}</select></div>\n"
  "    <label>Status light brightness — bright room / dark room (1–40)${q('Peak brightness of the small breathing status light on every device (hub, switch, tank), out of 255. Keep these low so the lights are barely noticeable.')}</label>\n"
  "    <div class=\"row\" style=\"margin:0\"><input id=\"gLd\" type=\"number\" min=\"1\" max=\"40\" value=\"${g.ledDay}\"><input id=\"gLn\" type=\"number\" min=\"1\" max=\"40\" value=\"${g.ledNight}\"></div>\n"
  "    <label>Room light — bright above / dark below${q('The tank\\'s light sensor is the room light sensor for every device. Above the first value the room counts as BRIGHT, below the second it counts as DARK again (the gap stops flicker at dusk). Higher numbers = more light needed.'+(ldr!=null?' The sensor reads <b>'+ldr+'</b> right now.':''))}</label>\n"
  "    <div class=\"row\" style=\"margin:0\"><input id=\"gLon\" type=\"number\" min=\"10\" max=\"4000\" value=\"${g.litOn}\"><input id=\"gLoff\" type=\"number\" min=\"5\" max=\"3999\" value=\"${g.litOff}\"></div>\n"
  "    ${ldr!=null?`<p class=\"note\">Room light now: <b>${ldr}</b> → ${esc(S.hub.room||'')}</p>`:''}\n"
  "    <div class=\"row\"><button class=\"btn p\" onclick=\"saveHomeSet()\">Save home settings</button></div><div class=\"note\" id=\"homemsg\"></div>`}\n"
  "async function saveHomeSet(){const v=id=>Math.round(+$(id).value),b={quietFrom:+$('#gQf').value,quietTo:+$('#gQt').value,dayFrom:+$('#gDf').value,dayTo:+$('#gDt').value,\n"
  "    ledDay:v('#gLd'),ledNight:v('#gLn'),litOn:v('#gLon'),litOff:v('#gLoff')},m=$('#homemsg');\n"
  "  if(!(b.ledDay>=1&&b.ledDay<=40&&b.ledNight>=1&&b.ledNight<=40)){m.textContent='Status light brightness must be 1–40.';return}\n"
  "  if(!(b.litOff>=5&&b.litOn<=4000&&b.litOff<b.litOn)){m.textContent='\"Bright above\" must be higher than \"dark below\".';return}\n"
  "  m.textContent=await post('/api/global',b)?'Saved — every device follows within a few seconds.':'Could not save.'}\n"
  "/* read-only line for a device page: a global value, with where to change it */\n"
  "function globalNote(txt){return `<p class=\"note\">${txt} — <a href=\"#\" onclick=\"nav('hub');return false\" style=\"color:var(--acc)\">change in Hub → Home settings</a> (applies to every device)</p>`}\n"
  "</script>\n"
  "</body>\n"
  "</html>\n"
  "\n";

void webBegin() {
  ws.handleHandshake([](AsyncWebServerRequest* r) { return authOk(r); });
  ws.onEvent([](AsyncWebSocket*, AsyncWebSocketClient* c, AwsEventType t, void*, uint8_t*, size_t) {
    if (t == WS_EVT_CONNECT) c->text(stateJson());
  });
  server.addHandler(&ws);
  consoleWs.handleHandshake([](AsyncWebServerRequest* r) { return authOk(r); });
  consoleWs.onEvent([](AsyncWebSocket*, AsyncWebSocketClient* c, AwsEventType t, void*, uint8_t*, size_t) {
    if (t == WS_EVT_CONNECT) { String h = consoleHistory(); if (h.length()) c->text(h); }
  });
  server.addHandler(&consoleWs);

  auto sendIndex = [](AsyncWebServerRequest* r) {         // cached by the browser until the firmware changes
    const char* etag = "\"leo-" HUB_FW "\"";
    if (r->hasHeader("If-None-Match") && r->header("If-None-Match") == etag) { r->send(304); return; }
    AsyncWebServerResponse* res = r->beginResponse(200, "text/html", (const uint8_t*)INDEX_HTML, strlen_P(INDEX_HTML));
    res->addHeader("ETag", etag); res->addHeader("Cache-Control", "no-cache");
    r->send(res);
  };
  server.on("/", HTTP_GET, sendIndex);
  server.on("/index.html", HTTP_GET, sendIndex);
  server.on("/manifest.json", HTTP_GET, [](AsyncWebServerRequest* r) {
    r->send(200, "application/manifest+json",
      "{\"id\":\"/\",\"name\":\"LEO Home Hub\",\"short_name\":\"LEO Home\",\"description\":\"Control your LEO switch and water tank\","
      "\"start_url\":\"/\",\"scope\":\"/\",\"display\":\"standalone\",\"orientation\":\"portrait\","
      "\"background_color\":\"#0c0f12\",\"theme_color\":\"#0c0f12\",\"icons\":["
      "{\"src\":\"/icon-192.png\",\"sizes\":\"192x192\",\"type\":\"image/png\",\"purpose\":\"any\"},"
      "{\"src\":\"/icon-512.png\",\"sizes\":\"512x512\",\"type\":\"image/png\",\"purpose\":\"any\"},"
      "{\"src\":\"/icon-512.png\",\"sizes\":\"512x512\",\"type\":\"image/png\",\"purpose\":\"maskable\"},"
      "{\"src\":\"/icon.svg\",\"sizes\":\"any\",\"type\":\"image/svg+xml\"}]}");
  });
  auto sendPng = [](AsyncWebServerRequest* r, const uint8_t* d, size_t n) {
    AsyncWebServerResponse* res = r->beginResponse(200, "image/png", d, n);
    res->addHeader("Cache-Control", "max-age=604800"); r->send(res);
  };
  server.on("/icon-192.png", HTTP_GET, [sendPng](AsyncWebServerRequest* r) { sendPng(r, ICON_192_PNG, sizeof(ICON_192_PNG)); });
  server.on("/icon-512.png", HTTP_GET, [sendPng](AsyncWebServerRequest* r) { sendPng(r, ICON_512_PNG, sizeof(ICON_512_PNG)); });
  /* service worker: lets Chrome install the web app (needs a secure origin - on a LAN that means the
     "insecure origins treated as secure" flag). It only passes requests through; when the hub can't be
     reached it shows a short offline note instead of a browser error. */
  server.on("/sw.js", HTTP_GET, [](AsyncWebServerRequest* r) {
    AsyncWebServerResponse* res = r->beginResponse(200, "application/javascript",
      "self.addEventListener('install',e=>self.skipWaiting());"
      "self.addEventListener('activate',e=>e.waitUntil(self.clients.claim()));"
      "self.addEventListener('fetch',e=>{if(e.request.mode!=='navigate')return;"
      "e.respondWith(fetch(e.request).catch(()=>new Response('<meta name=viewport content=\"width=device-width\">"
      "<body style=\"background:#0c0f12;color:#cfd8df;font:16px sans-serif;padding:24px\"><h3>LEO Home Hub is not reachable</h3>"
      "<p>Check that your phone is on the home WiFi and the hub has power, then pull down to retry.</p>',{headers:{'Content-Type':'text/html'}})))});");
    res->addHeader("Cache-Control", "no-cache"); r->send(res);
  });
  server.on("/icon.svg", HTTP_GET, [](AsyncWebServerRequest* r) {
    r->send(200, "image/svg+xml",
      "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 96 96'><rect width='96' height='96' rx='22' fill='#0c0f12'/>"
      "<path d='M22 46l26-22 26 22M28 42v30h40V42M42 72V56h12v16' fill='none' stroke='#34d3b0' stroke-width='6' stroke-linecap='round' stroke-linejoin='round'/></svg>");
  });

  /* ---- login / password ---- */
  server.addHandler(new AsyncCallbackJsonWebHandler("/api/login", [](AsyncWebServerRequest* r, JsonVariant& j) {
    if (!originOk(r)) { r->send(403); return; }
    if (millis() < loginLockUntil) { r->send(429, "application/json", "{\"err\":\"locked\"}"); return; }
    String p = j["pass"] | "";
    if (!pwHash.length() || !constEq(hashPass(p), pwHash)) {
      if (pwHash.length() && ++loginFails >= 5) { loginFails = 0; loginLockUntil = millis() + 30000; activity("5 wrong hub passwords from " + who(r) + " - sign-in paused 30 s", true); }
      r->send(401, "application/json", "{\"err\":\"bad\"}"); return;
    }
    loginFails = 0;
    String t = newToken();
    if (tokenCount >= MAX_TOKENS) { for (int i = 1; i < MAX_TOKENS; ++i) tokens[i - 1] = tokens[i]; tokenCount = MAX_TOKENS - 1; }
    tokens[tokenCount++] = t; tokensSave();
    setTokenCookie(r, t);
    dbg("Sign-in from " + who(r));
  }));
  server.on("/api/logout", HTTP_POST, [](AsyncWebServerRequest* r) {
    String t = cookieToken(r);
    for (int i = 0; i < tokenCount; ++i) if (tokens[i] == t) { for (int k = i + 1; k < tokenCount; ++k) tokens[k - 1] = tokens[k]; tokenCount--; tokensSave(); break; }
    AsyncWebServerResponse* res = r->beginResponse(200, "application/json", "{\"ok\":1}");
    res->addHeader("Set-Cookie", "leo_t=; Path=/; Max-Age=0"); r->send(res);
  });
  server.addHandler(new AsyncCallbackJsonWebHandler("/api/password", [](AsyncWebServerRequest* r, JsonVariant& j) {
    if (!guard(r)) return;
    String o = j["old"] | ""; String n = j["new"] | "";
    if (pwHash.length() && !constEq(hashPass(o), pwHash)) { r->send(403, "application/json", "{\"err\":\"old\"}"); return; }
    if (j["remove"] | false) {                                 // remove the password (needs the current one)
      pwHash = ""; prefs.remove("pw"); tokenCount = 0; tokensSave();
      activity("Hub password removed (from " + who(r) + ")", false);
      jsonOk(r); return;
    }
    if (n.length() < 6) { r->send(400, "application/json", "{\"err\":\"short\"}"); return; }
    pwHash = hashPass(n); prefs.putString("pw", pwHash);
    String t = newToken(); tokenCount = 0; tokens[tokenCount++] = t; tokensSave();   // everyone else signs in again
    setTokenCookie(r, t);
    activity("Hub password changed (from " + who(r) + ")", false);
  }));

  /* ---- read APIs ---- */
  server.on("/api/ping", HTTP_GET, [](AsyncWebServerRequest* r) {   // reachability check for the leohub.local switch (no data)
    r->send(204);
  });
  server.on("/api/state", HTTP_GET, [](AsyncWebServerRequest* r) {
    if (!authOk(r)) { r->send(401, "application/json", "{\"err\":\"login\"}"); return; }
    r->send(200, "application/json", stateJson());
  });
  server.on("/api/hub", HTTP_GET, [](AsyncWebServerRequest* r) {
    if (!authOk(r)) { r->send(401, "application/json", "{\"err\":\"login\"}"); return; }
    JsonDocument d; d["name"] = hubName; d["id"] = hubId; d["fw"] = HUB_FW; d["ssid"] = cfgSsid;
    d["wifi"] = (WiFi.status() == WL_CONNECTED); d["ip"] = WiFi.localIP().toString();
    d["channel"] = WiFi.channel(); d["rssi"] = WiFi.RSSI(); d["heap"] = ESP.getFreeHeap();
    d["heapMin"] = ESP.getMinFreeHeap(); d["temp"] = temperatureRead(); d["fsUsed"] = LittleFS.usedBytes(); d["fsTotal"] = LittleFS.totalBytes();
    d["flash"] = ESP.getFlashChipSize(); d["sketch"] = ESP.getSketchSize(); d["sketchMax"] = ESP.getFreeSketchSpace(); d["psram"] = ESP.getPsramSize();
    d["reset"] = (int)esp_reset_reason(); d["cpu"] = getCpuFrequencyMhz(); d["sdk"] = ESP.getSdkVersion(); d["uptime"] = millis() / 1000;
    d["mac"] = WiFi.macAddress(); d["chip"] = ESP.getChipModel(); d["setupMode"] = setupMode;
    d["passwordSet"] = pwHash.length() > 0; d["apSsid"] = apSsid(); d["apPass"] = apPass;
    String s; serializeJson(d, s); r->send(200, "application/json", s);
  });
  server.on("/api/activity", HTTP_GET, [](AsyncWebServerRequest* r) {
    if (!authOk(r)) { r->send(401, "application/json", "{\"err\":\"login\"}"); return; }
    std::vector<String> lines;                                 // newest first, at most 200
    xSemaphoreTake(actLock, portMAX_DELAY);
    File f = LittleFS.open(ACT_FILE, "r");
    if (f) { while (f.available()) { String l = f.readStringUntil('\n'); l.trim(); if (l.length()) lines.push_back(l); } f.close(); }
    xSemaphoreGive(actLock);
    String s = "{\"items\":["; int n = 0;
    for (int i = (int)lines.size() - 1; i >= 0 && n < 200; --i, ++n) { if (n) s += ","; s += lines[i]; }
    s += "]}"; r->send(200, "application/json", s);
  });

  /* ---- trends, chip details, log clearing, factory reset ---- */
  server.on("/api/history", HTTP_GET, [](AsyncWebServerRequest* r) {   // last 24 h, oldest first, null = no data
    if (!authOk(r)) { r->send(401, "application/json", "{\"err\":\"login\"}"); return; }
    uint8_t mac[6]; if (!r->hasParam("mac") || !parseMac(r->getParam("mac")->value(), mac)) { r->send(400); return; }
    Hist* h = histFor(mac, 0);
    if (r->hasParam("range") && r->getParam("range")->value() == "fine") {      // 10-second readings, last hour
      int f = -1; for (int j = 0; j < 4; ++j) if (fine[j].used && !memcmp(fine[j].mac, mac, 6)) f = j;
      String s; s.reserve(2400); s = "{\"step\":10,\"end\":" + String(f >= 0 ? (uint32_t)(fine[f].lastTick * 10) : 0) + ",\"v\":[";
      if (f >= 0) for (int k = FINE_SLOTS - 1; k >= 0; --k) {
        uint16_t v = fine[f].v[(fine[f].lastTick - k) % FINE_SLOTS];
        if (k != FINE_SLOTS - 1) s += ','; s += v == 0xFFFF ? String("null") : String(v);
      }
      s += "]}"; r->send(200, "application/json", s); return;
    }
    if (r->hasParam("range") && r->getParam("range")->value() == "week") {      // hourly averages, 7 days
      String s; s.reserve(1400); s = "{\"step\":3600,\"end\":" + String(h ? (uint32_t)(h->lastHour * 3600) : 0) + ",\"v\":[";
      if (h) for (int k = HIST_HOURS - 1; k >= 0; --k) {
        uint16_t v = k == 0 ? (h->hAccN ? (uint16_t)(h->hAccSum / h->hAccN) : 0xFFFF) : h->h[(h->lastHour - k) % HIST_HOURS];
        if (k != HIST_HOURS - 1) s += ','; s += v == 0xFFFF ? String("null") : String(v);
      }
      s += "]}"; r->send(200, "application/json", s); return;
    }
    String s; s.reserve(2200); s = "{\"step\":" + String(HIST_STEP) + ",\"end\":" + String(h ? (uint32_t)(h->lastSlot * HIST_STEP) : 0) + ",\"v\":[";
    if (h) for (int k = HIST_SLOTS - 1; k >= 0; --k) {
      uint16_t v = k == 0 ? (h->accN ? (uint16_t)(h->accSum / h->accN) : 0xFFFF) : h->v[(h->lastSlot - k) % HIST_SLOTS];
      if (k != HIST_SLOTS - 1) s += ','; s += v == 0xFFFF ? String("null") : String(v);
    }
    s += "]}"; r->send(200, "application/json", s);
  });
  server.on("/api/diag", HTTP_GET, [](AsyncWebServerRequest* r) {        // an edge's chip details
    if (!authOk(r)) { r->send(401, "application/json", "{\"err\":\"login\"}"); return; }
    uint8_t mac[6]; if (!r->hasParam("mac") || !parseMac(r->getParam("mac")->value(), mac)) { r->send(400); return; }
    JsonDocument d;
    { DevGuard g; int i = findDev(mac); if (i < 0) { r->send(404); return; } Dev& v = devs[i];
      d["mac"] = macStr(v.mac); d["fw"] = v.fw; d["rssi"] = v.rssi; d["uptime"] = v.uptime; d["known"] = v.diagKnown;
      if (v.diagKnown) { d["temp"] = v.dTemp / 10.0; d["heap"] = v.dHeap; d["heapMin"] = v.dHeapMin; d["fsUsed"] = v.dFsUsed; d["fsTotal"] = v.dFsTotal;
        d["flash"] = v.dFlash; d["sketch"] = v.dSketch; d["sketchMax"] = v.dSketchMax; d["reset"] = v.dReset; d["cpu"] = v.dCpu; d["sdk"] = v.dSdk; } }
    String s; serializeJson(d, s); r->send(200, "application/json", s);
  });
  server.on("/api/clearactivity", HTTP_POST, [](AsyncWebServerRequest* r) {
    if (!guard(r)) return;
    xSemaphoreTake(actLock, portMAX_DELAY); LittleFS.remove(ACT_FILE); xSemaphoreGive(actLock);
    activity("Activity log cleared (from " + who(r) + ")", false); jsonOk(r);
  });
  server.on("/api/clearconsole", HTTP_POST, [](AsyncWebServerRequest* r) {
    if (!guard(r)) return;
    xSemaphoreTake(consoleLock, portMAX_DELAY); consoleHead = 0; consoleCount = 0; xSemaphoreGive(consoleLock);
    jsonOk(r);
  });
  server.addHandler(new AsyncCallbackJsonWebHandler("/api/factory", [](AsyncWebServerRequest* r, JsonVariant& j) {
    if (!guard(r)) return;
    if (String(j["confirm"] | "") != "RESET") { r->send(400, "application/json", "{\"err\":\"confirm\"}"); return; }
    dbg("Factory reset requested from " + who(r)); jsonOk(r); factoryPending = true;
  }));
  server.on("/api/reboot", HTTP_POST, [](AsyncWebServerRequest* r) {
    if (!guard(r)) return; jsonOk(r); activity("Hub restarted (from " + who(r) + ")", false); restartAt = millis() + 800;
  });
  server.addHandler(new AsyncCallbackJsonWebHandler("/api/cmd", [](AsyncWebServerRequest* r, JsonVariant& j) {
    if (!guard(r)) return;
    uint8_t mac[6]; if (!parseMac(j["mac"] | "", mac)) { r->send(400, "application/json", "{\"err\":\"mac\"}"); return; }
    int i; { DevGuard g; i = findDev(mac); }
    if (i < 0) { r->send(404, "application/json", "{\"err\":\"unknown device\"}"); return; }
    uint8_t cmd = j["cmd"] | 0; uint8_t idx = j["idx"] | 0; uint8_t val = j["val"] | 0; float f = j["f"] | 0.0f;
    String text = j["text"] | "";
    String dn, rn; { DevGuard g; dn = devs[i].name; rn = relayName(devs[i], idx); }
    if ((cmd == C_RELAY || cmd == C_ALL) && val && lockActive()) {
      activity("BLOCKED by night lock: " + dn + ": " + (cmd == C_ALL ? String("all ON") : rn + " ON") + " (from " + who(r) + ")", true);
      r->send(423, "application/json", "{\"err\":\"night lock\"}"); return;
    }
    if (cmd == C_RENAME && text.length()) {
      { DevGuard g; copyStr(devs[i].name, sizeof(devs[i].name), text.c_str()); }
      devsSave(); stateDirty = true;
    }
    if (cmd == C_RELAY || cmd == C_ALL) {
      DevGuard g; Dev& d = devs[i];
      uint8_t m = d.onMask;
      if (cmd == C_RELAY) { if (val) m |= (1 << idx); else m &= ~(1 << idx); }
      else m = val ? (uint8_t)(((1 << (d.n ? d.n : 4)) - 1) & ~d.hideMask) | (d.onMask & d.hideMask) : 0;   // All on skips relays not in use
      d.expectMask = m; d.expectValid = 1; d.expectAt = millis(); d.onMask = m; stateDirty = true;   // optimistic; the edge confirms
    }
    if (cmd == C_RELAY) activity(dn + ": " + rn + (val ? " ON" : " OFF") + " (from " + who(r) + ")", false);
    if (cmd == C_ALL)   activity(dn + ": all " + (val ? "ON" : "OFF") + " (from " + who(r) + ")", false);
    if (cmd == C_TOUCH) activity(dn + ": touch buttons " + (val ? "enabled" : "disabled") + " (from " + who(r) + ")", false);
    if (cmd == C_SILENCE) activity(dn + ": alarm silenced (from " + who(r) + ")", false);
    if (cmd == C_TANK_SET) {
      static const char* names[] = { "", "full distance", "empty distance", "full alarm level", "low alarm level", "buzzer", "quiet hours from", "quiet hours until", "LED colours", "level LEDs", "daytime display from", "daytime display until", "daytime minimum brightness" };
      char hx[8]; snprintf(hx, sizeof(hx), "#%06lx", (unsigned long)f & 0xFFFFFFUL);
      if (idx >= 13 && idx <= 20) activity(dn + ": LED " + String(idx - 12) + " colour set to " + hx + " (from " + who(r) + ")", false);
      if (idx == 21) activity(dn + ": current-level highlight set to " + String((int)f) + " % (from " + who(r) + ")", false);
      if (idx >= 22 && idx <= 29) activity(dn + ": LED " + String(idx - 21) + " colour-matching brightness set to " + String((int)f) + " % (from " + who(r) + ")", false);
      String v = idx == 5 ? String(f != 0 ? "on" : "off") : idx == 8 ? String(f >= 3 ? "spectrum" : f >= 2 ? "custom" : f != 0 ? "red to green" : "red to blue") : idx == 9 || idx == 12 ? String((int)f) :
                 idx <= 2 ? String(f, 1) + " cm" : idx <= 4 ? String((int)f) + " %" : String((int)f) + ":00";
      if (idx >= 1 && idx <= 12) activity(dn + ": " + names[idx] + " set to " + v + " (from " + who(r) + ")", false);
    }
    if (cmd == C_FACTORY) {                                   // wipe the device and drop it from this hub
      MsgCmd c = {}; fillHdr(c.h, M_CMD); c.cmd = C_FACTORY; sendSigned(i, &c, sizeof(c)); sendSigned(i, &c, sizeof(c));
      { DevGuard g; devs[i].used = false; } histDrop(mac); devsSave(); stateDirty = true;
      activity("Factory reset sent to '" + dn + "' - it restarts unpaired (from " + who(r) + ")", false);
      jsonOk(r); return;
    }
    uint8_t hide; { DevGuard g; hide = devs[i].hideMask; }
    if (cmd == C_ALL && val && hide) {                        // All on with unused relays: switch on only the ones in use
      uint8_t n; { DevGuard g; n = devs[i].n ? devs[i].n : 4; }
      for (int k = 0; k < n; ++k) if (!(hide & (1 << k))) queueCmd(mac, C_RELAY, k, 1, 0, "");
    } else queueCmd(mac, cmd, idx, val, f, text.c_str());
    jsonOk(r);
  }));
  server.addHandler(new AsyncCallbackJsonWebHandler("/api/global", [](AsyncWebServerRequest* r, JsonVariant& j) {   // Home settings
    if (!guard(r)) return;
    int qf = j["quietFrom"] | (int)gQuietFrom, qt = j["quietTo"] | (int)gQuietTo, df = j["dayFrom"] | (int)gDayFrom, dt = j["dayTo"] | (int)gDayTo;
    int ld = j["ledDay"] | (int)gLedDay, ln = j["ledNight"] | (int)gLedNight, lon = j["litOn"] | (int)gLitOn, loff = j["litOff"] | (int)gLitOff;
    if (qf < 0 || qf > 23 || qt < 0 || qt > 23 || df < 0 || df > 23 || dt < 0 || dt > 23 || ld < 1 || ld > 40 || ln < 1 || ln > 40 ||
        lon < 10 || lon > 4000 || loff < 5 || loff >= lon) { r->send(400, "application/json", "{\"err\":\"range\"}"); return; }
    gQuietFrom = qf; gQuietTo = qt; gDayFrom = df; gDayTo = dt; gLedDay = ld; gLedNight = ln; gLitOn = lon; gLitOff = loff;
    globalsSave(); stateDirty = true;
    char buf[160]; snprintf(buf, sizeof(buf), "Home settings: quiet %02d-%02d, daytime %02d-%02d, status light %d/%d, room bright above %d / dark below %d",
                            qf, qt, df, dt, ld, ln, lon, loff);
    activity(String(buf) + " (from " + who(r) + ")", false);
    jsonOk(r);
  }));
  server.addHandler(new AsyncCallbackJsonWebHandler("/api/tankrule", [](AsyncWebServerRequest* r, JsonVariant& j) {
    if (!guard(r)) return;
    uint8_t mac[6]; if (!parseMac(j["mac"] | "", mac)) { r->send(400); return; }
    int idx = j["idx"] | -1; if (idx < 0 || idx > 5) { r->send(400); return; }
    uint8_t rb[6] = { (uint8_t)((j["on"] | false) ? 1 : 0), (uint8_t)constrain((int)(j["level"] | 50), 0, 100), (uint8_t)((j["dir"] | 0) ? 1 : 0),
                      (uint8_t)constrain((int)(j["pattern"] | 1), 0, 5), (uint8_t)constrain((int)(j["repeats"] | 10), 1, 30), (uint8_t)constrain((int)(j["color"] | 2), 0, 5) };
    String dn; { DevGuard g; int i = findDev(mac); if (i < 0) { r->send(404); return; } dn = devs[i].name; }
    TxItem t; memcpy(t.mac, mac, 6); memset(&t.cmd, 0, sizeof(t.cmd));
    fillHdr(t.cmd.h, M_CMD); t.cmd.cmd = C_TANK_RULE; t.cmd.idx = (uint8_t)idx; memcpy(t.cmd.text, rb, 6);  // raw bytes: queueCmd() would stop at a 0
    xQueueSend(txq, &t, 0);
    static const char* snd[] = { "chirp", "short beeps", "long beeps", "triple beep", "siren", "LEDs only" };
    static const char* col[] = { "no flash", "green", "red", "blue", "white", "amber" };
    activity(dn + ": alarm rule " + String(idx + 1) + (rb[0] ? String(" - ") + (rb[2] ? "drops to " : "rises to ") + String(rb[1]) + "%: " + snd[rb[3]] + " x" + String(rb[4]) + ", " + col[rb[5]] : String(" turned off")) + " (from " + who(r) + ")", false);
    jsonOk(r);
  }));
  server.addHandler(new AsyncCallbackJsonWebHandler("/api/relayuse", [](AsyncWebServerRequest* r, JsonVariant& j) {
    if (!guard(r)) return;
    uint8_t mac[6]; if (!parseMac(j["mac"] | "", mac)) { r->send(400); return; }
    int idx = j["idx"] | -1; bool used = j["used"] | true;
    int i; String dn, rn;
    { DevGuard g; i = findDev(mac); if (i < 0 || idx < 0 || idx > 3) { r->send(400); return; }
      if (used) devs[i].hideMask &= ~(1 << idx); else devs[i].hideMask |= (1 << idx);
      dn = devs[i].name; rn = relayName(devs[i], idx); }
    devsSave(); stateDirty = true;
    activity(dn + ": " + rn + (used ? " marked in use" : " marked not in use (hidden)") + " (from " + who(r) + ")", false);
    jsonOk(r);
  }));
  server.addHandler(new AsyncCallbackJsonWebHandler("/api/forget", [](AsyncWebServerRequest* r, JsonVariant& j) {
    if (!guard(r)) return;
    uint8_t mac[6]; if (!parseMac(j["mac"] | "", mac)) { r->send(400); return; }
    int i; String dn; { DevGuard g; i = findDev(mac); if (i >= 0) dn = devs[i].name; }
    if (i >= 0) {
      MsgCmd c = {}; fillHdr(c.h, M_CMD); c.cmd = C_UNPAIR; sendSigned(i, &c, sizeof(c));   // tell it to drop its key
      { DevGuard g; devs[i].used = false; } histDrop(mac);
      devsSave(); stateDirty = true;
      activity("Forgot device '" + dn + "' (from " + who(r) + ")", false);
    }
    jsonOk(r);
  }));
  server.addHandler(new AsyncCallbackJsonWebHandler("/api/pairing", [](AsyncWebServerRequest* r, JsonVariant& j) {
    if (!guard(r)) return;
    int secs = j["secs"] | 120; if (secs < 0) secs = 0; if (secs > 600) secs = 600;
    pairingUntil = millis() + secs * 1000UL; stateDirty = true;
    if (secs) activity("Pairing opened for " + String(secs) + " s (from " + who(r) + ")", false);
    jsonOk(r);
  }));
  server.addHandler(new AsyncCallbackJsonWebHandler("/api/lock", [](AsyncWebServerRequest* r, JsonVariant& j) {
    if (!guard(r)) return;
    if (j["from"].is<const char*>()) { lockFrom = parseHHMM(j["from"].as<String>(), lockFrom); prefs.putInt("lockF", lockFrom); }
    if (j["to"].is<const char*>())   { lockTo = parseHHMM(j["to"].as<String>(), lockTo); prefs.putInt("lockT", lockTo); }
    if (j["manual"].is<bool>()) { lockManual = j["manual"].as<bool>(); prefs.putBool("lockM", lockManual); activity(String("Night lock ") + (lockManual ? "turned ON" : "turned OFF") + " (from " + who(r) + ")", false); }
    if (j["sched"].is<bool>())  { lockSched = j["sched"].as<bool>(); prefs.putBool("lockS", lockSched); activity(String("Night lock schedule ") + (lockSched ? "enabled " + hm12(lockFrom) + "-" + hm12(lockTo) : String("disabled")) + " (from " + who(r) + ")", false); }
    if (j["from"].is<const char*>() || j["to"].is<const char*>()) activity("Night lock hours set to " + hm12(lockFrom) + " - " + hm12(lockTo) + " (from " + who(r) + ")", false);
    stateDirty = true; jsonOk(r);
  }));
  server.addHandler(new AsyncCallbackJsonWebHandler("/api/appass", [](AsyncWebServerRequest* r, JsonVariant& j) {
    if (!guard(r)) return;
    String p = j["pass"] | "";
    if (p.length() < 8 || p.length() > 63) { r->send(400, "application/json", "{\"err\":\"8-63 chars\"}"); return; }
    apPass = p; prefs.putString("appass", apPass); activity("Emergency hotspot password changed (from " + who(r) + ")", false);
    jsonOk(r);
  }));
  server.addHandler(new AsyncCallbackJsonWebHandler("/api/wifi", [](AsyncWebServerRequest* r, JsonVariant& j) {
    if (!guard(r)) return;
    String s = j["ssid"] | ""; String p = j["pass"] | "";
    if (!s.length()) { r->send(400, "application/json", "{\"err\":\"ssid\"}"); return; }
    prefs.putString("ssid", s); if (p.length() || s != cfgSsid) prefs.putString("pass", p); prefs.remove("setup");
    activity("WiFi settings changed to '" + s + "' (from " + who(r) + ")", false);
    jsonOk(r); restartAt = millis() + 1000;
  }));
  server.addHandler(new AsyncCallbackJsonWebHandler("/api/hubname", [](AsyncWebServerRequest* r, JsonVariant& j) {
    if (!guard(r)) return;
    String n = j["name"] | ""; n.trim();
    if (n.length()) { hubName = n.substring(0, 23); prefs.putString("name", hubName); stateDirty = true; }
    jsonOk(r);
  }));

  // hub's own OTA
  server.on("/api/ota", HTTP_POST,
    [](AsyncWebServerRequest* r) {
      if (!guard(r)) return;
      if (otaFailed || Update.hasError() || !Update.isFinished()) {
        r->send(500, "application/json", "{\"err\":\"" + (otaErr.length() ? otaErr : String(Update.errorString())) + "\"}"); return;
      }
      jsonOk(r); activity("Hub firmware updated (from " + who(r) + ")", false); restartAt = millis() + 1000;
    },
    [](AsyncWebServerRequest* r, const String& fn, size_t index, uint8_t* data, size_t len, bool final) {
      if (index == 0) {
        otaFailed = false; otaErr = "";
        if (!originOk(r) || !authOk(r)) { otaFailed = true; otaErr = "login"; return; }
        if (Update.isRunning()) Update.abort();
        if (!Update.begin(UPDATE_SIZE_UNKNOWN, U_FLASH)) { otaFailed = true; otaErr = Update.errorString(); return; }
        dbg("Hub OTA: receiving " + fn);
      }
      if (otaFailed) return;
      if (Update.write(data, len) != len) { otaFailed = true; otaErr = Update.errorString(); Update.abort(); return; }
      if (final && !Update.end(true)) { otaFailed = true; otaErr = Update.errorString(); }
    });

  // edge OTA: upload the edge's .bin to the hub, then the hub streams it over ESP-NOW (signed)
  server.on("/api/edge-ota", HTTP_POST,
    [](AsyncWebServerRequest* r) {
      if (!guard(r)) return;
      uint8_t mac[6];
      if (!r->hasParam("mac") || !parseMac(r->getParam("mac")->value(), mac)) { r->send(400, "application/json", "{\"err\":\"mac\"}"); return; }
      if (!eota.uploadOk) { r->send(500, "application/json", "{\"err\":\"" + eota.upErr + "\"}"); return; }
      if (!edgeOtaStart(mac)) { r->send(409, "application/json", "{\"err\":\"another update is running\"}"); return; }
      jsonOk(r);
    },
    [](AsyncWebServerRequest* r, const String&, size_t index, uint8_t* data, size_t len, bool final) {
      static File up;
      if (index == 0) {
        eota.uploadOk = false; eota.upErr = "";
        if (!originOk(r) || !authOk(r)) { eota.upErr = "login"; return; }
        if (eota.active) { eota.upErr = "another update is running"; return; }
        if (len < 1 || data[0] != 0xE9) { eota.upErr = "not an ESP32 firmware .bin"; return; }
        LittleFS.remove(EDGE_BIN); up = LittleFS.open(EDGE_BIN, "w");
        if (!up) { eota.upErr = "hub storage error"; return; }
      }
      if (!up) return;
      if (up.write(data, len) != len) { up.close(); LittleFS.remove(EDGE_BIN); eota.upErr = "hub storage full"; return; }
      if (final) { up.close(); eota.uploadOk = true; }
    });

  server.onNotFound([](AsyncWebServerRequest* r) {
    if (r->method() == HTTP_OPTIONS) { r->send(200); return; }
    r->send(404, "text/plain", "404");
  });
  server.begin();
}

/* ------------------------- USB serial commands ---------------------- */
/* (needs physical access to the hub)
   SETWIFI<TAB>ssid<TAB>password  - save WiFi and restart (password never echoed)
   RESETPASS                      - remove the web password + sign out all browsers
   SHOWAP                         - print the emergency hotspot name and password  */
void serialTick() {
  static String in;
  while (Serial.available()) {
    char c = Serial.read();
    if (c == '\r') continue;
    if (c != '\n') { if (in.length() < 200) in += c; continue; }
    if (in.startsWith("SETWIFI\t")) {
      int a = in.indexOf('\t', 8);
      String s = a > 8 ? in.substring(8, a) : String(""); String p = a > 8 ? in.substring(a + 1) : String("");
      if (s.length()) { prefs.putString("ssid", s); prefs.putString("pass", p); dbg("WiFi saved via USB for '" + s + "' - restarting"); restartAt = millis() + 500; }
    } else if (in == "RESETPASS") {
      pwHash = ""; prefs.remove("pw"); tokenCount = 0; tokensSave();
      activity("Hub password removed via USB", false);
    } else if (in == "SHOWAP") {
      if (Serial) Serial.println("Hotspot " + apSsid() + " password " + apPass);
    }
    in = "";
  }
}

/* ------------------------------ setup / loop ------------------------ */
void setup() {
  // power-on glow FIRST (before files, WiFi or ESP-NOW): "power is good, booting".
  // Brightness from the room light saved last time - after a power cut we don't know day/night yet.
  prefs.begin("leohub", false);
  savedRoom = prefs.getUChar("room", 0);             // never known -> assume dark (dim)
  ledA.begin(); ledB.begin();
  { uint8_t k = bootGlowLevel(); uint32_t c = ledA.Color(k, k * 3 / 5, k / 4);
    ledA.setPixelColor(0, c); ledA.show(); ledB.setPixelColor(0, c); ledB.show(); }
  devLock = xSemaphoreCreateMutex(); consoleLock = xSemaphoreCreateMutex(); actLock = xSemaphoreCreateMutex();
  rxq = xQueueCreate(24, sizeof(RxItem)); txq = xQueueCreate(16, sizeof(TxItem)); txres = xQueueCreate(32, sizeof(TxResult));
  Serial.begin(115200); Serial.setTxTimeoutMs(0);

  uint8_t mac[6]; esp_read_mac(mac, ESP_MAC_WIFI_STA);
  char idb[16]; snprintf(idb, sizeof(idb), "HUB-%02x%02x%02x", mac[3], mac[4], mac[5]); hubId = idb;

  if (!LittleFS.begin(false)) { delay(100); if (!LittleFS.begin(false)) LittleFS.begin(true); }
  LittleFS.remove(EDGE_BIN);                         // leftover from an interrupted edge update
  cfgSsid = prefs.getString("ssid", ""); cfgPass = prefs.getString("pass", "");
  hubName = prefs.getString("name", "LEO Home Hub");
  pwHash  = prefs.getString("pw", "");
  apPass  = prefs.getString("appass", "");
  if (apPass.length() < 8) { apPass = randomText(10); prefs.putString("appass", apPass); }   // unique per hub
  lockManual = prefs.getBool("lockM", false); lockSched = prefs.getBool("lockS", false);
  gQuietFrom = prefs.getUChar("gqf", 22) % 24; gQuietTo = prefs.getUChar("gqt", 7) % 24; gDayFrom = prefs.getUChar("gdf", 7) % 24; gDayTo = prefs.getUChar("gdt", 18) % 24;
  gLedDay = prefs.getUChar("gld", 5); gLedNight = prefs.getUChar("gln", 2); gLitOn = prefs.getUShort("glon", 120); gLitOff = prefs.getUShort("gloff", 80);
  if (gLitOff >= gLitOn) { gLitOn = 120; gLitOff = 80; }
  gInit = prefs.getBool("ginit", false);
  lockFrom = prefs.getInt("lockF", 23 * 60); lockTo = prefs.getInt("lockT", 6 * 60);
  tokensLoad();
  devsLoad();
  histLoad();
  fineLoad();
  setupMode = prefs.getBool("setup", false);
  pinMode(HUB_RESET_PIN, INPUT_PULLUP);
  setenv("TZ", "IST-5:30", 1); tzset();
  dbg("LEO Hub " HUB_FW " " + hubId);

  WiFi.persistent(false);
  WiFi.onEvent(wifiEvent);
  WiFi.mode(WIFI_STA);
  WiFi.setHostname("LEO-Hub");
  WiFi.setSleep(false);            // keep the radio awake: ESP-NOW edges must always be heard
  if (cfgSsid.length()) staBegin(); else apStart();
  if (esp_now_init() == ESP_OK) { esp_now_register_recv_cb(onRecv); esp_now_register_send_cb(onSent); dbg("ESP-NOW ready (signed protocol v2)"); }
  else dbg("ESP-NOW init FAILED");
  bool any = false; for (int i = 0; i < MAX_DEV; ++i) if (devs[i].used) any = true;
  if (!any) pairingUntil = millis() + 10UL * 60 * 1000;      // brand-new hub: accept the first devices
  webBegin();

  esp_task_wdt_config_t wdt = { .timeout_ms = 15000, .idle_core_mask = 0, .trigger_panic = true };
  if (esp_task_wdt_init(&wdt) == ESP_ERR_INVALID_STATE) esp_task_wdt_reconfigure(&wdt);
  esp_task_wdt_add(NULL);
}

/* Status LED: one quick, faint breath (0.8 s); dark the rest of the time.
     green  every 5 s : on WiFi, all good
     cyan   every 2 s : pairing window open ("Allow new devices")
     amber  every 2 s : WiFi lost / still connecting
     blue   every 2 s : emergency hotspot is on
   Peak 5/255 when the room is lit, 2/255 when dark (room light from the tank's LDR, else the clock). */
void hubLedTick() {
  static uint32_t last = 0, shown = 0xFFFFFFFF; if (millis() - last < 20) return; last = millis();
  if (resetArmed()) {                                       // BOOT held: factory reset is armed
    uint32_t c = ledA.Color(resetLevel(), 0, 0);
    if (c != shown) { shown = c; ledA.setPixelColor(0, c); ledA.show(); ledB.setPixelColor(0, c); ledB.show(); }
    return;
  }
  if (millis() < BOOT_GLOW_MS) {                            // power-on glow still fading out
    uint8_t k = bootGlowLevel(); uint32_t c = ledA.Color(k, k * 3 / 5, k / 4);
    if (c != shown) { shown = c; ledA.setPixelColor(0, c); ledA.show(); ledB.setPixelColor(0, c); ledB.show(); }
    return;
  }
  uint8_t r, g, b; uint32_t period;
  if (apUp)                          { r = 0; g = 0; b = 1; period = 2000; }
  else if (!staUp)                   { r = 1; g = 1; b = 0; period = 2000; }
  else if (millis() < pairingUntil)  { r = 0; g = 1; b = 1; period = 2000; }
  else                               { r = 0; g = 1; b = 0; period = 5000; }
  bool day = roomLight == 1;                                // room light from the tank's LDR ...
  if (roomLight == 255 && timeValid()) { time_t now = time(nullptr); struct tm tm; localtime_r(&now, &tm); int m = tm.tm_hour * 60 + tm.tm_min, a = gDayFrom * 60, b = gDayTo * 60; day = a < b ? (m >= a && m < b) : (m >= a || m < b); }   // ... else the daytime hours
  uint32_t len = 800, t = millis() % period;                // quick breath: 0.8 s up and down, then dark
  float s = t < len ? sinf(PI * t / len) : 0;
  uint8_t k = (uint8_t)(s * s * (day ? gLedDay : gLedNight) + 0.5f);   // global status-light brightness
  uint32_t c = ledA.Color(r * k, g * k, b * k);
  if (c != shown) { shown = c; ledA.setPixelColor(0, c); ledA.show(); ledB.setPixelColor(0, c); ledB.show(); }
}

void loop() {
  esp_task_wdt_reset();
  hubLedTick();
  resetBtnTick();
  if (factoryPending) hubFactoryReset();
  { static uint32_t lastHist = 0; if (millis() - lastHist >= 1000) { lastHist = millis(); histTick(); } }
  serialTick();
  ws.cleanupClients(); consoleWs.cleanupClients();
  wifiTick();

  RxItem it; int n = 0;
  while (n++ < 16 && xQueueReceive(rxq, &it, 0) == pdTRUE) handlePacket(it);
  TxItem t; n = 0;
  while (n++ < 8 && xQueueReceive(txq, &t, 0) == pdTRUE) {
    int i; { DevGuard g; i = findDev(t.mac); }
    if (i >= 0) sendSigned(i, &t.cmd, sizeof(t.cmd));
  }
  edgeOtaTick();

  // radio delivery results: a missed ACK makes the next keep-alive go out quickly
  TxResult tr; n = 0;
  while (n++ < 32 && xQueueReceive(txres, &tr, 0) == pdTRUE) {
    DevGuard g; int i = findDev(tr.mac); if (i < 0) continue;
    Dev& d = devs[i]; d.txSent++;
    if (tr.ok) d.failRun = 0; else { d.txFail++; if (d.failRun < 255) d.failRun++; }
    d.pingRetry = d.failRun > 0 && d.failRun < 12;              // give up fast retries if it is really gone
  }

  // the router can move the WiFi channel; edges then have to find the hub again
  static uint8_t lastCh = 0;
  if (WiFi.status() == WL_CONNECTED) {
    uint8_t ch = WiFi.channel();
    if (lastCh && ch != lastCh) dbg("Router moved WiFi from channel " + String(lastCh) + " to " + String(ch) + " - edges will re-link");
    lastCh = ch;
  }

  // signed keep-alive pings (edges re-link if they stop hearing verified packets)
  static uint32_t lastPingScan = 0;
  if (millis() - lastPingScan > 100) {
    lastPingScan = millis();
    for (int i = 0; i < MAX_DEV; ++i) {
      bool due = false;
      { DevGuard g; Dev& d = devs[i];
        due = d.used && d.hasKey && d.session && millis() - d.lastPing > (d.pingRetry ? 300u : (uint32_t)PING_MS) &&
              !(eota.active && !memcmp(eota.mac, d.mac, 6));
        if (due) d.lastPing = millis(); }
      if (due) {
        MsgPing p = {}; fillHdr(p.h, M_PING); p.mins = -1; p.room = roomLight;
        if (timeValid()) { time_t now = time(nullptr); struct tm tm; localtime_r(&now, &tm); p.mins = tm.tm_hour * 60 + tm.tm_min; }
        p.beat = millis() % 10000;                             // edges breathe in step with the hub's LED
        p.g = 1; p.quietFrom = gQuietFrom; p.quietTo = gQuietTo; p.dayFrom = gDayFrom; p.dayTo = gDayTo;   // global home settings
        p.ledDay = gLedDay; p.ledNight = gLedNight; p.litOn = gLitOn; p.litOff = gLitOff;
        sendSigned(i, &p, sizeof(p));
      }
    }
  }

  // online/offline transitions, pairing countdown, lock changes -> push to browsers
  static uint32_t lastScan = 0;
  if (millis() - lastScan > 1000) {
    lastScan = millis();
    static uint32_t prevOnline = 0; uint32_t mask = 0; int ldr = -1;
    { DevGuard g; for (int i = 0; i < MAX_DEV; ++i) if (devs[i].used && devs[i].lastSeen && millis() - devs[i].lastSeen < OFFLINE_MS) {
        mask |= (1u << i);
        if (devs[i].type == DEV_TANK && devs[i].ldr != 0xFFFF) ldr = max(ldr, (int)devs[i].ldr);
      } }
    if (!gInit) {                         // upgrading: start the Home settings from the tank's own quiet / daytime hours
      bool got = false;
      { DevGuard g; for (int i = 0; i < MAX_DEV; ++i) if (devs[i].used && devs[i].type == DEV_TANK && devs[i].tcfgKnown) {
          gQuietFrom = devs[i].tQuietFrom; gQuietTo = devs[i].tQuietTo; gDayFrom = devs[i].tShowFrom; gDayTo = devs[i].tShowTo; got = true; break; } }
      if (got) { globalsSave(); dbg("Home settings started from the tank's quiet / daytime hours"); stateDirty = true; }
    }
    uint8_t room = ldr < 0 ? 255 : (roomLight == 1 ? (ldr > gLitOff ? 1 : 0) : (ldr > gLitOn ? 1 : 0));
    if (room != roomLight) {
      dbg(String("Room light: ") + (room == 1 ? "bright" : room == 0 ? "dark" : "unknown (no tank) - using the clock") + (ldr >= 0 ? " (LDR " + String(ldr) + ")" : ""));
      roomLight = room; stateDirty = true;
      if (room != 255 && room != savedRoom) { savedRoom = room; prefs.putUChar("room", room); }   // for the next power-on glow
    }
    if (mask != prevOnline) { prevOnline = mask; stateDirty = true; }
    static bool prevLock = false; bool lk = lockActive();
    if (lk != prevLock) { prevLock = lk; stateDirty = true; if (lockSched && !lockManual) activity(String("Night lock ") + (lk ? "started" : "ended") + " (schedule)", false); }
    if (millis() < pairingUntil + 1500) stateDirty = true;    // countdown in the UI
  }
  if (ws.count() && ((stateDirty && millis() - lastPush > 250) || millis() - lastPush > 2000)) {   // >= every 2 s: the page's "still live" signal
    stateDirty = false; lastPush = millis(); ws.textAll(stateJson());
  }
  if (restartAt && (int32_t)(millis() - restartAt) >= 0) { histSave(); fineSave(); ESP.restart(); }   // planned restart (update, reboot): keep the history
  delay(2);
}
