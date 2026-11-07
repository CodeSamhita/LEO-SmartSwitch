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

#define HUB_FW            "1.5.0"
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
enum : uint8_t { M_HELLO = 1, M_WELCOME = 2, M_SW_STATE = 3, M_SW_INFO = 4, M_TANK_STATE = 5,
                 M_CMD = 7, M_OTA_BEGIN = 10, M_OTA_DATA = 11, M_OTA_END = 12, M_OTA_ACK = 13, M_PING = 14 };
enum : uint8_t { DEV_SWITCH = 1, DEV_TANK = 2 };
enum : uint8_t { C_RELAY = 1, C_ALL = 2, C_IDENTIFY = 3, C_RENAME = 4, C_RELAY_META = 5, C_REBOOT = 6, C_INFO = 7, C_UNPAIR = 8, C_TOUCH = 9 };
struct __attribute__((packed)) LeoHdr      { uint16_t magic; uint8_t proto; uint8_t type; uint8_t dev; uint8_t seq; };
struct __attribute__((packed)) LeoAuth     { uint32_t ctr; uint8_t tag[8]; };
struct __attribute__((packed)) MsgHello    { LeoHdr h; uint32_t nonce; uint8_t hasKey; char fw[16]; char name[24]; };
struct __attribute__((packed)) MsgWelcome  { LeoHdr h; uint8_t channel; uint8_t keyIncluded; uint8_t key[16]; char hubName[24]; };
struct __attribute__((packed)) MsgPing     { LeoHdr h; int16_t mins; uint8_t room; uint16_t beat; };   // beat: hub millis() % 10000 when sent (LED breathing sync)   // mins: hub local time (-1 unknown); room: 1 lit, 0 dark, 255 unknown (from the tank's LDR)
struct __attribute__((packed)) MsgSwState  { LeoHdr h; uint8_t n; uint8_t onMask; uint32_t uptime; uint32_t onSecs[4]; };
struct __attribute__((packed)) MsgSwInfo   { LeoHdr h; char name[24]; char fw[16]; uint8_t n; char rname[4][20]; float watts[4]; uint8_t gpio[4]; uint8_t touch; };   // touch: 1 = touch buttons enabled (switch 2.2+)
struct __attribute__((packed)) MsgTankState{ LeoHdr h; float levelPct; float distCm; uint8_t leds; uint8_t state; uint8_t sensorOk; uint8_t flags; uint32_t uptime; char stateTxt[24]; uint16_t ldr; };   // ldr: room light 0..4095 (tank 1.1+)
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
};
Dev devs[MAX_DEV];
SemaphoreHandle_t devLock;
struct DevGuard { DevGuard() { xSemaphoreTake(devLock, portMAX_DELAY); } ~DevGuard() { xSemaphoreGive(devLock); } };

struct TxItem { uint8_t mac[6]; MsgCmd cmd; };
struct TxResult { uint8_t mac[6]; bool ok; };
QueueHandle_t rxq, txq, txres;

Preferences prefs;
String cfgSsid, cfgPass, hubName, apPass, pwHash;
String hubId;                       // "HUB-XXXXXX"
String tokens[MAX_TOKENS]; int tokenCount = 0;
int    loginFails = 0; uint32_t loginLockUntil = 0;
uint32_t pairingUntil = 0;
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
#define ROOM_LIT_ON   120                 // same dead band as the tank: lit above 120, dark again below 80
#define ROOM_LIT_OFF  80
uint32_t staDownSince = 0, lastStaTry = 0, lastPush = 0, restartAt = 0;
bool     stateDirty = true;
uint8_t  txSeq = 0;
bool     otaFailed = false; String otaErr;     // hub's own OTA

struct {                                       // edge OTA (hub -> edge over ESP-NOW, stop-and-wait)
  bool active; uint8_t mac[6]; File f; uint32_t size, off; uint16_t lastLen;
  uint8_t phase;                               // 1 begin, 2 data, 3 end
  uint32_t lastSend; uint8_t retries; int pct; String msg; bool uploadOk; String upErr;
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
    struct tm tm; localtime_r(&now, &tm); strftime(stamp, sizeof(stamp), "%y-%m-%d %H:%M:%S", &tm);
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

/* ---------------------------- night lock --------------------------- */
bool lockActive() {
  if (lockManual) return true;
  if (!lockSched || !timeValid()) return false;
  time_t now = time(nullptr); struct tm tm; localtime_r(&now, &tm);
  int m = tm.tm_hour * 60 + tm.tm_min;
  return lockFrom <= lockTo ? (m >= lockFrom && m < lockTo) : (m >= lockFrom || m < lockTo);
}
String hhmm(int m) { char b[6]; snprintf(b, sizeof(b), "%02d:%02d", m / 60, m % 60); return String(b); }
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
      if (!pairingOpen) { static uint32_t lastNag = 0; if (millis() - lastNag > 10000) { lastNag = millis(); dbg("New device " + macStr(it.mac) + " wants to pair - press 'Allow new devices' to accept"); } return; }
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
    if ((int)d.levelPct != (int)m.levelPct || d.leds != m.leds || d.sensorOk != m.sensorOk || strncmp(d.stateTxt, m.stateTxt, sizeof(d.stateTxt))) stateDirty = true;
    d.levelPct = m.levelPct; d.distCm = m.distCm; d.leds = m.leds; d.tstate = m.state;
    d.sensorOk = m.sensorOk; d.uptime = m.uptime; copyStr(d.stateTxt, sizeof(d.stateTxt), m.stateTxt);
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
String apSsid() { return "LEO-Hub-" + hubId.substring(4); }
void apStart() {
  if (apUp) return;
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP(apSsid().c_str(), apPass.c_str());
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
          x["on"] = (bool)(v.onMask & (1 << r)); x["onSecs"] = v.onSecs[r];
        }
      } else if (v.type == DEV_TANK) {
        JsonObject t = o["tank"].to<JsonObject>();
        t["level"] = v.levelPct; t["dist"] = v.distCm; t["leds"] = v.leds;
        t["sensorOk"] = (bool)v.sensorOk; t["stateTxt"] = v.stateTxt;
        if (v.ldr != 0xFFFF) t["ldr"] = v.ldr;
      }
    } }
  if (eota.active || eota.msg.length()) {
    JsonObject o = d["ota"].to<JsonObject>();
    o["mac"] = macStr(eota.mac); o["pct"] = eota.pct; o["msg"] = eota.msg; o["active"] = eota.active;
  }
  String s; serializeJson(d, s); return s;
}

/* -------------------------------- web ------------------------------ */
// Web UI (generated from hub_ui.html): plain C string lines.
static const char INDEX_HTML[] PROGMEM =
  "<!DOCTYPE html>\n"
  "<html lang=\"en\">\n"
  "<head>\n"
  "<meta charset=\"utf-8\">\n"
  "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1,viewport-fit=cover\">\n"
  "<title>LEO Home Hub</title>\n"
  "<link rel=\"manifest\" href=\"/manifest.json\">\n"
  "<link rel=\"icon\" href=\"/icon.svg\" type=\"image/svg+xml\">\n"
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
  "    <div class=\"row\" style=\"margin:0 0 12px\"><button class=\"btn p\" onclick=\"everything(true)\">Everything On</button><button class=\"btn\" onclick=\"everything(false)\">Everything Off</button></div>\n"
  "    <div class=\"grid\" id=\"cards\"></div>\n"
  "  </section>\n"
  "\n"
  "  <section class=\"page\" id=\"p-devices\">\n"
  "    <div class=\"card\" style=\"margin-bottom:12px\">\n"
  "      <b>Add a new device</b>\n"
  "      <p class=\"note\">For security the hub only accepts new devices while pairing is open. Press the button, then power the new device on near the hub.</p>\n"
  "      <div class=\"row\"><button class=\"btn p\" id=\"pairbtn\" onclick=\"openPairing()\">Allow new devices for 2 minutes</button></div>\n"
  "    </div>\n"
  "    <div id=\"devlist\"></div>\n"
  "  </section>\n"
  "\n"
  "  <section class=\"page\" id=\"p-activity\">\n"
  "    <div class=\"row\" style=\"margin:0 0 10px\"><button class=\"btn\" onclick=\"loadActivity()\">Refresh</button></div>\n"
  "    <div class=\"card\" id=\"actlist\"><div class=\"meta\">Loading…</div></div>\n"
  "  </section>\n"
  "\n"
  "  <section class=\"page\" id=\"p-hub\">\n"
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
  "    <h3>Live log</h3>\n"
  "    <div class=\"logbox\" id=\"log\">Connecting…</div>\n"
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
  "async function connect(){\n"
  "  const st=await call('/api/state');if(!st)return;          // 401 shows the login screen\n"
  "  try{S=await st.json();render()}catch(e){}\n"
  "  if(sock){sock.onclose=null;sock.close()}\n"
  "  const ws=new WebSocket('ws://'+location.host+'/ws');sock=ws;\n"
  "  ws.onmessage=e=>{try{S=JSON.parse(e.data);render()}catch(_){}};\n"
  "  ws.onclose=()=>{if(sock===ws)setTimeout(connect,2000)}}\n"
  "function nav(p){page=p;$$('.page').forEach(s=>s.classList.toggle('active',s.id==='p-'+p));\n"
  "  $$('nav button').forEach(b=>b.classList.toggle('sel',b.dataset.p===p));\n"
  "  if(p==='devices'){devKeys='';render()} if(p==='hub'){loadHub();logOn()}else logOff(); if(p==='activity')loadActivity()}\n"
  "\n"
  "function render(){\n"
  "  const h=S.hub||{};$('#hubName').textContent=h.name||'LEO Home Hub';\n"
  "  $('#wifiDot').className='dot '+(h.wifi?'on':'off');$('#wifiTxt').textContent=h.wifi?('WiFi · '+h.ip):(h.ap?'Hotspot '+h.ap:'Connecting…');\n"
  "  const on=S.devices.filter(d=>d.online).length;$('#devSum').textContent=S.devices.length?(on+'/'+S.devices.length+' devices online'):'';\n"
  "  let b='';const L=h.lock||{};\n"
  "  if(L.active)b+=`<div class=\"banner\"><b>🌙 Night lock is on — lights can't be switched ON${L.manual?'':(' until '+esc(L.to))}.</b>${L.manual?'<button class=\"btn\" onclick=\"setLock({manual:false})\">Unlock</button>':''}</div>`;\n"
  "  if(h.passwordSet===false)b+=`<div class=\"banner\"><b>⚠ No hub password yet — anyone on your WiFi can control your devices.</b><button class=\"btn\" onclick=\"nav('hub')\">Set one</button></div>`;\n"
  "  if(h.pairing>0)b+=`<div class=\"banner info\"><b>Pairing open for ${h.pairing}s — power on the new device near the hub.</b></div>`;\n"
  "  $('#banners').innerHTML=b;\n"
  "  const pb=$('#pairbtn');if(pb)pb.textContent=h.pairing>0?('Pairing open — '+h.pairing+'s left'):'Allow new devices for 2 minutes';\n"
  "  if(page==='home')renderHome();\n"
  "  if(page==='devices')renderDevices();\n"
  "  if(page==='hub')renderLock();\n"
  "}\n"
  "function totalW(d){return (d.relays||[]).reduce((a,r)=>a+(r.on?r.watts:0),0)}\n"
  "function renderHome(){\n"
  "  const box=$('#cards');\n"
  "  if(!S.devices.length){box.innerHTML='<div class=\"card empty\" style=\"grid-column:1/-1\">No devices yet.<br>Go to <b>Devices → Allow new devices</b>, then power on a LEO switch or tank near the hub.</div>';return}\n"
  "  box.innerHTML=S.devices.map(d=>{\n"
  "    const st=d.online?'<span class=\"dot on\"></span>':'<span class=\"dot off\"></span>';\n"
  "    const meta=d.online?('signal '+d.rssi+' dBm · up '+up(d.uptime||0)+(d.secure?' · 🔒 secured':' · ⚠ not secured')):('offline · last seen '+ago(d.seenAgo)+' ago');\n"
  "    if(d.type==='switch'){\n"
  "      const rel=(d.relays||[]).map((r,i)=>`<div class=\"rel\"><div class=\"n\"><b>${esc(r.name)}</b><span class=\"meta\">${r.on?('On · '+r.watts+' W'):'Off'}</span></div>\n"
  "        <button class=\"tgl ${r.on?'on':''}\" ${d.online?'':'disabled'} onclick=\"tog(this,'${d.mac}',${i},${!r.on})\"></button></div>`).join('');\n"
  "      return `<div class=\"card ${d.online?'':'offline'}\"><div class=\"chead\">${st}<span class=\"nm\">${esc(d.name)}</span><span class=\"w\">${totalW(d).toFixed(0)} W</span></div>\n"
  "        ${rel||'<div class=\"meta\">Waiting for relay info…</div>'}\n"
  "        <div class=\"row\"><button class=\"btn\" ${d.online?'':'disabled'} onclick=\"cmd('${d.mac}',2,{val:1})\">All on</button><button class=\"btn\" ${d.online?'':'disabled'} onclick=\"cmd('${d.mac}',2,{val:0})\">All off</button></div>\n"
  "        <div class=\"meta\" style=\"margin-top:8px\">${meta}</div></div>`}\n"
  "    if(d.type==='tank'){const t=d.tank||{};const segs=[...Array(9)].map((_,i)=>`<div class=\"seg ${i<(t.leds||0)?'on':''}\"></div>`).join('');\n"
  "      return `<div class=\"card ${d.online?'':'offline'}\"><div class=\"chead\">${st}<span class=\"nm\">${esc(d.name)}</span></div>\n"
  "        <div class=\"tank\"><div class=\"tankbar\">${segs}</div><div><div class=\"big\">${t.sensorOk===false?'—':Math.round(t.level||0)}<small>%</small></div>\n"
  "        <div class=\"meta\" style=\"margin-top:6px\">${t.sensorOk===false?'<span class=\"err\">Sensor error</span>':('Water distance '+(t.dist||0).toFixed(1)+' cm')}</div>\n"
  "        <div class=\"meta\">${esc(t.stateTxt||'')}</div>${t.ldr!==undefined?`<div class=\"meta\">Room light: ${esc(S.hub.room||'')} (${t.ldr})</div>`:''}</div></div>\n"
  "        <div class=\"meta\" style=\"margin-top:8px\">${meta}</div></div>`}\n"
  "    return `<div class=\"card\"><div class=\"chead\">${st}<span class=\"nm\">${esc(d.name)}</span></div><div class=\"meta\">Unknown device type</div></div>`}).join('');\n"
  "}\n"
  "async function tog(el,mac,i,on){el.classList.toggle('on',on);if(!await cmd(mac,1,{idx:i,val:on?1:0}))el.classList.toggle('on',!on)}\n"
  "async function everything(on){for(const d of S.devices)if(d.type==='switch'&&d.online)await cmd(d.mac,2,{val:on?1:0})}\n"
  "async function openPairing(){if(await post('/api/pairing',{secs:120}))toast('Pairing open for 2 minutes')}\n"
  "\n"
  "/* devices page: rebuilt only when the device set changes, so typing isn't clobbered */\n"
  "function renderDevices(){\n"
  "  const keys=S.devices.map(d=>d.mac+(d.relays?d.relays.length:0)+d.type+d.touch).join(',');\n"
  "  if(keys!==devKeys){devKeys=keys;\n"
  "    $('#devlist').innerHTML=S.devices.length?S.devices.map(d=>`<div class=\"card\" style=\"margin-bottom:12px\" id=\"dv-${d.mac.replace(/:/g,'')}\">\n"
  "      <div class=\"chead\"><span class=\"dot\" data-k=\"dot\"></span><span class=\"nm\">${esc(d.name)}</span><span class=\"pill\">${esc(d.type)}</span></div>\n"
  "      <div class=\"meta\" data-k=\"meta\"></div>\n"
  "      <label>Device name</label><div class=\"row\" style=\"margin:0\"><input value=\"${esc(d.name)}\" data-k=\"name\"><button class=\"btn\" style=\"flex:0 0 90px\" onclick=\"rename('${d.mac}',this)\">Save</button></div>\n"
  "      ${d.type==='switch'?(d.relays||[]).map((r,i)=>`<label>Relay ${i+1} (GPIO ${r.gpio}) — name / watts</label>\n"
  "        <div class=\"row\" style=\"margin:0\"><input value=\"${esc(r.name)}\" data-r=\"${i}n\"><input type=\"number\" value=\"${r.watts}\" style=\"flex:0 0 90px\" data-r=\"${i}w\">\n"
  "        <button class=\"btn\" style=\"flex:0 0 70px\" onclick=\"relMeta('${d.mac}',${i},this)\">Save</button></div>`).join(''):''}\n"
  "      ${d.type==='switch'&&d.touch!==undefined?`<label>Touch buttons on the switch (GPIO 4–7)</label><div class=\"row\" style=\"margin:0\"><button class=\"btn ${d.touch?'p':''}\" onclick=\"cmd('${d.mac}',9,{val:${d.touch?0:1}})\">${d.touch?'Enabled — tap to disable':'Disabled — tap to enable'}</button></div>`:''}\n"
  "      <div class=\"row\"><button class=\"btn\" onclick=\"cmd('${d.mac}',3)\">Identify</button><button class=\"btn\" onclick=\"if(confirm('Restart this device?'))cmd('${d.mac}',6)\">Restart</button><button class=\"btn d\" onclick=\"forget('${d.mac}')\">Forget</button></div>\n"
  "      <label>Update this device's firmware — choose its .bin</label><input type=\"file\" accept=\".bin\" data-k=\"bin\">\n"
  "      <div class=\"row\"><button class=\"btn p\" onclick=\"edgeOta('${d.mac}',this)\">Upload &amp; install</button></div>\n"
  "      <div class=\"bar\"><i data-k=\"bar\"></i></div><div class=\"note\" data-k=\"otamsg\"></div>\n"
  "    </div>`).join(''):'<div class=\"card empty\">No devices paired yet.</div>'}\n"
  "  for(const d of S.devices){const c=$('#dv-'+d.mac.replace(/:/g,''));if(!c)continue;\n"
  "    c.querySelector('[data-k=dot]').className='dot '+(d.online?'on':'off');\n"
  "    c.querySelector('[data-k=meta]').textContent=d.mac+' · fw '+(d.fw||'?')+' · '+(d.secure?'🔒 secured link':'⚠ link not secured')+' · '+(d.online?('signal '+d.rssi+' dBm · up '+up(d.uptime||0)):('offline, last seen '+ago(d.seenAgo)+' ago'));\n"
  "    const o=S.ota||{};if(o.mac===d.mac){c.querySelector('[data-k=bar]').style.width=(o.pct||0)+'%';c.querySelector('[data-k=otamsg]').textContent=o.msg||''}}\n"
  "}\n"
  "async function rename(mac,btn){const v=btn.parentElement.querySelector('input').value.trim();if(v)await cmd(mac,4,{text:v})}\n"
  "async function relMeta(mac,i,btn){const p=btn.parentElement;await cmd(mac,5,{idx:i,text:p.querySelector('[data-r=\"'+i+'n\"]').value.trim(),f:parseFloat(p.querySelector('[data-r=\"'+i+'w\"]').value)||0})}\n"
  "async function forget(mac){if(confirm('Forget this device?\\n\\nIf it is online it is told to unpair too. To add it again later, use \"Allow new devices\".')){await post('/api/forget',{mac});devKeys=''}}\n"
  "function upload(url,file,bar,msg,done){\n"
  "  const fd=new FormData();fd.append('firmware',file,file.name);const x=new XMLHttpRequest();x.open('POST',url);\n"
  "  x.upload.onprogress=e=>{if(e.lengthComputable){bar.style.width=Math.round(e.loaded*100/e.total)+'%';msg.textContent='Uploading to hub… '+Math.round(e.loaded*100/e.total)+'%'}};\n"
  "  x.onload=()=>{if(x.status===401){needLogin();done(false,'sign in first');return}let e='';try{e=JSON.parse(x.responseText).err}catch(_){}done(x.status===200,e)};\n"
  "  x.onerror=()=>done(false,'upload interrupted');x.send(fd)}\n"
  "function edgeOta(mac,btn){const c=btn.closest('.card'),f=c.querySelector('[data-k=bin]').files[0],bar=c.querySelector('[data-k=bar]'),msg=c.querySelector('[data-k=otamsg]');\n"
  "  if(!f||!/\\.bin$/i.test(f.name)){msg.textContent='Choose the device\\'s .bin file first.';return}\n"
  "  if(!confirm('Send '+f.name+' to this device? It restarts when done.'))return;\n"
  "  upload('/api/edge-ota?mac='+encodeURIComponent(mac),f,bar,msg,(ok,e)=>{msg.textContent=ok?'Sending to device over ESP-NOW…':('Failed: '+(e||'error'))})}\n"
  "\n"
  "/* activity */\n"
  "async function loadActivity(){const a=await jget('/api/activity');if(!a)return;\n"
  "  $('#actlist').innerHTML=a.items.length?a.items.map(x=>`<div class=\"act ${x.blocked?'blocked':''}\"><time>${x.t?((d,p)=>`${p(d.getFullYear()%100)}-${p(d.getMonth()+1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`)(new Date(x.t*1000),n=>String(n).padStart(2,'0')):'(clock not set)'}</time><span>${esc(x.msg)}</span></div>`).join(''):'<div class=\"meta\">Nothing recorded yet.</div>'}\n"
  "\n"
  "/* hub page */\n"
  "function renderLock(){const L=(S.hub||{}).lock||{};$('#lockManual').classList.toggle('on',!!L.manual);$('#lockSched').classList.toggle('on',!!L.sched);\n"
  "  if(document.activeElement!==$('#lockFrom'))$('#lockFrom').value=L.from||'23:00';if(document.activeElement!==$('#lockTo'))$('#lockTo').value=L.to||'06:00';\n"
  "  $('#lockmsg').textContent=L.active?'Lock is ACTIVE now.':'Lock is not active now.'}\n"
  "async function setLock(x){if(!await post('/api/lock',x))toast('Could not change the lock')}\n"
  "async function loadHub(){const h=await jget('/api/hub');if(!h)return;$('#ssid').value=h.ssid||'';$('#hname').value=h.name||'';$('#appw').value=h.apPass||'';\n"
  "  $('#netinfo').textContent=(h.wifi?('Connected to '+h.ssid+' · '+h.ip+' · channel '+h.channel+' · '+h.rssi+' dBm'):'Not connected to WiFi')+' · hub fw '+h.fw+' · leohub.local';\n"
  "  $('#pwstate').textContent=h.passwordSet?'A hub password is set. Phones that signed in are remembered.':'No password set yet — set one so only you can control your devices.';\n"
  "  $('#oldlbl').style.display=$('#oldpw').style.display=h.passwordSet?'':'none';renderLock()}\n"
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
  "connect();\n"
  "setInterval(()=>{if(page==='home')renderHome()},5000);\n"
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

  auto sendIndex = [](AsyncWebServerRequest* r) { r->send(200, "text/html", (const uint8_t*)INDEX_HTML, strlen_P(INDEX_HTML)); };
  server.on("/", HTTP_GET, sendIndex);
  server.on("/index.html", HTTP_GET, sendIndex);
  server.on("/manifest.json", HTTP_GET, [](AsyncWebServerRequest* r) {
    r->send(200, "application/manifest+json",
      "{\"name\":\"LEO Home Hub\",\"short_name\":\"LEO Home\",\"start_url\":\"/\",\"display\":\"standalone\","
      "\"background_color\":\"#0c0f12\",\"theme_color\":\"#0c0f12\",\"icons\":[{\"src\":\"/icon.svg\",\"sizes\":\"any\",\"type\":\"image/svg+xml\"}]}");
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
    if (n.length() < 6) { r->send(400, "application/json", "{\"err\":\"short\"}"); return; }
    pwHash = hashPass(n); prefs.putString("pw", pwHash);
    String t = newToken(); tokenCount = 0; tokens[tokenCount++] = t; tokensSave();   // everyone else signs in again
    setTokenCookie(r, t);
    activity("Hub password changed (from " + who(r) + ")", false);
  }));

  /* ---- read APIs ---- */
  server.on("/api/state", HTTP_GET, [](AsyncWebServerRequest* r) {
    if (!authOk(r)) { r->send(401, "application/json", "{\"err\":\"login\"}"); return; }
    r->send(200, "application/json", stateJson());
  });
  server.on("/api/hub", HTTP_GET, [](AsyncWebServerRequest* r) {
    if (!authOk(r)) { r->send(401, "application/json", "{\"err\":\"login\"}"); return; }
    JsonDocument d; d["name"] = hubName; d["id"] = hubId; d["fw"] = HUB_FW; d["ssid"] = cfgSsid;
    d["wifi"] = (WiFi.status() == WL_CONNECTED); d["ip"] = WiFi.localIP().toString();
    d["channel"] = WiFi.channel(); d["rssi"] = WiFi.RSSI(); d["heap"] = ESP.getFreeHeap();
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

  /* ---- control ---- */
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
      else m = val ? (uint8_t)((1 << (d.n ? d.n : 4)) - 1) : 0;
      d.expectMask = m; d.expectValid = 1; d.expectAt = millis(); d.onMask = m; stateDirty = true;   // optimistic; the edge confirms
    }
    if (cmd == C_RELAY) activity(dn + ": " + rn + (val ? " ON" : " OFF") + " (from " + who(r) + ")", false);
    if (cmd == C_ALL)   activity(dn + ": all " + (val ? "ON" : "OFF") + " (from " + who(r) + ")", false);
    if (cmd == C_TOUCH) activity(dn + ": touch buttons " + (val ? "enabled" : "disabled") + " (from " + who(r) + ")", false);
    queueCmd(mac, cmd, idx, val, f, text.c_str());
    jsonOk(r);
  }));
  server.addHandler(new AsyncCallbackJsonWebHandler("/api/forget", [](AsyncWebServerRequest* r, JsonVariant& j) {
    if (!guard(r)) return;
    uint8_t mac[6]; if (!parseMac(j["mac"] | "", mac)) { r->send(400); return; }
    int i; String dn; { DevGuard g; i = findDev(mac); if (i >= 0) dn = devs[i].name; }
    if (i >= 0) {
      MsgCmd c = {}; fillHdr(c.h, M_CMD); c.cmd = C_UNPAIR; sendSigned(i, &c, sizeof(c));   // tell it to drop its key
      { DevGuard g; devs[i].used = false; }
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
    if (j["sched"].is<bool>())  { lockSched = j["sched"].as<bool>(); prefs.putBool("lockS", lockSched); activity(String("Night lock schedule ") + (lockSched ? "enabled " + hhmm(lockFrom) + "-" + hhmm(lockTo) : String("disabled")) + " (from " + who(r) + ")", false); }
    if (j["from"].is<const char*>() || j["to"].is<const char*>()) activity("Night lock hours set to " + hhmm(lockFrom) + "-" + hhmm(lockTo) + " (from " + who(r) + ")", false);
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
    prefs.putString("ssid", s); if (p.length() || s != cfgSsid) prefs.putString("pass", p);
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
  lockFrom = prefs.getInt("lockF", 23 * 60); lockTo = prefs.getInt("lockT", 6 * 60);
  tokensLoad();
  devsLoad();
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
  if (roomLight == 255 && timeValid()) { time_t now = time(nullptr); struct tm tm; localtime_r(&now, &tm); day = tm.tm_hour >= 7 && tm.tm_hour < 18; }   // ... else the clock
  uint32_t len = 800, t = millis() % period;                // quick breath: 0.8 s up and down, then dark
  float s = t < len ? sinf(PI * t / len) : 0;
  uint8_t k = (uint8_t)(s * s * (day ? 5 : 2) + 0.5f);      // peak 5/255 in a lit room, 2/255 dark
  uint32_t c = ledA.Color(r * k, g * k, b * k);
  if (c != shown) { shown = c; ledA.setPixelColor(0, c); ledA.show(); ledB.setPixelColor(0, c); ledB.show(); }
}

void loop() {
  esp_task_wdt_reset();
  hubLedTick();
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
    uint8_t room = ldr < 0 ? 255 : (roomLight == 1 ? (ldr > ROOM_LIT_OFF ? 1 : 0) : (ldr > ROOM_LIT_ON ? 1 : 0));
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
  if (ws.count() && ((stateDirty && millis() - lastPush > 250) || millis() - lastPush > 5000)) {
    stateDirty = false; lastPush = millis(); ws.textAll(stateJson());
  }
  if (restartAt && (int32_t)(millis() - restartAt) >= 0) ESP.restart();
  delay(2);
}
