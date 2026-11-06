/* =====================================================================
   LEO Home Hub  -  LEO_Hub.ino            (ESP32-S3, Arduino-ESP32 core 3.x)

   The ONE device on your home WiFi. Edge devices (LEO switches, AquaNode
   tank) talk to this hub over ESP-NOW - they need no WiFi password, run no
   web server and make no hotspot. This hub serves a single web app for all
   of them, relays commands, and can push firmware updates to them.

   Board settings (Arduino IDE / arduino-cli):
     Board            : ESP32S3 Dev Module
     Flash Size       : 8MB (64Mb)
     Partition Scheme : 8M with spiffs (3MB APP/1.5MB SPIFFS)   <- OTA needs this
     USB Mode         : Hardware CDC and JTAG,  USB CDC On Boot: Enabled
   Libraries: ESPAsyncWebServer + AsyncTCP (ESP32Async), ArduinoJson 7

   First boot / no WiFi saved: the hub opens hotspot "LEO-Hub-XXXXXX"
   (password leo12345) -> open http://192.168.4.1 -> Hub -> WiFi.
   Afterwards: http://leohub.local or the hub's IP on your network.
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
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>

#define HUB_FW            "1.0.0"
#define HUB_AP_PASS       "leo12345"
#define HUB_MDNS          "leohub"
#define MAX_DEV           16
#define OFFLINE_MS        9000      // edge counted offline after this long without a packet
#define STA_RETRY_MS      15000
#define AP_FALLBACK_MS    30000     // open the setup hotspot if WiFi isn't up within this
#define CONSOLE_LINES     150
#define CONSOLE_LINE_LEN  110
#define DEV_FILE          "/devices.json"
#define EDGE_BIN          "/edge.bin"

/* ===================== LEO EDGE PROTOCOL v1 ==========================
   Keep IDENTICAL in the hub and every edge sketch. Packed, little-endian,
   every packet < 250 bytes (ESP-NOW v1 limit).                          */
#define LEO_MAGIC  0x4C45
#define LEO_PROTO  1
enum : uint8_t { M_HELLO = 1, M_WELCOME = 2, M_SW_STATE = 3, M_SW_INFO = 4, M_TANK_STATE = 5,
                 M_CMD = 7, M_OTA_BEGIN = 10, M_OTA_DATA = 11, M_OTA_END = 12, M_OTA_ACK = 13 };
enum : uint8_t { DEV_SWITCH = 1, DEV_TANK = 2 };
enum : uint8_t { C_RELAY = 1, C_ALL = 2, C_IDENTIFY = 3, C_RENAME = 4, C_RELAY_META = 5, C_REBOOT = 6, C_INFO = 7 };
struct __attribute__((packed)) LeoHdr      { uint16_t magic; uint8_t proto; uint8_t type; uint8_t dev; uint8_t seq; };
struct __attribute__((packed)) MsgHello    { LeoHdr h; char fw[16]; char name[24]; };
struct __attribute__((packed)) MsgWelcome  { LeoHdr h; uint8_t channel; char hubName[24]; };
struct __attribute__((packed)) MsgSwState  { LeoHdr h; uint8_t n; uint8_t onMask; uint32_t uptime; uint32_t onSecs[4]; };
struct __attribute__((packed)) MsgSwInfo   { LeoHdr h; char name[24]; char fw[16]; uint8_t n; char rname[4][20]; float watts[4]; uint8_t gpio[4]; };
struct __attribute__((packed)) MsgTankState{ LeoHdr h; float levelPct; float distCm; uint8_t leds; uint8_t state; uint8_t sensorOk; uint8_t flags; uint32_t uptime; char stateTxt[24]; };
struct __attribute__((packed)) MsgCmd      { LeoHdr h; uint8_t cmd; uint8_t idx; uint8_t val; float f; char text[24]; };
struct __attribute__((packed)) MsgOtaBegin { LeoHdr h; uint32_t size; };
struct __attribute__((packed)) MsgOtaData  { LeoHdr h; uint32_t off; uint16_t len; uint8_t data[200]; };
struct __attribute__((packed)) MsgOtaAck   { LeoHdr h; uint8_t phase; uint32_t off; uint8_t ok; char err[24]; };
/* ===================================================================== */

/* ------------------------------ state ------------------------------ */
struct Dev {
  bool     used;
  uint8_t  mac[6];
  uint8_t  type;
  char     name[24];
  char     fw[16];
  uint32_t lastSeen;     // millis, 0 = never this boot
  int8_t   rssi;
  uint32_t uptime;
  // switch
  uint8_t  n, onMask;
  uint32_t onSecs[4];
  char     rname[4][20];
  float    watts[4];
  uint8_t  gpio[4];
  bool     infoKnown;
  // tank
  float    levelPct, distCm;
  uint8_t  leds, tstate, sensorOk;
  char     stateTxt[24];
};
Dev devs[MAX_DEV];
SemaphoreHandle_t devLock;
struct DevGuard { DevGuard() { xSemaphoreTake(devLock, portMAX_DELAY); } ~DevGuard() { xSemaphoreGive(devLock); } };

struct RxItem { uint8_t mac[6]; int8_t rssi; uint8_t len; uint8_t data[250]; };
struct TxItem { uint8_t mac[6]; MsgCmd cmd; };
QueueHandle_t rxq, txq;

Preferences prefs;
String cfgSsid, cfgPass, hubName;
String hubId;                       // "HUB-XXXXXX"
AsyncWebServer server(80);
AsyncWebSocket ws("/ws");
AsyncWebSocket consoleWs("/console");

volatile bool netUpPending = false, netDownPending = false;
bool     staUp = false, apUp = false;
uint32_t staDownSince = 0, lastStaTry = 0, lastPush = 0, restartAt = 0;
bool     stateDirty = true, devsDirty = false;
uint8_t  txSeq = 0;
bool     otaFailed = false; String otaErr;     // hub's own OTA

/* edge OTA (hub -> edge over ESP-NOW, stop-and-wait) */
struct {
  bool active; uint8_t mac[6]; File f; uint32_t size, off; uint16_t lastLen;
  uint8_t phase;            // 1 begin, 2 data, 3 end
  uint32_t lastSend; uint8_t retries; int pct; String msg; bool uploadOk; String upErr;
} eota;

char consoleBuf[CONSOLE_LINES][CONSOLE_LINE_LEN];
int  consoleHead = 0, consoleCount = 0;
SemaphoreHandle_t consoleLock;

/* ------------------------------ helpers ---------------------------- */
void dbg(const String& msg) {
  char line[CONSOLE_LINE_LEN];
  snprintf(line, sizeof(line), "[%lus] %s", (unsigned long)(millis() / 1000), msg.c_str());
  xSemaphoreTake(consoleLock, portMAX_DELAY);
  memcpy(consoleBuf[consoleHead], line, sizeof(line));
  consoleHead = (consoleHead + 1) % CONSOLE_LINES;
  if (consoleCount < CONSOLE_LINES) consoleCount++;
  xSemaphoreGive(consoleLock);
  // never block on USB serial (cable in a PC with no terminal open)
  if (Serial && Serial.availableForWrite() >= (int)strlen(line) + 2) Serial.println(line);
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
void copyStr(char* dst, size_t n, const char* src) { strncpy(dst, src, n - 1); dst[n - 1] = 0; }
void fillHdr(LeoHdr& h, uint8_t type) { h.magic = LEO_MAGIC; h.proto = LEO_PROTO; h.type = type; h.dev = 0; h.seq = ++txSeq; }
const char* typeName(uint8_t t) { return t == DEV_SWITCH ? "switch" : t == DEV_TANK ? "tank" : "unknown"; }

/* only accept control requests from pages served on the LAN (blocks a
   random internet page from POSTing to the hub through your browser) */
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
    i++;
  }
}
void ensurePeer(const uint8_t* mac) {
  if (esp_now_is_peer_exist(mac)) return;
  esp_now_peer_info_t p = {}; memcpy(p.peer_addr, mac, 6);
  p.channel = 0;                 // = whatever channel the radio is on (the router's)
  p.ifidx = WIFI_IF_STA; p.encrypt = false;
  esp_now_add_peer(&p);
}
bool sendTo(const uint8_t* mac, const void* data, size_t len) {
  ensurePeer(mac);
  return esp_now_send(mac, (const uint8_t*)data, len) == ESP_OK;
}
// (no default args anywhere: Arduino's auto-generated prototypes reject them)
void sendCmd(const uint8_t* mac, uint8_t cmd, uint8_t idx, uint8_t val, float f, const char* text) {
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
void onSent(const esp_now_send_info_t*, esp_now_send_status_t) {}

void handlePacket(const RxItem& it) {
  const LeoHdr* h = (const LeoHdr*)it.data;
  if (h->magic != LEO_MAGIC || h->proto != LEO_PROTO) return;

  if (h->type == M_HELLO && it.len >= sizeof(MsgHello)) {
    const MsgHello* m = (const MsgHello*)it.data;
    bool added = false; int i;
    { DevGuard g;
      i = findDev(it.mac);
      if (i < 0) {
        for (int k = 0; k < MAX_DEV; ++k) if (!devs[k].used) { i = k; break; }
        if (i < 0) { dbg("Device table full - ignoring " + macStr(it.mac)); return; }
        memset(&devs[i], 0, sizeof(Dev)); devs[i].used = true; memcpy(devs[i].mac, it.mac, 6);
        copyStr(devs[i].name, sizeof(devs[i].name), m->name[0] ? m->name : (h->dev == DEV_TANK ? "Water tank" : "Smart switch"));
        added = true;
      }
      devs[i].type = h->dev; copyStr(devs[i].fw, sizeof(devs[i].fw), m->fw);
      devs[i].lastSeen = millis(); devs[i].rssi = it.rssi;
    }
    MsgWelcome w = {}; fillHdr(w.h, M_WELCOME); w.channel = WiFi.channel();
    copyStr(w.hubName, sizeof(w.hubName), hubName.c_str());
    sendTo(it.mac, &w, sizeof(w));
    if (added) { dbg("Paired new " + String(typeName(h->dev)) + " " + macStr(it.mac) + " (" + m->name + ")"); devsSave(); }
    else dbg("Edge " + macStr(it.mac) + " (re)joined");
    // (no C_INFO here: the edge sends its INFO by itself after WELCOME - asking again
    //  made edge and hub answer each other forever)
    stateDirty = true; devsDirty = true;
    return;
  }

  int i;
  { DevGuard g; i = findDev(it.mac); if (i >= 0) { devs[i].lastSeen = millis(); devs[i].rssi = it.rssi; } }
  if (i < 0) {                       // unknown sender (e.g. forgotten): ask it to say hello again
    if (h->type == M_SW_STATE || h->type == M_TANK_STATE) sendCmd(it.mac, C_INFO, 0, 1, 0, "");   // val=1: "introduce yourself (HELLO)"
    return;
  }

  if (h->type == M_SW_STATE && it.len >= sizeof(MsgSwState)) {
    const MsgSwState* m = (const MsgSwState*)it.data;
    DevGuard g; Dev& d = devs[i];
    if (d.onMask != m->onMask || d.n != m->n) stateDirty = true;
    { uint8_t nn = m->n; d.n = nn > 4 ? 4 : nn; } d.onMask = m->onMask; d.uptime = m->uptime;
    memcpy(d.onSecs, m->onSecs, sizeof(d.onSecs));
    if (!d.infoKnown) sendCmd(it.mac, C_INFO, 0, 0, 0, "");
  } else if (h->type == M_SW_INFO && it.len >= sizeof(MsgSwInfo)) {
    const MsgSwInfo* m = (const MsgSwInfo*)it.data;
    DevGuard g; Dev& d = devs[i];
    { uint8_t nn = m->n; d.n = nn > 4 ? 4 : nn; } copyStr(d.fw, sizeof(d.fw), m->fw);
    for (int r = 0; r < 4; ++r) { copyStr(d.rname[r], sizeof(d.rname[r]), m->rname[r]); d.watts[r] = m->watts[r]; d.gpio[r] = m->gpio[r]; }
    d.infoKnown = true; stateDirty = true; devsDirty = true;
  } else if (h->type == M_TANK_STATE && it.len >= sizeof(MsgTankState)) {
    const MsgTankState* m = (const MsgTankState*)it.data;
    DevGuard g; Dev& d = devs[i];
    if ((int)d.levelPct != (int)m->levelPct || d.leds != m->leds || d.sensorOk != m->sensorOk) stateDirty = true;
    d.levelPct = m->levelPct; d.distCm = m->distCm; d.leds = m->leds; d.tstate = m->state;
    d.sensorOk = m->sensorOk; d.uptime = m->uptime; copyStr(d.stateTxt, sizeof(d.stateTxt), m->stateTxt);
  } else if (h->type == M_OTA_ACK && it.len >= sizeof(MsgOtaAck)) {
    const MsgOtaAck* a = (const MsgOtaAck*)it.data;
    edgeOtaOnAck(it.mac, a);
  }
}

/* ------------------------- edge OTA streaming ----------------------- */
void edgeOtaFinish(bool ok, const String& msg) {
  if (eota.f) eota.f.close();
  LittleFS.remove(EDGE_BIN);
  eota.active = false; eota.pct = ok ? 100 : eota.pct; eota.msg = msg;
  dbg("Edge OTA " + macStr(eota.mac) + ": " + msg); stateDirty = true;
}
void edgeOtaSendCurrent() {
  eota.lastSend = millis();
  if (eota.phase == 1) {
    MsgOtaBegin b = {}; fillHdr(b.h, M_OTA_BEGIN); b.size = eota.size; sendTo(eota.mac, &b, sizeof(b));
  } else if (eota.phase == 2) {
    MsgOtaData d = {}; fillHdr(d.h, M_OTA_DATA); d.off = eota.off;
    eota.f.seek(eota.off);
    d.len = (uint16_t)eota.f.read(d.data, min<uint32_t>(sizeof(d.data), eota.size - eota.off));
    eota.lastLen = d.len;
    sendTo(eota.mac, &d, sizeof(LeoHdr) + 6 + d.len);
  } else if (eota.phase == 3) {
    MsgOtaBegin e = {}; fillHdr(e.h, M_OTA_END); e.size = eota.size; sendTo(eota.mac, &e, sizeof(e));
  }
}
void edgeOtaOnAck(const uint8_t* mac, const MsgOtaAck* a) {
  if (!eota.active || memcmp(mac, eota.mac, 6)) return;
  if (!a->ok) { edgeOtaFinish(false, String("device rejected update: ") + a->err); return; }
  if (a->phase != eota.phase) return;                       // stale/duplicate ack
  if (eota.phase == 1) { eota.phase = 2; eota.off = 0; }
  else if (eota.phase == 2) {
    if (a->off != eota.off + eota.lastLen) return;          // ack for an older chunk
    eota.off += eota.lastLen;
    int pct = (int)((uint64_t)eota.off * 100 / eota.size);
    if (pct != eota.pct) { eota.pct = pct; eota.msg = "Sending to device… " + String(pct) + "%"; stateDirty = true; }
    if (eota.off >= eota.size) eota.phase = 3;
  } else if (eota.phase == 3) { edgeOtaFinish(true, "Installed — the device is restarting."); return; }
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

/* ------------------------------- WiFi ------------------------------ */
void wifiEvent(WiFiEvent_t e) {           // WiFi event task: flags only
  if (e == ARDUINO_EVENT_WIFI_STA_GOT_IP) netUpPending = true;
  if (e == ARDUINO_EVENT_WIFI_STA_DISCONNECTED) netDownPending = true;
}
void apStart() {
  if (apUp) return;
  WiFi.mode(WIFI_AP_STA);
  String ssid = "LEO-Hub-" + hubId.substring(4);
  WiFi.softAP(ssid.c_str(), HUB_AP_PASS);
  apUp = true; dbg("Setup hotspot " + ssid + " (password " HUB_AP_PASS ") at 192.168.4.1");
}
void apStop() { if (!apUp) return; WiFi.softAPdisconnect(true); WiFi.mode(WIFI_STA); apUp = false; dbg("Setup hotspot off"); }
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
  if (!cfgSsid.length() || millis() - staDownSince > AP_FALLBACK_MS) apStart();   // user can still reach the hub
  if (cfgSsid.length() && millis() - lastStaTry > STA_RETRY_MS) staBegin();
}

/* ------------------------------ JSON ------------------------------- */
String stateJson() {
  JsonDocument d;
  JsonObject h = d["hub"].to<JsonObject>();
  h["name"] = hubName; h["id"] = hubId; h["fw"] = HUB_FW;
  h["wifi"] = (WiFi.status() == WL_CONNECTED); h["ip"] = WiFi.localIP().toString();
  h["ap"] = apUp ? ("LEO-Hub-" + hubId.substring(4)) : String("");
  JsonArray a = d["devices"].to<JsonArray>();
  uint32_t now = millis();
  { DevGuard g;
    for (int i = 0; i < MAX_DEV; ++i) {
      Dev& v = devs[i]; if (!v.used) continue;
      JsonObject o = a.add<JsonObject>();
      o["mac"] = macStr(v.mac); o["type"] = typeName(v.type); o["name"] = v.name; o["fw"] = v.fw;
      bool online = v.lastSeen && (now - v.lastSeen < OFFLINE_MS);
      o["online"] = online; o["rssi"] = v.rssi; o["uptime"] = v.uptime;
      o["seenAgo"] = v.lastSeen ? (now - v.lastSeen) : 0;
      if (v.type == DEV_SWITCH && v.infoKnown) {
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
  "</style>\n"
  "</head>\n"
  "<body>\n"
  "<div class=\"wrap\">\n"
  "  <header>\n"
  "    <div class=\"logo\"><svg width=\"22\" height=\"22\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"#34d3b0\" stroke-width=\"1.7\"><path d=\"M3 11l9-8 9 8M5 10v10h14V10M10 20v-6h4v6\"/></svg></div>\n"
  "    <div style=\"flex:1;min-width:0\"><h1 id=\"hubName\">LEO Home Hub</h1>\n"
  "      <div class=\"sub\"><span class=\"pill\"><span class=\"dot\" id=\"wifiDot\"></span><span id=\"wifiTxt\">…</span></span> <span id=\"devSum\"></span></div></div>\n"
  "  </header>\n"
  "\n"
  "  <section class=\"page active\" id=\"p-home\">\n"
  "    <div class=\"row\" style=\"margin:0 0 12px\"><button class=\"btn p\" onclick=\"everything(true)\">Everything On</button><button class=\"btn\" onclick=\"everything(false)\">Everything Off</button></div>\n"
  "    <div class=\"grid\" id=\"cards\"></div>\n"
  "  </section>\n"
  "\n"
  "  <section class=\"page\" id=\"p-devices\">\n"
  "    <p class=\"note\">Edge devices pair with this hub automatically over ESP-NOW — just power them on near the hub. They need no WiFi password and make no hotspot.</p>\n"
  "    <div id=\"devlist\"></div>\n"
  "  </section>\n"
  "\n"
  "  <section class=\"page\" id=\"p-hub\">\n"
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
  "  <button data-p=\"hub\" onclick=\"nav('hub')\">Hub</button>\n"
  "</nav>\n"
  "\n"
  "<script>\n"
  "const $=s=>document.querySelector(s),$$=s=>document.querySelectorAll(s);\n"
  "let S={hub:{},devices:[],ota:{}},page='home',devKeys='';\n"
  "function esc(s){return(s==null?'':s+'').replace(/[<>&\"']/g,m=>({'<':'&lt;','>':'&gt;','&':'&amp;','\"':'&quot;',\"'\":'&#39;'}[m]))}\n"
  "function ago(ms){const s=Math.round(ms/1000);return s<60?s+'s':s<3600?Math.round(s/60)+'m':Math.round(s/3600)+'h'}\n"
  "function up(s){const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);return d?d+'d '+h+'h':h?h+'h '+m+'m':m+'m'}\n"
  "async function post(p,b){try{const r=await fetch(p,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b||{})});return r.ok}catch(e){return false}}\n"
  "function cmd(mac,c,x){return post('/api/cmd',Object.assign({mac:mac,cmd:c},x||{}))}\n"
  "\n"
  "/* live state */\n"
  "function connect(){const ws=new WebSocket('ws://'+location.host+'/ws');\n"
  "  ws.onmessage=e=>{try{S=JSON.parse(e.data);render()}catch(_){}};\n"
  "  ws.onclose=()=>setTimeout(connect,1500)}\n"
  "function nav(p){page=p;$$('.page').forEach(s=>s.classList.toggle('active',s.id==='p-'+p));\n"
  "  $$('nav button').forEach(b=>b.classList.toggle('sel',b.dataset.p===p));\n"
  "  if(p==='devices'){devKeys='';render()} if(p==='hub')loadHub(); if(p==='hub')logOn();else logOff()}\n"
  "\n"
  "function render(){\n"
  "  const h=S.hub||{};$('#hubName').textContent=h.name||'LEO Home Hub';\n"
  "  $('#wifiDot').className='dot '+(h.wifi?'on':'off');$('#wifiTxt').textContent=h.wifi?('WiFi · '+h.ip):(h.ap?'Setup hotspot '+h.ap:'Connecting…');\n"
  "  const on=S.devices.filter(d=>d.online).length;$('#devSum').textContent=S.devices.length?(on+'/'+S.devices.length+' devices online'):'';\n"
  "  if(page==='home')renderHome();\n"
  "  if(page==='devices')renderDevices();\n"
  "}\n"
  "function totalW(d){return (d.relays||[]).reduce((a,r)=>a+(r.on?r.watts:0),0)}\n"
  "function renderHome(){\n"
  "  const box=$('#cards');\n"
  "  if(!S.devices.length){box.innerHTML='<div class=\"card empty\" style=\"grid-column:1/-1\">No devices yet.<br>Power on a LEO switch or tank near the hub — it pairs automatically.</div>';return}\n"
  "  box.innerHTML=S.devices.map(d=>{\n"
  "    const st=d.online?'<span class=\"dot on\"></span>':'<span class=\"dot off\"></span>';\n"
  "    const meta=d.online?('signal '+d.rssi+' dBm · up '+up(d.uptime||0)):('offline · last seen '+ago(d.seenAgo)+' ago');\n"
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
  "        <div class=\"meta\">${esc(t.stateTxt||'')}</div></div></div>\n"
  "        <div class=\"meta\" style=\"margin-top:8px\">${meta}</div></div>`}\n"
  "    return `<div class=\"card\"><div class=\"chead\">${st}<span class=\"nm\">${esc(d.name)}</span></div><div class=\"meta\">Unknown device type</div></div>`}).join('');\n"
  "}\n"
  "async function tog(el,mac,i,on){el.classList.toggle('on',on);if(!await cmd(mac,1,{idx:i,val:on?1:0}))el.classList.toggle('on',!on)}\n"
  "async function everything(on){for(const d of S.devices)if(d.type==='switch'&&d.online)cmd(d.mac,2,{val:on?1:0})}\n"
  "\n"
  "/* devices page: rebuilt only when the device set changes, so typing isn't clobbered */\n"
  "function renderDevices(){\n"
  "  const keys=S.devices.map(d=>d.mac+(d.relays?d.relays.length:0)+d.type).join(',');\n"
  "  if(keys!==devKeys){devKeys=keys;\n"
  "    $('#devlist').innerHTML=S.devices.length?S.devices.map(d=>`<div class=\"card\" style=\"margin-bottom:12px\" id=\"dv-${d.mac.replace(/:/g,'')}\">\n"
  "      <div class=\"chead\"><span class=\"dot\" data-k=\"dot\"></span><span class=\"nm\">${esc(d.name)}</span><span class=\"pill\">${esc(d.type)}</span></div>\n"
  "      <div class=\"meta\" data-k=\"meta\"></div>\n"
  "      <label>Device name</label><div class=\"row\" style=\"margin:0\"><input value=\"${esc(d.name)}\" data-k=\"name\"><button class=\"btn\" style=\"flex:0 0 90px\" onclick=\"rename('${d.mac}',this)\">Save</button></div>\n"
  "      ${d.type==='switch'?(d.relays||[]).map((r,i)=>`<label>Relay ${i+1} (GPIO ${r.gpio}) — name / watts</label>\n"
  "        <div class=\"row\" style=\"margin:0\"><input value=\"${esc(r.name)}\" data-r=\"${i}n\"><input type=\"number\" value=\"${r.watts}\" style=\"flex:0 0 90px\" data-r=\"${i}w\">\n"
  "        <button class=\"btn\" style=\"flex:0 0 70px\" onclick=\"relMeta('${d.mac}',${i},this)\">Save</button></div>`).join(''):''}\n"
  "      <div class=\"row\"><button class=\"btn\" onclick=\"cmd('${d.mac}',3)\">Identify</button><button class=\"btn\" onclick=\"if(confirm('Restart this device?'))cmd('${d.mac}',6)\">Restart</button><button class=\"btn d\" onclick=\"forget('${d.mac}')\">Forget</button></div>\n"
  "      <label>Update this device's firmware — choose its .bin</label><input type=\"file\" accept=\".bin\" data-k=\"bin\">\n"
  "      <div class=\"row\"><button class=\"btn p\" onclick=\"edgeOta('${d.mac}',this)\">Upload &amp; install</button></div>\n"
  "      <div class=\"bar\"><i data-k=\"bar\"></i></div><div class=\"note\" data-k=\"otamsg\"></div>\n"
  "    </div>`).join(''):'<div class=\"card empty\">No devices paired yet.</div>'}\n"
  "  for(const d of S.devices){const c=$('#dv-'+d.mac.replace(/:/g,''));if(!c)continue;\n"
  "    c.querySelector('[data-k=dot]').className='dot '+(d.online?'on':'off');\n"
  "    c.querySelector('[data-k=meta]').textContent=d.mac+' · fw '+(d.fw||'?')+' · '+(d.online?('signal '+d.rssi+' dBm · up '+up(d.uptime||0)):('offline, last seen '+ago(d.seenAgo)+' ago'));\n"
  "    const o=S.ota||{};if(o.mac===d.mac){c.querySelector('[data-k=bar]').style.width=(o.pct||0)+'%';c.querySelector('[data-k=otamsg]').textContent=o.msg||''}}\n"
  "}\n"
  "async function rename(mac,btn){const v=btn.parentElement.querySelector('input').value.trim();if(v)await cmd(mac,4,{text:v})}\n"
  "async function relMeta(mac,i,btn){const p=btn.parentElement;await cmd(mac,5,{idx:i,text:p.querySelector('[data-r=\"'+i+'n\"]').value.trim(),f:parseFloat(p.querySelector('[data-r=\"'+i+'w\"]').value)||0})}\n"
  "async function forget(mac){if(confirm('Forget this device? It will pair again if it is still powered on.')){await post('/api/forget',{mac});devKeys=''}}\n"
  "function upload(url,file,bar,msg,done){\n"
  "  const fd=new FormData();fd.append('firmware',file,file.name);const x=new XMLHttpRequest();x.open('POST',url);\n"
  "  x.upload.onprogress=e=>{if(e.lengthComputable){bar.style.width=Math.round(e.loaded*100/e.total)+'%';msg.textContent='Uploading to hub… '+Math.round(e.loaded*100/e.total)+'%'}};\n"
  "  x.onload=()=>{let e='';try{e=JSON.parse(x.responseText).err}catch(_){}done(x.status===200,e)};\n"
  "  x.onerror=()=>done(false,'upload interrupted');x.send(fd)}\n"
  "function edgeOta(mac,btn){const c=btn.closest('.card'),f=c.querySelector('[data-k=bin]').files[0],bar=c.querySelector('[data-k=bar]'),msg=c.querySelector('[data-k=otamsg]');\n"
  "  if(!f||!/\\.bin$/i.test(f.name)){msg.textContent='Choose the device\\'s .bin file first.';return}\n"
  "  if(!confirm('Send '+f.name+' to this device? It restarts when done.'))return;\n"
  "  upload('/api/edge-ota?mac='+encodeURIComponent(mac),f,bar,msg,(ok,e)=>{msg.textContent=ok?'Sending to device over ESP-NOW…':('Failed: '+(e||'error'))})}\n"
  "\n"
  "/* hub page */\n"
  "async function loadHub(){try{const h=await(await fetch('/api/hub')).json();$('#ssid').value=h.ssid||'';$('#hname').value=h.name||'';\n"
  "  $('#netinfo').textContent=(h.wifi?('Connected to '+h.ssid+' · '+h.ip+' · channel '+h.channel+' · '+h.rssi+' dBm'):'Not connected to WiFi')+' · hub fw '+h.fw+' · leohub.local'}catch(e){}}\n"
  "async function saveWifi(){const ssid=$('#ssid').value.trim();if(!ssid){$('#wifimsg').textContent='Enter the network name.';return}\n"
  "  $('#wifimsg').textContent=await post('/api/wifi',{ssid,pass:$('#pass').value})?'Saved — the hub is reconnecting. If it moves to a new IP, find it at leohub.local or in your router.':'Could not save.'}\n"
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
  DefaultHeaders::Instance().addHeader("Access-Control-Allow-Origin", "*");
  ws.onEvent([](AsyncWebSocket*, AsyncWebSocketClient* c, AwsEventType t, void*, uint8_t*, size_t) {
    if (t == WS_EVT_CONNECT) c->text(stateJson());
  });
  server.addHandler(&ws);
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

  server.on("/api/state", HTTP_GET, [](AsyncWebServerRequest* r) { r->send(200, "application/json", stateJson()); });
  server.on("/api/hub", HTTP_GET, [](AsyncWebServerRequest* r) {
    JsonDocument d; d["name"] = hubName; d["id"] = hubId; d["fw"] = HUB_FW; d["ssid"] = cfgSsid;
    d["wifi"] = (WiFi.status() == WL_CONNECTED); d["ip"] = WiFi.localIP().toString();
    d["channel"] = WiFi.channel(); d["rssi"] = WiFi.RSSI(); d["heap"] = ESP.getFreeHeap();
    String s; serializeJson(d, s); r->send(200, "application/json", s);
  });
  server.on("/api/reboot", HTTP_POST, [](AsyncWebServerRequest* r) {
    if (!originOk(r)) { r->send(403); return; }
    r->send(200, "application/json", "{\"ok\":1}"); restartAt = millis() + 800;
  });

  server.addHandler(new AsyncCallbackJsonWebHandler("/api/cmd", [](AsyncWebServerRequest* r, JsonVariant& j) {
    if (!originOk(r)) { r->send(403); return; }
    uint8_t mac[6]; if (!parseMac(j["mac"] | "", mac)) { r->send(400, "application/json", "{\"err\":\"mac\"}"); return; }
    int i; { DevGuard g; i = findDev(mac); }
    if (i < 0) { r->send(404, "application/json", "{\"err\":\"unknown device\"}"); return; }
    uint8_t cmd = j["cmd"] | 0; uint8_t idx = j["idx"] | 0; uint8_t val = j["val"] | 0; float f = j["f"] | 0.0f;
    String text = j["text"] | "";
    if (cmd == C_RENAME && text.length()) {           // hub keeps the display name too
      { DevGuard g; copyStr(devs[i].name, sizeof(devs[i].name), text.c_str()); }
      devsSave(); stateDirty = true; devsDirty = true;
    }
    if (cmd == C_RELAY) {                            // optimistic: reflect immediately, edge confirms
      DevGuard g; if (val) devs[i].onMask |= (1 << idx); else devs[i].onMask &= ~(1 << idx); stateDirty = true;
    }
    sendCmd(mac, cmd, idx, val, f, text.c_str());
    r->send(200, "application/json", "{\"ok\":1}");
  }));
  server.addHandler(new AsyncCallbackJsonWebHandler("/api/forget", [](AsyncWebServerRequest* r, JsonVariant& j) {
    if (!originOk(r)) { r->send(403); return; }
    uint8_t mac[6]; if (!parseMac(j["mac"] | "", mac)) { r->send(400); return; }
    { DevGuard g; int i = findDev(mac); if (i >= 0) devs[i].used = false; }
    esp_now_del_peer(mac); devsSave(); stateDirty = true; devsDirty = true;
    dbg("Forgot " + macStr(mac));
    r->send(200, "application/json", "{\"ok\":1}");
  }));
  server.addHandler(new AsyncCallbackJsonWebHandler("/api/wifi", [](AsyncWebServerRequest* r, JsonVariant& j) {
    if (!originOk(r)) { r->send(403); return; }
    String s = j["ssid"] | ""; String p = j["pass"] | "";
    if (!s.length()) { r->send(400, "application/json", "{\"err\":\"ssid\"}"); return; }
    prefs.putString("ssid", s); if (p.length() || s != cfgSsid) prefs.putString("pass", p);
    r->send(200, "application/json", "{\"ok\":1}"); restartAt = millis() + 1000;   // clean restart onto the new network
  }));
  server.addHandler(new AsyncCallbackJsonWebHandler("/api/hubname", [](AsyncWebServerRequest* r, JsonVariant& j) {
    if (!originOk(r)) { r->send(403); return; }
    String n = j["name"] | ""; n.trim();
    if (n.length()) { hubName = n.substring(0, 23); prefs.putString("name", hubName); stateDirty = true; }
    r->send(200, "application/json", "{\"ok\":1}");
  }));

  // hub's own OTA
  server.on("/api/ota", HTTP_POST,
    [](AsyncWebServerRequest* r) {
      if (!originOk(r)) { r->send(403); return; }
      if (otaFailed || Update.hasError() || !Update.isFinished()) {
        r->send(500, "application/json", "{\"err\":\"" + (otaErr.length() ? otaErr : String(Update.errorString())) + "\"}"); return;
      }
      r->send(200, "application/json", "{\"ok\":1}"); dbg("Hub OTA installed - restarting"); restartAt = millis() + 1000;
    },
    [](AsyncWebServerRequest* r, const String& fn, size_t index, uint8_t* data, size_t len, bool final) {
      if (index == 0) {
        otaFailed = false; otaErr = "";
        if (!originOk(r)) { otaFailed = true; otaErr = "origin"; return; }
        if (Update.isRunning()) Update.abort();
        if (!Update.begin(UPDATE_SIZE_UNKNOWN, U_FLASH)) { otaFailed = true; otaErr = Update.errorString(); return; }
        dbg("Hub OTA: receiving " + fn);
      }
      if (otaFailed) return;
      if (Update.write(data, len) != len) { otaFailed = true; otaErr = Update.errorString(); Update.abort(); return; }
      if (final && !Update.end(true)) { otaFailed = true; otaErr = Update.errorString(); }
    });

  // edge OTA: upload the edge's .bin to the hub, then the hub streams it over ESP-NOW
  server.on("/api/edge-ota", HTTP_POST,
    [](AsyncWebServerRequest* r) {
      if (!originOk(r)) { r->send(403); return; }
      uint8_t mac[6];
      if (!r->hasParam("mac") || !parseMac(r->getParam("mac")->value(), mac)) { r->send(400, "application/json", "{\"err\":\"mac\"}"); return; }
      if (!eota.uploadOk) { r->send(500, "application/json", "{\"err\":\"" + eota.upErr + "\"}"); return; }
      if (!edgeOtaStart(mac)) { r->send(409, "application/json", "{\"err\":\"another update is running\"}"); return; }
      r->send(200, "application/json", "{\"ok\":1}");
    },
    [](AsyncWebServerRequest* r, const String&, size_t index, uint8_t* data, size_t len, bool final) {
      static File up;
      if (index == 0) {
        eota.uploadOk = false; eota.upErr = "";
        if (!originOk(r)) { eota.upErr = "origin"; return; }
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

/* ------------------------------ setup / loop ------------------------ */
void espNowBegin() {
  if (esp_now_init() != ESP_OK) { dbg("ESP-NOW init FAILED"); return; }
  esp_now_register_recv_cb(onRecv);
  esp_now_register_send_cb(onSent);
  dbg("ESP-NOW ready");
}

void setup() {
  devLock = xSemaphoreCreateMutex(); consoleLock = xSemaphoreCreateMutex();
  rxq = xQueueCreate(24, sizeof(RxItem)); txq = xQueueCreate(16, sizeof(TxItem));
  Serial.begin(115200); Serial.setTxTimeoutMs(0);

  uint8_t mac[6]; esp_read_mac(mac, ESP_MAC_WIFI_STA);
  char idb[16]; snprintf(idb, sizeof(idb), "HUB-%02x%02x%02x", mac[3], mac[4], mac[5]); hubId = idb;

  if (!LittleFS.begin(false)) { delay(100); if (!LittleFS.begin(false)) LittleFS.begin(true); }
  LittleFS.remove(EDGE_BIN);                         // leftover from an interrupted edge update
  prefs.begin("leohub", false);
  cfgSsid = prefs.getString("ssid", ""); cfgPass = prefs.getString("pass", "");
  hubName = prefs.getString("name", "LEO Home Hub");
  devsLoad();
  dbg("LEO Hub " HUB_FW " " + hubId);

  WiFi.persistent(false);
  WiFi.onEvent(wifiEvent);
  WiFi.mode(WIFI_STA);
  WiFi.setHostname("LEO-Hub");
  WiFi.setSleep(false);            // keep the radio awake: ESP-NOW edges must always be heard
  if (cfgSsid.length()) staBegin(); else apStart();
  espNowBegin();
  webBegin();

  esp_task_wdt_config_t wdt = { .timeout_ms = 15000, .idle_core_mask = 0, .trigger_panic = true };
  if (esp_task_wdt_init(&wdt) == ESP_ERR_INVALID_STATE) esp_task_wdt_reconfigure(&wdt);
  esp_task_wdt_add(NULL);
}

/* USB-serial setup (needs physical access): "SETWIFI\t<ssid>\t<password>\n"
   saves WiFi without the setup hotspot. The password is never echoed. */
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
    }
    in = "";
  }
}

void loop() {
  esp_task_wdt_reset();
  serialTick();
  ws.cleanupClients(); consoleWs.cleanupClients();
  wifiTick();

  RxItem it; int n = 0;
  while (n++ < 16 && xQueueReceive(rxq, &it, 0) == pdTRUE) handlePacket(it);
  TxItem t; n = 0;
  while (n++ < 8 && xQueueReceive(txq, &t, 0) == pdTRUE) sendTo(t.mac, &t.cmd, sizeof(t.cmd));
  edgeOtaTick();

  // online/offline transitions also count as state changes
  static uint32_t lastScan = 0;
  if (millis() - lastScan > 1000) {
    lastScan = millis();
    static uint32_t prevOnline = 0; uint32_t mask = 0;
    { DevGuard g; for (int i = 0; i < MAX_DEV; ++i) if (devs[i].used && devs[i].lastSeen && millis() - devs[i].lastSeen < OFFLINE_MS) mask |= (1u << i); }
    if (mask != prevOnline) { prevOnline = mask; stateDirty = true; }
  }
  // push to browsers: on change (max 4/s) and every 5 s regardless
  if (ws.count() && ((stateDirty && millis() - lastPush > 250) || millis() - lastPush > 5000)) {
    stateDirty = false; lastPush = millis(); ws.textAll(stateJson());
  }
  if (restartAt && (int32_t)(millis() - restartAt) >= 0) ESP.restart();
  delay(2);
}
