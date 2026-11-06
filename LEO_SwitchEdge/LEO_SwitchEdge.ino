/* =====================================================================
   LEO Switch Edge  -  LEO_SwitchEdge.ino   (ESP32-C3, Arduino-ESP32 core 3.x)

   A 4-relay LEO switch that is controlled ONLY through the LEO Home Hub
   over ESP-NOW. No WiFi password, no web server, no hotspot: power it on
   near the hub and it pairs automatically. Firmware updates arrive from
   the hub over ESP-NOW (Hub web app -> Devices -> Update firmware).

   Board settings: ESP32C3 Dev Module, USB CDC On Boot: Enabled,
     Partition Scheme: Minimal SPIFFS (1.9MB APP with OTA/128KB SPIFFS)
   Libraries: ArduinoJson 7, Adafruit NeoPixel

   Settings (relay names / GPIO / watts, device name) live in LittleFS
   /config.json - the same file the stand-alone LEO switch firmware uses,
   so converting an existing switch keeps its relay names.

   Status LED: amber pulse = looking for the hub, green = linked (turns off
   after 20 s), white blink = "Identify" from the web app.
   Relays: all OFF at power-up (fail-safe). If the hub goes away, relays
   KEEP their current state; the edge keeps searching for the hub.
   ===================================================================== */
#include <Arduino.h>
#include <WiFi.h>
#include <esp_now.h>
#include <esp_wifi.h>
#include <LittleFS.h>
#include <Preferences.h>
#include <Update.h>
#include <ArduinoJson.h>
#include <Adafruit_NeoPixel.h>
#include <esp_task_wdt.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>

#define EDGE_FW           "1.0.1-sw"
#define RELAY_COUNT       4
#define RELAY_ACTIVE_LOW  1
#define NEOPIXEL_PIN      2
#define CFG_FILE          "/config.json"
#define STATE_MS          2000        // heartbeat / state report
#define LINK_FAIL_LIMIT   5           // undelivered reports in a row -> search for the hub again
#define SCAN_DWELL_MS     250         // per channel while searching
#define NEW_HUB_AFTER_MS  300000UL    // accept a different hub only after the old one is gone 5 min
static const int RELAY_GPIO_POOL[RELAY_COUNT] = { 0, 1, 3, 10 };
static const char* RELAY_DEFAULT_NAMES[RELAY_COUNT] = { "Relay 1", "Relay 2", "Relay 3", "Relay 4" };

/* ===================== LEO EDGE PROTOCOL v1 ==========================
   Keep IDENTICAL in the hub and every edge sketch.                      */
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

struct Relay { String name; int gpio; float watts; bool on; uint32_t onSince; };
Relay relays[RELAY_COUNT];
String devName = "Smart Switch";

struct RxItem { uint8_t mac[6]; uint8_t len; uint8_t data[250]; };
QueueHandle_t rxq;
Preferences prefs;
Adafruit_NeoPixel pix(1, NEOPIXEL_PIN, NEO_GRB + NEO_KHZ800);

const uint8_t BCAST[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
uint8_t  hubMac[6] = { 0 };
bool     hubKnown = false, linked = false;
uint8_t  channel = 1, txSeq = 0;
volatile uint8_t sendFails = 0;
uint32_t lastState = 0, lastScanStep = 0, lastHubHeard = 0, linkedSince = 0, identifyUntil = 0, restartAt = 0;
bool     stateDirty = true;
// OTA receive
bool     otaActive = false; uint32_t otaSize = 0, otaWritten = 0;

/* ------------------------------ helpers ---------------------------- */
void dbg(const String& m) {           // never blocks (USB host present but not reading)
  String line = "[" + String(millis() / 1000) + "s] " + m;
  if (Serial && Serial.availableForWrite() >= (int)line.length() + 2) Serial.println(line);
}
void copyStr(char* dst, size_t n, const char* src) { strncpy(dst, src, n - 1); dst[n - 1] = 0; }
void fillHdr(LeoHdr& h, uint8_t type) { h.magic = LEO_MAGIC; h.proto = LEO_PROTO; h.type = type; h.dev = DEV_SWITCH; h.seq = ++txSeq; }
String macStr(const uint8_t* m) { char b[18]; snprintf(b, sizeof(b), "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]); return String(b); }

/* ------------------------------ relays ----------------------------- */
int relayOffLevel() { return RELAY_ACTIVE_LOW ? HIGH : LOW; }
int relayOnLevel()  { return RELAY_ACTIVE_LOW ? LOW : HIGH; }
void relaysInit() {
  for (int i = 0; i < RELAY_COUNT; ++i) {
    digitalWrite(relays[i].gpio, relayOffLevel());     // OFF before enabling the output
    pinMode(relays[i].gpio, OUTPUT);
    digitalWrite(relays[i].gpio, relayOffLevel());
    relays[i].on = false; relays[i].onSince = 0;
  }
}
void relaySet(int i, bool on) {
  if (i < 0 || i >= RELAY_COUNT || relays[i].on == on) return;
  relays[i].on = on; relays[i].onSince = on ? millis() : 0;
  digitalWrite(relays[i].gpio, on ? relayOnLevel() : relayOffLevel());
  dbg("Relay " + String(i) + " (" + relays[i].name + ") -> " + (on ? "ON" : "OFF"));
  stateDirty = true;
}

/* ------------------------------ config ----------------------------- */
void configLoad() {
  for (int i = 0; i < RELAY_COUNT; ++i) { relays[i].name = RELAY_DEFAULT_NAMES[i]; relays[i].gpio = RELAY_GPIO_POOL[i]; relays[i].watts = 60; }
  File f = LittleFS.open(CFG_FILE, "r"); if (!f) return;
  JsonDocument d; if (deserializeJson(d, f)) { f.close(); return; } f.close();
  devName = d["deviceName"] | devName.c_str();
  int i = 0;
  for (JsonObject o : d["relays"].as<JsonArray>()) {
    if (i >= RELAY_COUNT) break;
    relays[i].name = o["name"] | relays[i].name.c_str();
    int g = o["gpio"] | relays[i].gpio; bool ok = false;
    for (int k = 0; k < RELAY_COUNT; ++k) if (RELAY_GPIO_POOL[k] == g) ok = true;
    if (ok) relays[i].gpio = g;
    relays[i].watts = o["watts"] | relays[i].watts;
    i++;
  }
}
/* rewrite only the keys this edge owns; everything else in the file is kept */
void configSave() {
  JsonDocument d;
  File f = LittleFS.open(CFG_FILE, "r"); if (f) { deserializeJson(d, f); f.close(); }
  d["deviceName"] = devName;
  JsonArray a = d["relays"].to<JsonArray>();
  for (int i = 0; i < RELAY_COUNT; ++i) { JsonObject o = a.add<JsonObject>(); o["name"] = relays[i].name; o["gpio"] = relays[i].gpio; o["watts"] = relays[i].watts; }
  f = LittleFS.open(CFG_FILE, "w"); if (f) { serializeJson(d, f); f.close(); }
}

/* ------------------------------ ESP-NOW ---------------------------- */
void onRecv(const esp_now_recv_info_t* info, const uint8_t* data, int len) {
  if (len < (int)sizeof(LeoHdr) || len > 250) return;
  RxItem it; memcpy(it.mac, info->src_addr, 6); it.len = (uint8_t)len; memcpy(it.data, data, len);
  xQueueSend(rxq, &it, 0);
}
void onSent(const esp_now_send_info_t* info, esp_now_send_status_t st) {
  if (!info || !info->des_addr || memcmp(info->des_addr, hubMac, 6)) return;   // only count unicasts to the hub
  if (st == ESP_NOW_SEND_SUCCESS) sendFails = 0; else if (sendFails < 250) sendFails++;
}
void addPeer(const uint8_t* mac) {
  if (esp_now_is_peer_exist(mac)) esp_now_del_peer(mac);       // re-add so it follows the current channel
  esp_now_peer_info_t p = {}; memcpy(p.peer_addr, mac, 6); p.channel = 0; p.ifidx = WIFI_IF_STA; p.encrypt = false;
  esp_now_add_peer(&p);
}
void setChannel(uint8_t ch) {
  channel = ch;
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
  esp_wifi_set_promiscuous(false);
}
void sendHub(const void* d, size_t n) { if (hubKnown) esp_now_send(hubMac, (const uint8_t*)d, n); }

void sendHello(const uint8_t* to) {
  static uint32_t lastHello = 0;                   // safety net against any request loop
  if (lastHello && millis() - lastHello < 2000 && linked) return;
  lastHello = millis();
  MsgHello m = {}; fillHdr(m.h, M_HELLO);
  copyStr(m.fw, sizeof(m.fw), EDGE_FW); copyStr(m.name, sizeof(m.name), devName.c_str());
  esp_now_send(to, (const uint8_t*)&m, sizeof(m));
}
void sendInfo() {
  MsgSwInfo m = {}; fillHdr(m.h, M_SW_INFO);
  copyStr(m.name, sizeof(m.name), devName.c_str()); copyStr(m.fw, sizeof(m.fw), EDGE_FW); m.n = RELAY_COUNT;
  for (int i = 0; i < RELAY_COUNT; ++i) { copyStr(m.rname[i], sizeof(m.rname[i]), relays[i].name.c_str()); m.watts[i] = relays[i].watts; m.gpio[i] = (uint8_t)relays[i].gpio; }
  sendHub(&m, sizeof(m));
}
void sendState() {
  MsgSwState m = {}; fillHdr(m.h, M_SW_STATE);
  m.n = RELAY_COUNT; m.uptime = millis() / 1000;
  for (int i = 0; i < RELAY_COUNT; ++i) {
    if (relays[i].on) { m.onMask |= (1 << i); m.onSecs[i] = (millis() - relays[i].onSince) / 1000; }
  }
  sendHub(&m, sizeof(m));
  lastState = millis(); stateDirty = false;
}
void sendOtaAck(uint8_t phase, uint32_t off, bool ok, const char* err) {
  MsgOtaAck a = {}; fillHdr(a.h, M_OTA_ACK); a.phase = phase; a.off = off; a.ok = ok ? 1 : 0;
  copyStr(a.err, sizeof(a.err), err);
  sendHub(&a, sizeof(a));
}

void goSearching(const char* why) {
  if (linked) dbg(String("Hub link lost: ") + why);
  linked = false; sendFails = 0; lastScanStep = 0;
}
void becomeLinked(const uint8_t* mac, uint8_t ch, const char* hubName) {
  bool changed = !hubKnown || memcmp(mac, hubMac, 6) || ch != prefs.getUChar("ch", 0);
  memcpy(hubMac, mac, 6); hubKnown = true; setChannel(ch); addPeer(hubMac);
  if (changed) { prefs.putBytes("hub", hubMac, 6); prefs.putUChar("ch", ch); }
  linked = true; sendFails = 0; linkedSince = millis(); lastHubHeard = millis();
  dbg("Linked to hub " + macStr(hubMac) + " (" + hubName + ") on channel " + String(ch));
  sendInfo(); sendState();
}

void handleCmd(const MsgCmd* c) {
  switch (c->cmd) {
    case C_RELAY:   relaySet(c->idx, c->val); break;
    case C_ALL:     for (int i = 0; i < RELAY_COUNT; ++i) relaySet(i, c->val); break;
    case C_IDENTIFY: identifyUntil = millis() + 4000; break;
    case C_RENAME:  if (c->text[0]) { devName = String(c->text); configSave(); sendInfo(); } break;
    case C_RELAY_META:
      if (c->idx < RELAY_COUNT) {
        if (c->text[0]) relays[c->idx].name = String(c->text);
        float w = c->f; if (w >= 0 && w < 100000) relays[c->idx].watts = w;
        configSave(); sendInfo();
      } break;
    case C_REBOOT:  restartAt = millis() + 300; break;
    case C_INFO:                                   // val=1: the hub doesn't know us (forgotten) -> HELLO first
      if (c->val == 1) sendHello(hubMac);
      sendInfo(); stateDirty = true; break;
  }
}

void handlePacket(const RxItem& it) {
  const LeoHdr* h = (const LeoHdr*)it.data;
  if (h->magic != LEO_MAGIC || h->proto != LEO_PROTO) return;

  if (h->type == M_WELCOME && it.len >= sizeof(MsgWelcome)) {
    // accept our own hub; a different hub only if ours has been silent for a long time
    bool ours = hubKnown && !memcmp(it.mac, hubMac, 6);
    if (!ours && hubKnown && millis() - lastHubHeard < NEW_HUB_AFTER_MS && millis() > NEW_HUB_AFTER_MS) return;
    const MsgWelcome* w = (const MsgWelcome*)it.data;
    becomeLinked(it.mac, w->channel ? w->channel : channel, w->hubName);
    return;
  }
  if (!hubKnown || memcmp(it.mac, hubMac, 6)) return;       // commands only from our hub
  lastHubHeard = millis();

  if (h->type == M_CMD && it.len >= sizeof(MsgCmd)) { handleCmd((const MsgCmd*)it.data); return; }

  if (h->type == M_OTA_BEGIN && it.len >= sizeof(MsgOtaBegin)) {
    const MsgOtaBegin* b = (const MsgOtaBegin*)it.data;
    if (otaActive && otaSize == b->size && otaWritten == 0) { sendOtaAck(1, 0, true, ""); return; }   // duplicate
    if (Update.isRunning()) Update.abort();
    otaActive = Update.begin(b->size, U_FLASH); otaSize = b->size; otaWritten = 0;
    dbg("OTA begin " + String(b->size) + " bytes: " + (otaActive ? "ok" : Update.errorString()));
    sendOtaAck(1, 0, otaActive, otaActive ? "" : Update.errorString());
  } else if (h->type == M_OTA_DATA && it.len >= sizeof(LeoHdr) + 6) {
    const MsgOtaData* d = (const MsgOtaData*)it.data;
    uint32_t off = d->off; uint16_t len = d->len;
    if (!otaActive) { sendOtaAck(2, off, false, "no update in progress"); return; }
    if (off + len == otaWritten) { sendOtaAck(2, otaWritten, true, ""); return; }   // repeat of last chunk (ack was lost)
    if (off != otaWritten || len > sizeof(d->data)) return;                          // out of order: hub will resend
    uint8_t buf[200]; memcpy(buf, d->data, len);
    if (Update.write(buf, len) != len) { otaActive = false; Update.abort(); sendOtaAck(2, off, false, Update.errorString()); return; }
    otaWritten += len;
    sendOtaAck(2, otaWritten, true, "");
  } else if (h->type == M_OTA_END) {
    if (!otaActive) { sendOtaAck(3, otaWritten, false, "no update in progress"); return; }
    bool ok = (otaWritten == otaSize) && Update.end(true);
    otaActive = false;
    dbg(String("OTA end: ") + (ok ? "installed, restarting" : Update.errorString()));
    sendOtaAck(3, otaWritten, ok, ok ? "" : Update.errorString());
    if (ok) restartAt = millis() + 500;
  }
}

/* ------------------------------ link / LED ------------------------- */
void linkTick() {
  if (linked) {
    if (sendFails >= LINK_FAIL_LIMIT) goSearching("reports not delivered");
    return;
  }
  if (millis() - lastScanStep < SCAN_DWELL_MS) return;
  lastScanStep = millis();
  // dwell twice on the remembered channel, then sweep 1..13
  static uint8_t step = 0;
  uint8_t saved = prefs.getUChar("ch", 0);
  uint8_t k = step++ % 15;                         // 0,1 -> remembered channel; 2..14 -> channels 1..13
  uint8_t ch = (k < 2 && saved) ? saved : (uint8_t)((k < 2 ? k : k - 2) % 13 + 1);
  setChannel(ch);
  addPeer(BCAST);
  sendHello(BCAST);
}
void ledTick() {
  static uint32_t last = 0; if (millis() - last < 40) return; last = millis();
  if (millis() < identifyUntil) { bool on = (millis() / 150) % 2; pix.setPixelColor(0, on ? pix.Color(120, 120, 120) : 0); pix.show(); return; }
  if (!linked) { float ph = (sinf(millis() / 400.0f) + 1) / 2; pix.setPixelColor(0, pix.Color((uint8_t)(20 + ph * 60), (uint8_t)(8 + ph * 25), 0)); }
  else if (millis() - linkedSince < 20000) pix.setPixelColor(0, pix.Color(0, 25, 0));
  else pix.setPixelColor(0, 0);
  pix.show();
}

/* ------------------------------ setup / loop ------------------------ */
void setup() {
  rxq = xQueueCreate(16, sizeof(RxItem));
  Serial.begin(115200); Serial.setTxTimeoutMs(0);
  pix.begin(); pix.setBrightness(40); pix.setPixelColor(0, 0); pix.show();

  if (!LittleFS.begin(false)) { delay(100); if (!LittleFS.begin(false)) LittleFS.begin(true); }
  configLoad();
  relaysInit();                                   // all OFF, glitch-safe
  prefs.begin("leoedge", false);
  if (prefs.getBytes("hub", hubMac, 6) == 6) hubKnown = true;
  uint8_t ch = prefs.getUChar("ch", 1);

  WiFi.persistent(false);
  WiFi.mode(WIFI_STA);
  WiFi.disconnect(false, true);                   // never join a router; forget any stored AP
  WiFi.setSleep(false);
  WiFi.setTxPower(WIFI_POWER_8_5dBm);             // C3 radio is unstable at full power
  setChannel(ch ? ch : 1);
  if (esp_now_init() != ESP_OK) { dbg("ESP-NOW init failed - restarting"); delay(1000); ESP.restart(); }
  esp_now_register_recv_cb(onRecv);
  esp_now_register_send_cb(onSent);
  if (hubKnown) { addPeer(hubMac); sendHello(hubMac); }          // fast path: hub usually answers right away
  dbg("LEO Switch Edge " EDGE_FW " '" + devName + "' - looking for hub" + (hubKnown ? " " + macStr(hubMac) : String("")));

  esp_task_wdt_config_t wdt = { .timeout_ms = 10000, .idle_core_mask = 0, .trigger_panic = true };
  if (esp_task_wdt_init(&wdt) == ESP_ERR_INVALID_STATE) esp_task_wdt_reconfigure(&wdt);
  esp_task_wdt_add(NULL);
}

void loop() {
  esp_task_wdt_reset();
  RxItem it; int n = 0;
  while (n++ < 12 && xQueueReceive(rxq, &it, 0) == pdTRUE) handlePacket(it);
  linkTick();
  if (linked && !otaActive && (stateDirty || millis() - lastState >= STATE_MS)) sendState();
  ledTick();
  if (restartAt && (int32_t)(millis() - restartAt) >= 0) ESP.restart();
  delay(2);
}
