/* =====================================================================
   LEO Switch Edge  -  LEO_SwitchEdge.ino   (ESP32-C3, Arduino-ESP32 core 3.x)

   A 4-relay LEO switch that is controlled ONLY through the LEO Home Hub
   over ESP-NOW. No WiFi password, no web server, no hotspot: power it on
   near the hub (with "Allow new devices" pressed in the hub web app) and it
   pairs. Firmware updates arrive from the hub over ESP-NOW.

   Security (protocol v2): every packet from the hub must carry a valid
   HMAC-SHA256 signature made with this device's own 128-bit key, for the
   current session, with a counter higher than the last one - forged or
   replayed commands are ignored. The key is received once, when pairing.
   USB serial command "UNPAIR" (115200) forgets the hub + key (re-pair).

   Board settings: ESP32C3 Dev Module, USB CDC On Boot: Enabled,
     Partition Scheme: Minimal SPIFFS (1.9MB APP with OTA/128KB SPIFFS)
   Libraries: ArduinoJson 7, Adafruit NeoPixel

   Settings (relay names / GPIO / watts, device name) live in LittleFS
   /config.json - the same file the stand-alone LEO switch firmware uses.

   Status LED: amber pulse = looking for the hub, green = linked (turns off
   after 20 s), white blink = "Identify" from the web app.
   Relays: all OFF at power-up (fail-safe), never saved. If the hub goes
   away, relays KEEP their current state; the edge keeps searching.
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
#include <mbedtls/md.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>

#define EDGE_FW           "2.0.1-sw"
#define RELAY_COUNT       4
#define RELAY_ACTIVE_LOW  1
#define NEOPIXEL_PIN      2
#define CFG_FILE          "/config.json"
#define STATE_MS          2000        // heartbeat / state report
#define HUB_SILENT_MS     10000       // no verified packet from the hub this long -> search again
#define SCAN_DWELL_MS     250         // per channel while searching
static const int RELAY_GPIO_POOL[RELAY_COUNT] = { 0, 1, 3, 10 };
static const char* RELAY_DEFAULT_NAMES[RELAY_COUNT] = { "Relay 1", "Relay 2", "Relay 3", "Relay 4" };

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
enum : uint8_t { C_RELAY = 1, C_ALL = 2, C_IDENTIFY = 3, C_RENAME = 4, C_RELAY_META = 5, C_REBOOT = 6, C_INFO = 7, C_UNPAIR = 8 };
struct __attribute__((packed)) LeoHdr      { uint16_t magic; uint8_t proto; uint8_t type; uint8_t dev; uint8_t seq; };
struct __attribute__((packed)) LeoAuth     { uint32_t ctr; uint8_t tag[8]; };
struct __attribute__((packed)) MsgHello    { LeoHdr h; uint32_t nonce; uint8_t hasKey; char fw[16]; char name[24]; };
struct __attribute__((packed)) MsgWelcome  { LeoHdr h; uint8_t channel; uint8_t keyIncluded; uint8_t key[16]; char hubName[24]; };
struct __attribute__((packed)) MsgPing     { LeoHdr h; };
struct __attribute__((packed)) MsgSwState  { LeoHdr h; uint8_t n; uint8_t onMask; uint32_t uptime; uint32_t onSecs[4]; };
struct __attribute__((packed)) MsgSwInfo   { LeoHdr h; char name[24]; char fw[16]; uint8_t n; char rname[4][20]; float watts[4]; uint8_t gpio[4]; };
struct __attribute__((packed)) MsgTankState{ LeoHdr h; float levelPct; float distCm; uint8_t leds; uint8_t state; uint8_t sensorOk; uint8_t flags; uint32_t uptime; char stateTxt[24]; };
struct __attribute__((packed)) MsgCmd      { LeoHdr h; uint8_t cmd; uint8_t idx; uint8_t val; float f; char text[24]; };
struct __attribute__((packed)) MsgOtaBegin { LeoHdr h; uint32_t size; };
struct __attribute__((packed)) MsgOtaData  { LeoHdr h; uint32_t off; uint16_t len; uint8_t data[200]; };
struct __attribute__((packed)) MsgOtaAck   { LeoHdr h; uint8_t phase; uint32_t off; uint8_t ok; char err[24]; };

/* types used by functions must precede the first function (Arduino auto-prototypes) */
struct RxItem { uint8_t mac[6]; uint8_t len; uint8_t data[250]; };

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
size_t leoSign(uint8_t* out, const void* body, size_t len, const uint8_t* key, uint32_t session, uint32_t ctr) {
  memcpy(out, body, len);
  LeoAuth a; a.ctr = ctr; leoTag(key, session, out, len, ctr, a.tag);
  memcpy(out + len, &a, sizeof(a));
  return len + sizeof(a);
}
size_t leoVerify(const uint8_t* pkt, size_t total, const uint8_t* key, uint32_t session, uint32_t* ctr) {
  if (total < sizeof(LeoHdr) + sizeof(LeoAuth)) return 0;
  size_t len = total - sizeof(LeoAuth);
  LeoAuth a; memcpy(&a, pkt + len, sizeof(a));
  uint8_t t[8]; leoTag(key, session, pkt, len, a.ctr, t);
  uint8_t diff = 0; for (int i = 0; i < 8; ++i) diff |= t[i] ^ a.tag[i];
  if (diff) return 0;
  *ctr = a.ctr; return len;
}
/* ===================================================================== */

struct Relay { String name; int gpio; float watts; bool on; uint32_t onSince; };
Relay relays[RELAY_COUNT];
String devName = "Smart Switch";

QueueHandle_t rxq;
Preferences prefs;
Adafruit_NeoPixel pix(1, NEOPIXEL_PIN, NEO_GRB + NEO_KHZ800);

const uint8_t BCAST[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
uint8_t  hubMac[6] = { 0 };
bool     hubKnown = false, linked = false;
uint8_t  key[16]; bool hasKey = false;
uint32_t nonce = 0, txCtr = 0, rxCtr = 0;
uint8_t  channel = 1, txSeq = 0;
uint8_t scanStep = 0;
uint32_t lastState = 0, lastScanStep = 0, lastVerified = 0, linkedSince = 0, identifyUntil = 0, restartAt = 0;
bool     stateDirty = true;
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
void configSave() {             // rewrite only the keys this edge owns; everything else is kept
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
void onSent(const esp_now_send_info_t*, esp_now_send_status_t) {}
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
void sendHub(const void* body, size_t len) {                    // signed with our key + session
  if (!hubKnown || !hasKey || !linked) return;
  uint8_t buf[250]; size_t n = leoSign(buf, body, len, key, nonce, ++txCtr);
  esp_now_send(hubMac, buf, n);
}
void sendHello(const uint8_t* to) {
  MsgHello m = {}; fillHdr(m.h, M_HELLO);
  m.nonce = nonce; m.hasKey = hasKey ? 1 : 0;
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
  for (int i = 0; i < RELAY_COUNT; ++i) if (relays[i].on) { m.onMask |= (1 << i); m.onSecs[i] = (millis() - relays[i].onSince) / 1000; }
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
  linked = false; lastScanStep = 0; scanStep = 0;                 // retry the hub's last channel first
  do { nonce = esp_random(); } while (!nonce);                  // fresh session: old packets can't be replayed
  txCtr = 0; rxCtr = 0;
}
void forgetHub(const char* why) {
  dbg(String("Unpairing: ") + why);
  hasKey = false; hubKnown = false; memset(key, 0, sizeof(key));
  prefs.remove("key"); prefs.remove("hub");
  goSearching("unpaired");
}

void handleCmd(const MsgCmd& c) {
  switch (c.cmd) {
    case C_RELAY:   relaySet(c.idx, c.val); break;
    case C_ALL:     for (int i = 0; i < RELAY_COUNT; ++i) relaySet(i, c.val); break;
    case C_IDENTIFY: identifyUntil = millis() + 4000; break;
    case C_RENAME:  if (c.text[0]) { devName = String(c.text); configSave(); sendInfo(); } break;
    case C_RELAY_META:
      if (c.idx < RELAY_COUNT) {
        if (c.text[0]) relays[c.idx].name = String(c.text);
        float w = c.f; if (w >= 0 && w < 100000) relays[c.idx].watts = w;
        configSave(); sendInfo();
      } break;
    case C_REBOOT:  restartAt = millis() + 300; break;
    case C_INFO:    sendInfo(); stateDirty = true; break;
    case C_UNPAIR:  forgetHub("hub asked us to forget it"); break;
  }
}

void handleWelcome(const RxItem& it) {
  if (linked && hubKnown && !memcmp(it.mac, hubMac, 6)) return;   // already linked in this session
  if (it.len < sizeof(MsgWelcome) + sizeof(LeoAuth)) return;
  MsgWelcome w; memcpy(&w, it.data, sizeof(w));
  uint8_t k[16]; bool newKey = false;
  if (hasKey) memcpy(k, key, 16);
  else if (w.keyIncluded) { memcpy(k, w.key, 16); newKey = true; }
  else return;                                                   // we need a key and none was offered
  uint32_t ctr;
  if (!leoVerify(it.data, it.len, k, nonce, &ctr)) return;       // not our hub / not our session
  if (newKey) { memcpy(key, k, 16); hasKey = true; prefs.putBytes("key", key, 16); dbg("Received security key from hub"); }
  rxCtr = ctr;
  bool changed = !hubKnown || memcmp(it.mac, hubMac, 6) || w.channel != prefs.getUChar("ch", 0);
  memcpy(hubMac, it.mac, 6); hubKnown = true;
  if (w.channel) setChannel(w.channel);
  addPeer(hubMac);
  if (changed) { prefs.putBytes("hub", hubMac, 6); prefs.putUChar("ch", channel); }
  linked = true; linkedSince = millis(); lastVerified = millis();
  dbg("Linked to hub " + macStr(hubMac) + " (" + String(w.hubName) + ") on channel " + String(channel) + " - signed session");
  sendInfo(); sendState();
}

void handlePacket(const RxItem& it) {
  const LeoHdr* h = (const LeoHdr*)it.data;
  if (h->magic != LEO_MAGIC || h->proto != LEO_PROTO) return;
  if (h->type == M_WELCOME) { handleWelcome(it); return; }
  if (!linked || !hubKnown || !hasKey || memcmp(it.mac, hubMac, 6)) return;

  uint32_t ctr; size_t blen = leoVerify(it.data, it.len, key, nonce, &ctr);
  if (!blen || ctr <= rxCtr) return;                             // forged, wrong session or replay
  rxCtr = ctr; lastVerified = millis();

  if (h->type == M_PING) return;
  if (h->type == M_CMD && blen >= sizeof(MsgCmd)) { MsgCmd c; memcpy(&c, it.data, sizeof(c)); handleCmd(c); return; }

  if (h->type == M_OTA_BEGIN && blen >= sizeof(MsgOtaBegin)) {
    MsgOtaBegin b; memcpy(&b, it.data, sizeof(b));
    if (otaActive && otaSize == b.size && otaWritten == 0) { sendOtaAck(1, 0, true, ""); return; }   // duplicate
    if (Update.isRunning()) Update.abort();
    otaActive = Update.begin(b.size, U_FLASH); otaSize = b.size; otaWritten = 0;
    dbg("OTA begin " + String(b.size) + " bytes: " + (otaActive ? "ok" : Update.errorString()));
    sendOtaAck(1, 0, otaActive, otaActive ? "" : Update.errorString());
  } else if (h->type == M_OTA_DATA && blen >= sizeof(LeoHdr) + 6) {
    MsgOtaData d; memcpy(&d, it.data, min(blen, sizeof(d)));
    uint32_t off = d.off; uint16_t len = d.len;
    if (!otaActive) { sendOtaAck(2, off, false, "no update in progress"); return; }
    if (off + len == otaWritten) { sendOtaAck(2, otaWritten, true, ""); return; }   // repeat of last chunk (ack lost)
    if (off != otaWritten || len > sizeof(d.data) || blen < sizeof(LeoHdr) + 6 + len) return;
    if (Update.write(d.data, len) != len) { otaActive = false; Update.abort(); sendOtaAck(2, off, false, Update.errorString()); return; }
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
    if (millis() - lastVerified > HUB_SILENT_MS) goSearching("no signed packet from the hub");
    return;
  }
  if (millis() - lastScanStep < SCAN_DWELL_MS) return;
  lastScanStep = millis();
  uint8_t saved = prefs.getUChar("ch", 0);
  uint8_t k = scanStep++ % 15;                        // 0,1 -> remembered channel; 2..14 -> channels 1..13
  uint8_t ch = (k < 2 && saved) ? saved : (uint8_t)((k < 2 ? k : k - 2) % 13 + 1);
  setChannel(ch);
  if (hubKnown && k < 2) { addPeer(hubMac); sendHello(hubMac); }
  else { addPeer(BCAST); sendHello(BCAST); }
}
void ledTick() {
  static uint32_t last = 0; if (millis() - last < 40) return; last = millis();
  if (millis() < identifyUntil) { bool on = (millis() / 150) % 2; pix.setPixelColor(0, on ? pix.Color(120, 120, 120) : 0); pix.show(); return; }
  if (!linked) { float ph = (sinf(millis() / 400.0f) + 1) / 2; pix.setPixelColor(0, pix.Color((uint8_t)(20 + ph * 60), (uint8_t)(8 + ph * 25), 0)); }
  else if (millis() - linkedSince < 20000) pix.setPixelColor(0, pix.Color(0, 25, 0));
  else pix.setPixelColor(0, 0);
  pix.show();
}
void serialTick() {                                 // USB: "UNPAIR" forgets the hub and key
  static String in;
  while (Serial.available()) {
    char c = Serial.read(); if (c == '\r') continue;
    if (c != '\n') { if (in.length() < 40) in += c; continue; }
    if (in == "UNPAIR") forgetHub("USB command");
    in = "";
  }
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
  if (prefs.getBytes("key", key, 16) == 16) hasKey = true;
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
  goSearching("boot");
  dbg("LEO Switch Edge " EDGE_FW " '" + devName + "' - " + (hasKey ? "paired, looking for hub" : "not paired yet"));

  esp_task_wdt_config_t wdt = { .timeout_ms = 10000, .idle_core_mask = 0, .trigger_panic = true };
  if (esp_task_wdt_init(&wdt) == ESP_ERR_INVALID_STATE) esp_task_wdt_reconfigure(&wdt);
  esp_task_wdt_add(NULL);
}

void loop() {
  esp_task_wdt_reset();
  serialTick();
  RxItem it; int n = 0;
  while (n++ < 12 && xQueueReceive(rxq, &it, 0) == pdTRUE) handlePacket(it);
  linkTick();
  if (linked && !otaActive && (stateDirty || millis() - lastState >= STATE_MS)) sendState();
  ledTick();
  if (restartAt && (int32_t)(millis() - restartAt) >= 0) ESP.restart();
  delay(2);
}
