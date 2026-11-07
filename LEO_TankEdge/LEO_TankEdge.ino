/* =====================================================================
   LEO Tank Edge  -  LEO_TankEdge.ino   (ESP32-C3 Super Mini, Arduino-ESP32 core 3.x)

   The AquaNode water-tank monitor as a LEO edge device: it measures the
   tank, shows the level on its LED strip and sounds full / low alerts on
   its own - with or without the hub - and reports to the LEO Home Hub over
   signed ESP-NOW (protocol v2). No WiFi password, no web server, no hotspot.
   Firmware updates arrive from the hub over ESP-NOW.

   Hardware (same wiring as tank_v9 / AquaNode v2.12):
     HC-SR04  TRIG GPIO4, ECHO GPIO3      9x WS2812B  GPIO2 (GRB)
     LDR      GPIO0 (ADC, higher = brighter)
     Button   GPIO1 to GND                 Buzzer      GPIO10 (HIGH = sound)
   LED strip: LEDs 0..6 = level (bottom red -> top blue), LED 7 spare,
              LED 8 = faint status blink (same meaning as the LEO switch).

   Behaviour
     - Level: distance tankFullCm (15 cm) = 100 %, tankEmptyCm (103 cm) = 0 %.
     - Alerts: FULL at >= 95 % (long beeps, green), LOW at <= 10 % (short
       beeps, red), 10 rounds each, then quiet until the level is back in
       the normal band (15..90 %). The button silences the current alert.
       The buzzer only sounds when the room is lit (LDR) - quiet at night.
     - No sensor / sensor error: level LEDs off, status reports the fault,
       no alarms. Three good readings in a row clear the fault.
     - Level LEDs follow room light (dark room -> LEDs off), like before.

   Board settings: ESP32C3 Dev Module, USB CDC On Boot: Enabled,
     Partition Scheme: Minimal SPIFFS (1.9MB APP with OTA/128KB SPIFFS)
   Libraries: Adafruit NeoPixel
   USB serial (115200): "UNPAIR" forgets the hub + key.
   ===================================================================== */
#include <Arduino.h>
#include <WiFi.h>
#include <esp_now.h>
#include <esp_wifi.h>
#include <Preferences.h>
#include <Update.h>
#include <Adafruit_NeoPixel.h>
#include <esp_task_wdt.h>
#include <mbedtls/md.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>

#define EDGE_FW           "1.2.0-tank"
#define TRIG_PIN          4
#define ECHO_PIN          3
#define LDR_PIN           0
#define BTN_PIN           1
#define BUZZER_PIN        10
#define LED_PIN           2
#define NUM_LEDS          9
#define LEVEL_LEDS        7
#define STATUS_LED        8
#define STATE_MS          2000        // report to the hub
#define HUB_SILENT_MS     10000       // no verified packet from the hub this long -> search again
#define SCAN_DWELL_MS     250         // per channel while searching
#define MEASURE_MS        1500        // one level measurement (10 pings) this often
#define FULL_PCT          95
#define LOW_PCT           10
#define REARM_LOW_PCT     15
#define REARM_HIGH_PCT    90
#define ALERT_ROUNDS      10
#define LIT_ON_LDR        120         // room counts as lit above this ...
#define LIT_OFF_LDR       80          // ... and as dark again below this (no flicker at dusk)
#define QUIET_FROM_H      22          // buzzer also quiet 22:00-06:00 (clock from the hub)
#define QUIET_TO_H        6

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
struct __attribute__((packed)) MsgPing     { LeoHdr h; int16_t mins; uint8_t room; };   // mins: hub local time (-1 unknown); room: 1 lit, 0 dark, 255 unknown (from the tank's LDR)
struct __attribute__((packed)) MsgSwState  { LeoHdr h; uint8_t n; uint8_t onMask; uint32_t uptime; uint32_t onSecs[4]; };
struct __attribute__((packed)) MsgSwInfo   { LeoHdr h; char name[24]; char fw[16]; uint8_t n; char rname[4][20]; float watts[4]; uint8_t gpio[4]; uint8_t touch; };   // touch: 1 = touch buttons enabled (switch 2.2+)
struct __attribute__((packed)) MsgTankState{ LeoHdr h; float levelPct; float distCm; uint8_t leds; uint8_t state; uint8_t sensorOk; uint8_t flags; uint32_t uptime; char stateTxt[24]; uint16_t ldr; };   // ldr: room light 0..4095 (tank 1.1+)
struct __attribute__((packed)) MsgCmd      { LeoHdr h; uint8_t cmd; uint8_t idx; uint8_t val; float f; char text[24]; };
struct __attribute__((packed)) MsgOtaBegin { LeoHdr h; uint32_t size; };
struct __attribute__((packed)) MsgOtaData  { LeoHdr h; uint32_t off; uint16_t len; uint8_t data[200]; };
struct __attribute__((packed)) MsgOtaAck   { LeoHdr h; uint8_t phase; uint32_t off; uint8_t ok; char err[24]; };

/* types used by functions must precede the first function (Arduino auto-prototypes) */
struct RxItem { uint8_t mac[6]; uint8_t len; uint8_t data[250]; };
enum TankState : uint8_t { T_NORMAL = 0, T_FULL = 1, T_LOW = 2, T_SENSOR = 3, T_BOOT = 4 };
enum AlertKind : uint8_t { A_NONE = 0, A_FULL = 1, A_LOW = 2 };

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

String devName = "Water tank";
float  tankFullCm = 15.0f, tankEmptyCm = 103.0f;     // calibration (Preferences "full" / "empty")

QueueHandle_t rxq;
Preferences prefs;
Adafruit_NeoPixel strip(NUM_LEDS, LED_PIN, NEO_GRB + NEO_KHZ800);

const uint8_t BCAST[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
uint8_t  hubMac[6] = { 0 };
bool     hubKnown = false, linked = false;
uint8_t  key[16]; bool hasKey = false;
uint32_t nonce = 0, txCtr = 0, rxCtr = 0;
uint8_t  channel = 1, txSeq = 0, scanStep = 0;
int16_t  hubMins = -1; uint32_t hubMinsAt = 0;
uint32_t lastState = 0, lastScanStep = 0, lastVerified = 0, linkedSince = 0, identifyUntil = 0, restartAt = 0;
bool     stateDirty = true;
bool     otaActive = false; uint32_t otaSize = 0, otaWritten = 0;

// tank state
float    distCm = 0, levelPct = 0;
bool     sensorOk = false;              // false until the first good measurement
uint8_t  goodStreak = 0, badStreak = 0;
uint8_t  levelLeds = 0;                 // 0..LEVEL_LEDS
int      ldrRaw = 0;
TankState tstate = T_BOOT;
AlertKind alertNow = A_NONE;            // alert currently sounding
bool     armedFull = true, armedLow = true;
uint8_t  alertRound = 0; uint32_t alertPhaseAt = 0; bool alertOn = false;
bool     silenced = false;              // button pressed during this alert

/* ------------------------------ helpers ---------------------------- */
void dbg(const String& m) {           // never blocks (USB host present but not reading)
  String line = "[" + String(millis() / 1000) + "s] " + m;
  if (Serial && Serial.availableForWrite() >= (int)line.length() + 2) Serial.println(line);
}
void copyStr(char* dst, size_t n, const char* src) { strncpy(dst, src, n - 1); dst[n - 1] = 0; }
void fillHdr(LeoHdr& h, uint8_t type) { h.magic = LEO_MAGIC; h.proto = LEO_PROTO; h.type = type; h.dev = DEV_TANK; h.seq = ++txSeq; }
String macStr(const uint8_t* m) { char b[18]; snprintf(b, sizeof(b), "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]); return String(b); }
bool litState = true;
bool roomLit() { return litState; }
int  clockMins() {                                       // local time from the hub, -1 if unknown
  if (hubMins < 0 || millis() - hubMinsAt > 24UL * 3600 * 1000) return -1;
  return (hubMins + (int)((millis() - hubMinsAt) / 60000)) % 1440;
}
bool quietHours() { int m = clockMins(); return m >= 0 && (m >= QUIET_FROM_H * 60 || m < QUIET_TO_H * 60); }
bool buzzerAllowed() { return roomLit() && !quietHours(); }

/* ------------------------------ sensors ---------------------------- */
float pingOnceCm() {                    // one HC-SR04 ping; <0 = no echo
  digitalWrite(TRIG_PIN, LOW); delayMicroseconds(2);
  digitalWrite(TRIG_PIN, HIGH); delayMicroseconds(10);
  digitalWrite(TRIG_PIN, LOW);
  unsigned long us = pulseIn(ECHO_PIN, HIGH, 25000);       // ~4 m max
  if (us == 0) return -1;
  float cm = us * 0.0343f / 2;
  return (cm < 2 || cm > 400) ? -1 : cm;
}
// 10 pings spread over the measurement period (one per call, ~150 ms apart), median of the good ones
float    pings[10]; uint8_t pingCount = 0, pingFails = 0; uint32_t lastPingAt = 0;
void measureTick() {
  if (millis() - lastPingAt < MEASURE_MS / 10) return;
  lastPingAt = millis();
  float cm = pingOnceCm();
  if (cm < 0) pingFails++; else pings[pingCount - pingFails] = cm;
  pingCount++;
  if (pingCount < 10) return;

  int good = pingCount - pingFails; pingCount = pingFails = 0;
  if (good < 5) {                                         // sensor missing / not seeing water
    goodStreak = 0;
    if (++badStreak >= 2 && sensorOk) { sensorOk = false; stateDirty = true; dbg("Ultrasonic sensor: no echo"); }
    if (!sensorOk) { distCm = 0; levelPct = 0; levelLeds = 0; }
    return;
  }
  for (int i = 1; i < good; ++i) { float v = pings[i]; int j = i - 1; while (j >= 0 && pings[j] > v) { pings[j + 1] = pings[j]; j--; } pings[j + 1] = v; }
  float med = pings[good / 2];
  badStreak = 0;
  if (!sensorOk) { if (++goodStreak < 3) return; sensorOk = true; dbg("Ultrasonic sensor OK"); }
  distCm = med;
  float pct = (tankEmptyCm - med) * 100.0f / (tankEmptyCm - tankFullCm);
  levelPct = constrain(pct, 0.0f, 100.0f);
  uint8_t leds = (uint8_t)roundf(levelPct * LEVEL_LEDS / 100.0f);
  if (leds != levelLeds || fabsf(levelPct - pct) > 1) stateDirty = true;
  levelLeds = leds;
}
void ldrTick() {
  static uint32_t last = 0; if (millis() - last < 500) return; last = millis();
  long s = 0; for (int i = 0; i < 16; ++i) s += analogRead(LDR_PIN);
  ldrRaw = s / 16;
  bool lit = litState ? ldrRaw > LIT_OFF_LDR : ldrRaw > LIT_ON_LDR;
  if (lit != litState) { litState = lit; stateDirty = true; dbg(lit ? "Room is lit" : "Room is dark"); }
}

/* ------------------------------ alerts ----------------------------- */
void buzzer(bool on) { digitalWrite(BUZZER_PIN, on ? HIGH : LOW); }
void stopAlert() { alertNow = A_NONE; alertOn = false; buzzer(false); stateDirty = true; }
void alertTick() {
  if (!sensorOk) { if (alertNow) stopAlert(); tstate = T_SENSOR; return; }
  // re-arm once the level is back in the normal band
  if (levelPct >= REARM_LOW_PCT && levelPct <= REARM_HIGH_PCT) { armedFull = armedLow = true; silenced = false; }
  TankState s = levelPct >= FULL_PCT ? T_FULL : levelPct <= LOW_PCT ? T_LOW : T_NORMAL;
  if (s != tstate) { tstate = s; stateDirty = true; }

  if (!alertNow) {
    if (s == T_FULL && armedFull) { alertNow = A_FULL; armedFull = false; }
    else if (s == T_LOW && armedLow) { alertNow = A_LOW; armedLow = false; }
    else return;
    alertRound = 0; alertOn = false; alertPhaseAt = 0; silenced = false; stateDirty = true;
    dbg(alertNow == A_FULL ? "ALERT: tank full" : "ALERT: tank low");
  }
  if (silenced || (alertNow == A_FULL && s != T_FULL) || (alertNow == A_LOW && s != T_LOW)) { stopAlert(); return; }
  uint32_t onMs = alertNow == A_FULL ? 500 : 200, offMs = alertNow == A_FULL ? 500 : 300;
  if (millis() - alertPhaseAt < (alertOn ? onMs : offMs)) return;
  alertPhaseAt = millis();
  if (alertOn) { alertOn = false; buzzer(false); if (++alertRound >= ALERT_ROUNDS) stopAlert(); }
  else { alertOn = true; buzzer(buzzerAllowed()); }      // quiet in a dark room or 22-06; LEDs still flash
}

/* ------------------------------ button ----------------------------- */
uint32_t btnFeedbackUntil = 0;
void buttonTick() {
  static bool stable = true, raw = true; static uint32_t changedAt = 0;
  bool r = digitalRead(BTN_PIN);                          // HIGH = released (pull-up)
  if (r != raw) { raw = r; changedAt = millis(); return; }
  if (r == stable || millis() - changedAt < 40) return;
  stable = r;
  if (r == LOW) {                                         // pressed
    if (alertNow) { silenced = true; dbg("Alert silenced by button"); }
    btnFeedbackUntil = millis() + 400;
  }
}

/* ------------------------------ LEDs ------------------------------- */
const uint8_t GRAD[LEVEL_LEDS][3] = { {255,0,0}, {223,0,32}, {159,0,96}, {128,0,128}, {64,0,191}, {32,0,223}, {0,0,255} };
float daylight() { return roomLit() ? 1 : 0; }           // the tank's own LDR is the room's light sensor
uint8_t breathLevel(uint32_t period, uint8_t peak) {     // quick sine breath at the start of each period
  uint32_t len = period < 1000 ? period * 4 / 5 : 800, t = millis() % period;
  if (t >= len) return 0;
  float s = sinf(PI * t / len);
  return (uint8_t)(s * s * peak + 0.5f);
}
void ledTick() {
  static uint32_t last = 0; if (millis() - last < 30) return; last = millis();
  // level brightness follows the room, like the original: dark room -> level LEDs off
  int br = map(ldrRaw, 10, 4000, 1, 255); br = constrain(br, 0, 255); if (br < 3) br = 0;
  uint32_t c[NUM_LEDS]; for (int i = 0; i < NUM_LEDS; ++i) c[i] = 0;
  auto scaled = [&](uint8_t r, uint8_t g, uint8_t b, int k) { return strip.Color(r * k / 255, g * k / 255, b * k / 255); };

  if (millis() < identifyUntil) {
    bool on = (millis() / 150) % 2; for (int i = 0; i < NUM_LEDS; ++i) c[i] = on ? strip.Color(60, 60, 60) : 0;
  } else if (millis() < btnFeedbackUntil) {
    for (int i = 0; i < LEVEL_LEDS; ++i) c[i] = scaled(128, 0, 128, max(br, 20));     // purple = button seen
  } else if (alertNow && alertOn) {
    for (int i = 0; i < LEVEL_LEDS; ++i) c[i] = alertNow == A_FULL ? scaled(0, 255, 0, max(br, 20)) : scaled(255, 0, 0, max(br, 20));
  } else if (sensorOk) {
    for (int i = 0; i < levelLeds && i < LEVEL_LEDS; ++i) c[i] = scaled(GRAD[i][0], GRAD[i][1], GRAD[i][2], br);
  }
  // LED 8: faint quick breath, same scheme as the LEO switch; red = sensor fault
  uint8_t r, g, b; uint32_t period;
  if (otaActive)        { r = 0; g = 1; b = 1; period = 500;  }
  else if (!linked)     { r = hasKey ? 1 : 0; g = hasKey ? 1 : 0; b = hasKey ? 0 : 1; period = 2000; }
  else if (!sensorOk)   { r = 1; g = 0; b = 0; period = 2000; }
  else                  { r = 0; g = 1; b = 0; period = 5000; }
  uint8_t k = breathLevel(period, daylight() > 0.5f ? 5 : 2);   // quick faint breath, like every LEO device
  if (millis() >= identifyUntil && k) c[STATUS_LED] = strip.Color(r * k, g * k, b * k);

  static uint32_t shown[NUM_LEDS]; static bool first = true; bool dirty = first; first = false;
  for (int i = 0; i < NUM_LEDS; ++i) if (shown[i] != c[i]) { shown[i] = c[i]; strip.setPixelColor(i, c[i]); dirty = true; }
  if (dirty) strip.show();
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
const char* stateText() {
  if (otaActive) return "Updating firmware";
  if (!sensorOk) return tstate == T_BOOT ? "Starting" : "Sensor not connected";
  if (alertNow == A_FULL) return silenced ? "Full (silenced)" : "FULL - alarm";
  if (alertNow == A_LOW)  return silenced ? "Low (silenced)" : "LOW - alarm";
  if (tstate == T_FULL) return "Full";
  if (tstate == T_LOW)  return "Low";
  return "Normal";
}
void sendState() {
  MsgTankState m = {}; fillHdr(m.h, M_TANK_STATE);
  m.levelPct = sensorOk ? levelPct : 0; m.distCm = sensorOk ? distCm : 0;
  m.leds = sensorOk ? (uint8_t)roundf(levelPct * 9 / 100.0f) : 0;          // hub draws a 9-segment bar
  m.state = tstate; m.sensorOk = sensorOk ? 1 : 0;
  m.flags = (alertNow ? 1 : 0) | (silenced ? 2 : 0) | (roomLit() ? 0 : 4);
  m.uptime = millis() / 1000;
  copyStr(m.stateTxt, sizeof(m.stateTxt), stateText());
  m.ldr = (uint16_t)ldrRaw;
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
    case C_IDENTIFY: identifyUntil = millis() + 4000; break;
    case C_RENAME:   if (c.text[0]) { devName = String(c.text); prefs.putString("name", devName); } break;
    case C_REBOOT:   restartAt = millis() + 300; break;
    case C_INFO:     stateDirty = true; break;
    case C_UNPAIR:   forgetHub("hub asked us to forget it"); break;
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
  sendState();
}

void handlePacket(const RxItem& it) {
  const LeoHdr* h = (const LeoHdr*)it.data;
  if (h->magic != LEO_MAGIC || h->proto != LEO_PROTO) return;
  if (h->type == M_WELCOME) { handleWelcome(it); return; }
  if (!linked || !hubKnown || !hasKey || memcmp(it.mac, hubMac, 6)) return;

  uint32_t ctr; size_t blen = leoVerify(it.data, it.len, key, nonce, &ctr);
  if (!blen || ctr <= rxCtr) return;                             // forged, wrong session or replay
  rxCtr = ctr; lastVerified = millis();

  if (h->type == M_PING) {
    if (blen >= sizeof(LeoHdr) + 2) { MsgPing p = {}; memcpy(&p, it.data, min(blen, sizeof(p))); if (p.mins >= 0 && p.mins < 1440) { hubMins = p.mins; hubMinsAt = millis(); } }
    return;
  }
  if (h->type == M_CMD && blen >= sizeof(MsgCmd)) { MsgCmd c; memcpy(&c, it.data, sizeof(c)); handleCmd(c); return; }

  if (h->type == M_OTA_BEGIN && blen >= sizeof(MsgOtaBegin)) {
    MsgOtaBegin b; memcpy(&b, it.data, sizeof(b));
    if (otaActive && otaSize == b.size && otaWritten == 0) { sendOtaAck(1, 0, true, ""); return; }   // duplicate
    if (Update.isRunning()) Update.abort();
    buzzer(false); alertNow = A_NONE;
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

/* ------------------------------ link ------------------------------- */
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
void serialTick() {                                 // USB: "UNPAIR" forgets the hub and key
  static String in;
  while (Serial.available()) {
    char c = Serial.read(); if (c == '\r') continue;
    if (c != '\n') { if (in.length() < 40) in += c; continue; }
    if (in == "UNPAIR") forgetHub("USB command");
    in = "";
  }
}
void statusPrint() {                                // once every 5 s on USB, for bench testing
  static uint32_t last = 0; if (millis() - last < 5000) return; last = millis();
  dbg("dist " + String(distCm, 1) + " cm, level " + String(levelPct, 0) + "%, leds " + String(levelLeds) +
      ", ldr " + String(ldrRaw) + ", sensor " + (sensorOk ? "ok" : "none") + ", " + stateText() + (linked ? ", linked" : ", searching"));
}

/* ------------------------------ setup / loop ------------------------ */
/* Power-on check, before anything else: red -> blue -> green sweep over the whole strip (~1.2 s)
   = "power is good, LEDs work". The room light is read FIRST from our own LDR, so at night the
   sweep is barely visible (3/255) and silent; in a lit room it is 25/255 with a short chirp.   */
void selfTest() {
  long s = 0; for (int i = 0; i < 16; ++i) s += analogRead(LDR_PIN);
  ldrRaw = s / 16; litState = ldrRaw > (LIT_ON_LDR + LIT_OFF_LDR) / 2;
  uint8_t k = litState ? 25 : 3;
  const uint32_t cols[3] = { strip.Color(k, 0, 0), strip.Color(0, 0, k), strip.Color(0, k, 0) };
  for (int c = 0; c < 3; ++c) { for (int i = 0; i < NUM_LEDS; ++i) strip.setPixelColor(i, cols[c]); strip.show(); delay(400); }
  strip.clear(); strip.show();
  if (litState) { buzzer(true); delay(60); buzzer(false); }
}

void setup() {
  rxq = xQueueCreate(16, sizeof(RxItem));
  Serial.begin(115200); Serial.setTxTimeoutMs(0);
  pinMode(BUZZER_PIN, OUTPUT); buzzer(false);
  pinMode(TRIG_PIN, OUTPUT); digitalWrite(TRIG_PIN, LOW);
  pinMode(ECHO_PIN, INPUT_PULLDOWN);               // no sensor -> reads LOW -> clean "no echo"
  pinMode(BTN_PIN, INPUT_PULLUP);
  analogReadResolution(12);
  strip.begin(); strip.setBrightness(255); strip.clear(); strip.show();
  selfTest();

  prefs.begin("leotank", false);
  devName = prefs.getString("name", devName);
  tankFullCm = prefs.getFloat("full", tankFullCm);
  tankEmptyCm = prefs.getFloat("empty", tankEmptyCm);
  if (tankEmptyCm - tankFullCm < 10) { tankFullCm = 15; tankEmptyCm = 103; }
  if (prefs.getBytes("hub", hubMac, 6) == 6) hubKnown = true;
  if (prefs.getBytes("key", key, 16) == 16) hasKey = true;
  uint8_t ch = prefs.getUChar("ch", 1);

  WiFi.persistent(false);
  WiFi.mode(WIFI_STA);
  WiFi.disconnect(false, true);                   // never join a router; forget any stored AP
  WiFi.setSleep(false);
  WiFi.setTxPower(WIFI_POWER_8_5dBm);             // C3 Super Mini radio is unstable at full power
  setChannel(ch ? ch : 1);
  if (esp_now_init() != ESP_OK) { dbg("ESP-NOW init failed - restarting"); delay(1000); ESP.restart(); }
  esp_now_register_recv_cb(onRecv);
  esp_now_register_send_cb(onSent);
  goSearching("boot");
  dbg("LEO Tank Edge " EDGE_FW " '" + devName + "' - " + (hasKey ? "paired, looking for hub" : "not paired yet") +
      " - full at " + String(tankFullCm, 0) + " cm, empty at " + String(tankEmptyCm, 0) + " cm");

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
  if (!otaActive) {
    ldrTick();
    measureTick();
    buttonTick();
    alertTick();
    ledTick();
  }
  if (linked && !otaActive && (stateDirty || millis() - lastState >= STATE_MS)) sendState();
  statusPrint();
  if (restartAt && (int32_t)(millis() - restartAt) >= 0) ESP.restart();
  delay(2);
}
