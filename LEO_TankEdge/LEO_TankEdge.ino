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

#define EDGE_FW           "1.13.0-tank"
#define TRIG_PIN          4
#define ECHO_PIN          3
#define LDR_PIN           0
#define BTN_PIN           1
#define BUZZER_PIN        10
#define LED_PIN           2
#define NUM_LEDS          9
#define MAX_LEVEL_LEDS    8           // LED 8 is the status LED; the level uses LEDs 0..ledCount-1
#define STATUS_LED        8
#define STATE_MS          2000        // report to the hub
#define HUB_SILENT_MS     10000       // no verified packet from the hub this long -> search again
#define SCAN_DWELL_MS     250         // per channel while searching
#define MEASURE_MS        1500        // one level measurement (10 pings) this often
// alert levels, buzzer and quiet hours are settings (Preferences), changed from the hub web app
#define ALERT_ROUNDS      10
// room light thresholds and status-light brightness are GLOBAL home settings, sent by the hub (saved here)

/* ===================== LEO EDGE PROTOCOL v2 ==========================
   Keep IDENTICAL in the hub and every edge sketch. Packed, little-endian.
   Every packet except HELLO ends with a LeoAuth trailer:
     tag = HMAC-SHA256(key, session || body || ctr)[0..7]
   session = the edge's random nonce from its latest HELLO; ctr strictly
   increases per direction within a session (replays are dropped).       */
#define LEO_MAGIC  0x4C45
#define LEO_PROTO  2
enum : uint8_t { M_HELLO = 1, M_WELCOME = 2, M_SW_STATE = 3, M_SW_INFO = 4, M_TANK_STATE = 5, M_TANK_INFO = 6,
                 M_CMD = 7, M_OTA_BEGIN = 10, M_OTA_DATA = 11, M_OTA_END = 12, M_OTA_ACK = 13, M_PING = 14, M_DIAG = 15, M_TANK_RULES = 16, M_EVENT = 17 };   // M_EVENT: edge -> hub, a line for the activity log
enum : uint8_t { DEV_SWITCH = 1, DEV_TANK = 2 };
enum : uint8_t { C_RELAY = 1, C_ALL = 2, C_IDENTIFY = 3, C_RENAME = 4, C_RELAY_META = 5, C_REBOOT = 6, C_INFO = 7, C_UNPAIR = 8, C_TOUCH = 9,
                 C_TANK_SET = 10, C_SILENCE = 11, C_BEEP = 12, C_FACTORY = 13, C_TANK_RULE = 14, C_SW_SET = 15, C_LEDTEST = 16 };   // C_FACTORY: wipe all settings + pairing, restart; C_TANK_RULE: idx = rule 0..5, text[0..5] = on,level,dir,pattern,repeats,color; C_BEEP idx>0 = play sound pattern idx-1 once   // C_TANK_SET: idx 1 fullCm 2 emptyCm 3 fullPct 4 lowPct 5 buzzer 6 quietFrom 7 quietTo 8 palette 9 ledCount 10 showFrom 11 showTo 12 minBright 13..20 custom colour of LED 1..8 (0xRRGGBB) 21 current-level highlight 0..50 % 22..29 colour-matching brightness of LED 1..8 (10..100 %) 30 light all level LEDs for f seconds (0 = stop), value in f
struct __attribute__((packed)) LeoHdr      { uint16_t magic; uint8_t proto; uint8_t type; uint8_t dev; uint8_t seq; };
struct __attribute__((packed)) LeoAuth     { uint32_t ctr; uint8_t tag[8]; };
struct __attribute__((packed)) MsgHello    { LeoHdr h; uint32_t nonce; uint8_t hasKey; char fw[16]; char name[24]; };
struct __attribute__((packed)) MsgWelcome  { LeoHdr h; uint8_t channel; uint8_t keyIncluded; uint8_t key[16]; char hubName[24]; };
struct __attribute__((packed)) MsgPing     { LeoHdr h; int16_t mins; uint8_t room; uint16_t beat;
                                              uint8_t g; uint8_t quietFrom, quietTo, dayFrom, dayTo, ledDay, ledNight; uint16_t litOn, litOff;
                                              uint8_t ledStyle; uint16_t ledPeriod; uint8_t okR, okG, okB; uint8_t minR, minG, minB;
                                              uint8_t emMode, emR, emG, emB; };   // emergency light on the status LED (hub 2.9+): 0 off, 1 steady, 2 strobe, 3 slow flash; full brightness, day or night   // status light: style 0 breath 1 blink 2 double blink 3 steady 4 off; period ms (divides 10000); colour when all is well (hub 2.1+)   // g = 1: global home settings follow (hub 2.0+)   // beat: hub millis() % 10000 when sent (LED breathing sync)   // mins: hub local time (-1 unknown); room: 1 lit, 0 dark, 255 unknown (from the tank's LDR)
struct __attribute__((packed)) MsgSwState  { LeoHdr h; uint8_t n; uint8_t onMask; uint32_t uptime; uint32_t onSecs[4]; };
struct __attribute__((packed)) MsgSwInfo   { LeoHdr h; char name[24]; char fw[16]; uint8_t n; char rname[4][20]; float watts[4]; uint8_t gpio[4]; uint8_t touch; uint8_t mode[4]; uint16_t pulseMs[4]; uint8_t activeHigh[4]; uint8_t tmap[4]; uint8_t tact[4]; };   // touch: 1 = touch buttons enabled (switch 2.2+)
struct __attribute__((packed)) MsgTankState{ LeoHdr h; float levelPct; float distCm; uint8_t leds; uint8_t state; uint8_t sensorOk; uint8_t flags; uint32_t uptime; char stateTxt[24]; uint16_t ldr; };   // ldr: room light 0..4095 (tank 1.1+)
struct __attribute__((packed)) MsgTankInfo { LeoHdr h; float fullCm; float emptyCm; uint8_t fullPct; uint8_t lowPct; uint8_t buzzer; uint8_t quietFrom; uint8_t quietTo; uint8_t palette; uint8_t ledCount; uint8_t showFrom; uint8_t showTo; uint8_t minBright; uint8_t colors[24]; uint8_t highlight; uint8_t gain[8]; uint16_t ldrMin; uint16_t ldrMax; uint8_t buzzMode; uint8_t nightMax; };   // tank settings (palette 0 red-blue, 1 red-green, 2 custom = colors[] RGB x8, bottom first)
struct __attribute__((packed)) MsgTankRules { LeoHdr h; uint8_t count; uint8_t r[6][6]; };   // alarm rules: on, level %, dir (0 rises to, 1 drops to), pattern, repeats, colour
struct __attribute__((packed)) MsgEvent    { LeoHdr h; uint8_t id; char text[64]; };   // id counts up per event (hub drops repeats)
struct __attribute__((packed)) MsgDiag     { LeoHdr h; int16_t tempC10; uint32_t heapFree; uint32_t heapMin; uint32_t fsUsed; uint32_t fsTotal; uint32_t flashSize; uint32_t sketchSize; uint32_t sketchMax; uint8_t resetReason; uint8_t cpuMHz; char sdk[16]; };   // chip details for the Advanced view
struct __attribute__((packed)) MsgCmd      { LeoHdr h; uint8_t cmd; uint8_t idx; uint8_t val; float f; char text[24]; };
struct __attribute__((packed)) MsgOtaBegin { LeoHdr h; uint32_t size; };
struct __attribute__((packed)) MsgOtaData  { LeoHdr h; uint32_t off; uint16_t len; uint8_t data[200]; };
struct __attribute__((packed)) MsgOtaAck   { LeoHdr h; uint8_t phase; uint32_t off; uint8_t ok; char err[24]; };

/* types used by functions must precede the first function (Arduino auto-prototypes) */
struct RxItem { uint8_t mac[6]; uint8_t len; uint8_t data[250]; };
enum TankState : uint8_t { T_NORMAL = 0, T_FULL = 1, T_LOW = 2, T_SENSOR = 3, T_BOOT = 4 };
enum AlertKind : uint8_t { A_NONE = 0, A_FULL = 1, A_LOW = 2 };
/* alarm rule: when the level RISES TO (dir 0) or DROPS TO (dir 1) `level` %, play `pattern` `repeats` times
   and flash the level LEDs in `color`. Up to 6 rules, saved on the tank ("rules"). */
struct AlarmRule { uint8_t on, level, dir, pattern, repeats, color; };
struct Sound { uint16_t on, off; uint8_t count; uint16_t pause; };

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
uint8_t fullPct = 95, lowPct = 10;                    // alarm levels   (Preferences "fp" / "lp")
bool    buzzerOn = true;                              // buzzer enabled (Preferences "bz")
uint8_t quietFrom = 22, quietTo = 6;                  // buzzer quiet hours, from == to -> none ("qf" / "qt")
uint16_t litOn = 120, litOff = 80;                    // global: room bright above litOn, dark again below litOff ("lon" / "loff")
uint8_t  ledDay = 5, ledNight = 2;                     // global: status light peak in a bright / dark room ("ld" / "ln")
uint32_t beepUntil = 0;                               // "test buzzer" from the web app
uint8_t palette = 0;                                  // level colours: 0 red->blue, 1 red->green, 2 custom ("pal")
uint8_t custom[8][3] = { {255,0,0}, {218,0,36}, {182,0,73}, {146,0,109}, {109,0,146}, {73,0,182}, {36,0,218}, {0,0,255} };   // per-LED colours, bottom first ("cols")
uint8_t ledCount = 7;                                 // LEDs used for the level, 1..8 ("leds")
uint8_t showFrom = 7, showTo = 22;                    // daytime hours: level LEDs never go fully dark ("sf" / "st"; from == to -> off)
uint8_t minBright = 6;                                // ... at least this bright (1..60, "mb")
uint8_t highlight = 10;                               // current-level LED is this % brighter than the ones below (0..100, "hl")
uint8_t gain[8] = { 100, 100, 100, 100, 100, 100, 100, 100 };   // colour matching: each level LED's max brightness % ("gain")
uint32_t showAllUntil = 0;                            // colour-matching test: light every level LED until then
uint8_t  buzzMode = 3;                                // when the buzzer may sound: 0 always, 1 outside quiet hours, 2 when the room is lit, 3 both ("bzm")
uint8_t  nightMax = 255;                              // outside the daytime hours the level LEDs are at most this bright ("nmx")
uint16_t ldrMin = 10, ldrMax = 4000;                 // light sensor calibration: dark room reading -> brightness 1, full daylight -> 255 ("lmn" / "lmx")
// global status light look (from the hub): style 0 breath, 1 blink, 2 double blink, 3 steady, 4 off; period when all is well; colour when all is well
uint8_t  ledStyle = 0; uint16_t ledPeriod = 5000; uint8_t okCol[3] = { 0, 255, 0 };
uint8_t  minC[3] = { 1, 1, 1 };                       // colour calibration (global): lowest R/G/B value while that colour is lit ("mnc")
uint8_t  emMode = 0, emCol[3] = { 255, 255, 255 };     // emergency light on the status LED, from the hub (not saved: a power cut clears it)
bool emOnNow() {                                         // emergency pattern: 1 steady, 2 strobe, 3 slow flash
  return emMode == 1 || (emMode == 2 && millis() % 140 < 50) || (emMode == 3 && millis() % 1000 < 500);
}
// LED test for calibration (from the app): every LED shows testCol at brightness testK with the minimums testMin, day or night
uint32_t testUntil = 0; uint8_t testCol[3] = { 255, 255, 255 }, testMin[3] = { 1, 1, 1 }, testK = 5;
bool ledTestOn() { return testUntil && (int32_t)(testUntil - millis()) > 0; }
uint8_t hexByte(const char* s) { auto h = [](char c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : 0; }; return (uint8_t)(h(s[0]) * 16 + h(s[1])); }
void ledTestCmd(uint8_t k, float secs, const char* t) {   // t = "rrggbbRRGGBB": colour, then the R/G/B minimums
  testUntil = secs > 0 ? millis() + (uint32_t)constrain(secs, 1.0f, 600.0f) * 1000 : 0;
  if (strlen(t) >= 12) for (int i = 0; i < 3; ++i) { testCol[i] = hexByte(t + i * 2); testMin[i] = hexByte(t + 6 + i * 2); }
  testK = k ? k : 1;
}
// simulation from the web app (Advanced): drives the real strip with made-up values for a while; nothing is saved, no alarms
uint32_t simUntil = 0; float simLevel = 50; int simLdr = 2000; bool simDay = true, simFault = false;
bool simActive() { return simUntil && (int32_t)(simUntil - millis()) > 0; }

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
/* Breathing sync: the hub sends its beat (millis() % 10000) in every keep-alive; we keep an
   offset so all LEO LEDs breathe on the same beat. Big jumps are taken at once, small radio
   jitter is smoothed. Without the hub we just keep breathing on our own clock.               */
int32_t beatOffset = 0; bool beatKnown = false;
uint32_t beatMillis() { return millis() + (uint32_t)beatOffset; }
void beatSync(uint16_t beat) {
  if (beat >= 10000) return;
  int32_t d = (int32_t)beat - (int32_t)(beatMillis() % 10000);
  if (d > 5000) d -= 10000; else if (d < -5000) d += 10000;
  if (!beatKnown || d > 60 || d < -60) beatOffset += d; else beatOffset += d / 4;
  beatKnown = true;
}
uint32_t lastState = 0, lastScanStep = 0, lastVerified = 0, linkedSince = 0, identifyUntil = 0, restartAt = 0;
bool     stateDirty = true;
bool     otaActive = false; uint32_t otaSize = 0, otaWritten = 0;

// tank state
float    distCm = 0, levelPct = 0;
bool     sensorOk = false;              // false until the first good measurement
uint8_t  goodStreak = 0, badStreak = 0;
uint8_t  levelLeds = 0;                 // 0..ledCount
int      ldrRaw = 0;
TankState tstate = T_BOOT;
AlertKind alertNow = A_NONE;            // alert currently sounding (A_FULL = a "rises to" rule, A_LOW = "drops to")
uint8_t  alertRound = 0; uint32_t alertPhaseAt = 0; bool alertOn = false;
// sounds: 0 chirp, 1 short beeps, 2 long beeps, 3 triple beep, 4 siren, 5 LEDs only (no sound)
const Sound SOUNDS[6] = { {60, 0, 1, 1500}, {200, 300, 1, 0}, {500, 500, 1, 0}, {80, 80, 3, 800}, {1000, 300, 1, 0}, {400, 400, 1, 0} };
// flash colours: 0 none, 1 green, 2 red, 3 blue, 4 white, 5 amber
const uint8_t FLASH[6][3] = { {0, 0, 0}, {0, 255, 0}, {255, 0, 0}, {0, 0, 255}, {255, 255, 255}, {255, 140, 0} };
AlarmRule rules[6] = { {1, 95, 0, 2, 10, 1}, {1, 10, 1, 1, 10, 2} };   // default = the old full and low alarms
bool     ruleArmed[6] = { true, true, true, true, true, true };
AlarmRule alertR; int8_t alertRule = -1; bool alertTest = false; uint8_t beepIdx = 0; uint32_t alertWait = 0;
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
bool quietHours() {
  int m = clockMins(); if (m < 0 || quietFrom == quietTo) return false;
  int a = quietFrom * 60, b = quietTo * 60;
  return a < b ? (m >= a && m < b) : (m >= a || m < b);       // window may cross midnight
}
bool inShowHours() {                                     // daytime window for the minimum level brightness
  int m = clockMins(); if (m < 0 || showFrom == showTo) return false;
  int a = showFrom * 60, b = showTo * 60;
  return a < b ? (m >= a && m < b) : (m >= a || m < b);
}
bool buzzerAllowed() {
  if (!buzzerOn) return false;
  bool timeOk = !quietHours(), lightOk = roomLit();
  switch (buzzMode) { case 0: return true; case 1: return timeOk; case 2: return lightOk; default: return timeOk && lightOk; }
}

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
void recomputeLevel() {                 // distance -> % with the current calibration
  float pct = (tankEmptyCm - distCm) * 100.0f / (tankEmptyCm - tankFullCm);
  pct = constrain(pct, 0.0f, 100.0f);
  uint8_t leds = (uint8_t)roundf(pct * ledCount / 100.0f);
  if (leds != levelLeds || fabsf(levelPct - pct) >= 1) stateDirty = true;
  levelPct = pct; levelLeds = leds;
}
// 10 pings spread over the measurement period (one per call, ~150 ms apart), median of the good ones
float    pings[10]; uint8_t pingCount = 0, pingFails = 0; uint32_t lastPingAt = 0;
uint32_t measureSeq = 0;                // counts good level readings
void tankEvent(const String& s);
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
    if (++badStreak >= 2 && sensorOk) { sensorOk = false; stateDirty = true; tankEvent("Level sensor: no echo (sensor problem)"); }
    if (!sensorOk) { distCm = 0; levelPct = 0; levelLeds = 0; }
    return;
  }
  for (int i = 1; i < good; ++i) { float v = pings[i]; int j = i - 1; while (j >= 0 && pings[j] > v) { pings[j + 1] = pings[j]; j--; } pings[j + 1] = v; }
  float med = pings[good / 2];
  badStreak = 0;
  if (!sensorOk) { if (++goodStreak < 3) return; sensorOk = true; tankEvent("Level sensor working again (" + String(med, 0) + " cm)"); }
  distCm = med;
  recomputeLevel();
  measureSeq++;
}
void ldrTick() {
  static uint32_t last = 0; if (millis() - last < 500) return; last = millis();
  long s = 0; for (int i = 0; i < 16; ++i) s += analogRead(LDR_PIN);
  ldrRaw = s / 16;
  bool lit = litState ? ldrRaw > litOff : ldrRaw > litOn;
  if (lit != litState) { litState = lit; stateDirty = true; tankEvent(String(lit ? "Room is lit" : "Room is dark") + " (light sensor " + String(ldrRaw) + ")"); }
}

/* ------------------------------ alerts ----------------------------- */
void buzzer(bool on) { digitalWrite(BUZZER_PIN, on ? HIGH : LOW); }
const char* SND_NAME[6] = { "chirp", "short beeps", "long beeps", "triple beep", "siren", "LEDs only" };
const char* FLASH_NAME[6] = { "no flash", "green flash", "red flash", "blue flash", "white flash", "amber flash" };
String ruleTxt(const AlarmRule& r) { return String(r.dir ? "drops to " : "rises to ") + String(r.level) + "%"; }
String muteWhy() {                                       // why the buzzer would be silent right now ("" = it may sound)
  if (!buzzerOn) return "buzzer switched off";
  bool q = quietHours(), d = !roomLit();
  switch (buzzMode) {
    case 0: return "";
    case 1: return q ? "quiet hours" : "";
    case 2: return d ? "room is dark" : "";
    default: return q && d ? "quiet hours and room is dark" : q ? "quiet hours" : d ? "room is dark" : "";
  }
}
uint8_t silencedBy = 0;                                  // 1 button, 2 web app
String alertName() { return alertTest ? String("Test") : "Alarm rule " + String(alertRule + 1) + " (" + ruleTxt(alertR) + ")"; }
void stopAlert(const String& why) {
  if (alertNow) tankEvent(alertName() + " ended: " + why + " - played " + String(alertRound) + " of " + String(alertR.repeats ? alertR.repeats : 1));
  alertNow = A_NONE; alertRule = -1; alertTest = false; alertOn = false; buzzer(false); stateDirty = true;
}
bool alertAllowed = true;                                // last buzzer permission seen during this alarm (for the log)
void startAlert(const AlarmRule& r, int8_t idx, bool test) {
  alertR = r; alertRule = idx; alertTest = test; alertNow = (test || r.dir == 0) ? A_FULL : A_LOW;
  alertRound = 0; beepIdx = 0; alertOn = false; alertPhaseAt = millis(); alertWait = 0; silenced = false; silencedBy = 0; stateDirty = true;
  String m = muteWhy(); alertAllowed = test || !m.length();
  tankEvent(alertName() + (test ? String(" started") : " started at " + String(levelPct, 0) + "%") + ": " + SND_NAME[r.pattern < 6 ? r.pattern : 1] +
            " x" + String(r.repeats ? r.repeats : 1) + ", " + FLASH_NAME[r.color < 6 ? r.color : 2] +
            (r.pattern == 5 ? String("") : m.length() ? (test ? " (a real alarm now would be silent: " + m + ")" : " - buzzer silent: " + m) : String("")));
}
bool ruleHit(const AlarmRule& r)   { return r.dir == 0 ? levelPct >= r.level : levelPct <= r.level; }
bool ruleClear(const AlarmRule& r) { return r.dir == 0 ? levelPct < r.level - 5 : levelPct > r.level + 5; }   // 5 % back
/* A rule starts only after 2 readings in a row at its mark (one stray reading can't start it), and once started it
   always plays its full count - readings never stop it; only the button, Silence in the web app, or changing the
   rule do. It re-arms after the level has stayed 5 % away for a minute, so a jumpy reading can't repeat it. */
#define REARM_MS 60000
uint8_t  ruleHits[6] = { 0 }; uint32_t ruleAwaySince[6] = { 0 };
void alertTick() {
  static uint32_t seenSeq = 0; bool fresh = measureSeq != seenSeq; seenSeq = measureSeq;
  if (!sensorOk) {
    tstate = T_SENSOR;                                   // an alarm already playing carries on
  } else {
    TankState s = levelPct >= fullPct ? T_FULL : levelPct <= lowPct ? T_LOW : T_NORMAL;
    if (s != tstate) { tstate = s; stateDirty = true; }
    // first good reading after a restart (power cut, update): a level we are ALREADY at doesn't sound an alarm -
    // a rule fires only when the level actually rises/drops into it
    static bool primed = false;
    if (!primed && fresh) { primed = true; for (int i = 0; i < 6; ++i) ruleArmed[i] = !(rules[i].on && ruleHit(rules[i])); }
    if (primed && fresh) for (int i = 0; i < 6; ++i) {
      const AlarmRule& r = rules[i]; if (!r.on) { ruleHits[i] = 0; ruleAwaySince[i] = 0; continue; }
      if (ruleHit(r)) { ruleAwaySince[i] = 0; if (ruleHits[i] < 255) ruleHits[i]++; }
      else {
        ruleHits[i] = 0;
        if (!ruleClear(r)) ruleAwaySince[i] = 0;
        else if (!ruleAwaySince[i]) ruleAwaySince[i] = millis() | 1;
        else if (!ruleArmed[i] && millis() - ruleAwaySince[i] >= REARM_MS) { ruleArmed[i] = true; dbg("Rule " + String(i + 1) + " re-armed"); }
      }
      if (!alertNow && ruleArmed[i] && ruleHits[i] >= 2) { ruleArmed[i] = false; startAlert(r, i, false); }
    }
  }
  if (!alertNow) return;
  if (silenced) { stopAlert(silencedBy == 2 ? "silenced from the web app" : "silenced with the button"); return; }
  if (!alertTest && alertRule >= 0 && !rules[alertRule].on) { stopAlert("rule turned off"); return; }
  const Sound& snd = SOUNDS[alertR.pattern < 6 ? alertR.pattern : 1];
  if (millis() - alertPhaseAt < alertWait) return;
  alertPhaseAt = millis();
  if (alertOn) {
    alertOn = false; buzzer(false);
    if (++beepIdx >= snd.count) {
      beepIdx = 0;
      if (++alertRound >= (alertR.repeats ? alertR.repeats : 1)) { stopAlert("finished"); return; }
      alertWait = snd.off + snd.pause;
    } else alertWait = snd.off;
  } else {
    alertOn = true; alertWait = snd.on;
    bool ok = alertTest || buzzerAllowed();
    if (!alertTest && alertR.pattern != 5 && beepIdx == 0 && ok != alertAllowed) {   // quiet hours began / room went dark mid-alarm
      alertAllowed = ok; tankEvent(alertName() + (ok ? String(": buzzer sounding again") : ": buzzer now silent - " + muteWhy()));
    }
    buzzer(alertR.pattern != 5 && ok);                   // quiet in a dark room / quiet hours; LEDs still flash
  }
}

/* ------------------------------ button ----------------------------- */
uint32_t btnFeedbackUntil = 0;
/* factory reset: forget the hub, the key and every setting (calibration, alarms, LEDs), then restart unpaired */
void factoryReset(const char* why) {
  dbg(String("FACTORY RESET: ") + why);
  buzzer(false); prefs.clear();
  restartAt = millis() + 300;
}
/* the board's BOOT button held 15 s = factory reset (same on every LEO device). From 2 s all LEDs blink red,
   slow and dim at first, faster and brighter the longer you hold; at 15 s they turn solid bright red (accepted)
   and the tank wipes itself and restarts. Let go before 15 s to cancel. */
#define RESET_HOLD_MS 15000
uint32_t resetHeldSince = 0; bool resetAccepted = false;
bool resetArmed() { return resetAccepted || (resetHeldSince && millis() - resetHeldSince > 2000); }
uint8_t resetLevel() {                  // red level for the reset light right now (0 = dark half of a blink)
  if (resetAccepted) return 160;
  float p = constrain((float)(millis() - resetHeldSince - 2000) / (RESET_HOLD_MS - 2000), 0.0f, 1.0f);
  uint32_t period = 1000 - (uint32_t)(p * 880);          // 1 s -> 0.12 s
  return (millis() % period) < period / 2 ? (uint8_t)(6 + p * 144) : 0;
}
#define BOOT_BTN_PIN 9                  // the C3 Super Mini's own BOOT button (pull-up, always fitted)
void resetBtnTick() {
  // needs a solid LOW for 15 s on a pin with a pull-up: a missing or loose button can never trigger it
  if (resetAccepted) return;
  if (digitalRead(BOOT_BTN_PIN) != LOW) { resetHeldSince = 0; return; }       // BOOT button only (the push button just silences alarms)
  if (!resetHeldSince) resetHeldSince = millis();
  if (millis() - resetHeldSince >= RESET_HOLD_MS && !restartAt) { resetAccepted = true; factoryReset("BOOT button held 15 s"); restartAt = millis() + 1500; }
}
void buttonTick() {
  static bool stable = true, raw = true; static uint32_t changedAt = 0;
  bool r = digitalRead(BTN_PIN);                          // HIGH = released (pull-up)
  if (r != raw) { raw = r; changedAt = millis(); return; }
  if (r == stable || millis() - changedAt < 40) return;
  stable = r;
  if (r == LOW) {                                         // pressed
    if (alertNow) { silenced = true; silencedBy = 1; dbg("Alert silenced by button"); }
    btnFeedbackUntil = millis() + 400;
  }
}

/* ------------------------------ LEDs ------------------------------- */
// level colours: red at the bottom fading to blue (palette 0) or green (palette 1) at the top
void gradColor(int i, uint8_t& r, uint8_t& g, uint8_t& b) {
  if (palette == 2 && i >= 0 && i < 8) { r = custom[i][0]; g = custom[i][1]; b = custom[i][2]; return; }   // your own colours
  if (palette == 3) {                                    // spectrum: red -> orange -> yellow -> green -> cyan -> blue (hue 0..240)
    float h = (ledCount > 1 ? (float)i / (ledCount - 1) : 1) * 240.0f, x = 1 - fabsf(fmodf(h / 60.0f, 2) - 1);
    float rf, gf, bf;
    if (h < 60)       { rf = 1; gf = x; bf = 0; }
    else if (h < 120) { rf = x; gf = 1; bf = 0; }
    else if (h < 180) { rf = 0; gf = 1; bf = x; }
    else              { rf = 0; gf = x; bf = 1; }
    r = (uint8_t)(rf * 255); g = (uint8_t)(gf * 255); b = (uint8_t)(bf * 255); return;
  }
  float t = ledCount > 1 ? (float)i / (ledCount - 1) : 1;
  r = (uint8_t)(255 * (1 - t)); g = palette == 1 ? (uint8_t)(255 * t) : 0; b = palette == 1 ? 0 : (uint8_t)(255 * t);
}
float daylight() { return roomLit() ? 1 : 0; }           // the tank's own LDR is the room's light sensor
uint8_t breathLevel(uint32_t period, uint8_t peak) {     // quick sine breath at the start of each period
  uint32_t len = period < 1000 ? period * 4 / 5 : 800, t = beatMillis() % period;   // on the hub's beat
  if (t >= len) return 0;
  float s = sinf(PI * t / len);
  return (uint8_t)(s * s * peak + 0.5f);
}
uint8_t statusLevel(uint32_t period, uint8_t peak) {     // the global status light style, on the hub's beat
  uint32_t t = beatMillis() % period;
  switch (ledStyle) {
    case 1: return t < 120 ? peak : 0;                                      // blink
    case 2: return (t < 100 || (t >= 250 && t < 350)) ? peak : 0;           // double blink
    case 3: return peak;                                                    // steady
    case 4: return 0;                                                       // off
    default: return breathLevel(period, peak);                              // breath
  }
}
// colour channel ch (0 R, 1 G, 2 B) of colour value col at brightness k; never below the calibrated minimum while lit,
// so a dim colour keeps all its parts instead of one of them rounding down to off
/* colour (r,g,b) at brightness k with the colour calibration, keeping the colour's mix: when dim, the strongest
   part is held at its minimum and the others follow in proportion; a part that would be far below its own minimum
   goes off instead of jumping up (jumping up turned dim colours white / yellow / cyan). */
uint32_t calColor(uint8_t r, uint8_t g, uint8_t b, int k) {
  k = constrain(k, 0, 255); uint8_t c[3] = { r, g, b }, o[3] = { 0, 0, 0 };
  int d = 0; for (int ch = 1; ch < 3; ++ch) if (c[ch] > c[d]) d = ch;
  if (k && c[d]) {
    float v[3]; for (int ch = 0; ch < 3; ++ch) v[ch] = c[ch] * k / 255.0f;
    float md = minC[d] ? minC[d] : 1;
    if (v[d] < md) { float s = md / v[d]; for (int ch = 0; ch < 3; ++ch) v[ch] *= s; }
    for (int ch = 0; ch < 3; ++ch) {
      if (!c[ch]) continue; float m = minC[ch] ? minC[ch] : 1;
      if (v[ch] < m) v[ch] = v[ch] >= m * 0.5f ? m : 0;
      o[ch] = (uint8_t)min(255.0f, v[ch] + 0.5f);
    }
  }
  return strip.Color(o[0], o[1], o[2]);
}
int ldrBrightness(int ldr) {                             // light sensor -> level LED brightness with the calibration (dark room = off)
  int br = map(ldr, ldrMin, ldrMax, 1, 255); br = constrain(br, 0, 255); return br < 3 ? 0 : br;
}
void ledTick() {
  static uint32_t last = 0; if (millis() - last < 30) return; last = millis();
  // level brightness follows the room, like the original: dark room -> level LEDs off
  const bool sim = simActive();
  const int ldrNow = sim ? simLdr : ldrRaw;
  const bool okNow = sim ? !simFault : sensorOk;
  const int lvLeds = sim ? (int)roundf(simLevel * ledCount / 100.0f) : levelLeds;
  int br = ldrBrightness(ldrNow);
  const bool dayNow = sim ? simDay : inShowHours();
  if (dayNow && br < minBright) br = minBright;          // daytime: always show the level, dimly
  if (!dayNow && br > nightMax) br = nightMax;           // night: never brighter than this
  uint32_t c[NUM_LEDS]; for (int i = 0; i < NUM_LEDS; ++i) c[i] = 0;
  auto scaled = [&](uint8_t r, uint8_t g, uint8_t b, int k) { return calColor(r, g, b, k); };

  if (resetArmed()) {                                   // holding the button for a factory reset
    uint8_t lv = resetLevel(); for (int i = 0; i < NUM_LEDS; ++i) c[i] = strip.Color(lv, 0, 0);
  } else if (millis() < identifyUntil) {
    bool on = (millis() / 150) % 2; for (int i = 0; i < NUM_LEDS; ++i) c[i] = on ? strip.Color(60, 60, 60) : 0;
  } else if (millis() < btnFeedbackUntil) {
    for (int i = 0; i < ledCount; ++i) c[i] = scaled(128, 0, 128, max(br, 20));     // purple = button seen
  } else if (alertNow && alertOn && !sim) {
    const uint8_t* fc = FLASH[alertR.color < 6 ? alertR.color : 2];        // the rule's flash colour (none = dark)
    for (int i = 0; i < ledCount; ++i) c[i] = scaled(fc[0], fc[1], fc[2], max(br, 20));
  } else if (millis() < showAllUntil) {                  // colour matching: every level LED on, with its own brightness
    for (int i = 0; i < ledCount; ++i) { uint8_t r, g, b; gradColor(i, r, g, b); c[i] = scaled(r * gain[i] / 100, g * gain[i] / 100, b * gain[i] / 100, max(br, 30)); }
  } else if (okNow) {
    const int levelLeds = lvLeds;
    for (int i = 0; i < levelLeds && i < ledCount; ++i) {
      uint8_t r, g, b; gradColor(i, r, g, b);
      r = r * gain[i] / 100; g = g * gain[i] / 100; b = b * gain[i] / 100;              // colour matching
      // current level LED brighter by highlight/2 %, the ones below dimmer by highlight/2 % (always at least one step apart)
      int k = br;
      if (br > 0 && highlight) {
        if (i == levelLeds - 1) k = min(255, max(br + 1, br * (200 + highlight) / 200));
        else k = max(1, br * (200 - highlight) / 200);
      }
      c[i] = scaled(r, g, b, k);
    }
  } else if (sim || millis() > 8000) {                   // ultrasonic sensor problem: all level LEDs blink yellow, rapidly
    bool on = (millis() / 150) % 2;
    for (int i = 0; i < ledCount; ++i) c[i] = on ? scaled(255, 170, 0, max(br, (int)minBright)) : 0;
  }
  // LED 8: faint quick breath, same scheme as the LEO switch; red = sensor fault
  uint8_t r, g, b; uint32_t period;
  if (otaActive)        { r = 0; g = 1; b = 1; period = 500;  }
  else if (!linked)     { r = hasKey ? 1 : 0; g = hasKey ? 1 : 0; b = hasKey ? 0 : 1; period = 2000; }
  else if (!okNow)      { r = 1; g = 0; b = 0; period = 2000; }
  else                  { r = 255; g = 255; b = 255; period = ledPeriod; }    // all well: the global colour and speed
  uint8_t k = statusLevel(period, daylight() > 0.5f ? ledDay : ledNight);   // global style + brightness
  if (otaActive || restartAt) {                          // update = rapid cyan, restart coming = rapid white
    k = (millis() / 100) % 2 ? max<uint8_t>(daylight() > 0.5f ? ledDay : ledNight, 6) : 0;
    r = otaActive ? 0 : 1; g = 1; b = 1;
  }
  if (millis() >= identifyUntil && k) {
    if (r == 255) c[STATUS_LED] = calColor(okCol[0], okCol[1], okCol[2], k);
    else c[STATUS_LED] = strip.Color(r * k, g * k, b * k);
  }

  if (emMode && !otaActive && !restartAt && !resetArmed())                   // emergency light: the chosen colour, full power, day or night
    c[STATUS_LED] = emOnNow() ? strip.Color(emCol[0], emCol[1], emCol[2]) : 0;
  if (ledTestOn()) {                                     // calibration test: every LED, the test colour, the test minimums
    auto t = [&](int ch) -> uint8_t { if (!testCol[ch]) return 0; int v = (testCol[ch] * testK + 127) / 255; return (uint8_t)min(255, max(v, (int)testMin[ch])); };
    uint32_t tc = strip.Color(t(0), t(1), t(2)); for (int i = 0; i < NUM_LEDS; ++i) c[i] = tc;
  }
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
/* events for the hub's activity log (alarms, buzzer, room light, level sensor). Kept until we are linked (newest 8);
   each is sent twice, the hub drops the repeat by its id. */
char evq[8][64]; uint8_t evHead = 0, evCount = 0, evId = 0; uint32_t evLast = 0;
void tankEvent(const String& s) {
  dbg("EVENT: " + s);
  if (evCount == 8) { evHead = (evHead + 1) % 8; evCount--; }
  copyStr(evq[(evHead + evCount) % 8], 64, s.c_str()); evCount++;
}
void eventTick() {
  if (!evCount || !linked || otaActive || millis() - evLast < 120) return;
  evLast = millis();
  MsgEvent m = {}; fillHdr(m.h, M_EVENT); m.id = ++evId; copyStr(m.text, sizeof(m.text), evq[evHead]);
  sendHub(&m, sizeof(m)); delay(8); sendHub(&m, sizeof(m));
  evHead = (evHead + 1) % 8; evCount--;
}
void sendHello(const uint8_t* to) {
  MsgHello m = {}; fillHdr(m.h, M_HELLO);
  m.nonce = nonce; m.hasKey = hasKey ? 1 : 0;
  copyStr(m.fw, sizeof(m.fw), EDGE_FW); copyStr(m.name, sizeof(m.name), devName.c_str());
  esp_now_send(to, (const uint8_t*)&m, sizeof(m));
}
const char* stateText() {
  if (otaActive) return "Updating firmware";
  if (simActive()) return "Simulation running";
  if (!sensorOk) return tstate == T_BOOT ? "Starting" : "Sensor not connected";
  if (alertNow && alertTest) return "Testing sound";
  if (alertNow) { static char t[24]; snprintf(t, sizeof(t), "Alarm %d: %s %d%%", alertRule + 1, alertR.dir ? "below" : "above", alertR.level); return t; }
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
void sendDiag() {                       // chip details for the hub's Advanced view (no file system on the tank)
  MsgDiag m = {}; fillHdr(m.h, M_DIAG);
  m.tempC10 = (int16_t)(temperatureRead() * 10);
  m.heapFree = ESP.getFreeHeap(); m.heapMin = ESP.getMinFreeHeap();
  m.flashSize = ESP.getFlashChipSize(); m.sketchSize = ESP.getSketchSize(); m.sketchMax = ESP.getFreeSketchSpace();
  m.resetReason = (uint8_t)esp_reset_reason(); m.cpuMHz = (uint8_t)getCpuFrequencyMhz();
  copyStr(m.sdk, sizeof(m.sdk), ESP.getSdkVersion());
  sendHub(&m, sizeof(m));
}
void sendTankRules() {                  // alarm rules for the web app
  MsgTankRules m = {}; fillHdr(m.h, M_TANK_RULES); m.count = 6;
  memcpy(m.r, rules, sizeof(m.r));
  sendHub(&m, sizeof(m));
}
void sendTankInfo();
/* GLOBAL home settings from the hub's keep-alive: quiet hours, daytime hours, room light thresholds, status
   light brightness. Saved only when they change, so the tank keeps following them when the hub is off. */
bool havePingStyle = false, havePingCal = false;     // the last keep-alive carried the status light look / colour calibration
void applyGlobals(const MsgPing& p) {
  bool ch = false;
  auto set8 = [&](uint8_t& v, uint8_t n, const char* k, uint8_t lo, uint8_t hi) { if (n >= lo && n <= hi && v != n) { v = n; prefs.putUChar(k, n); ch = true; } };
  set8(quietFrom, p.quietFrom, "qf", 0, 23); set8(quietTo, p.quietTo, "qt", 0, 23);
  set8(showFrom, p.dayFrom, "sf", 0, 23);    set8(showTo, p.dayTo, "st", 0, 23);
  set8(ledDay, p.ledDay, "ld", 0, 255);      set8(ledNight, p.ledNight, "ln", 0, 255);
  if (p.litOff >= 5 && p.litOn <= 4095 && p.litOff < p.litOn && (p.litOn != litOn || p.litOff != litOff)) {
    litOn = p.litOn; litOff = p.litOff; prefs.putUShort("lon", litOn); prefs.putUShort("loff", litOff); ch = true;
  }
  if (havePingStyle) {                                    // status light look (hub 2.1+)
    set8(ledStyle, p.ledStyle, "ls", 0, 4);
    if ((p.ledPeriod == 1000 || p.ledPeriod == 2000 || p.ledPeriod == 2500 || p.ledPeriod == 5000 || p.ledPeriod == 10000) && p.ledPeriod != ledPeriod) { ledPeriod = p.ledPeriod; prefs.putUShort("lp2", ledPeriod); ch = true; }
    if (p.okR != okCol[0] || p.okG != okCol[1] || p.okB != okCol[2]) { okCol[0] = p.okR; okCol[1] = p.okG; okCol[2] = p.okB; prefs.putBytes("okc", okCol, 3); ch = true; }
  }
  if (havePingCal && (p.minR != minC[0] || p.minG != minC[1] || p.minB != minC[2])) {   // colour calibration (hub 2.6+)
    minC[0] = p.minR; minC[1] = p.minG; minC[2] = p.minB; prefs.putBytes("mnc", minC, 3); ch = true;
  }
  if (ch) { dbg("Home settings from the hub updated"); sendTankInfo(); stateDirty = true; }
}
void sendTankInfo() {                   // our settings, so the hub web app can show and edit them
  MsgTankInfo m = {}; fillHdr(m.h, M_TANK_INFO);
  m.fullCm = tankFullCm; m.emptyCm = tankEmptyCm; m.fullPct = fullPct; m.lowPct = lowPct;
  m.buzzer = buzzerOn ? 1 : 0; m.quietFrom = quietFrom; m.quietTo = quietTo; m.palette = palette; m.ledCount = ledCount;
  m.showFrom = showFrom; m.showTo = showTo; m.minBright = minBright; memcpy(m.colors, custom, sizeof(m.colors)); m.highlight = highlight; memcpy(m.gain, gain, sizeof(m.gain));
  m.ldrMin = ldrMin; m.ldrMax = ldrMax; m.buzzMode = buzzMode; m.nightMax = nightMax;
  sendHub(&m, sizeof(m));
}
void applySetting(uint8_t idx, float v) {
  switch (idx) {
    case 1: if (v >= 2 && v < tankEmptyCm - 10) { tankFullCm = v; prefs.putFloat("full", v); } break;
    case 2: if (v > tankFullCm + 10 && v <= 400) { tankEmptyCm = v; prefs.putFloat("empty", v); } break;
    case 3: if (v > lowPct + 10 && v <= 100) { fullPct = (uint8_t)v; prefs.putUChar("fp", fullPct); } break;
    case 4: if (v >= 0 && v < fullPct - 10) { lowPct = (uint8_t)v; prefs.putUChar("lp", lowPct); } break;
    case 5: buzzerOn = v != 0; prefs.putBool("bz", buzzerOn); if (!buzzerOn && !beepUntil) buzzer(false); break;
    case 6: if (v >= 0 && v < 24) { quietFrom = (uint8_t)v; prefs.putUChar("qf", quietFrom); } break;
    case 7: if (v >= 0 && v < 24) { quietTo = (uint8_t)v; prefs.putUChar("qt", quietTo); } break;
    case 8: palette = v >= 3 ? 3 : v >= 2 ? 2 : v >= 1 ? 1 : 0; prefs.putUChar("pal", palette); break;   // 0 red-blue, 1 red-green, 2 custom, 3 spectrum
    case 13: case 14: case 15: case 16: case 17: case 18: case 19: case 20: {             // custom colour of one LED
      uint32_t rgb = (uint32_t)v; uint8_t* c = custom[idx - 13];
      c[0] = (rgb >> 16) & 255; c[1] = (rgb >> 8) & 255; c[2] = rgb & 255;
      prefs.putBytes("cols", custom, sizeof(custom)); break; }
    case 9: if (v >= 1 && v <= MAX_LEVEL_LEDS) { ledCount = (uint8_t)v; prefs.putUChar("leds", ledCount); if (sensorOk) recomputeLevel(); } break;
    case 10: if (v >= 0 && v < 24) { showFrom = (uint8_t)v; prefs.putUChar("sf", showFrom); } break;
    case 11: if (v >= 0 && v < 24) { showTo = (uint8_t)v; prefs.putUChar("st", showTo); } break;
    case 12: if (v >= 1 && v <= 60) { minBright = (uint8_t)v; prefs.putUChar("mb", minBright); } break;
    case 21: if (v >= 0 && v <= 100) { highlight = (uint8_t)v; prefs.putUChar("hl", highlight); } break;
    case 22: case 23: case 24: case 25: case 26: case 27: case 28: case 29:
      if (v >= 10 && v <= 100) { gain[idx - 22] = (uint8_t)v; prefs.putBytes("gain", gain, sizeof(gain)); } break;
    case 30: showAllUntil = v > 0 ? millis() + (uint32_t)constrain(v, 1.0f, 300.0f) * 1000 : 0; break;
    case 31: if (v >= 0 && v <= ldrMax - 50) { ldrMin = (uint16_t)v; prefs.putUShort("lmn", ldrMin); } break;     // light sensor: dark reading
    case 32: if (v >= ldrMin + 50 && v <= 4095) { ldrMax = (uint16_t)v; prefs.putUShort("lmx", ldrMax); } break;  // light sensor: daylight reading
    case 33: if (v >= 0 && v <= 3) { buzzMode = (uint8_t)v; prefs.putUChar("bzm", buzzMode); } break;       // when sounds are allowed
    case 34: if (v >= 0 && v <= 255) { nightMax = (uint8_t)v; prefs.putUChar("nmx", nightMax); } break;     // night brightness limit
    // simulation (not saved): any value (re)starts it for 3 minutes; 44 = start for v seconds (0 = stop)
    case 40: simLevel = constrain(v, 0.0f, 100.0f); if (!simActive()) simUntil = millis() + 180000; break;
    case 41: simLdr = constrain((int)v, 0, 4095);   if (!simActive()) simUntil = millis() + 180000; break;
    case 42: simDay = v != 0;                       if (!simActive()) simUntil = millis() + 180000; break;
    case 43: simFault = v != 0;                     if (!simActive()) simUntil = millis() + 180000; break;
    case 44: simUntil = v > 0 ? millis() + (uint32_t)constrain(v, 5.0f, 600.0f) * 1000 : 0; break;
  }
  if (idx >= 40) { stateDirty = true; return; }                     // simulation: nothing to save or report
  if (idx <= 2 && sensorOk) recomputeLevel();
  dbg("Setting " + String(idx) + " = " + String(v, 1));
  sendTankInfo(); stateDirty = true;
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
    case C_INFO:     stateDirty = true; sendTankInfo(); sendTankRules(); sendDiag(); break;
    case C_UNPAIR:   forgetHub("hub asked us to forget it"); break;
    case C_TANK_SET: applySetting(c.idx, c.f); break;
    case C_LEDTEST:  { char t[25]; memcpy(t, c.text, 24); t[24] = 0; ledTestCmd(c.idx, c.f, t); } break;
    case C_SILENCE:  if (alertNow) { silenced = true; silencedBy = 2; dbg("Alert silenced from the web app"); } break;
    case C_BEEP:     // test a rule: idx = sound + 1, val = flash colour, f = how many times (hub 2.9+; older hubs: once)
      if (c.idx >= 1 && c.idx <= 6) {
        if (!alertNow || alertTest) {
          if (alertNow) stopAlert("replaced by a new test");
          uint8_t n = c.f >= 1 && c.f <= 30 ? (uint8_t)c.f : 1;
          AlarmRule t = { 1, 0, 0, (uint8_t)(c.idx - 1), n, (uint8_t)(c.val < 6 ? c.val : 0) }; startAlert(t, -1, true);
        } else tankEvent("Test not played: " + alertName() + " is sounding");
      }
      else { buzzer(true); beepUntil = millis() + 150; }
      break;
    case C_TANK_RULE:
      if (c.idx < 6) {
        AlarmRule r; memcpy(&r, c.text, sizeof(r));
        r.on = r.on ? 1 : 0; if (r.level > 100) r.level = 100; r.dir = r.dir ? 1 : 0;
        if (r.pattern > 5) r.pattern = 1; if (r.repeats < 1) r.repeats = 1; if (r.repeats > 30) r.repeats = 30; if (r.color > 5) r.color = 2;
        rules[c.idx] = r; ruleArmed[c.idx] = !ruleHit(r);              // don't fire at once for a level we're already at
        if (alertRule == (int8_t)c.idx) stopAlert("rule changed");
        ruleHits[c.idx] = 0; ruleAwaySince[c.idx] = 0;
        prefs.putBytes("rules", rules, sizeof(rules)); sendTankRules();
        dbg("Rule " + String(c.idx + 1) + " saved");
      } break;
    case C_FACTORY:  factoryReset("requested from the web app"); break;
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
  sendState(); sendTankInfo(); sendTankRules(); sendDiag();
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
    if (blen >= sizeof(LeoHdr) + 2) { MsgPing p = {}; memcpy(&p, it.data, min(blen, sizeof(p))); if (p.mins >= 0 && p.mins < 1440) { hubMins = p.mins; hubMinsAt = millis(); } if (blen >= offsetof(MsgPing, g)) beatSync(p.beat); if (blen >= offsetof(MsgPing, ledStyle) && p.g == 1) { havePingStyle = blen >= offsetof(MsgPing, minR); havePingCal = blen >= offsetof(MsgPing, emMode); applyGlobals(p); } if (blen >= sizeof(MsgPing)) { emMode = p.emMode <= 3 ? p.emMode : 0; emCol[0] = p.emR; emCol[1] = p.emG; emCol[2] = p.emB; } }
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
/* Power-on glow, before anything else - the same on every LEO device: soft warm white for ~1.5 s
   (on, hold, fade out over the last 0.3 s) = "power is good, booting". The room light is read FIRST from
   our own LDR: 14/255 in a lit room (plus a short chirp), 3/255 and silent in a dark one.            */
void selfTest() {
  long s = 0; for (int i = 0; i < 16; ++i) s += analogRead(LDR_PIN);
  ldrRaw = s / 16; litState = ldrRaw > (litOn + litOff) / 2;
  const uint8_t peak = litState ? 14 : 3;
  auto glow = [&](uint8_t k) { for (int i = 0; i < NUM_LEDS; ++i) strip.setPixelColor(i, strip.Color(k, k * 3 / 5, k / 4)); strip.show(); };
  if (litState) { buzzer(true); delay(60); buzzer(false); }
  for (int n = 0; n < 7; ++n) { glow(peak); delay(100); glow(0); delay(100); }   // booting: rapid warm flashes (~1.4 s)
  strip.clear(); strip.show();
}

void setup() {
  rxq = xQueueCreate(16, sizeof(RxItem));
  Serial.begin(115200); Serial.setTxTimeoutMs(0);
  pinMode(BUZZER_PIN, OUTPUT); buzzer(false);
  pinMode(TRIG_PIN, OUTPUT); digitalWrite(TRIG_PIN, LOW);
  pinMode(ECHO_PIN, INPUT_PULLDOWN);               // no sensor -> reads LOW -> clean "no echo"
  pinMode(BTN_PIN, INPUT_PULLUP);
  pinMode(BOOT_BTN_PIN, INPUT_PULLUP);
  analogReadResolution(12);
  strip.begin(); strip.setBrightness(255); strip.clear(); strip.show();
  selfTest();

  prefs.begin("leotank", false);
  devName = prefs.getString("name", devName);
  tankFullCm = prefs.getFloat("full", tankFullCm);
  tankEmptyCm = prefs.getFloat("empty", tankEmptyCm);
  if (tankEmptyCm - tankFullCm < 10) { tankFullCm = 15; tankEmptyCm = 103; }
  fullPct = prefs.getUChar("fp", fullPct); lowPct = prefs.getUChar("lp", lowPct);
  if (fullPct > 100 || lowPct + 10 >= fullPct) { fullPct = 95; lowPct = 10; }
  buzzerOn = prefs.getBool("bz", true);
  quietFrom = prefs.getUChar("qf", quietFrom) % 24; quietTo = prefs.getUChar("qt", quietTo) % 24;
  palette = prefs.getUChar("pal", 0); if (palette > 3) palette = 0;
  ledCount = prefs.getUChar("leds", 7); if (ledCount < 1 || ledCount > MAX_LEVEL_LEDS) ledCount = 7;
  showFrom = prefs.getUChar("sf", showFrom) % 24; showTo = prefs.getUChar("st", showTo) % 24;
  minBright = prefs.getUChar("mb", minBright); if (minBright < 1 || minBright > 60) minBright = 6;
  ldrMin = prefs.getUShort("lmn", 10); ldrMax = prefs.getUShort("lmx", 4000); if (ldrMax > 4095 || ldrMin + 50 > ldrMax) { ldrMin = 10; ldrMax = 4000; }
  buzzMode = prefs.getUChar("bzm", 3); if (buzzMode > 3) buzzMode = 3;
  nightMax = prefs.getUChar("nmx", 255);
  ledStyle = prefs.getUChar("ls", 0); if (ledStyle > 4) ledStyle = 0;
  ledPeriod = prefs.getUShort("lp2", 5000); if (!ledPeriod || 10000 % ledPeriod) ledPeriod = 5000;
  prefs.getBytes("okc", okCol, 3);
  prefs.getBytes("mnc", minC, 3);
  highlight = prefs.getUChar("hl", 10); if (highlight > 100) highlight = 10;
  litOn = prefs.getUShort("lon", 120); litOff = prefs.getUShort("loff", 80); if (litOff >= litOn) { litOn = 120; litOff = 80; }
  ledDay = prefs.getUChar("ld", 5); ledNight = prefs.getUChar("ln", 2);
  if (prefs.getBytesLength("gain") == sizeof(gain)) prefs.getBytes("gain", gain, sizeof(gain));
  for (int i = 0; i < 8; ++i) if (gain[i] < 10 || gain[i] > 100) gain[i] = 100;
  if (prefs.getBytesLength("cols") == sizeof(custom)) prefs.getBytes("cols", custom, sizeof(custom));
  if (prefs.getBytesLength("rules") == sizeof(rules)) prefs.getBytes("rules", rules, sizeof(rules));
  else { rules[0].level = fullPct; rules[1].level = lowPct; }      // first start with rules: carry over the old full/low alarm levels
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
  resetBtnTick();
  { static uint32_t lastDiag = 0; if (linked && millis() - lastDiag > 60000) { lastDiag = millis(); sendDiag(); } }
  if (!otaActive) {
    ldrTick();
    measureTick();
    buttonTick();
    alertTick();
    ledTick();
  }
  eventTick();
  if (beepUntil && (int32_t)(millis() - beepUntil) >= 0) { beepUntil = 0; if (!alertOn) buzzer(false); }
  if (linked && !otaActive && (stateDirty || millis() - lastState >= STATE_MS)) sendState();
  statusPrint();
  if (restartAt && (int32_t)(millis() - restartAt) >= 0) ESP.restart();
  delay(2);
}
