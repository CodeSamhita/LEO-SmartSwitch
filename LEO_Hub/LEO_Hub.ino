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

#define HUB_FW            "2.8.0"
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
                 C_TANK_SET = 10, C_SILENCE = 11, C_BEEP = 12, C_FACTORY = 13, C_TANK_RULE = 14, C_SW_SET = 15, C_LEDTEST = 16 };   // C_FACTORY: wipe all settings + pairing, restart; C_TANK_RULE: idx = rule 0..5, text[0..5] = on,level,dir,pattern,repeats,color; C_BEEP idx>0 = play sound pattern idx-1 once   // C_TANK_SET: idx 1 fullCm 2 emptyCm 3 fullPct 4 lowPct 5 buzzer 6 quietFrom 7 quietTo 8 palette 9 ledCount 10 showFrom 11 showTo 12 minBright 13..20 custom colour of LED 1..8 (0xRRGGBB) 21 current-level highlight 0..50 % 22..29 colour-matching brightness of LED 1..8 (10..100 %) 30 light all level LEDs for f seconds (0 = stop), value in f
struct __attribute__((packed)) LeoHdr      { uint16_t magic; uint8_t proto; uint8_t type; uint8_t dev; uint8_t seq; };
struct __attribute__((packed)) LeoAuth     { uint32_t ctr; uint8_t tag[8]; };
struct __attribute__((packed)) MsgHello    { LeoHdr h; uint32_t nonce; uint8_t hasKey; char fw[16]; char name[24]; };
struct __attribute__((packed)) MsgWelcome  { LeoHdr h; uint8_t channel; uint8_t keyIncluded; uint8_t key[16]; char hubName[24]; };
struct __attribute__((packed)) MsgPing     { LeoHdr h; int16_t mins; uint8_t room; uint16_t beat;
                                              uint8_t g; uint8_t quietFrom, quietTo, dayFrom, dayTo, ledDay, ledNight; uint16_t litOn, litOff;
                                              uint8_t ledStyle; uint16_t ledPeriod; uint8_t okR, okG, okB; uint8_t minR, minG, minB; };   // status light: style 0 breath 1 blink 2 double blink 3 steady 4 off; period ms (divides 10000); colour when all is well (hub 2.1+)   // g = 1: global home settings follow (hub 2.0+)   // beat: hub millis() % 10000 when sent (LED breathing sync)   // mins: hub local time (-1 unknown); room: 1 lit, 0 dark, 255 unknown (from the tank's LDR)
struct __attribute__((packed)) MsgSwState  { LeoHdr h; uint8_t n; uint8_t onMask; uint32_t uptime; uint32_t onSecs[4]; };
struct __attribute__((packed)) MsgSwInfo   { LeoHdr h; char name[24]; char fw[16]; uint8_t n; char rname[4][20]; float watts[4]; uint8_t gpio[4]; uint8_t touch; uint8_t mode[4]; uint16_t pulseMs[4]; uint8_t activeHigh[4]; uint8_t tmap[4]; uint8_t tact[4]; };   // touch: 1 = touch buttons enabled (switch 2.2+)
struct __attribute__((packed)) MsgTankState{ LeoHdr h; float levelPct; float distCm; uint8_t leds; uint8_t state; uint8_t sensorOk; uint8_t flags; uint32_t uptime; char stateTxt[24]; uint16_t ldr; };   // ldr: room light 0..4095 (tank 1.1+)
struct __attribute__((packed)) MsgTankInfo { LeoHdr h; float fullCm; float emptyCm; uint8_t fullPct; uint8_t lowPct; uint8_t buzzer; uint8_t quietFrom; uint8_t quietTo; uint8_t palette; uint8_t ledCount; uint8_t showFrom; uint8_t showTo; uint8_t minBright; uint8_t colors[24]; uint8_t highlight; uint8_t gain[8]; uint16_t ldrMin; uint16_t ldrMax; uint8_t buzzMode; uint8_t nightMax; };   // tank settings (palette 0 red-blue, 1 red-green, 2 custom = colors[] RGB x8, bottom first)
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
  uint16_t tLdrMin, tLdrMax; bool tLdrKnown;            // light sensor calibration (tank 1.9+)
  uint8_t  tBuzzMode, tNightMax; bool tBzKnown;         // when sounds are allowed, night LED limit (tank 1.10+)
  uint32_t offAt[4];                                    // switch: relay timer, epoch seconds (0 = none)
  uint8_t  rMode[4], rHigh[4], tMap[4], tAct[4]; uint16_t rPulse[4]; bool swExtKnown;   // switch 2.9+: output mode, pulse, active level, touch mapping
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
#define RELH_FILE "/relh.bin"                // switch usage: seconds ON per relay per hour, 7 days
struct RelH { bool used; uint8_t mac[6]; uint32_t lastHour; uint16_t s[4][HIST_HOURS]; };
RelH relh[2];
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
/* Read-only tank view for people on another network (through a port forward on your room router): port 8080
   serves ONLY a level page and its numbers - no settings, no controls, no device list. Can be switched off. */
AsyncWebServer viewServer(8080);
bool gViewOn = true;
const char VIEW_HTML[] PROGMEM = R"VIEW(<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Water tank</title><meta name="theme-color" content="#0c0f12"><style>
:root{--bg:#0c0f12;--s1:#151b21;--line:#25303a;--txt:#e8eef3;--mut:#7d8b97;--acc:#4aa8ff}
body{margin:0;background:var(--bg);color:var(--txt);font:15px/1.4 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;display:grid;place-items:center;min-height:100vh}
.c{background:var(--s1);border:1px solid var(--line);border-radius:22px;padding:22px 26px;display:flex;gap:26px;align-items:center;margin:16px;max-width:420px;width:calc(100% - 32px);box-sizing:border-box}
.bar{width:64px;height:230px;border:2px solid var(--line);border-radius:14px;display:flex;flex-direction:column-reverse;gap:4px;padding:5px;flex:0 0 auto}
.seg{flex:1;border-radius:4px;background:#1d2630;transition:background .6s,opacity .6s}
.big{font-size:56px;font-weight:300;line-height:1;color:var(--acc)}.big small{font-size:20px;color:var(--mut)}
.m{color:var(--mut);font-size:13px;margin-top:8px}.st{font-size:17px;margin-top:10px;font-weight:600}.bad{color:#f0b429}
</style></head><body><div class="c"><div class="bar" id="bar"></div><div><div class="m">Water tank</div><div class="big" id="lv">—</div><div class="st" id="st"></div><div class="m" id="up">connecting…</div></div></div>
<script>
let n=0,last=0;
async function go(){try{const r=await fetch('/level',{cache:'no-store'});if(!r.ok)throw 0;const d=await r.json();last=Date.now();
 if(d.leds!==n){n=d.leds;document.getElementById('bar').innerHTML=Array.from({length:n},()=>'<div class="seg"></div>').join('')}
 const segs=[...document.querySelectorAll('.seg')],lit=d.ok?Math.round(d.level*n/100):0;
 segs.forEach((s,i)=>{s.style.background=!d.ok?'#d9a400':i<lit?(d.colors[i]||'#4aa8ff'):'#1d2630';s.style.opacity=!d.ok?.85:1});
 document.getElementById('lv').innerHTML=d.ok?Math.round(d.level)+'<small> %</small>':'—';
 const st=document.getElementById('st');st.textContent=!d.online?'Tank offline':!d.ok?'Sensor problem':d.state;st.className='st'+(!d.online||!d.ok?' bad':'');
}catch(e){}tick()}
function tick(){const s=Math.round((Date.now()-last)/1000);document.getElementById('up').textContent=last?(s<15?'live':'updated '+s+' s ago'):'connecting…'}
go();setInterval(go,5000);setInterval(tick,1000);
</script></body></html>)VIEW";
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
uint8_t  gLedStyle = 0;                  // status light: 0 breath, 1 blink, 2 double blink, 3 steady, 4 off
uint16_t gLedPeriod = 5000;              // ... repeats every (ms; 1000/2000/2500/5000/10000 so every device stays in step)
uint8_t  gOk[3] = { 0, 255, 0 };         // ... colour when all is well (warnings keep their own colours)
uint8_t  gMin[3] = { 1, 1, 1 };          // colour calibration: lowest R/G/B value while that colour is lit (all LEDs, all devices)
uint32_t hubTestUntil = 0; uint8_t hubTestCol[3] = { 255, 255, 255 }, hubTestMin[3] = { 1, 1, 1 }, hubTestK = 5;   // LED calibration test
uint16_t gPriceDay = 616, gPriceNight = 616;   // electricity price, paise per kWh, in / outside the daytime hours (BESCOM LT domestic: Rs 5.80 + 36 p surcharge)
bool     gInit = false;                  // copied once from the tank's own values when upgrading
bool okPeriod(int p) { return p == 1000 || p == 2000 || p == 2500 || p == 5000 || p == 10000; }
void globalsSave() {
  prefs.putUChar("gqf", gQuietFrom); prefs.putUChar("gqt", gQuietTo); prefs.putUChar("gdf", gDayFrom); prefs.putUChar("gdt", gDayTo);
  prefs.putUChar("gld", gLedDay); prefs.putUChar("gln", gLedNight); prefs.putUShort("glon", gLitOn); prefs.putUShort("gloff", gLitOff);
  prefs.putUChar("gls", gLedStyle); prefs.putUShort("glp", gLedPeriod); prefs.putBytes("gok", gOk, 3);
  prefs.putUShort("gpd", gPriceDay); prefs.putUShort("gpn", gPriceNight); prefs.putBytes("gmc", gMin, 3); prefs.putBool("gvw", gViewOn);
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
/* switch usage per relay: seconds ON in each hour, 7 days (for the "which light is used most" chart) */
RelH* relhFor(const uint8_t* mac, uint32_t createHour) {
  for (int k = 0; k < 2; ++k) if (relh[k].used && !memcmp(relh[k].mac, mac, 6)) return &relh[k];
  if (!createHour) return nullptr;
  for (int k = 0; k < 2; ++k) if (!relh[k].used) { memset(&relh[k], 0, sizeof(RelH)); relh[k].used = true; memcpy(relh[k].mac, mac, 6); relh[k].lastHour = createHour; return &relh[k]; }
  return nullptr;
}
void relhAdvance(uint32_t hour) {
  for (int k = 0; k < 2; ++k) { RelH& h = relh[k]; if (!h.used || hour == h.lastHour) continue;
    uint32_t gap = hour > h.lastHour ? hour - h.lastHour : HIST_HOURS;
    for (uint32_t s = 1; s <= gap && s <= HIST_HOURS; ++s) for (int r = 0; r < 4; ++r) h.s[r][(h.lastHour + s) % HIST_HOURS] = 0;
    h.lastHour = hour; }
}
/* relay timers: "off in 30 min" / "off at 23:00" - kept by the hub (RAM; a hub restart cancels them) */
String relayName(const Dev& d, int r);
void queueCmd(const uint8_t* mac, uint8_t cmd, uint8_t idx, uint8_t val, float f, const char* text);
void relayTimerTick() {
  if (!timeValid()) return;
  uint32_t now = (uint32_t)time(nullptr);
  struct { uint8_t mac[6]; int r; String dn, rn; } due[4]; int n = 0;
  { DevGuard g;
    for (int i = 0; i < MAX_DEV && n < 4; ++i) { Dev& d = devs[i]; if (!d.used || d.type != DEV_SWITCH) continue;
      for (int r = 0; r < 4 && n < 4; ++r) if (d.offAt[r] && now >= d.offAt[r]) {
        d.offAt[r] = 0; memcpy(due[n].mac, d.mac, 6); due[n].r = r; due[n].dn = d.name; due[n].rn = relayName(d, r);
        d.onMask &= ~(1 << r); d.expectMask = d.onMask; d.expectValid = 1; d.expectAt = millis(); n++; stateDirty = true; } } }
  for (int k = 0; k < n; ++k) { queueCmd(due[k].mac, C_RELAY, due[k].r, 0, 0, ""); activity(due[k].dn + ": " + due[k].rn + " OFF (timer)", false); }
}
void histDrop(const uint8_t* mac) {
  Hist* h = histFor(mac, 0); if (h) h->used = false;
  RelH* rh = relhFor(mac, 0); if (rh) rh->used = false;
  for (int j = 0; j < 4; ++j) if (fine[j].used && !memcmp(fine[j].mac, mac, 6)) fine[j].used = false;
}
void histSave() {
  File f = LittleFS.open(HIST_FILE, "w"); if (!f) return;
  uint32_t magic = 0x4C484932; f.write((uint8_t*)&magic, 4); f.write((uint8_t*)hist, sizeof(hist)); f.close();
  File g = LittleFS.open(RELH_FILE, "w"); if (g) { uint32_t m2 = 0x4C524831; g.write((uint8_t*)&m2, 4); g.write((uint8_t*)relh, sizeof(relh)); g.close(); }
}
void histLoad() {
  File f = LittleFS.open(HIST_FILE, "r"); if (!f) return;
  uint32_t magic = 0;
  if (f.size() == 4 + sizeof(hist) && f.read((uint8_t*)&magic, 4) == 4 && magic == 0x4C484932) f.read((uint8_t*)hist, sizeof(hist));
  else memset(hist, 0, sizeof(hist));
  f.close();
  File g = LittleFS.open(RELH_FILE, "r");
  if (g) { uint32_t m2 = 0; if (!(g.size() == 4 + sizeof(relh) && g.read((uint8_t*)&m2, 4) == 4 && m2 == 0x4C524831 && g.read((uint8_t*)relh, sizeof(relh)) == sizeof(relh))) memset(relh, 0, sizeof(relh)); g.close(); }
}
void histTick() {                       // once a second from loop(): advance slots, then add the current values
  if (!timeValid()) return;
  uint32_t slot = (uint32_t)time(nullptr) / HIST_STEP; bool save = false;
  uint32_t hour = (uint32_t)time(nullptr) / 3600;
  relhAdvance(hour);
  { struct { uint8_t mac[6]; uint8_t mask; } sw[2]; int ns = 0;     // seconds ON per relay this hour
    { DevGuard g; for (int i = 0; i < MAX_DEV && ns < 2; ++i) { Dev& d = devs[i];
        if (d.used && d.type == DEV_SWITCH && d.maskKnown && d.lastSeen && millis() - d.lastSeen < OFFLINE_MS) { memcpy(sw[ns].mac, d.mac, 6); sw[ns].mask = d.onMask; ns++; } } }
    for (int k = 0; k < ns; ++k) { RelH* rh = relhFor(sw[k].mac, hour); if (!rh) continue;
      for (int r = 0; r < 4; ++r) if ((sw[k].mask & (1 << r)) && rh->s[r][hour % HIST_HOURS] < 3600) rh->s[r][hour % HIST_HOURS]++; } }
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
/* lowest / highest room light (tank LDR) in the last 24 h: one min/max per hour, in RAM */
uint16_t ldrLo[24], ldrHi[24]; uint32_t ldrStamp[24];   // stamp = hour number + 1 (0 = empty)
uint32_t hourNo() { time_t n = time(nullptr); return n > 1700000000 ? (uint32_t)(n / 3600) : millis() / 3600000UL; }
void ldrTrack(uint16_t v) {
  uint32_t h = hourNo(); int s = h % 24;
  if (ldrStamp[s] != h + 1) { ldrStamp[s] = h + 1; ldrLo[s] = ldrHi[s] = v; return; }
  if (v < ldrLo[s]) ldrLo[s] = v; if (v > ldrHi[s]) ldrHi[s] = v;
}
bool ldrRange24(int& lo, int& hi) {
  uint32_t h = hourNo(); lo = 4096; hi = -1;
  for (int s = 0; s < 24; ++s) if (ldrStamp[s] && ldrStamp[s] + 24 > h + 1) { lo = min(lo, (int)ldrLo[s]); hi = max(hi, (int)ldrHi[s]); }
  return hi >= 0;
}
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
        for (int r = 0; r < 4; ++r) if (!(m.onMask & (1 << r)) && d.offAt[r]) { d.offAt[r] = 0; changed = true; }   // turned off: timer done
      }
      d.n = m.n > 4 ? 4 : m.n; d.uptime = m.uptime; d.maskKnown = true;
      memcpy(d.onSecs, m.onSecs, sizeof(d.onSecs));
      needInfo = !d.infoKnown;
    }
    if (needInfo) queueCmd(mac, C_INFO, 0, 0, 0, "");
    if (note.length()) activity(note, false);
    if (changed) stateDirty = true;
  } else if (h->type == M_SW_INFO && blen >= offsetof(MsgSwInfo, touch)) {   // older switches send fewer fields
    MsgSwInfo m = {}; memcpy(&m, it.data, min(blen, sizeof(m)));
    DevGuard g; Dev& d = devs[i];
    d.touch = blen >= offsetof(MsgSwInfo, mode) ? (m.touch ? 1 : 0) : 255;
    d.swExtKnown = blen >= sizeof(MsgSwInfo);
    for (int r = 0; r < 4; ++r) { d.rMode[r] = m.mode[r]; d.rPulse[r] = m.pulseMs[r]; d.rHigh[r] = m.activeHigh[r]; d.tMap[r] = m.tmap[r]; d.tAct[r] = m.tact[r]; }
    d.n = m.n > 4 ? 4 : m.n; copyStr(d.fw, sizeof(d.fw), m.fw);
    for (int r = 0; r < 4; ++r) { copyStr(d.rname[r], sizeof(d.rname[r]), m.rname[r]); d.watts[r] = m.watts[r]; d.gpio[r] = m.gpio[r]; }
    d.infoKnown = true; stateDirty = true;
  } else if (h->type == M_TANK_STATE && blen >= sizeof(MsgTankState) - 2) {   // tank 1.0 has no 'ldr'
    MsgTankState m = {}; memcpy(&m, it.data, min(blen, sizeof(m)));
    DevGuard g; Dev& d = devs[i];
    d.ldr = blen >= sizeof(MsgTankState) ? m.ldr : 0xFFFF;
    if (d.ldr != 0xFFFF) ldrTrack(d.ldr);
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
    d.tLdrKnown = blen >= offsetof(MsgTankInfo, buzzMode); d.tLdrMin = m.ldrMin; d.tLdrMax = m.ldrMax;
    d.tBzKnown = blen >= sizeof(MsgTankInfo); d.tBuzzMode = m.buzzMode; d.tNightMax = m.nightMax;
    d.tGainKnown = blen >= offsetof(MsgTankInfo, ldrMin); d.tHighlight = m.highlight; memcpy(d.tGain, m.gain, sizeof(d.tGain));
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
    g["ledDay"] = gLedDay; g["ledNight"] = gLedNight; g["litOn"] = gLitOn; g["litOff"] = gLitOff;
    g["ledStyle"] = gLedStyle; g["ledPeriod"] = gLedPeriod; char hx[8]; snprintf(hx, sizeof(hx), "#%02x%02x%02x", gOk[0], gOk[1], gOk[2]); g["okColor"] = hx;
    g["priceDay"] = gPriceDay; g["priceNight"] = gPriceNight; g["minR"] = gMin[0]; g["minG"] = gMin[1]; g["minB"] = gMin[2]; g["viewOn"] = gViewOn; }
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
        if (v.swExtKnown) { JsonArray tm = o["touchMap"].to<JsonArray>(), ta = o["touchAct"].to<JsonArray>(); for (int p = 0; p < 4; ++p) { tm.add(v.tMap[p] < 4 ? (int)v.tMap[p] : -1); ta.add(v.tAct[p]); } }
        JsonArray rl = o["relays"].to<JsonArray>();
        for (int r = 0; r < v.n; ++r) {
          JsonObject x = rl.add<JsonObject>();
          x["name"] = v.rname[r]; x["watts"] = v.watts[r]; x["gpio"] = v.gpio[r];
          x["on"] = (bool)(v.onMask & (1 << r)); x["onSecs"] = v.onSecs[r]; x["used"] = !(v.hideMask & (1 << r));
          if (v.swExtKnown) { x["mode"] = v.rMode[r]; x["pulseMs"] = v.rPulse[r]; x["activeHigh"] = v.rHigh[r]; }
          if (v.offAt[r]) { time_t tn = time(nullptr); x["timer"] = v.offAt[r] > (uint32_t)tn ? v.offAt[r] - (uint32_t)tn : 0; }
        }
      } else if (v.type == DEV_TANK) {
        JsonObject t = o["tank"].to<JsonObject>();
        t["level"] = v.levelPct; t["dist"] = v.distCm; t["leds"] = v.leds;
        t["sensorOk"] = (bool)v.sensorOk; t["stateTxt"] = v.stateTxt;
        if (v.ldr != 0xFFFF) { t["ldr"] = v.ldr; int lo, hi; if (ldrRange24(lo, hi)) { t["ldrLo"] = lo; t["ldrHi"] = hi; } }
        t["alert"] = (bool)(v.tflags & 1);
        if (v.tcfgKnown) {
          JsonObject c = t["cfg"].to<JsonObject>();
          c["fullCm"] = v.tFullCm; c["emptyCm"] = v.tEmptyCm; c["fullPct"] = v.tFullPct; c["lowPct"] = v.tLowPct;
          c["buzzer"] = (bool)v.tBuzzer; c["quietFrom"] = v.tQuietFrom; c["quietTo"] = v.tQuietTo;
          c["palette"] = v.tPalette; c["ledCount"] = v.tLedCount;
          c["showFrom"] = v.tShowFrom; c["showTo"] = v.tShowTo; c["minBright"] = v.tMinBright;
          if (v.tLdrKnown) { c["ldrMin"] = v.tLdrMin; c["ldrMax"] = v.tLdrMax; }
          if (v.tBzKnown) { c["buzzMode"] = v.tBuzzMode; c["nightMax"] = v.tNightMax; }
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
  "/* motion: smooth page/tab changes, tactile buttons, live feedback while a change is sent */\n"
  ".page.active{animation:pgin .22s ease-out}@keyframes pgin{from{opacity:0;transform:translateY(8px)}}\n"
  "button{transition:transform .12s ease,background-color .2s,color .2s,box-shadow .3s,opacity .2s;-webkit-tap-highlight-color:transparent}button:active:not(:disabled){transform:scale(.96)}\n"
  ".tgl,.tgl:after{transition:all .22s cubic-bezier(.4,1.4,.6,1)}\n"
  ".card{transition:opacity .3s,transform .12s,border-color .3s}\n"
  ".seg{transition:background-color .5s,filter .5s,box-shadow .5s}.bar i{transition:width .4s ease}\n"
  ".toast{animation:tin .25s ease-out}@keyframes tin{from{opacity:0;transform:translate(-50%,10px)}}\n"
  ".btn{position:relative}.busy{pointer-events:none;opacity:.8}\n"
  ".btn.busy{padding-right:30px}.btn.busy:after{content:\"\";position:absolute;right:10px;top:50%;width:12px;height:12px;margin-top:-7px;border:2px solid currentColor;border-right-color:transparent;border-radius:50%;animation:spin .6s linear infinite}\n"
  ".tgl.busy,span.busy{animation:pulse .7s ease-in-out infinite}\n"
  "button.done{box-shadow:0 0 0 2px var(--good)}span.done{color:var(--good)}\n"
  "button.fail{box-shadow:0 0 0 2px var(--bad);animation:shake .35s}span.fail{color:var(--bad)}\n"
  "@keyframes spin{to{transform:rotate(360deg)}}@keyframes pulse{50%{opacity:.45}}@keyframes shake{25%{transform:translateX(-4px)}75%{transform:translateX(4px)}}\n"
  "details[open]>*:not(summary){animation:pgin .2s ease-out}\n"
  ".slr input[type=range]{flex:1;min-width:0;padding:0}.sln{flex:0 0 64px!important;width:64px;padding:6px 7px;text-align:right;font-variant-numeric:tabular-nums}.sls{flex:0 0 auto!important;min-width:44px;white-space:nowrap}\n"
  "input.done{border-color:var(--good);transition:border-color .3s}input.fail{border-color:var(--bad)}input.busy{opacity:.6}\n"
  ".sgrp{font-size:11px;text-transform:uppercase;letter-spacing:.7px;color:var(--mut);padding:14px 0 2px}.sgrp:first-child{padding-top:6px}\n"
  ".slist{padding:4px 14px}.srow{display:flex;align-items:center;gap:12px;width:100%;padding:13px 0;background:none;border:0;border-bottom:1px solid #1e2731;color:var(--txt);text-align:left;font:inherit}.srow:last-child{border:0}\n"
  ".srow .ic{flex:0 0 26px;font-size:16px;text-align:center}.srow .t{flex:1;font-weight:600;font-size:14px}.srow .meta{flex:0 1 auto;text-align:right;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:50%}\n"
  ".tophead{display:none;align-items:center;gap:10px;margin:0 0 10px}.tophead button{flex:0 0 38px;height:34px;border-radius:10px;border:1px solid var(--line);background:var(--s2);color:var(--txt);font-size:18px}.tophead b{font-size:16px}\n"
  ".savebar{position:fixed;left:12px;right:12px;bottom:calc(var(--navh) + 10px);z-index:55;background:var(--s1);border:1px solid var(--acc);border-radius:14px;padding:8px 10px;display:none;align-items:center;gap:8px;box-shadow:0 6px 24px #000a}\n"
  ".savebar.show{display:flex;animation:tin .2s ease-out}.savebar span{flex:1;font-size:13px;font-weight:600}.savebar .btn{flex:0 0 auto;padding:8px 14px}\n"
  "@media(min-width:760px){.savebar{max-width:496px;left:50%;right:auto;transform:translateX(-50%)}}\n"
  ".dtrk{position:relative;height:30px;margin-top:4px}.dtrk:before{content:\"\";position:absolute;left:11px;right:11px;top:13px;height:4px;border-radius:2px;background:var(--line)}\n"
  ".dfill{position:absolute;top:13px;height:4px;border-radius:2px;background:var(--acc);margin:0 11px}\n"
  ".dtrk input[type=range]{position:absolute;left:0;top:0;width:100%;height:30px;margin:0;padding:0;border:0;background:none;pointer-events:none;-webkit-appearance:none;appearance:none}\n"
  ".dtrk input[type=range]::-webkit-slider-runnable-track{background:transparent;height:30px}.dtrk input[type=range]::-moz-range-track{background:transparent}\n"
  ".dtrk input[type=range]::-webkit-slider-thumb{pointer-events:auto;-webkit-appearance:none;width:22px;height:22px;margin-top:4px;border-radius:50%;background:var(--acc);border:3px solid var(--s1);box-shadow:0 1px 4px #0008;cursor:pointer}\n"
  ".dtrk input[type=range]::-moz-range-thumb{pointer-events:auto;width:18px;height:18px;border-radius:50%;background:var(--acc);border:3px solid var(--s1);cursor:pointer}\n"
  ".dnums{display:flex;justify-content:space-between;gap:10px;margin-top:4px}.dnums label{margin:0;font-size:11.5px}.dnums span{display:flex;align-items:center;gap:4px;margin-top:3px;color:var(--mut);font-size:12px}\n"
  "body.devpage nav{display:none}body.devpage .savebar{bottom:calc(12px + env(safe-area-inset-bottom))}body.devpage .toast{bottom:calc(16px + env(safe-area-inset-bottom))}body.devpage .wrap{padding-bottom:80px}\n"
  ".gmid .gauto{display:none}.gmid.glinked .gauto{display:inline}.gmid.glinked .slr{opacity:.5}\n"
  ".zoomc{margin:2px 0 4px}.zlab{display:flex;justify-content:space-between;align-items:center;font-size:11px;color:var(--mut);margin-top:-2px}.zlab a{color:var(--acc);font-weight:650;text-decoration:none}\n"
  ".why{background:var(--s2);border-radius:10px;padding:9px 11px;font-size:12.5px;line-height:1.5;margin-top:10px}\n"
  "fieldset{border:0;padding:0;margin:0;min-width:0}fieldset:disabled{opacity:.45}\n"
  ".copt{display:flex;align-items:center;gap:12px;width:100%;padding:10px;margin-bottom:6px;border-radius:12px;border:1px solid var(--line);background:var(--s2);color:var(--txt);font:inherit;text-align:left}.copt.on{border-color:var(--acc);box-shadow:0 0 0 1px var(--acc)}\n"
  ".strip{display:flex;flex-direction:column-reverse;gap:2px;width:22px;padding:2px;border:1px solid var(--line);border-radius:5px;flex:0 0 auto}.strip i{height:7px;border-radius:2px;display:block}\n"
  ".lab2{display:flex;justify-content:space-between;align-items:baseline;font-size:12.5px;margin:10px 0 2px}\n"
  ".rdot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:7px;vertical-align:0;flex:0 0 auto}\n"
  ".tmb{flex:0 0 34px;height:31px;border-radius:10px;border:1px solid var(--line);background:var(--s2);color:var(--mut);font-size:15px}.tmb.on{color:var(--acc);border-color:var(--acc)}\n"
  ".tmp{background:var(--s2);border-radius:12px;padding:10px;margin:2px 0 8px;animation:pgin .2s ease-out}\n"
  "details.more{margin-top:10px}details.more>summary{cursor:pointer;color:var(--acc);font-size:12.5px;font-weight:650;list-style:none}details.more>summary:before{content:\"＋ \"}details.more[open]>summary:before{content:\"－ \"}\n"
  "/* charts */\n"
  ".chd{display:flex;justify-content:space-between;align-items:flex-end;gap:10px;margin-bottom:10px}.cv{font-size:32px;font-weight:300;line-height:1;font-variant-numeric:tabular-nums}.cv small{font-size:14px;margin-left:3px;opacity:.7}\n"
  ".cst{display:flex;gap:6px}.cst div{background:var(--s2);border-radius:10px;padding:5px 9px;text-align:center;min-width:52px}.cst span{display:block;font-size:10px;color:var(--mut)}.cst b{font-size:13px;font-variant-numeric:tabular-nums}\n"
  ".rng{display:flex;gap:4px;background:var(--s2);border-radius:20px;padding:3px}.rng button{flex:1;border:0;background:none;color:var(--mut);font-size:12px;font-weight:650;padding:6px 0;border-radius:16px}.rng button.on{background:var(--s1);color:var(--txt);box-shadow:0 1px 3px #0006}\n"
  ".cl{stroke-dasharray:2000;stroke-dashoffset:2000;animation:draw 1s ease-out forwards}@keyframes draw{to{stroke-dashoffset:0}}\n"
  "@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}\n"
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
  "<div class=\"savebar\" id=\"savebar\"><span>Unsaved changes</span><button class=\"btn\" onclick=\"unstage()\">Cancel</button><button class=\"btn p\" onclick=\"saveStaged()\">Save</button></div>\n"
  "\n"
  "<div class=\"wrap\">\n"
  "  <header>\n"
  "    <div class=\"logo\" onclick=\"nav('home')\" style=\"cursor:pointer\"><svg width=\"22\" height=\"22\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"#34d3b0\" stroke-width=\"1.7\"><path d=\"M3 11l9-8 9 8M5 10v10h14V10M10 20v-6h4v6\"/></svg></div>\n"
  "    <div style=\"flex:1;min-width:0\"><h1 id=\"hubName\" onclick=\"nav('home')\" style=\"cursor:pointer\">LEO Home Hub</h1>\n"
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
  "  <section class=\"page\" id=\"p-cal\">\n"
  "    <div class=\"tophead\" style=\"display:flex\"><button onclick=\"nav('hub')\">‹</button><b>LED colour calibration</b></div>\n"
  "    <div class=\"card\" id=\"calbox\"></div>\n"
  "  </section>\n"
  "\n"
  "  <section class=\"page\" id=\"p-hub\">\n"
  "    <h3>Home settings</h3>\n"
  "    <div class=\"card\" id=\"homeset\"><div class=\"meta\">Loading…</div></div>\n"
  "    <h3>Tank view for another network</h3>\n"
  "    <div class=\"card\" id=\"viewcard\"></div>\n"
  "    <div class=\"card slist\" style=\"margin-top:12px\"><button class=\"srow\" onclick=\"nav('cal')\"><span class=\"ic\">🎨</span><span class=\"t\">LED colour calibration</span><span class=\"meta\">lights every LED to test</span><span class=\"chev\">›</span></button></div>\n"
  "    <h3>Night lock</h3>\n"
  "    <div class=\"card\">\n"
  "      <p class=\"note\" style=\"margin-top:0\">Blocks turning things ON. OFF always works.</p>\n"
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
  "      <p class=\"note\">Erases everything. Or hold <b>BOOT</b> 15 s.</p>\n"
  "    </details>\n"
  "  </section>\n"
  "\n"
  "  <section class=\"page\" id=\"p-sw\">\n"
  "    <div class=\"subtabs\"><button class=\"back\" onclick=\"nav('home')\">‹</button><button data-t=\"ov\" onclick=\"subTab('sw','ov')\">Control</button><button data-t=\"set\" onclick=\"subTab('sw','set')\">Settings</button></div>\n"
  "    <div class=\"tophead\" id=\"swTop\"><button onclick=\"subTab('sw','set')\">‹</button><b></b></div>\n"
  "    <div data-tab=\"ov\"><div id=\"swlive\"></div>\n"
  "    <h3>Power use</h3><div class=\"card\" id=\"swchart\"><div class=\"meta\">Loading…</div></div>\n"
  "    <h3>By light · cost</h3><div class=\"card\" id=\"swuse\"><div class=\"meta\">Loading…</div></div></div>\n"
  "    <div id=\"swset\"></div>\n"
  "    <details class=\"card adv\" data-tab=\"adv\" id=\"swadvd\" style=\"margin-top:14px\" ontoggle=\"if(this.open)loadAdv(swMac,'#swadv')\"><summary>Advanced</summary><div id=\"swadv\" class=\"meta\">Loading…</div></details>\n"
  "  </section>\n"
  "\n"
  "  <section class=\"page\" id=\"p-tank\">\n"
  "    <div class=\"subtabs\"><button class=\"back\" onclick=\"nav('home')\">‹</button><button data-t=\"ov\" onclick=\"subTab('tank','ov')\">Control</button><button data-t=\"set\" onclick=\"subTab('tank','set')\">Settings</button></div>\n"
  "    <div class=\"tophead\" id=\"tankTop\"><button onclick=\"subTab('tank','set')\">‹</button><b></b></div>\n"
  "    <div data-tab=\"ov\"><div id=\"tlive\"></div>\n"
  "    <h3>Water level</h3><div class=\"card\" id=\"tchart\"><div class=\"meta\">Loading…</div></div></div>\n"
  "    <div id=\"tset\"></div>\n"
  "    <details class=\"card adv\" data-tab=\"adv\" id=\"tadvd\" style=\"margin-top:14px\" ontoggle=\"if(this.open)loadAdv(tankMac,'#tadv')\"><summary>Advanced</summary><div id=\"tadv\" class=\"meta\">Loading…</div></details>\n"
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
  "/* every API call goes through here: 401 -> login screen.\n"
  "   Feedback: the button (or slider readout) that started a change spins while it is sent, then flashes green (done) or red (failed). */\n"
  "let tapBtn=null,tapAt=0;\n"
  "function fbTarget(){if(tapBtn&&Date.now()-tapAt<800&&document.contains(tapBtn))return tapBtn;const a=document.activeElement;return a&&a.type==='range'?a.nextElementSibling:a&&a.classList&&a.classList.contains('sln')?a:null}\n"
  "function fbEnd(el,ok){if(!el)return;el.classList.remove('busy');el.classList.add(ok?'done':'fail');setTimeout(()=>el.classList.remove('done','fail'),900)}\n"
  "async function call(p,b,m){const post=b!==undefined,el=post?fbTarget():null;if(el){el.classList.remove('done','fail');el.classList.add('busy')}\n"
  "  try{const r=await fetch(p,{method:m||(post?'POST':'GET'),headers:{'Content-Type':'application/json'},body:post?JSON.stringify(b):undefined});\n"
  "  fbEnd(el,r.ok);if(r.status===401){needLogin();return null}return r}catch(e){fbEnd(el,false);if(post)toast('Hub not reachable');return null}}\n"
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
  "    try{const txt=await st.text();lastData=txt;S=JSON.parse(txt);render();restoreRoute()}catch(e){}\n"
  "    if(sock){sock.onclose=null;try{sock.close()}catch(_){}}\n"
  "    const ws=new WebSocket('ws://'+location.host+'/ws');sock=ws;lastMsg=Date.now();\n"
  "    ws.onmessage=e=>{lastMsg=Date.now();if(e.data===lastData)return;lastData=e.data;try{S=JSON.parse(e.data);render()}catch(_){}};\n"
  "    ws.onclose=()=>{if(sock===ws){liveState(false);retryT=setTimeout(connect,1500)}};\n"
  "  }finally{connecting=false}}\n"
  "setInterval(()=>{if(sock&&Date.now()-lastMsg>7000&&!connecting){liveState(false);connect()}},2000);\n"
  "document.addEventListener('visibilitychange',()=>{if(!document.hidden&&Date.now()-lastMsg>3000)connect()});\n"
  "window.addEventListener('online',()=>connect());\n"
  "/* the address bar remembers where you are (#tank/<mac>/display), so a refresh brings you back there */\n"
  "function route(){const m=page==='tank'?tankMac:page==='sw'?swMac:'',s=page==='tank'||page==='sw'?subSel[page]:'';\n"
  "  const h='#'+page+(m?'/'+m+'/'+s:'');if(location.hash!==h)history.replaceState(null,'',h)}\n"
  "let routed=false;\n"
  "function restoreRoute(){if(routed)return;routed=true;const [p,m,s]=location.hash.slice(1).split('/');\n"
  "  if(p==='tank'||p==='sw'){const d=S.devices.find(x=>x.mac===m)||S.devices.find(x=>x.type===(p==='tank'?'tank':'switch'));if(!d)return;\n"
  "    if(p==='tank')tankMac=d.mac;else swMac=d.mac;subSel[p]=s||'ov';nav(p)}\n"
  "  else if(['devices','activity','hub','cal'].includes(p))nav(p)}\n"
  "function nav(p){if(p!==page&&!leaveOk())return;if(p!==page)simStop(true);if(page==='cal'&&p!=='cal')calStop();page=p;document.body.classList.toggle('devpage',p==='tank'||p==='sw'||p==='cal');if(p==='cal')setTimeout(renderCal,0);   // device pages: no bottom bar (they have ‹ back)\n"
  "$$('.page').forEach(s=>s.classList.toggle('active',s.id==='p-'+p));\n"
  "  $$('nav button').forEach(b=>b.classList.toggle('sel',b.dataset.p===p));\n"
  "  if(p==='devices'){devKeys='';render()} if(p==='hub'){loadHub();logOn()}else logOff(); if(p==='activity')loadActivity();\n"
  "  if(p==='tank'){tsetKey='';renderTank();pageExtras('tank')} if(p==='sw'){swKey='';renderSw();pageExtras('sw')} window.scrollTo({top:0,behavior:'smooth'});route()}\n"
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
  "  if(page==='hub'){renderLock();renderHomeSet();renderView()}\n"
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
  "async function relMeta(mac,i,btn){const p=btn.parentElement;return await cmd(mac,5,{idx:i,text:p.querySelector('[data-r=\"'+i+'n\"]').value.trim(),f:parseFloat(p.querySelector('[data-r=\"'+i+'w\"]').value)||0})}\n"
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
  "function typing(sel){const a=document.activeElement,box=$(sel);if(box&&[...pend.keys()].some(e=>box.contains(e)))return true;   // unsaved changes here: keep them on screen\n"
  "  if(!a||!box||!box.contains(a))return false;\n"
  "  return a.tagName==='SELECT'||a.tagName==='TEXTAREA'||(a.tagName==='INPUT'&&!['button','checkbox','radio','submit'].includes(a.type))}\n"
  "document.addEventListener('click',e=>{const b=e.target.closest('button');if(b){tapBtn=b;tapAt=Date.now();setTimeout(()=>b.blur(),0)}},true);\n"
  "/* q(text): a circled ? that shows/hides an explanation right below it */\n"
  "function q(t){return ''}   /* help bubbles removed: labels say it all */\n"
  "/* device pages are split into tabs (Overview / Alarms / Display / Setup, or Overview / Relays / Setup) */\n"
  "const subSel={tank:'ov',sw:'ov'};\n"
  "/* device pages: Control (live view, buttons, charts) and Settings (a list; each row opens ONE topic screen with a Back button) */\n"
  "const TOPIC={tank:{size:'Water level sensor',ldr:'Light sensor',alarms:'Alarm rules',buzzer:'Buzzer',colours:'Level LEDs · colours',level:'Level LEDs · how many & highlight',bright:'Level LEDs · day / night brightness',device:'Name, restart, update',adv:'Advanced'},\n"
  "  sw:{r0:'Relay 1',r1:'Relay 2',r2:'Relay 3',r3:'Relay 4',touch:'Touch pads',device:'Name, restart, update',adv:'Advanced'}};\n"
  "function srow(k,t,ic,label,sum){return `<button class=\"srow\" onclick=\"subTab('${k}','${t}')\"><span class=\"ic\">${ic}</span><span class=\"t\">${label}</span><span class=\"meta\">${sum||''}</span><span class=\"chev\">›</span></button>`}\n"
  "function subTab(k,t){if(subSel[k]!==t&&!leaveOk())return;if(t!=='adv')simStop(true);const ch=subSel[k]!==t;subSel[k]=t;applySub(k,ch);window.scrollTo({top:0,behavior:'smooth'});if(t==='ov')pageExtras(k);route()}\n"
  "function applySub(k,anim){const sec=$(k==='tank'?'#p-tank':'#p-sw');if(!sec)return;let t=subSel[k];if(t!=='ov'&&t!=='set'&&!TOPIC[k][t])t=subSel[k]='set';\n"
  "  sec.querySelectorAll('[data-tab]').forEach(e=>{const show=e.dataset.tab===t;e.style.display=show?'':'none';if(show&&anim&&e.animate)e.animate([{opacity:0,transform:'translateX(10px)'},{opacity:1,transform:'none'}],{duration:200,easing:'ease-out'})});\n"
  "  sec.querySelectorAll('.subtabs [data-t]').forEach(b=>b.classList.toggle('on',b.dataset.t===t||(b.dataset.t==='set'&&t!=='ov')));\n"
  "  let topic=TOPIC[k][t];if(k==='sw'&&/^r\\d$/.test(t)){const r=((swDev()||{}).relays||[])[+t[1]];if(r)topic=r.name+' · relay '+(+t[1]+1)}\n"
  "  const top=$(k==='tank'?'#tankTop':'#swTop');if(top){top.style.display=topic?'flex':'none';top.querySelector('b').textContent=topic||''}\n"
  "  if(t==='adv'){const det=$(k==='tank'?'#tadvd':'#swadvd');if(det&&!det.open)det.open=true}}\n"
  "function ruleDesc(r){return r[0]?`${r[2]?'Drops to':'Rises to'} ${r[1]} % · ${SNDS[r[3]]} ×${r[4]||1} · ${FLCOL[r[5]]}`:'<span class=\"meta\">Off</span>'}\n"
  "let tankMac='',tsetKey='';\n"
  "function openTank(m){tankMac=m;subSel.tank='ov';nav('tank')}\n"
  "/* while a device is being updated it does not answer setting changes - say so instead of looking stuck */\n"
  "function otaNote(mac){const o=S.ota||{};return o.active&&o.mac===mac?`<div class=\"banner info\"><b>Updating firmware… ${o.pct||0}% — settings and controls work again when it has restarted.</b></div>`:''}\n"
  "function tankDev(){return S.devices.find(x=>x.mac===tankMac)}\n"
  "function tset(idx,v){return cmd(tankMac,10,{idx:idx,f:+v})}\n"
  "/* sliders for fixed ranges: the readout shows the real value next to the % (brightness out of 255, light sensor out of 4095...) */\n"
  "function tcfg(){const d=tankDev();return d&&d.tank&&d.tank.cfg||{}}\n"
  "function cmOf(p){const c=tcfg();return c.emptyCm?(p/100*(c.emptyCm-c.fullCm)).toFixed(1):'?'}\n"
  "function ldrCal(){const c=tcfg();return [c.ldrMin!=null?c.ldrMin:10,c.ldrMax!=null?c.ldrMax:4000]}\n"
  "function ldrBr(v){const [lo,hi]=ldrCal();let b=Math.trunc((v-lo)*254/(hi-lo))+1;b=Math.max(0,Math.min(255,b));return b<3?0:b}\n"
  "function calPct(v){const [lo,hi]=ldrCal();return Math.round(Math.max(0,Math.min(1,(v-lo)/(hi-lo)))*100)}\n"
  "/* slider + number box: drag, or type an exact value; the unit (and % of the range) sits after the box */\n"
  "const SUF={b255:v=>'/255 · '+Math.round(v/2.55)+'%',ldr:v=>'/4095 · '+Math.round(v/40.95)+'%',pct:v=>'%',leds:v=>'of 8',\n"
  "  lvl:v=>{const n=tcfg().ledCount||7;return '% · '+Math.round(v*n/100)+'/'+n+' LEDs · '+cmOf(v)+' cm'},ldrb:v=>'/4095 → LEDs '+ldrBr(v)+'/255',dark:v=>'/4095',ms:v=>'ms',cal:v=>'/255'};\n"
  "const SMAP={dark:[v=>sq2ldr(v),x=>Math.round(ldr2sq(x))]};   // sliders whose position is not the value itself\n"
  "const slVal=(f,v)=>SMAP[f]?SMAP[f][0](v):v;\n"
  "/* changes are STAGED: a slider/drop-down only shows the new value; nothing is sent until you press Save in the bar\n"
  "   (so a stray touch while scrolling changes nothing). chg starting with '!' = live (simulation). */\n"
  "const pend=new Map();\n"
  "function stage(el){if(el.dataset.grp)for(const k of [...pend.keys()])if(k.dataset.grp===el.dataset.grp)pend.delete(k);pend.delete(el);pend.set(el,el.dataset.chg);$('#savebar').classList.add('show')}\n"
  "/* colour choice applies at once (no Save needed) */\n"
  "async function palPick(el){const all=[...el.parentElement.querySelectorAll('.copt')],was=all.find(b=>b.classList.contains('on'));all.forEach(b=>b.classList.toggle('on',b===el));\n"
  "  if(!await (new Function('return '+el.dataset.chg)).call(el)){all.forEach(b=>b.classList.toggle('on',b===was));toast('Could not reach the tank');return}\n"
  "  const cb=$('#custBox');if(cb){const show=el.dataset.chg==='tset(8,2)';cb.style.display=show?'':'none';if(show&&cb.animate)cb.animate([{opacity:0},{opacity:1}],{duration:200})}}\n"
  "function palStrip(c,p){const n=c.ledCount||7,cc=Object.assign({},c,{palette:p});return `<span class=\"strip\">${[...Array(n)].map((_,i)=>`<i style=\"background:${ledCol(cc,i,n)}\"></i>`).join('')}</span>`}\n"
  "async function saveStaged(){const list=[...pend];let ok=true;for(const [el,code] of list){try{if(!await (new Function('return '+code)).call(el))ok=false}catch(e){ok=false}}\n"
  "  pend.clear();$('#savebar').classList.remove('show');toast(ok?'Saved ✓':'Some changes could not be saved');tsetKey='';swKey=''}\n"
  "function unstage(){pend.clear();$('#savebar').classList.remove('show');tsetKey='';swKey='';homeKey='';render()}\n"
  "function leaveOk(){if(!pend.size)return true;if(!confirm('Discard unsaved changes?'))return false;unstage();return true}\n"
  "function sl(id,min,max,v,f,chg,w){const live=chg&&chg[0]==='!',code=live?chg.slice(1):chg;\n"
  "  return `<div class=\"row slr\" style=\"margin:0;align-items:center;gap:6px\"><input type=\"range\" id=\"${id}\" min=\"${min}\" max=\"${max}\" value=\"${v}\" data-f=\"${f}\" oninput=\"slShow(this)\" ${code?(live?`onchange=\"${code};this.blur()\"`:`data-chg=\"${code}\" onchange=\"stage(this);this.blur()\"`):''}>\n"
  "  <input type=\"number\" class=\"sln\" inputmode=\"numeric\" value=\"${slVal(f,+v)}\" onchange=\"slNum(this)\" onkeydown=\"if(event.key==='Enter')this.blur()\"><span class=\"meta sls\">${SUF[f](+v)}</span></div>`}\n"
  "/* two-handle slider for a low / high pair; the two ends can't cross (min gap), each end has its own number box */\n"
  "const DSUF={cm:' cm',ldrr:' /4095',pct:' %'};\n"
  "function dsl(id,min,max,lo,hi,f,chg,gap,step,names){const p=v=>((v-min)/(max-min)*100).toFixed(2);\n"
  "  return `<div class=\"dsl\" id=\"${id}\" data-min=\"${min}\" data-max=\"${max}\" data-gap=\"${gap}\" data-f=\"${f}\" data-chg=\"${chg}\">\n"
  "  <div class=\"dtrk\"><div class=\"dfill\" style=\"left:${p(lo)}%;right:${100-p(hi)}%\"></div>\n"
  "   <input type=\"range\" class=\"dlo\" min=\"${min}\" max=\"${max}\" step=\"${step||1}\" value=\"${lo}\" oninput=\"dslIn(this,0)\" onchange=\"stage(this.closest('.dsl'));this.blur()\">\n"
  "   <input type=\"range\" class=\"dhi\" min=\"${min}\" max=\"${max}\" step=\"${step||1}\" value=\"${hi}\" oninput=\"dslIn(this,1)\" onchange=\"stage(this.closest('.dsl'));this.blur()\"></div>\n"
  "  <div class=\"dnums\"><label>${names[0]}<span><input type=\"number\" class=\"sln dn0\" step=\"${step||1}\" value=\"${lo}\" onchange=\"dslNum(this,0)\">${DSUF[f]}</span></label>\n"
  "   <label style=\"text-align:right\">${names[1]}<span><input type=\"number\" class=\"sln dn1\" step=\"${step||1}\" value=\"${hi}\" onchange=\"dslNum(this,1)\">${DSUF[f]}</span></label></div></div>`}\n"
  "function dslVals(box){return [+box.querySelector('.dlo').value,+box.querySelector('.dhi').value]}\n"
  "function dslDraw(box){const [lo,hi]=dslVals(box),mn=+box.dataset.min,mx=+box.dataset.max,f=box.querySelector('.dfill'),p=v=>(v-mn)/(mx-mn)*100;\n"
  "  f.style.left=p(lo)+'%';f.style.right=(100-p(hi))+'%';const n0=box.querySelector('.dn0'),n1=box.querySelector('.dn1');if(document.activeElement!==n0)n0.value=lo;if(document.activeElement!==n1)n1.value=hi}\n"
  "function dslIn(el,which){const box=el.closest('.dsl'),g=+box.dataset.gap,lo=box.querySelector('.dlo'),hi=box.querySelector('.dhi');\n"
  "  if(which===0&&+lo.value>+hi.value-g)lo.value=+hi.value-g;if(which===1&&+hi.value<+lo.value+g)hi.value=+lo.value+g;dslDraw(box)}\n"
  "function dslNum(n,which){const box=n.closest('.dsl'),r=box.querySelector(which?'.dhi':'.dlo');r.value=Math.max(+box.dataset.min,Math.min(+box.dataset.max,+n.value));dslIn(r,which);dslDraw(box);stage(box)}\n"
  "/* send a low/high pair in an order the tank accepts (it always keeps them the minimum gap apart) */\n"
  "async function rangeSend(iL,iH,box,curHi){const [lo,hi]=dslVals(box);return hi>curHi?(await tset(iH,hi)&&await tset(iL,lo)):(await tset(iL,lo)&&await tset(iH,hi))}\n"
  "function slShow(el){const n=el.nextElementSibling,f=el.dataset.f;if(document.activeElement!==n)n.value=slVal(f,+el.value);n.nextElementSibling.textContent=SUF[f](+el.value);const h=window['on_'+el.id];if(h)h(+el.value)}\n"
  "function slNum(n){const r=n.previousElementSibling,f=r.dataset.f;let x=+n.value;if(isNaN(x))return;const pos=SMAP[f]?SMAP[f][1](x):x;\n"
  "  const c=Math.max(+r.min,Math.min(+r.max,Math.round(pos)));r.value=c;n.value=slVal(f,c);slShow(r);r.dispatchEvent(new Event('change'))}\n"
  "function inDay(){const g=(S.hub||{}).global||{},n=new Date(),m=n.getHours()*60+n.getMinutes(),a=g.dayFrom*60,b=g.dayTo*60;if(a===b)return false;return a<b?(m>=a&&m<b):(m>=a||m<b)}\n"
  "function brNow(){const t=(tankDev()||{}).tank||{},mb=tcfg().minBright||6;let b=t.ldr!=null?ldrBr(t.ldr):0;if(inDay()&&b<mb)b=mb;return b}\n"
  "/* the tank's highlight maths: top LED brighter by half the %, the ones below dimmer by half */\n"
  "function hlVals(h,br){if(!br)return [0,0];if(!h)return [br,br];return [Math.min(255,Math.max(br+1,Math.trunc(br*(200+h)/200))),Math.max(1,Math.trunc(br*(200-h)/200))]}\n"
  "/* level screen: a picture of the strip with these settings (example: water at 60 %, full daylight) */\n"
  "function hlInfo(h){const el=$('#hlInfo');if(!el)return;const c=tcfg(),n=+(($('#tLeds')||{}).value||c.ledCount||7);if(h==null)h=+(($('#tHl')||{}).value||c.highlight||0);\n"
  "  const lit=Math.max(1,Math.round(n*0.6)),[ta,tb]=hlVals(h,255),cc=Object.assign({},c,{ledCount:n});\n"
  "  const gn=i=>+(($('#tG'+i)||{}).value||(c.gain?c.gain[i]:100))/100;   // each LED's own brightness\n"
  "  const strip=[...Array(n)].map((_,i)=>{const on=i<lit,k=(i===lit-1?ta:tb)*gn(i),col=ledCol(cc,i,n);return `<i style=\"height:12px;background:${on?col:'#1d2630'};opacity:${on?Math.max(.12,k/255).toFixed(2):1};${on&&i===lit-1&&h?'box-shadow:0 0 7px '+col:''}\"></i>`}).join('');\n"
  "  el.innerHTML=`<div style=\"display:flex;gap:14px;align-items:center\"><span class=\"strip\" style=\"width:32px\">${strip}</span><div>Example — water at 60 %: <b>${lit} of ${n}</b> LEDs lit (each LED ≈ ${Math.round(100/n)} % of the tank).<br>\n"
  "    In full daylight the top lit LED is <b>${ta}</b> and the LEDs below it <b>${tb}</b> (of 255).${h?'':'<br>0 % = all lit LEDs equally bright.'}<br><span class=\"meta\">In a dimmer room both scale down together.</span></div></div>`}\n"
  "window.on_tHl=window.on_tLeds=()=>hlInfo();for(let i=0;i<8;i++)window['on_tG'+i]=()=>{if(gLink)gInterp(i);hlInfo()};\n"
  "/* Link: LED 1 and LED n-1 set the ends; the LEDs between follow on a straight line (the top LED stays separate) */\n"
  "let gLink=false;\n"
  "function gCount(){return [...document.querySelectorAll('input[type=range][id^=tG]')].length}\n"
  "function gInterp(i){const n=gCount();if(n<4||(i!==0&&i!==n-2&&i!==-1))return;const a=+$('#tG0').value,b=+$('#tG'+(n-2)).value;\n"
  "  for(let j=1;j<=n-3;j++){const r=$('#tG'+j),v=Math.round(a+(b-a)*j/(n-2));if(+r.value!==v){r.value=v;slShow(r);stage(r)}}}\n"
  "function gApply(){document.querySelectorAll('.gmid').forEach(d=>{d.querySelectorAll('input').forEach(x=>x.disabled=gLink);d.classList.toggle('glinked',gLink)})}\n"
  "function gLinkSet(){gLink=!gLink;const t=$('#gLinkT');if(t)t.classList.toggle('on',gLink);gApply();if(gLink){gInterp(-1);hlInfo()}}\n"
  "function tankLive(){const t=(tankDev()||{}).tank||{},mb=tcfg().minBright||6,s=(id,v)=>{const e=$(id);if(e)e.innerHTML=v};\n"
  "  if(t.ldr!=null){const b=ldrBr(t.ldr);s('#ldrNow',`${inDay()&&b<mb?mb:b} / 255`);s('#ldrRaw',`${t.ldr} / 4095`)}\n"
  "  s('#ldr24',t.ldrLo!=null?`${t.ldrLo} / ${t.ldrHi}`:'collecting…');hlInfo();bzWhen();brWhy()}\n"
  "/* plain-language 'what happens' lines, computed from the settings and what the tank sees right now */\n"
  "function inQuiet(){const g=(S.hub||{}).global||{},n=new Date(),m=n.getHours()*60+n.getMinutes(),a=g.quietFrom*60,b=g.quietTo*60;if(a===b)return false;return a<b?(m>=a&&m<b):(m>=a||m<b)}\n"
  "function bzWhen(){const el=$('#bzWhen');if(!el)return;const c=tcfg(),g=(S.hub||{}).global||{},sel=$('#tBz'),m=sel?+sel.value:(c.buzzMode!=null?c.buzzMode:3);\n"
  "  if(!c.buzzer){el.innerHTML='🔇 <b>Never sounds</b> — the buzzer is off. Alarms still flash the LEDs.';return}\n"
  "  const qt=g.quietFrom!==g.quietTo,day=`${h12(g.quietTo)} to ${h12(g.quietFrom)}`,lit=S.hub.room!=='dark';\n"
  "  const rule=[`🔊 <b>Sounds at any time</b>, day or night, light or dark.`,qt?`🔊 <b>Sounds from ${day}</b>. Silent at night (${h12(g.quietFrom)}–${h12(g.quietTo)}), even if the room is lit.`:'🔊 <b>Sounds at any time</b> (no night hours set).',\n"
  "    `🔊 <b>Sounds only while the room is lit</b> (light sensor above ${g.litOff}). Silent in a dark room, at any hour.`,`🔊 <b>Sounds from ${day} and only while the room is lit</b>. Silent at night or in a dark room.`][m];\n"
  "  const tOk=!qt||!inQuiet(),lOk=lit,ok=m==0||(m==1&&tOk)||(m==2&&lOk)||(m==3&&tOk&&lOk);\n"
  "  el.innerHTML=rule+`<br>Right now: ${ok?'<b style=\"color:var(--good)\">would sound</b>':'<b style=\"color:var(--warn)\">silent</b>'} (${tOk?'daytime':'night hours'}, room ${lit?'lit':'dark'}).`}\n"
  "function brWhy(){const el=$('#brWhy');if(!el)return;const t=(tankDev()||{}).tank||{},c=tcfg(),mb=+(($('#tMb')||{}).value||c.minBright||6),nm=+(($('#tNm')||{}).value||(c.nightMax!=null?c.nightMax:255));\n"
  "  if(t.ldr==null){el.textContent='No light reading from the tank yet.';return}const f=ldrBr(t.ldr),day=inDay();let r=f,why='follows the room light';\n"
  "  if(day&&f<mb){r=mb;why='raised to the daytime minimum'}else if(!day&&f>nm){r=nm;why='lowered to the night maximum'}\n"
  "  el.innerHTML=`Right now (${hm(new Date())}, ${day?'daytime':'night'}): room light ${t.ldr} → LEDs would be ${f}, ${why} → <b>${r} / 255</b>${r?'':' (off)'}`}\n"
  "window.on_tMb=window.on_tNm=()=>brWhy();\n"
  "async function ldrUse(i){const t=(tankDev()||{}).tank||{};if(t.ldr==null){toast('No light reading');return}if(await tset(i,t.ldr))toast('Sent: '+t.ldr)}\n"
  "/* Advanced: LED simulation - the real strip shows made-up values for 3 minutes */\n"
  "function simPanel(){const c=tcfg(),t=(tankDev()||{}).tank||{};if(c.ldrMin==null)return '<p class=\"note\">LED simulation needs tank firmware 1.9 or newer.</p>';\n"
  "  return `<h3 style=\"margin-top:16px\">LED simulation${q('Drives the REAL tank LEDs with the values below for 3 minutes, so you can see how any water level and room light looks. Nothing is saved and no alarm sounds; the app keeps showing the real level. Press Stop, or wait 3 minutes, to go back to normal. The preview here shows the same thing.')}</h3>\n"
  "  <div class=\"row\" style=\"margin:0 0 10px\"><button class=\"btn ${simOn?'d':'p'}\" id=\"simBtn\" onclick=\"simOn?simStop():simStart()\">${simOn?'■ Stop simulation':'▶ Start simulation'}</button></div>\n"
  "  <fieldset id=\"simF\" ${simOn?'':'disabled'}>\n"
  "  <div id=\"simBar\"></div>\n"
  "  <label>Water level</label>${sl('sLv',0,100,Math.round(t.level||50),'lvl','!tset(40,this.value)',200)}\n"
  "  <label>Light sensor</label>${sl('sLdr',0,4095,t.ldr!=null?t.ldr:2000,'ldrb','!tset(41,this.value)',200)}\n"
  "  <div class=\"switchrow\"><span>Daytime hours (minimum brightness)</span><button class=\"tgl ${inDay()?'on':''}\" id=\"sDay\" onclick=\"this.classList.toggle('on');tset(42,this.classList.contains('on')?1:0);simBar()\"></button></div>\n"
  "  <div class=\"switchrow\"><span>Sensor fault (yellow blink)</span><button class=\"tgl\" id=\"sFault\" onclick=\"this.classList.toggle('on');tset(43,this.classList.contains('on')?1:0);simBar()\"></button></div>\n"
  "  </fieldset>\n"
  "  <p class=\"meta\">Stops by itself after 3 minutes, or when you leave this screen.</p>`}\n"
  "window.on_sLv=window.on_sLdr=()=>simBar();\n"
  "function simBar(){const el=$('#simBar');if(!el)return;const c=tcfg(),mb=c.minBright||6,lv=+$('#sLv').value,f=$('#sFault').classList.contains('on'),b=ldrBr(+$('#sLdr').value),br=$('#sDay').classList.contains('on')&&b<mb?mb:b;\n"
  "  el.innerHTML=`<div class=\"tank\" style=\"align-items:center\">${tankBar({tank:{level:lv,sensorOk:!f,cfg:c}},110)}<div class=\"meta\">Brightness ${br} / 255${br?'':' — LEDs off (dark room)'}</div></div>`}\n"
  "let simOn=false,simT=null;\n"
  "function simUi(){const b=$('#simBtn'),f=$('#simF');if(b){b.className='btn '+(simOn?'d':'p');b.textContent=simOn?'■ Stop simulation':'▶ Start simulation'}if(f)f.disabled=!simOn}\n"
  "async function simStart(){const on=id=>$(id).classList.contains('on')?1:0;\n"
  "  const ok=await tset(40,$('#sLv').value)&&await tset(41,$('#sLdr').value)&&await tset(42,on('#sDay'))&&await tset(43,on('#sFault'))&&await tset(44,180);\n"
  "  if(!ok){toast('Could not reach the hub');return}simOn=true;simUi();clearTimeout(simT);simT=setTimeout(()=>{simOn=false;simUi()},180000);toast('Simulation running on the tank')}\n"
  "function simStop(quiet){if(!simOn)return;simOn=false;clearTimeout(simT);simUi();\n"
  "  if(quiet)fetch('/api/cmd',{method:'POST',keepalive:true,headers:{'Content-Type':'application/json'},body:JSON.stringify({mac:tankMac,cmd:10,idx:44,f:0})}).catch(()=>{});\n"
  "  else tset(44,0).then(()=>toast('Simulation stopped'))}\n"
  "addEventListener('pagehide',()=>{simStop(true);calStop()});document.addEventListener('visibilitychange',()=>{if(document.hidden){simStop(true);calStop()}else if(page==='cal'&&!calOn)renderCal()});\n"
  "function hrs(v){return [...Array(24)].map((_,h)=>`<option value=\"${h}\" ${h==v?'selected':''}>${h12(h)}</option>`).join('')}\n"
  "/* the tank bar in the app looks like the real strip: same number of level LEDs, same colours, yellow when the sensor fails */\n"
  "function ledCol(c,i,n){if(c&&c.palette==2&&c.colors&&c.colors[i])return c.colors[i];if(c&&c.palette==3)return 'hsl('+Math.round((n>1?i/(n-1):1)*240)+',100%,50%)';const t=n>1?i/(n-1):1,r=Math.round(255*(1-t)),v=Math.round(255*t);\n"
  "  return c&&c.palette==1?`rgb(${r},${v},0)`:`rgb(${r},0,${v})`}\n"
  "function tankBar(d,h){const t=d.tank||{},c=t.cfg,n=c?(c.ledCount||7):9,ok=t.sensorOk!==false,lit=ok?Math.round((t.level||0)*n/100):0;\n"
  "  return `<div class=\"tankbar\" style=\"${h?'height:'+h+'px':''}\">${[...Array(n)].map((_,i)=>`<div class=\"seg\" style=\"${!ok?'background:#d9a400;opacity:.85':i<lit?'background:'+ledCol(c,i,n)+segLook(c,i,lit):''}\"></div>`).join('')}</div>`}\n"
  "/* app bar mirrors the strip: colour-matching brightness per LED, current level highlighted (shown a bit stronger so it reads on a phone) */\n"
  "function segLook(c,i,lit){const g=c&&c.gain?c.gain[i]/100:1,hl=c&&c.highlight!=null?c.highlight:10;\n"
  "  return i===lit-1?`;filter:brightness(${(g*(1+hl/100)).toFixed(2)});box-shadow:0 0 ${hl?6:0}px ${ledCol(c,i,lit)}`:`;filter:brightness(${(g*(1-hl/200)).toFixed(2)})`}\n"
  "const SNDS=['Chirp','Short beeps','Long beeps','Triple beep','Siren','LEDs only'],FLCOL=['No flash','Green','Red','Blue','White','Amber'];\n"
  "function opts(list,v){return list.map((x,i)=>`<option value=\"${i}\" ${i==v?'selected':''}>${x}</option>`).join('')}\n"
  "function renderTank(){  const d=tankDev();if(!d){nav('home');return}\n"
  "  const t=d.tank||{},c=t.cfg,ok=t.sensorOk!==false,on=d.online;\n"
  "  $('#tlive').innerHTML=otaNote(d.mac)+`<div class=\"card ${on?'':'offline'}\">\n"
  "    <div class=\"chead\"><span class=\"dot ${on?'on':'off'}\"></span><span class=\"nm\">${esc(d.name)}</span></div>\n"
  "    <div class=\"tank\">${tankBar(d,190)}<div style=\"flex:1;min-width:0\">\n"
  "      <div class=\"big\">${ok?Math.round(t.level||0):'—'}<small>%</small></div>\n"
  "      <div class=\"kv\"><span>Water depth</span><b>${ok?cmOf(t.level||0)+' cm':'no reading'}</b></div>\n"
  "      <div class=\"kv\"><span>Water distance</span><b>${ok?(t.dist||0).toFixed(1)+' cm':'no reading'}</b></div>\n"
  "      <div class=\"kv\"><span>Status</span><b class=\"${t.alert?'err':''}\">${esc(t.stateTxt||'')}</b></div>\n"
  "      ${t.ldr!==undefined?`<div class=\"kv\"><span>Room light</span><b>${esc(S.hub.room||'')} (${t.ldr} / 4095)</b></div>`:''}\n"
  "      <div class=\"kv\"><span>Signal</span><b>${on?d.rssi+' dBm':'offline'}</b></div>\n"
  "      <div class=\"kv\"><span>Firmware</span><b>${esc(d.fw||'')}</b></div></div></div>\n"
  "    <div class=\"row\"><button class=\"btn ${t.alert?'p':''}\" ${on&&t.alert?'':'disabled'} onclick=\"tankSilence()\">Silence alarm</button>\n"
  "      <button class=\"btn\" ${on?'':'disabled'} onclick=\"tankBeep()\">Beep</button>\n"
  "      <button class=\"btn\" ${on?'':'disabled'} onclick=\"cmd(tankMac,3)\">Identify</button></div></div>`;\n"
  "  // settings form: rebuilt only when the tank reports new values and you are not typing in it\n"
  "  const key=JSON.stringify(c||{})+d.name+JSON.stringify((S.hub||{}).global||{});\n"
  "  tankLive();\n"
  "  if(key===tsetKey||typing('#tset'))return;\n"
  "  tsetKey=key;\n"
  "  if(!c){$('#tset').innerHTML=`<div class=\"card\" style=\"margin-top:12px\"><div class=\"meta\">Waiting for the tank's settings… (tank firmware 1.4 or newer)</div></div>`;return}\n"
  "  const G=(S.hub||{}).global||{quietFrom:c.quietFrom,quietTo:c.quietTo,dayFrom:c.showFrom,dayTo:c.showTo};   // global home settings\n"
  "  const bm=['always','by time','by room light','by time + light'][c.buzzMode!=null?c.buzzMode:3],pal=['Red → Blue','Red → Green','Custom','Spectrum'][c.palette]||'';\n"
  "  $('#tset').innerHTML=`\n"
  "  <div data-tab=\"set\" class=\"card slist\">\n"
  "    <div class=\"sgrp\">Sensors</div>\n"
  "    ${srow('tank','size','📏','Water level sensor','full '+c.fullCm.toFixed(0)+' cm · empty '+c.emptyCm.toFixed(0)+' cm')}\n"
  "    ${srow('tank','ldr','◐','Light sensor',t.ldr!=null?'reading '+t.ldr:'')}\n"
  "    <div class=\"sgrp\">Alarm</div>\n"
  "    ${srow('tank','alarms','🔔','Alarm rules',c.rules?c.rules.filter(r=>r[0]).length+' on':'')}\n"
  "    ${srow('tank','buzzer','🔊','Buzzer',c.buzzer?'on · '+bm:'off')}\n"
  "    <div class=\"sgrp\">Level LEDs</div>\n"
  "    ${srow('tank','colours','🎨','Colours',pal)}\n"
  "    ${srow('tank','level','📶','How many & highlight',(c.ledCount||7)+' LEDs'+(c.highlight!=null?' · top +'+c.highlight+'%':''))}\n"
  "    ${srow('tank','bright','☀','Day / night brightness','day ≥'+(c.minBright||6)+(c.nightMax!=null?' · night ≤'+c.nightMax:''))}\n"
  "    <div class=\"sgrp\">Device</div>\n"
  "    ${srow('tank','device','✎','Name, restart, update',esc(d.name))}\n"
  "    ${srow('tank','adv','⚙','Advanced','simulation · chip · reset')}\n"
  "  </div>\n"
  "  <div data-tab=\"size\">\n"
  "  <div class=\"card\">\n"
  "    <div class=\"kv\" style=\"margin-top:-4px\"><span>Sensor reads now</span><b>${t.sensorOk!==false?(t.dist||0).toFixed(1)+' cm → '+Math.round(t.level||0)+' %':'no reading'}</b></div>\n"
  "    <label>Sensor-to-water distance: tank FULL ← → tank EMPTY</label>\n"
  "    ${dsl('tSz',2,400,c.fullCm,c.emptyCm,'cm',`rangeSend(1,2,this,${c.emptyCm})`,10,0.5,['Full at','Empty at'])}\n"
  "  </div>\n"
  "  </div><div data-tab=\"alarms\">\n"
  "  <div class=\"card\">\n"
  "    ${c.rules?c.rules.map((r,i)=>[r,i]).sort((a,b)=>(b[0][0]-a[0][0])||(b[0][1]-a[0][1])).map(([r,i],n)=>`<details class=\"rule\" data-rule=\"${i}\"><summary><span class=\"pill ${r[0]?'':'off'}\">${n+1}</span><span class=\"rd\">${ruleDesc(r)}</span><span class=\"chev\">›</span></summary>\n"
  "      <div class=\"switchrow\" style=\"margin:2px 0 0\"><span>Rule on</span><button class=\"tgl ${r[0]?'on':''}\" data-k=\"on\" onclick=\"this.classList.toggle('on')\"></button></div>\n"
  "      <div class=\"row\" style=\"margin-top:6px\"><select data-k=\"dir\">${opts(['When level rises to','When level drops to'],r[2])}</select><input data-k=\"level\" type=\"number\" min=\"0\" max=\"100\" value=\"${r[1]}\" style=\"flex:0 0 74px\" oninput=\"this.nextElementSibling.textContent='% ≈ '+cmOf(+this.value)+' cm water'\"><span class=\"meta\" style=\"flex:0 0 auto;align-self:center\">% ≈ ${cmOf(r[1])} cm water</span></div>\n"
  "      <div class=\"row\" style=\"margin-top:6px\"><select data-k=\"pattern\">${opts(SNDS,r[3])}</select><input data-k=\"repeats\" type=\"number\" min=\"1\" max=\"30\" value=\"${r[4]||1}\" style=\"flex:0 0 64px\" title=\"Times\"><span class=\"meta\" style=\"flex:0 0 auto;align-self:center\">times</span></div>\n"
  "      <div class=\"row\" style=\"margin-top:6px\"><select data-k=\"color\">${opts(FLCOL,r[5])}</select><button class=\"btn\" style=\"flex:0 0 70px\" onclick=\"testRule(${i})\">Test</button><button class=\"btn p\" style=\"flex:0 0 70px\" onclick=\"saveRule(${i})\">Save</button></div><div style=\"height:10px\"></div></details>`).join('')\n"
  "      :'<div class=\"meta\">Alarm rules need tank firmware 1.7 or newer.</div>'}\n"
  "  </div>\n"
  "  </div><div data-tab=\"buzzer\">\n"
  "  <div class=\"card\">\n"
  "    <div class=\"switchrow\" style=\"margin-top:0\"><span>Buzzer</span><button class=\"tgl ${c.buzzer?'on':''}\" onclick=\"tankBuzzer(this)\"></button></div>\n"
  "    ${c.buzzMode!=null?`<label>Buzzer may sound</label><select id=\"tBz\" data-chg=\"tset(33,this.value)\" onchange=\"stage(this);this.blur();bzWhen()\">${opts(['Always','By time (not in night hours)','By room light (only when lit)','By time and room light'],c.buzzMode)}</select>`:''}\n"
  "    <div class=\"why\" id=\"bzWhen\"></div>\n"
  "  </div>\n"
  "  </div><div data-tab=\"colours\">\n"
  "  <div class=\"card\">\n"
  "    ${[[3,'Spectrum','red → orange → yellow → green → cyan → blue'],[0,'Red → Blue','red at the bottom, fading to blue at the top'],[1,'Red → Green','red at the bottom, fading to green at the top']].concat(c.colors?[[2,'Custom','your own colour for every LED (pick them below)']]:[])\n"
  "      .map(([p,n,dsc])=>`<button class=\"copt ${c.palette==p?'on':''}\" data-grp=\"pal\" data-chg=\"tset(8,${p})\" onclick=\"palPick(this)\">${palStrip(c,p)}<span style=\"flex:1\"><b>${n}</b><br><span class=\"meta\">${dsc}</span></span></button>`).join('')}\n"
  "    ${c.colors?`<div id=\"custBox\" style=\"margin-top:10px;${c.palette==2?'':'display:none'}\">${c.colors.slice(0,c.ledCount||7).map((col,i)=>`<div class=\"switchrow\" style=\"margin:4px 0\"><span>LED ${i+1}${i==0?' (bottom)':i==(c.ledCount||7)-1?' (top)':''}</span>\n"
  "      <input type=\"color\" value=\"${col}\" data-led=\"${i}\" data-was=\"${col}\" data-chg=\"tset(${13+i},parseInt(this.value.slice(1),16))\" onchange=\"stage(this)\" style=\"flex:0 0 64px;height:34px;padding:2px\"></div>`).reverse().join('')}\n"
  "      <div class=\"row\"><button class=\"btn\" onclick=\"presetColors()\">Fill with preset: Red · greens · Blue</button></div>\n"
  "      </div>`:''}\n"
  "  </div>\n"
  "  </div><div data-tab=\"level\">\n"
  "  <div class=\"card\">\n"
  "    <label style=\"margin-top:0\">Number of LEDs that show the water level</label>\n"
  "    ${sl('tLeds',1,8,c.ledCount||7,'leds','tset(9,this.value)',60)}\n"
  "    ${c.gain?`<label>Top lit LED (the current level) stands out by</label>\n"
  "    ${sl('tHl',0,100,c.highlight,'pct','tset(21,this.value)',60)}\n"
  "    <label style=\"margin-top:14px\">Brightness of each LED (% of normal)</label>\n"
  "    ${(c.ledCount||7)>=4?`<div class=\"switchrow\" style=\"margin:4px 0 6px\"><span>Link LED 1 → LED ${(c.ledCount||7)-1}: fill the ones in between evenly</span><button class=\"tgl ${gLink?'on':''}\" id=\"gLinkT\" onclick=\"gLinkSet()\"></button></div>`:''}\n"
  "    ${[...Array(c.ledCount||7)].map((_,k)=>{const n=c.ledCount||7,i=n-1-k;return `<div class=\"${i>0&&i<n-2?'gmid':''}\"><div class=\"lab2\" style=\"margin-top:6px\"><span><span class=\"rdot\" style=\"background:${ledCol(c,i,n)}\"></span>LED ${i+1}${i==0?' (bottom)':i==n-1?' (top)':''}${i>0&&i<n-2?'<span class=\"meta gauto\"> · auto</span>':''}</span></div>${sl('tG'+i,10,100,c.gain[i],'pct','tset('+(22+i)+',this.value)')}</div>`}).join('')}`:''}\n"
  "    <div class=\"why\" id=\"hlInfo\"></div>\n"
  "  </div>\n"
  "  </div><div data-tab=\"bright\">\n"
  "  <div class=\"card\">\n"
  "    <p class=\"why\" style=\"margin-top:0\">The level LEDs follow the room light: dark room → off, bright room → full (255). These two limits change that:</p>\n"
  "    <div class=\"lab2\"><span>☀ ${h12(G.dayFrom)}–${h12(G.dayTo)}: never dimmer than</span></div>\n"
  "    ${sl('tMb',1,60,c.minBright||6,'b255','tset(12,this.value)',130)}\n"
  "    <div class=\"meta\">so you can always see the level during the day, even in a dark room</div>\n"
  "    ${c.nightMax!=null?`<div class=\"lab2\"><span>☾ ${h12(G.dayTo)}–${h12(G.dayFrom)}: never brighter than</span></div>\n"
  "    ${sl('tNm',0,255,c.nightMax,'b255','tset(34,this.value)',130)}\n"
  "    <div class=\"meta\">so they don't light up the room at night · 0 = off at night</div>`:''}\n"
  "    <div class=\"why\" id=\"brWhy\" style=\"margin-top:12px\"></div>\n"
  "  </div>\n"
  "  </div><div data-tab=\"ldr\">\n"
  "  <div class=\"card\">\n"
  "    <div class=\"kv\"><span>Light sensor reading now</span><b id=\"ldrRaw\">—</b></div>\n"
  "    <div class=\"kv\"><span>Lowest / highest in 24 h</span><b id=\"ldr24\">—</b></div>\n"
  "  ${c.ldrMin!=null?`\n"
  "    <label>Level LEDs: OFF at or below ← → FULL brightness at or above</label>\n"
  "    ${dsl('tLdr',0,4095,c.ldrMin,c.ldrMax,'ldrr',`rangeSend(31,32,this,${c.ldrMax})`,50,1,['OFF at','FULL at'])}\n"
  "    `:''}\n"
  "    ${globalNote('Room counts as dark (for every device) below '+((S.hub.global||{}).litOff||'?'))}\n"
  "  </div>\n"
  "  </div><div data-tab=\"size\">\n"
  "  <h3>Status text</h3>\n"
  "  <div class=\"card\">\n"
  "    <label style=\"margin-top:0\">Shows \"Low\" at or below ← → \"Full\" at or above</label>\n"
  "    ${dsl('tSt',0,100,c.lowPct,c.fullPct,'pct',`rangeSend(4,3,this,${c.fullPct})`,10,1,['Low at','Full at'])}\n"
  "  </div>\n"
  "  </div><div data-tab=\"device\">\n"
  "  <div class=\"card\">\n"
  "    <label style=\"margin-top:0\">Name</label>\n"
  "    <div class=\"row\" style=\"margin:0\"><input id=\"tName\" value=\"${esc(d.name)}\" data-chg=\"this.value.trim()&&cmd(tankMac,4,{text:this.value.trim()})\" oninput=\"stage(this)\"></div>\n"
  "    <div class=\"row\"><button class=\"btn\" onclick=\"if(confirm('Restart the tank monitor?'))cmd(tankMac,6)\">Restart</button><button class=\"btn\" onclick=\"nav('devices')\">Update firmware…</button></div>\n"
  "    <div class=\"row\"><button class=\"btn d\" onclick=\"forget(tankMac)\">Remove device…</button></div>\n"
  "  </div></div>`;\n"
  "  applySub('tank');tankLive();gApply();\n"
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
  "  els.forEach((el,i)=>{let c;if(i===0)c=[229,57,53];else if(i===n-1&&n>1)c=[47,59,255];else{const f=n>3?(i-1)/(n-3):0,p=f*(stops.length-1),k=Math.min(Math.floor(p),stops.length-2);c=mix(stops[k],stops[k+1],p-k)}el.value=hex(c);if(el.value!==el.dataset.was)stage(el)});\n"
  "  toast('Preset filled in — press Save to apply')}\n"
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
  "/* relay timers (kept by the hub): ⏱ opens quick choices - off in / on for 15 min…4 h, or off at a time */\n"
  "const RCOL=['#f5b841','#4aa8ff','#34d3b0','#e86fd0'];\n"
  "let tmOpen=-1;\n"
  "function tLeft(s){return s>=3600?Math.floor(s/3600)+'h '+Math.round(s%3600/60)+'m':s>=60?Math.round(s/60)+'m':s+'s'}\n"
  "function tmToggle(i){tmOpen=tmOpen===i?-1:i;renderSw()}\n"
  "async function tmGo(i,m,isOn){if(!isOn&&!await cmd(swMac,1,{idx:i,val:1}))return;if(await post('/api/timer',{mac:swMac,idx:i,mins:m})){tmOpen=-1;toast((isOn?'Off in ':'On for ')+(m<60?m+' min':m/60+' h'));renderSw()}}\n"
  "async function tmAt(i,isOn){const t=$('#tmAt').value;if(!/^\\d\\d:\\d\\d$/.test(t))return;if(!isOn&&!await cmd(swMac,1,{idx:i,val:1}))return;\n"
  "  if(await post('/api/timer',{mac:swMac,idx:i,at:t})){tmOpen=-1;const [h,m]=t.split(':');toast('Off at '+hm(new Date(2000,0,1,+h,+m)));renderSw()}}\n"
  "async function tmCancel(i){if(await post('/api/timer',{mac:swMac,idx:i,mins:0})){tmOpen=-1;toast('Timer cancelled');renderSw()}}\n"
  "/* usage by light: stacked bars (hours or days), coloured per relay, with kWh and estimated cost */\n"
  "async function loadUse(){const el=$('#swuse'),d=swDev();if(!el||!d)return;const h=await jget('/api/relayhist?mac='+encodeURIComponent(swMac));\n"
  "  if(!h||!h.end){el.innerHTML='<div class=\"meta\">Collecting — usage per light appears within the hour.</div>';return}\n"
  "  const G=(S.hub||{}).global||{},pD=(G.priceDay||616)/100,pN=(G.priceNight||616)/100,rl=d.relays||[],N=h.r[0].length,endMs=h.end*1000;\n"
  "  const isDay=ts=>{const hh=new Date(ts).getHours(),a=G.dayFrom,b=G.dayTo;return a<b?(hh>=a&&hh<b):(hh>=a||hh<b)};\n"
  "  const week=chartRange==='week',yday=chartRange==='yday';let bars=[];   // each bar: {label, kwh[4], cost}\n"
  "  const hourAt=k=>({ts:endMs-(N-1-k)*3600e3,s:h.r.map(a=>a[k])});\n"
  "  const add=(bar,x)=>x.s.forEach((s,r)=>{const e=s/3600*(+(rl[r]||{}).watts||0)/1000;bar.kwh[r]+=e;bar.cr[r]+=e*(isDay(x.ts)?pD:pN);bar.sec[r]+=s});\n"
  "  const mk=label=>({label,kwh:[0,0,0,0],cr:[0,0,0,0],sec:[0,0,0,0]});\n"
  "  if(week){for(let dd=6;dd>=0;dd--){const day=new Date();day.setHours(0,0,0,0);const a=day.getTime()-dd*864e5,b=a+864e5,bar=mk(dd?new Date(a).toLocaleDateString([], {weekday:'short'}):'Today');\n"
  "      for(let k=0;k<N;k++){const x=hourAt(k);if(x.ts>=a&&x.ts<b)add(bar,x)}bars.push(bar)}}\n"
  "  else{const day=new Date();day.setHours(0,0,0,0);const a=yday?day.getTime()-864e5:endMs-23*3600e3,b=yday?day.getTime():endMs+1;\n"
  "    for(let k=0;k<N;k++){const x=hourAt(k);if(x.ts<a||x.ts>=b)continue;const bar=mk(h12(new Date(x.ts).getHours()));add(bar,x);bars.push(bar)}}\n"
  "  const sum=f=>[0,1,2,3].map(r=>bars.reduce((a,b)=>a+b[f][r],0)),tot=sum('kwh'),cst=sum('cr'),sec=sum('sec');\n"
  "  const allK=tot.reduce((a,x)=>a+x,0),allC=cst.reduce((a,x)=>a+x,0),mx=Math.max(1e-6,...bars.map(b=>b.kwh.reduce((a,x)=>a+x,0)));\n"
  "  const W=340,H=130,pb=16,bw=(W-10)/Math.max(1,bars.length);let svg='';\n"
  "  bars.forEach((b,i)=>{let y=H-pb;b.kwh.forEach((e,r)=>{if(!e)return;const hh=(H-pb-8)*e/mx;y-=hh;svg+=`<rect x=\"${(5+i*bw+bw*.15).toFixed(1)}\" y=\"${y.toFixed(1)}\" width=\"${(bw*.7).toFixed(1)}\" height=\"${hh.toFixed(1)}\" rx=\"2\" fill=\"${RCOL[r]}\"><title>${b.label}: ${esc((rl[r]||{}).name||'')} ${(e*1000).toFixed(0)} Wh</title></rect>`});\n"
  "    if(week||i%6===0)svg+=`<text x=\"${(5+i*bw+bw/2).toFixed(1)}\" y=\"${H-3}\" fill=\"#64717d\" font-size=\"9\" text-anchor=\"middle\">${b.label}</text>`});\n"
  "  const span=week?'7 days':yday?'yesterday':'last 24 h',rs='₹';\n"
  "  el.innerHTML=`<div class=\"chd\"><div><div class=\"cv\" style=\"color:var(--txt)\">${rs}${allC.toFixed(2)}</div><div class=\"meta\">estimated · ${span}</div></div><div class=\"cst\"><div><span>Energy</span><b>${allK.toFixed(2)} kWh</b></div><div><span>Per month</span><b>${rs}${(allC/(week?7:1)*30).toFixed(0)}</b></div></div></div>\n"
  "    <svg viewBox=\"0 0 ${W} ${H}\" width=\"100%\" style=\"display:block\">${svg}</svg>\n"
  "    ${rl.map((r,i)=>r.used===false&&!tot[i]?'':`<div class=\"kv\"><span><span class=\"rdot\" style=\"background:${RCOL[i]}\"></span>${esc(r.name)}</span><b>${up(sec[i])} · ${tot[i].toFixed(2)} kWh · ${rs}${cst[i].toFixed(2)}</b></div><div class=\"bar\" style=\"margin:0 0 6px\"><i style=\"width:${allK?Math.round(tot[i]/allK*100):0}%;background:${RCOL[i]}\"></i></div>`).join('')}\n"
  "    <details class=\"more\"><summary>Price per unit</summary><div class=\"row\" style=\"align-items:center;gap:6px\"><span class=\"meta\" style=\"flex:0 0 auto\">Day ${rs}</span><input id=\"pDay\" type=\"number\" step=\"0.01\" value=\"${pD.toFixed(2)}\"><span class=\"meta\" style=\"flex:0 0 auto\">Night ${rs}</span><input id=\"pNight\" type=\"number\" step=\"0.01\" value=\"${pN.toFixed(2)}\"><button class=\"btn\" style=\"flex:0 0 64px\" onclick=\"savePrice()\">Save</button></div>\n"
  "      <p class=\"note\">BESCOM home rate ₹5.80 + 36 p surcharge = ₹6.16 per unit (same day and night). Estimate from each light's watts and on-time.</p></details>`}\n"
  "async function savePrice(){const d=Math.round(+$('#pDay').value*100),n=Math.round(+$('#pNight').value*100);if(!(d>=0&&d<=5000&&n>=0&&n<=5000)){toast('Price 0–50 ₹');return}\n"
  "  if(await post('/api/global',{priceDay:d,priceNight:n})){toast('Price saved');loadUse()}}\n"
  "function renderSw(){\n"
  "  const d=swDev();if(!d){nav('home');return}\n"
  "  const on=d.online,rl=d.relays||[];\n"
  "  if(!typing('#swlive'))$('#swlive').innerHTML=otaNote(d.mac)+`<div class=\"card ${on?'':'offline'}\">\n"
  "    <div class=\"chead\"><span class=\"dot ${on?'on':'off'}\"></span><span class=\"nm\">${esc(d.name)}</span><span class=\"w\">${totalW(d).toFixed(0)} W</span></div>\n"
  "    ${rl.map((r,i)=>`<div class=\"rel\"><span class=\"rdot\" style=\"background:${RCOL[i]}\"></span><div class=\"n\"><b>${esc(r.name)}${r.used===false?' <span class=\"meta\">(not in use)</span>':''}</b><span class=\"meta\">${r.on?('On · '+r.watts+' W'+(r.onSecs?' · '+up(r.onSecs):'')):'Off'}${r.timer!=null?` · <span style=\"color:var(--acc)\">⏱ off in ${tLeft(r.timer)}</span>`:''}</span></div>\n"
  "      <button class=\"tmb ${r.timer!=null?'on':''}\" ${on?'':'disabled'} onclick=\"tmToggle(${i})\">⏱</button>\n"
  "      <button class=\"tgl ${r.on?'on':''}\" ${on?'':'disabled'} onclick=\"tog(this,'${d.mac}',${i},${!r.on})\"></button></div>\n"
  "      ${tmOpen===i?`<div class=\"tmp\"><div class=\"meta\">${r.on?'Turn off in':'Turn on for'}</div><div class=\"row\" style=\"margin-top:4px;gap:6px\">${[15,30,60,120,240].map(m=>`<button class=\"btn\" style=\"padding:7px 0\" onclick=\"tmGo(${i},${m},${r.on})\">${m<60?m+'m':m/60+'h'}</button>`).join('')}</div>\n"
  "        <div class=\"row\" style=\"gap:6px;align-items:center\"><span class=\"meta\" style=\"flex:0 0 auto\">Off at</span><input type=\"time\" id=\"tmAt\" value=\"23:00\"><button class=\"btn p\" style=\"flex:0 0 64px\" onclick=\"tmAt(${i},${r.on})\">Set</button>${r.timer!=null?`<button class=\"btn d\" style=\"flex:0 0 70px\" onclick=\"tmCancel(${i})\">Cancel</button>`:''}</div></div>`:''}`).join('')||'<div class=\"meta\">Waiting for relay info…</div>'}\n"
  "    <div class=\"kv\" style=\"margin-top:8px\"><span>Signal</span><b>${on?d.rssi+' dBm':'offline'}</b></div>\n"
  "    <div class=\"kv\"><span>Up</span><b>${up(d.uptime||0)}</b></div>\n"
  "    <div class=\"kv\"><span>Firmware</span><b>${esc(d.fw||'')}</b></div></div>`;\n"
  "  const key=JSON.stringify(rl.map(r=>[r.name,r.watts,r.used,r.gpio,r.mode,r.pulseMs,r.activeHigh]))+d.touch+JSON.stringify([d.touchMap,d.touchAct])+d.name+JSON.stringify((S.hub||{}).global||{});\n"
  "  if(key===swKey||typing('#swset'))return;\n"
  "  swKey=key;\n"
  "  $('#swset').innerHTML=`\n"
  "  <div data-tab=\"set\" class=\"card slist\">\n"
  "    <div class=\"sgrp\">Relays</div>\n"
  "    ${rl.map((r,i)=>srow('sw','r'+i,`<span class=\"rdot\" style=\"background:${RCOL[i]};margin:0\"></span>`,esc(r.name),r.used===false?'not in use':r.watts+' W'+(r.mode==1?' · pulse':''))).join('')}\n"
  "    <div class=\"sgrp\">Device</div>\n"
  "    ${d.touch!==undefined?srow('sw','touch','👆','Touch pads',d.touch?'on':'off'):''}\n"
  "    ${srow('sw','device','✎','Name & device',esc(d.name))}\n"
  "    ${srow('sw','adv','⚙','Advanced','chip · reset')}\n"
  "  </div>\n"
  "  <div>\n"
  "    ${rl.map((r,i)=>`<div class=\"card\" data-tab=\"r${i}\">\n"
  "      <label style=\"margin-top:0\">What it powers (name)</label><input value=\"${esc(r.name)}\" data-r=\"${i}n\" placeholder=\"Name\" data-grp=\"rm${i}\" data-chg=\"relMeta(swMac,${i},this)\" oninput=\"stage(this)\">\n"
  "      <label>Power of the light / fan (watts)</label><input type=\"number\" value=\"${r.watts}\" data-r=\"${i}w\" data-grp=\"rm${i}\" data-chg=\"relMeta(swMac,${i},this)\" oninput=\"stage(this)\">\n"
  "      <div class=\"switchrow\" style=\"margin-top:14px\"><span>In use (shown on Home)</span><button class=\"tgl ${r.used===false?'':'on'}\" onclick=\"relUse(this,${i})\"></button></div>\n"
  "      ${r.mode!=null?`<h3 style=\"margin:16px 0 4px\">Output</h3>\n"
  "      <label style=\"margin-top:0\">When switched ON</label><select data-chg=\"swset(${16+i},this.value)\" onchange=\"stage(this);this.blur()\">${opts(['Stay ON until switched OFF','Pulse: ON briefly, then OFF by itself'],r.mode)}</select>\n"
  "      <label>Pulse length (only for pulse)</label>${sl('pl'+i,50,10000,r.pulseMs,'ms','swset('+(32+i)+',this.value)')}\n"
  "      <label>ON drives the relay pin</label><select data-chg=\"swset(${48+i},this.value)\" onchange=\"stage(this);this.blur()\">${opts(['LOW (most relay boards)','HIGH'],r.activeHigh)}</select>`:''}\n"
  "      <div class=\"kv\" style=\"margin-top:8px\"><span>Output pin</span><b>GPIO ${r.gpio}</b></div></div>`).join('')}\n"
  "  </div><div data-tab=\"touch\">\n"
  "  ${d.touch!==undefined?`<div class=\"card\"><div class=\"switchrow\" style=\"margin:0\"><span>Touch pads on</span>\n"
  "    <button class=\"tgl ${d.touch?'on':''}\" onclick=\"cmd(swMac,9,{val:${d.touch?0:1}})\"></button></div>\n"
  "    ${d.touchMap?d.touchMap.map((m,p)=>`<div class=\"lab2\" style=\"margin-top:14px\"><span>Pad ${p+1}</span><span class=\"meta\">GPIO ${4+p}</span></div>\n"
  "      <div class=\"row\" style=\"margin:0\"><select data-chg=\"swset(${64+p},this.value)\" onchange=\"stage(this);this.blur()\">${rl.map((r,i)=>`<option value=\"${i}\" ${m==i?'selected':''}>controls ${esc(r.name)}</option>`).join('')}<option value=\"-1\" ${m<0?'selected':''}>does nothing</option></select>\n"
  "      <select data-chg=\"swset(${80+p},this.value)\" onchange=\"stage(this);this.blur()\">${opts(['Toggle on each touch','ON only while touched'],d.touchAct[p])}</select></div>`).join(''):'<p class=\"note\">Pad mapping needs switch firmware 2.9 or newer.</p>'}</div>`:''}\n"
  "  </div><div data-tab=\"device\">\n"
  "  <div class=\"card\">\n"
  "    <label style=\"margin-top:0\">Name</label>\n"
  "    <div class=\"row\" style=\"margin:0\"><input id=\"swName\" value=\"${esc(d.name)}\" data-chg=\"this.value.trim()&&cmd(swMac,4,{text:this.value.trim()})\" oninput=\"stage(this)\"></div>\n"
  "    <div class=\"row\"><button class=\"btn\" onclick=\"cmd(swMac,3)\">Identify</button><button class=\"btn\" onclick=\"if(confirm('Restart the switch? All relays turn OFF.'))cmd(swMac,6)\">Restart</button></div>\n"
  "    <div class=\"row\"><button class=\"btn\" onclick=\"nav('devices')\">Update firmware…</button><button class=\"btn d\" onclick=\"forget(swMac)\">Remove device…</button></div>\n"
  "    ${(S.hub||{}).global?globalNote(`Status light ${S.hub.global.ledDay} / ${S.hub.global.ledNight} (day / night, of 255)`):''}\n"
  "  </div></div>`;\n"
  "  applySub('sw');\n"
  "}\n"
  "function swset(idx,v){return cmd(swMac,15,{idx:idx,f:+v})}   // switch setting: idx = field*16 + relay/pad\n"
  "async function relUse(el,i){const u=!el.classList.contains('on');el.classList.toggle('on',u);if(!await post('/api/relayuse',{mac:swMac,idx:i,used:u}))el.classList.toggle('on',!u)}\n"
  "async function swRename(){const n=$('#swName').value.trim();if(!n)return;if(await cmd(swMac,4,{text:n}))toast('Name saved')}\n"
  "\n"
  "/* 24 h trend chart (one point per 5 minutes, gaps where the device was offline) */\n"
  "let chartTimer=null;\n"
  "function pageExtras(kind){\n"
  "  const mac=kind==='tank'?tankMac:swMac,box=kind==='tank'?'#tchart':'#swchart',det=kind==='tank'?'#tadvd':'#swadvd';\n"
  "  const go=()=>{if(page===kind){loadChart(mac,box,kind==='tank'?'%':'W');if(kind==='sw')loadUse()}};\n"
  "  go();clearInterval(chartTimer);chartTimer=setInterval(go,20000);\n"
  "}\n"
  "function h12(h){h=+h;return (h%12||12)+' '+(h<12?'AM':'PM')}\n"
  "function hm(t,s){const h=t.getHours();return (h%12||12)+':'+String(t.getMinutes()).padStart(2,'0')+(s?':'+String(t.getSeconds()).padStart(2,'0'):'')+' '+(h<12?'AM':'PM')}\n"
  "let chartRange='day',chartDrawn='';\n"
  "const chartZ={};   // zoom per device+range: [from, to] as 0..1 of the range\n"
  "function zTime(ms,week){const t=new Date(ms);return week?t.toLocaleDateString([], {weekday:'short'})+' '+hm(t):hm(t)}\n"
  "function zIn(el,which){const c=el.closest('.zoomc'),lo=c.querySelector('.dlo'),hi=c.querySelector('.dhi'),N=+c.dataset.n;\n"
  "  if(which===0&&+lo.value>+hi.value-2)lo.value=+hi.value-2;if(which===1&&+hi.value<+lo.value+2)hi.value=+lo.value+2;\n"
  "  const f=c.querySelector('.dfill');f.style.left=(+lo.value/(N-1)*100)+'%';f.style.right=(100-+hi.value/(N-1)*100)+'%';\n"
  "  const t0=+c.dataset.t0,st=+c.dataset.step,wk=c.dataset.week==='1';c.querySelector('[data-k=za]').textContent=zTime(t0+lo.value*st,wk);\n"
  "  c.querySelector('[data-k=zb]').textContent=+hi.value>=N-1&&!wk?'now':zTime(t0+hi.value*st,wk);\n"
  "  // show the selection on the chart while dragging: a line at each end, everything outside dimmed\n"
  "  const svg=c.parentElement.querySelector('svg'),sel=svg&&svg.querySelector('.zsel');if(!sel)return;\n"
  "  const [x0,x1]=c.dataset.gx.split(',').map(Number),za=+c.dataset.za,vn=+c.dataset.vn,X=i=>Math.max(x0,Math.min(x1,x0+(x1-x0)*(i-za)/Math.max(1,vn-1)));\n"
  "  const a=X(+lo.value),b=X(+hi.value);sel.setAttribute('visibility','visible');\n"
  "  const s0=sel.querySelector('.zs0'),s1=sel.querySelector('.zs1');s0.setAttribute('x',x0);s0.setAttribute('width',Math.max(0,a-x0));s1.setAttribute('x',b);s1.setAttribute('width',Math.max(0,x1-b));\n"
  "  for(const [cl,x] of [['.zl0',a],['.zl1',b]]){const l=sel.querySelector(cl);l.setAttribute('x1',x);l.setAttribute('x2',x)}}\n"
  "function zSet(el){const c=el.closest('.zoomc'),N=+c.dataset.n,lo=+c.querySelector('.dlo').value,hi=+c.querySelector('.dhi').value;el.blur();\n"
  "  chartZ[c.dataset.k]=[lo/(N-1),hi/(N-1)];chartDrawn='';loadChart(c.dataset.mac,c.dataset.box,c.dataset.unit)}\n"
  "function zReset(a){const c=a.closest('.zoomc');chartZ[c.dataset.k]=null;chartDrawn='';loadChart(c.dataset.mac,c.dataset.box,c.dataset.unit)}\n"
  "function setRange(r){chartRange=r;pageExtras(page)}\n"
  "function hms(t){return hm(t,1)}\n"
  "async function loadChart(mac,box,unit){\n"
  "  const el=$(box);if(!el)return;\n"
  "  const week=chartRange==='yday'||chartRange==='week',fineR=chartRange==='h1',mq='/api/history?mac='+encodeURIComponent(mac);\n"
  "  const [h,h5]=await Promise.all([jget(mq+(week?'&range=week':fineR?'&range=fine':'')),fineR?jget(mq):null]);\n"
  "  const btns=`<div class=\"rng\">${[['h1','1H'],['h6','6H'],['day','24H'],['yday','Yday'],['week','7D']].map(([k,l])=>`<button class=\"${chartRange===k?'on':''}\" onclick=\"setRange('${k}')\">${l}</button>`).join('')}</div>`;\n"
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
  "  // zoom: the two-handle bar under the chart picks a part of this range (kept while the chart refreshes)\n"
  "  const zk=mac+chartRange,full=v.length,ft0=t0,z=chartZ[zk]||[0,1];let za=0,zb=full-1;\n"
  "  if(full>3&&(z[0]>0||z[1]<1)){za=Math.round(z[0]*(full-1));zb=Math.max(za+2,Math.round(z[1]*(full-1)));v=v.slice(za,zb+1);t0+=za*step}\n"
  "  const atEnd=zb>=full-1,zoomed=za>0||!atEnd;\n"
  "  const pts=v.filter(x=>x!=null),n=v.length;\n"
  "  if(!pts.length){el.innerHTML=btns+'<div class=\"meta\">No readings for this period yet.</div>'+(zoomed?`<a href=\"#\" onclick=\"chartZ['${zk}']=null;pageExtras(page);return false\" style=\"color:var(--acc)\">Show all</a>`:'');return}\n"
  "  // y-axis: water level always 0-100 %; power always 0 to the switch's total watts\n"
  "  // power: 0 to the total watts of the relays in use, the same on every range (stretches only if a reading is higher)\n"
  "  const dvc=S.devices.find(x=>x.mac===mac)||{},capW=(dvc.relays||[]).filter(r=>r.used!==false).reduce((a,r)=>a+(+r.watts||0),0);\n"
  "  let lo=0,hi=unit==='%'?100:Math.max(capW||10,...pts);\n"
  "  const W=340,H=150,pl=30,pr=10,pt=12,pb=20;\n"
  "  const X=i=>pl+(W-pl-pr)*i/Math.max(1,n-1),Y=y=>pt+(H-pt-pb)*(1-(y-lo)/(hi-lo||1));\n"
  "  // smooth curve that never overshoots (each step is a cubic with flat ends) + a soft gradient area under it\n"
  "  let line='',area='',dots='',seg=[];\n"
  "  const flush=()=>{if(!seg.length)return;if(seg.length===1)dots+=`<circle cx=\"${seg[0][0]}\" cy=\"${seg[0][1]}\" r=\"2.5\"/>`;\n"
  "    let d='M'+seg[0][0]+' '+seg[0][1];for(let k=1;k<seg.length;k++){const [x0,y0]=seg[k-1],[x1,y1]=seg[k],m=((+x0+ +x1)/2).toFixed(1);d+=` C${m} ${y0} ${m} ${y1} ${x1} ${y1}`}\n"
  "    line+=d;area+=d+` L${seg[seg.length-1][0]} ${H-pb} L${seg[0][0]} ${H-pb} Z`;seg=[]};\n"
  "  v.forEach((y,i)=>{if(y==null){flush();return}seg.push([X(i).toFixed(1),Y(y).toFixed(1)])});flush();\n"
  "  const dec=(hi-lo)<10?1:0,fmt=x=>x.toFixed(dec);\n"
  "  let g='';[0,.5,1].forEach(f=>{const val=lo+(hi-lo)*f,y=Y(val);g+=`<line x1=\"${pl}\" x2=\"${W-pr}\" y1=\"${y}\" y2=\"${y}\" stroke=\"#202a33\" stroke-dasharray=\"3 4\"/><text x=\"${pl-6}\" y=\"${y+3}\" fill=\"#64717d\" font-size=\"9\" text-anchor=\"end\">${fmt(val)}</text>`});\n"
  "  const lbl=(i,txt,anc)=>`<text x=\"${X(i)}\" y=\"${H-5}\" fill=\"#64717d\" font-size=\"9\" text-anchor=\"${anc||'middle'}\">${txt}</text>`;\n"
  "  if(chartRange==='yday')[0,6,12,18].forEach(hh=>{g+=lbl(hh,h12(hh),hh?'middle':'start')});\n"
  "  else{const parts=n>8?4:Math.max(1,n-1);for(let k=parts;k>=0;k--){const i=Math.round((n-1)*(parts-k)/parts),t=new Date(t0+i*step);\n"
  "    g+=lbl(i,!k&&!week&&atEnd?'now':(chartRange==='week'?t.toLocaleDateString([], {weekday:'short'})+' '+hm(t):hm(t)),k===parts?'start':k?'middle':'end')}}\n"
  "  const last=pts[pts.length-1],water=unit==='%',col=water?'#4aa8ff':'#f5b841',hrsPer=h.step/3600,u=water?'%':'W',gid='cg'+box.slice(1);\n"
  "  const fv=x=>water?x.toFixed(1):String(Math.round(x)),avg=pts.reduce((a,x)=>a+x,0)/pts.length;\n"
  "  const stats=water?[['Low',fv(Math.min(...pts))+'%'],['High',fv(Math.max(...pts))+'%']]\n"
  "    :[['Peak',Math.round(Math.max(...pts))+' W'],['Avg',Math.round(avg)+' W'],['Energy',(v.reduce((a,x)=>a+(x||0),0)*hrsPer/1000).toFixed(2)+' kWh']];\n"
  "  const liveDot=!week&&atEnd&&v[n-1]!=null?`<circle cx=\"${X(n-1)}\" cy=\"${Y(v[n-1])}\" r=\"7\" fill=\"${col}\" opacity=\".25\"><animate attributeName=\"r\" values=\"4;9;4\" dur=\"2.4s\" repeatCount=\"indefinite\"/><animate attributeName=\"opacity\" values=\".35;0;.35\" dur=\"2.4s\" repeatCount=\"indefinite\"/></circle><circle cx=\"${X(n-1)}\" cy=\"${Y(v[n-1])}\" r=\"3.5\" fill=\"${col}\" stroke=\"#0c0f12\" stroke-width=\"1.5\"/>`:'';\n"
  "  const res=(fineR?'every 10 s':week?'hourly':'5-min average')+note,anim=chartDrawn!==mac+chartRange;chartDrawn=mac+chartRange;   // draw-in only when the chart is new\n"
  "  el.innerHTML=`<div class=\"chd\"><div><div class=\"cv\" data-k=\"hv\" style=\"color:${col}\">${fv(last)}<small>${u}</small></div><div class=\"meta\" data-k=\"ht\">${week?'latest':'now'}</div></div>\n"
  "    <div class=\"cst\">${stats.map(([k,val])=>`<div><span>${k}</span><b>${val}</b></div>`).join('')}</div></div>${btns}\n"
  "    <svg viewBox=\"0 0 ${W} ${H}\" width=\"100%\" style=\"display:block;touch-action:pan-y;margin-top:6px\"><defs><linearGradient id=\"${gid}\" x1=\"0\" y1=\"0\" x2=\"0\" y2=\"1\"><stop offset=\"0\" stop-color=\"${col}\" stop-opacity=\".45\"/><stop offset=\"1\" stop-color=\"${col}\" stop-opacity=\"0\"/></linearGradient></defs>\n"
  "    ${g}<path d=\"${area}\" fill=\"url(#${gid})\"/><path class=\"${anim?'cl':''}\" d=\"${line}\" fill=\"none\" stroke=\"${col}\" stroke-width=\"2.2\" stroke-linejoin=\"round\" stroke-linecap=\"round\"/><g fill=\"${col}\">${dots}</g>${liveDot}\n"
  "    <g class=\"zsel\" visibility=\"hidden\"><rect class=\"zs0\" y=\"${pt}\" height=\"${H-pt-pb}\" fill=\"#0c0f12\" opacity=\".65\"/><rect class=\"zs1\" y=\"${pt}\" height=\"${H-pt-pb}\" fill=\"#0c0f12\" opacity=\".65\"/>\n"
  "      <line class=\"zl0\" y1=\"${pt-4}\" y2=\"${H-pb}\" stroke=\"var(--acc)\" stroke-width=\"2\"/><line class=\"zl1\" y1=\"${pt-4}\" y2=\"${H-pb}\" stroke=\"var(--acc)\" stroke-width=\"2\"/></g>\n"
  "    <line class=\"cx\" y1=\"${pt}\" y2=\"${H-pb}\" stroke=\"#8b98a4\" stroke-dasharray=\"2 3\" visibility=\"hidden\"/><circle class=\"cd\" r=\"4.5\" fill=\"${col}\" stroke=\"#fff\" stroke-width=\"1.5\" visibility=\"hidden\"/>\n"
  "    <g class=\"tipg\" visibility=\"hidden\" style=\"pointer-events:none\"><rect class=\"tipr\" rx=\"6\" height=\"17\" fill=\"#1b232b\" stroke=\"${col}\" stroke-width=\"1\"/><text class=\"tipt\" fill=\"#e8eef3\" font-size=\"10\" font-weight=\"650\" text-anchor=\"middle\"></text></g></svg>\n"
  "    ${full>3?`<div class=\"zoomc\" data-k=\"${zk}\" data-t0=\"${ft0}\" data-step=\"${step}\" data-n=\"${full}\" data-week=\"${week?1:0}\" data-mac=\"${mac}\" data-box=\"${box}\" data-unit=\"${unit}\" data-za=\"${za}\" data-vn=\"${n}\" data-gx=\"${pl},${W-pr},${W}\">\n"
  "      <div class=\"dtrk\"><div class=\"dfill\" style=\"left:${za/(full-1)*100}%;right:${100-zb/(full-1)*100}%\"></div>\n"
  "      <input type=\"range\" class=\"dlo\" min=\"0\" max=\"${full-1}\" value=\"${za}\" oninput=\"zIn(this,0)\" onchange=\"zSet(this)\"><input type=\"range\" class=\"dhi\" min=\"0\" max=\"${full-1}\" value=\"${zb}\" oninput=\"zIn(this,1)\" onchange=\"zSet(this)\"></div>\n"
  "      <div class=\"zlab\"><span data-k=\"za\">${zTime(ft0+za*step,week)}</span>${zoomed?`<a href=\"#\" onclick=\"zReset(this);return false\">⤢ Show all</a>`:'<span class=\"meta\">drag the ends to zoom in</span>'}<span data-k=\"zb\">${atEnd&&!week?'now':zTime(ft0+zb*step,week)}</span></div></div>`:''}\n"
  "    <div class=\"meta\" style=\"text-align:right\">${res}${zoomed?' · zoomed':''}</div>`;\n"
  "  // tap / hover: the big number shows the value and time at that point\n"
  "  const svg=el.querySelector('svg'),cx=svg.querySelector('.cx'),cd=svg.querySelector('.cd'),hv=el.querySelector('[data-k=hv]'),ht=el.querySelector('[data-k=ht]');\n"
  "  const tipg=svg.querySelector('.tipg'),tipr=svg.querySelector('.tipr'),tipt=svg.querySelector('.tipt');\n"
  "  svg.addEventListener('pointerleave',()=>{cx.setAttribute('visibility','hidden');cd.setAttribute('visibility','hidden');tipg.setAttribute('visibility','hidden');hv.innerHTML=fv(last)+'<small>'+u+'</small>';ht.textContent=week?'latest':'now'});\n"
  "  const show=e=>{const r=svg.getBoundingClientRect(),x=(e.clientX-r.left)*W/r.width;let i=Math.round((x-pl)/((W-pl-pr)/Math.max(1,n-1)));i=Math.max(0,Math.min(n-1,i));\n"
  "    let j=i;for(let d=0;d<n&&v[j]==null;d++){if(i+d<n&&v[i+d]!=null){j=i+d;break}if(i-d>=0&&v[i-d]!=null){j=i-d;break}}\n"
  "    if(v[j]==null)return;const t=new Date(t0+j*step);\n"
  "    cx.setAttribute('x1',X(j));cx.setAttribute('x2',X(j));cx.setAttribute('visibility','visible');cd.setAttribute('cx',X(j));cd.setAttribute('cy',Y(v[j]));cd.setAttribute('visibility','visible');\n"
  "    const when=(week?t.toLocaleDateString([], {weekday:'short',day:'numeric'})+' '+hm(t):fineR?hms(t):hm(t))+(j===n-1&&!week&&atEnd?' (now)':'');\n"
  "    hv.innerHTML=fv(v[j])+'<small>'+u+'</small>';ht.textContent=when;\n"
  "    // floating label right above the point (below it when the point is near the top)\n"
  "    tipt.textContent=fv(v[j])+(water?'%':' W')+' · '+when;tipg.setAttribute('visibility','visible');\n"
  "    const w=tipt.getComputedTextLength()+14,px=X(j),py=Y(v[j]),tx=Math.max(pl+w/2,Math.min(W-pr-w/2,px)),ty=py-12<pt+6?py+24:py-12;\n"
  "    tipt.setAttribute('x',tx);tipt.setAttribute('y',ty);tipr.setAttribute('x',tx-w/2);tipr.setAttribute('y',ty-12);tipr.setAttribute('width',w)};\n"
  "  svg.addEventListener('pointermove',show);svg.addEventListener('pointerdown',show);\n"
  "}\n"
  "\n"
  "/* Advanced: chip details + factory reset */\n"
  "const RST=['unknown','power on','reset pin','software restart','crash','interrupt watchdog','task watchdog','watchdog','deep sleep','brownout (low power)','SDIO','USB','JTAG','eFuse','power glitch','CPU lockup'];\n"
  "function fmtB(b){return b>=1048576?(b/1048576).toFixed(2)+' MB':Math.round(b/1024)+' KB'}\n"
  "function advRows(a){const r=[];\n"
  "  if(a.temp!==undefined)r.push(['Chip temperature',a.temp.toFixed(1)+' °C','The processor\\'s own sensor; it runs warmer than the room. Above ~80 °C is too hot.']);\n"
  "  if(a.heap!==undefined)r.push(['Working memory (RAM) free',fmtB(a.heap)+' (lowest '+fmtB(a.heapMin)+')','']);\n"
  "  if(a.psram)r.push(['PSRAM',fmtB(a.psram),'Extra memory chip on the board.']);\n"
  "  if(a.cpu)r.push(['CPU speed',a.cpu+' MHz','']);\n"
  "  if(a.reset!==undefined)r.push(['Last restart cause',RST[a.reset]||a.reset,'Why the chip last started. \"brownout\" means the power supply dipped; \"crash\" or \"watchdog\" means the program had a problem.']);\n"
  "  if(a.uptime!==undefined)r.push(['Running for',up(a.uptime),'']);\n"
  "  if(a.rssi!==undefined)r.push(['Signal',a.rssi+' dBm','Radio signal strength: -50 excellent, -70 good, -85 weak, below -90 unreliable.']);\n"
  "  if(a.channel)r.push(['WiFi channel',a.channel,'The router\\'s channel. All LEO devices follow it automatically.']);\n"
  "  if(a.mac)r.push(['MAC address',a.mac,'']);if(a.ip)r.push(['IP address',a.ip,'']);\n"
  "  if(a.fw)r.push(['Firmware',a.fw,'']);if(a.sdk)r.push(['ESP-IDF',a.sdk,'Version of Espressif\\'s system software inside the firmware.']);\n"
  "  return flashMap(a)+r.map(([k,v,h])=>`<div class=\"kv\"><span>${k}${h?q(h):''}</span><b>${esc(v)}</b></div>`).join('')}\n"
  "/* flash memory as one bar whose parts add up exactly to the chip size */\n"
  "function flashMap(a){if(!a.flash||!a.sketchMax)return '';const tot=a.flash,slot=a.sketchMax,fs=a.fsTotal||0,sys=Math.max(0,tot-2*slot-fs);\n"
  "  const parts=[['Firmware (running)',a.sketch,'#4aa8ff'],['Free in the firmware slot',slot-a.sketch,'#4aa8ff44'],['Kept free for wireless updates',slot,'#5d6a76']]\n"
  "    .concat(fs?[['Saved files (settings, logs, history)',a.fsUsed,'#34d3b0'],['Free for files',fs-a.fsUsed,'#34d3b044']]:[]).concat([[fs?'System (boot, WiFi, settings)':'System + unused file space',sys,'#2a333c']]);\n"
  "  return `<div class=\"kv\"><span>Flash memory</span><b>${fmtB(tot)} total</b></div><div style=\"display:flex;height:12px;border-radius:6px;overflow:hidden;margin:4px 0 6px\">${parts.map(([,b,c])=>`<i style=\"flex:${b} 0 0;background:${c}\"></i>`).join('')}</div>\n"
  "    ${parts.map(([n,b,c])=>`<div class=\"kv\" style=\"font-size:12px;padding:3px 0\"><span><span class=\"rdot\" style=\"background:${c}\"></span>${n}</span><b>${fmtB(b)} · ${(b/tot*100).toFixed(1)}%</b></div>`).join('')}`}\n"
  "async function loadAdv(mac,box){const el=$(box);el.innerHTML='Loading…';\n"
  "  const a=await jget('/api/diag?mac='+encodeURIComponent(mac));if(!a){el.textContent='Not available.';return}\n"
  "  el.innerHTML=(a.known?advRows(a):'<div class=\"meta\">Chip details arrive within a minute (device firmware: switch 2.6 / tank 1.6 or newer).</div>')+(mac===tankMac?simPanel():'')+\n"
  "    `<div class=\"row\" style=\"margin-top:14px\"><button class=\"btn d\" onclick=\"devFactory('${a.mac}')\">Factory reset this device…</button></div>\n"
  "     <p class=\"note\">Erases settings and pairing. Or hold <b>BOOT</b> 15 s.</p>`;\n"
  "  if(mac===tankMac)simBar()}\n"
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
  "let homeKey='',homeEdit=false;   // home settings stay locked (greyed) until you tap Edit\n"
  "function homeEditSet(on){homeEdit=on;homeKey='';renderHomeSet()}\n"
  "function renderHomeSet(){const box=$('#homeset'),g=(S.hub||{}).global;if(!box||!g)return;\n"
  "  const key=JSON.stringify(g)+homeEdit;if(key===homeKey||typing('#homeset')||(homeEdit&&homeKey)){homeLive();return}homeKey=key;\n"
  "  const tk=S.devices.find(d=>d.type==='tank'),tc=tk&&tk.tank&&tk.tank.cfg,mute=g.quietFrom!==g.quietTo;\n"
  "  box.innerHTML=`<style>#homeset .hs{border:1px solid var(--line);border-radius:12px;padding:10px 12px;margin:0 0 12px}#homeset .hs h4{margin:0 0 6px;display:flex;justify-content:space-between;align-items:center;font-size:13px}\n"
  "    #homeset .lab{display:flex;justify-content:space-between;font-size:12px;color:var(--mut);margin:8px 0 2px}#homeset .meter{position:relative;height:14px;border-radius:7px;background:linear-gradient(90deg,#111,#665d2e 60%,#fff3b0);margin:10px 0 4px}\n"
  "    #homeset .meter i{position:absolute;top:-4px;bottom:-4px;width:3px;background:var(--acc);border-radius:2px}#homeset .meter b{position:absolute;top:2px;width:10px;height:10px;margin-left:-5px;border-radius:50%;background:#fff;box-shadow:0 0 0 2px #000}</style>\n"
  "  <fieldset id=\"hsF\" ${homeEdit?'':'disabled'}>\n"
  "  <div class=\"hs\"><h4>☀ Day <span class=\"row\" style=\"margin:0;flex:0 0 auto;gap:4px\"><select id=\"gDf\">${hrs(g.dayFrom)}</select>→<select id=\"gDt\">${hrs(g.dayTo)}</select></span></h4>\n"
  "    <div class=\"lab\"><span>Status light</span></div>${sl('gLd',0,255,g.ledDay,'b255','',130)}\n"
  "    </div>\n"
  "  <div class=\"hs\"><h4>☾ Night <span class=\"row\" style=\"margin:0;flex:0 0 auto;gap:4px\"><select id=\"gQf\">${hrs(mute?g.quietFrom:22)}</select>→<select id=\"gQt\">${hrs(mute?g.quietTo:7)}</select></span></h4>\n"
  "    <div class=\"lab\"><span>Status light</span></div>${sl('gLn',0,255,g.ledNight,'b255','',130)}\n"
  "    <div class=\"switchrow\"><span>Mute sounds</span><button class=\"tgl ${mute?'on':''}\" id=\"gMute\" onclick=\"this.classList.toggle('on')\"></button></div></div>\n"
  "  <div class=\"hs\"><h4>◉ Status light <span id=\"slp\" style=\"width:18px;height:18px;border-radius:50%;display:inline-block;box-shadow:0 0 0 1px var(--line)\"></span></h4>\n"
  "    <div class=\"row\" style=\"margin:0\"><select id=\"gLs\">${opts(['Breath','Blink','Double blink','Steady','Off'],g.ledStyle||0)}</select><select id=\"gLp\">${[1000,2000,2500,5000,10000].map(p=>`<option value=\"${p}\" ${p==(g.ledPeriod||5000)?'selected':''}>every ${p/1000} s</option>`).join('')}</select></div>\n"
  "    <div class=\"row\" style=\"margin-top:8px;align-items:center\"><input type=\"color\" id=\"gOk\" value=\"${g.okColor||'#00ff00'}\" style=\"flex:0 0 52px;height:34px;padding:2px\">${['#00ff00','#00ffff','#0000ff','#ffffff','#ff8c1a','#ff00ff'].map(x=>`<button class=\"btn\" style=\"flex:0 0 34px;height:34px;padding:0;background:${x}\" onclick=\"$('#gOk').value='${x}'\"></button>`).join('')}</div></div>\n"
  "  <div class=\"hs\"><h4>◐ Room light <span class=\"meta\" id=\"rlNow\"></span></h4>\n"
  "    <div class=\"meter\" id=\"rlMeter\"></div>\n"
  "    <div class=\"lab\"><span>Dark below</span></div>${sl('gDark',0,100,Math.round(Math.sqrt(g.litOff/4095)*100),'dark','',80)}</div>\n"
  "  </fieldset>\n"
  "  ${homeEdit?`<div class=\"row\"><button class=\"btn p\" onclick=\"saveHomeSet()\">Save</button><button class=\"btn\" onclick=\"homeEditSet(false)\">Cancel</button></div>\n"
  "    <div class=\"row\"><button class=\"btn\" onclick=\"homeDefaults()\">Reset to defaults</button></div>`\n"
  "    :`<div class=\"row\"><button class=\"btn\" onclick=\"homeEditSet(true)\">✎ Edit home settings</button></div>`}<div class=\"note\" id=\"homemsg\"></div>`;\n"
  "  homeLive()}\n"
  "/* room light slider is on a square-root scale so the low readings (where rooms really are) get most of the travel */\n"
  "const sq2ldr=v=>Math.max(5,Math.min(4000,Math.round((v/100)**2*4095))),ldr2sq=x=>Math.sqrt(Math.max(0,x)/4095)*100;\n"
  "window.on_gDark=()=>homeLive();\n"
  "function homeLive(){const tk=S.devices.find(d=>d.type==='tank'),t=tk&&tk.tank||{},m=$('#rlMeter');if(!m)return;const dk=sq2ldr(+$('#gDark').value);\n"
  "  m.innerHTML=`<i style=\"left:${ldr2sq(dk)}%\"></i>`+(t.ldr!=null?`<b style=\"left:${ldr2sq(t.ldr)}%\"></b>`:'');\n"
  "  $('#rlNow').textContent=t.ldr!=null?`now ${t.ldr} → ${t.ldr<dk?'dark':'bright'}`:'no tank'}\n"
  "/* live preview of the status light pattern (same timing as the devices) */\n"
  "(function slAnim(){const el=$('#slp');if(el&&$('#gLs')){const st=+$('#gLs').value,p=+$('#gLp').value,t=Date.now()%p;let k;\n"
  "  if(st==1)k=t<120?1:0;else if(st==2)k=(t<100||(t>=250&&t<350))?1:0;else if(st==3)k=1;else if(st==4)k=0;else{const s=t<800?Math.sin(Math.PI*t/800):0;k=s*s}\n"
  "  el.style.background=$('#gOk').value;el.style.opacity=0.08+0.92*k}requestAnimationFrame(slAnim)})();\n"
  "async function saveHomeSet(){const v=id=>Math.round(+$(id).value),dk=sq2ldr(+$('#gDark').value),mute=$('#gMute').classList.contains('on'),qf=+$('#gQf').value;\n"
  "  const b={quietFrom:qf,quietTo:mute?+$('#gQt').value:qf,dayFrom:+$('#gDf').value,dayTo:+$('#gDt').value,ledDay:v('#gLd'),ledNight:v('#gLn'),\n"
  "    litOff:dk,litOn:Math.min(4095,dk+Math.max(10,Math.round(dk*0.3))),ledStyle:+$('#gLs').value,ledPeriod:+$('#gLp').value,okColor:parseInt($('#gOk').value.slice(1),16)},m=$('#homemsg');\n"
  "  if(mute&&b.quietFrom===b.quietTo){m.textContent='Night start and end must differ.';return}\n"
  "  const ok=await post('/api/global',b);\n"
  "  if(ok){homeEdit=false;homeKey='';renderHomeSet();toast('Home settings saved')}else m.textContent='Could not save.'}\n"
  "async function homeDefaults(){if(!confirm('Reset home settings to defaults?'))return;\n"
  "  const ok=await post('/api/global',{quietFrom:22,quietTo:7,dayFrom:7,dayTo:19,ledDay:5,ledNight:2,litOn:120,litOff:80,ledStyle:0,ledPeriod:5000,okColor:0x00ff00,minR:1,minG:1,minB:1});\n"
  "  homeEdit=false;homeKey='';renderHomeSet();toast(ok?'Defaults restored':'Could not save')}\n"
  "/* read-only tank page on port 8080, for people on the other router's WiFi (through a port forward) */\n"
  "let viewKey='';\n"
  "function renderView(){const el=$('#viewcard'),g=(S.hub||{}).global||{};if(!el)return;const key=String(g.viewOn)+S.hub.ip;if(key===viewKey)return;viewKey=key;const on=g.viewOn!==false,u='http://'+(S.hub.ip||'192.168.1.115')+':8080';\n"
  "  el.innerHTML=`<div class=\"switchrow\" style=\"margin:0\"><span>Read-only tank page (level only, no controls)</span><button class=\"tgl ${on?'on':''}\" onclick=\"viewSet(${!on})\"></button></div>\n"
  "    ${on?`<div class=\"kv\" style=\"margin-top:8px\"><span>On this WiFi</span><b><a href=\"${u}\" target=\"_blank\" style=\"color:var(--acc)\">${u}</a></b></div>\n"
  "    <details class=\"more\"><summary>Set up for the other WiFi</summary><ol class=\"note\" style=\"padding-left:18px;line-height:1.6\">\n"
  "      <li>On <b>your room router</b>: add a <b>port forward</b> — outside port <b>8080</b> → <b>${S.hub.ip||'192.168.1.115'}</b> port <b>8080</b> (TCP).</li>\n"
  "      <li>Find your room router's address on the other network (its <b>WAN / Internet IP</b> on the router's status page).</li>\n"
  "      <li>On the other WiFi open <b>http://&lt;that address&gt;:8080</b>. Bookmark it or add it to the home screen.</li>\n"
  "      <li>Optional, for a name: in the <b>other router's</b> settings add a local DNS / static hostname, e.g. <b>leotank.home</b> → that address, then use <b>http://leotank.home:8080</b>. (<i>.local</i> names don't pass through routers.)</li>\n"
  "      <li>Ask the router to keep giving your room router the same address (DHCP reservation), or the link changes.</li></ol></details>`:'<p class=\"note\">Off — port 8080 shows nothing.</p>'}`}\n"
  "async function viewSet(on){if(await post('/api/global',{viewOn:on})){toast(on?'Tank view on':'Tank view off');viewKey=''}}\n"
  "/* LED colour calibration screen: while it is open every LED on every device shows the test colour, day or night;\n"
  "   the minimums change the real LEDs live. Save keeps them, Cancel / leaving stops the test and restores normal. */\n"
  "let calOn=false,calT=null,calKeep=null;\n"
  "function renderCal(){const g=(S.hub||{}).global||{},el=$('#calbox');if(!el)return;\n"
  "  el.innerHTML=`<div class=\"why\" style=\"margin-top:0\">While this screen is open, <b>every LED on every device</b> (hub, switch, tank) shows exactly these values — also at night. All start at 0 (off). Raise one colour until the LEDs <b>just start to glow</b>: that is its minimum.</div>\n"
  "    ${[['minR','Red','#ff4d4d'],['minG','Green','#4dff7a'],['minB','Blue','#4d7bff']].map(([k,n,c])=>`<div class=\"lab2\"><span><span class=\"rdot\" style=\"background:${c}\"></span>${n}</span><span class=\"meta\">saved: ${g[k]!=null?g[k]:1}</span></div>${sl('c'+k,0,80,0,'cal','',90)}`).join('')}\n"
  "    <div class=\"why\" id=\"calNow\"></div>\n"
  "    <div class=\"row\"><button class=\"btn p\" onclick=\"calSave()\">Save</button><button class=\"btn\" onclick=\"calCancel()\">Cancel</button></div>`;\n"
  "  calKeep=[g.minR,g.minG,g.minB];calOn=true;calSend();clearInterval(calT);calT=setInterval(()=>{if(calOn)calSend()},60000)}\n"
  "/* the LEDs show exactly R/G/B = the slider values (colour 1 at brightness 1 rounds to 0, so the minimum is what shows) */\n"
  "function calVals(){const v=id=>Math.round(+(($(id)||{}).value||0)),m=[v('#cminR'),v('#cminG'),v('#cminB')];\n"
  "  return {k:1,color:(m[0]?1<<16:0)|(m[1]?1<<8:0)|(m[2]?1:0),minR:m[0],minG:m[1],minB:m[2]}}\n"
  "let calDeb=null;function calSend(){clearTimeout(calDeb);calDeb=setTimeout(()=>{if(!calOn)return;const b=calVals();post('/api/ledtest',Object.assign({secs:90},b));\n"
  "  const n=$('#calNow');if(n)n.innerHTML=`LEDs now show R <b>${b.minR}</b> · G <b>${b.minG}</b> · B <b>${b.minB}</b> (of 255)${b.minR||b.minG||b.minB?'':' — all off'}`},150)}\n"
  "window.on_cminR=window.on_cminG=window.on_cminB=()=>calSend();\n"
  "function calStop(){if(!calOn)return;calOn=false;clearInterval(calT);fetch('/api/ledtest',{method:'POST',keepalive:true,headers:{'Content-Type':'application/json'},body:JSON.stringify({secs:0})}).catch(()=>{})}\n"
  "async function calSave(){const b=calVals(),body={};['minR','minG','minB'].forEach(k=>{if(b[k]>0)body[k]=b[k]});   // only the colours you set; the others keep their saved value\n"
  "  if(!Object.keys(body).length){toast('Nothing to save — raise a colour first');return}\n"
  "  if(await post('/api/global',body)){toast('Saved: '+Object.entries(body).map(([k,v])=>k[3]+' '+v).join(' · '));calStop();nav('hub')}}\n"
  "function calCancel(){calStop();nav('hub')}\n"
  "/* read-only line for a device page: a global value, with where to change it */\n"
  "function globalNote(txt){return `<p class=\"note\">${txt} · <a href=\"#\" onclick=\"nav('hub');return false\" style=\"color:var(--acc)\">Home settings</a></p>`}\n"
  "</script>\n"
  "</body>\n"
  "</html>\n"
  "\n";

void webBegin() {
  ws.handleHandshake([](AsyncWebServerRequest* r) { return originOk(r) && authOk(r); });      // other web sites can't listen in
  ws.onEvent([](AsyncWebSocket*, AsyncWebSocketClient* c, AwsEventType t, void*, uint8_t*, size_t) {
    if (t == WS_EVT_CONNECT) c->text(stateJson());
  });
  server.addHandler(&ws);
  consoleWs.handleHandshake([](AsyncWebServerRequest* r) { return originOk(r) && authOk(r); });
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
  server.addHandler(new AsyncCallbackJsonWebHandler("/api/ledtest", [](AsyncWebServerRequest* r, JsonVariant& j) {   // LED calibration test on every device
    if (!guard(r)) return;
    int secs = constrain((int)(j["secs"] | 0), 0, 600), k = constrain((int)(j["k"] | 5), 1, 255);
    long col = j["color"] | 0xFFFFFFL; int mn[3] = { j["minR"] | 1, j["minG"] | 1, j["minB"] | 1 };
    for (int q = 0; q < 3; ++q) mn[q] = constrain(mn[q], 0, 80);
    hubTestCol[0] = (col >> 16) & 255; hubTestCol[1] = (col >> 8) & 255; hubTestCol[2] = col & 255;
    for (int q = 0; q < 3; ++q) hubTestMin[q] = mn[q];
    hubTestK = k; hubTestUntil = secs ? millis() + secs * 1000UL : 0;
    char t[16]; snprintf(t, sizeof(t), "%02x%02x%02x%02x%02x%02x", hubTestCol[0], hubTestCol[1], hubTestCol[2], mn[0], mn[1], mn[2]);
    uint8_t macs[MAX_DEV][6]; int n = 0;
    { DevGuard g; for (int i = 0; i < MAX_DEV; ++i) if (devs[i].used && devs[i].lastSeen && millis() - devs[i].lastSeen < OFFLINE_MS) memcpy(macs[n++], devs[i].mac, 6); }
    for (int i = 0; i < n; ++i) queueCmd(macs[i], C_LEDTEST, (uint8_t)k, 0, (float)secs, t);
    jsonOk(r);
  }));
  server.on("/api/relayhist", HTTP_GET, [](AsyncWebServerRequest* r) {   // seconds ON per relay per hour, 7 days, oldest first
    if (!authOk(r)) { r->send(401, "application/json", "{\"err\":\"login\"}"); return; }
    uint8_t mac[6]; if (!r->hasParam("mac") || !parseMac(r->getParam("mac")->value(), mac)) { r->send(400); return; }
    RelH* h = relhFor(mac, 0);
    String s; s.reserve(4 * HIST_HOURS * 5 + 64); s = "{\"step\":3600,\"end\":" + String(h ? h->lastHour * 3600 : 0) + ",\"r\":[";
    for (int q = 0; q < 4; ++q) { if (q) s += ','; s += '[';
      if (h) for (int k = HIST_HOURS - 1; k >= 0; --k) { if (k != HIST_HOURS - 1) s += ','; s += String(h->s[q][(h->lastHour - k) % HIST_HOURS]); }
      s += ']'; }
    s += "]}"; r->send(200, "application/json", s);
  });
  server.addHandler(new AsyncCallbackJsonWebHandler("/api/timer", [](AsyncWebServerRequest* r, JsonVariant& j) {   // relay off-timer
    if (!guard(r)) return;
    uint8_t mac[6]; if (!parseMac(j["mac"] | "", mac)) { r->send(400, "application/json", "{\"err\":\"mac\"}"); return; }
    int idx = j["idx"] | -1, mins = j["mins"] | -1; String at = j["at"] | "";
    if (idx < 0 || idx > 3 || !timeValid()) { r->send(400, "application/json", "{\"err\":\"range or clock\"}"); return; }
    uint32_t now = (uint32_t)time(nullptr), off = 0;
    if (at.length() == 5) {                                       // "HH:MM" today, or tomorrow if already past
      int hh = at.substring(0, 2).toInt(), mm = at.substring(3).toInt(); struct tm tm; time_t tn = now; localtime_r(&tn, &tm);
      int cur = tm.tm_hour * 3600 + tm.tm_min * 60 + tm.tm_sec, tgt = hh * 3600 + mm * 60; off = now + (tgt > cur ? tgt - cur : tgt + 86400 - cur);
    } else if (mins > 0 && mins <= 24 * 60) off = now + mins * 60;
    String dn, rn;
    { DevGuard g; int i = findDev(mac); if (i < 0) { r->send(404); return; } devs[i].offAt[idx] = off; dn = devs[i].name; rn = relayName(devs[i], idx); }
    stateDirty = true;
    activity(dn + ": " + rn + (off ? " timer: OFF at " + hm12((int)(((off + 19800) % 86400) / 60)) : String(" timer cancelled")) + " (from " + who(r) + ")", false);
    jsonOk(r);
  }));
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
    if (cmd == C_SW_SET) {
      int n = idx & 15, fld = idx >> 4, v = (int)f; String what;
      if (fld == 1) what = "Relay " + String(n + 1) + " output: " + (v == 1 ? "pulse" : "stays on");
      else if (fld == 2) what = "Relay " + String(n + 1) + " pulse length " + String(v) + " ms";
      else if (fld == 3) what = "Relay " + String(n + 1) + " ON drives the pin " + (v ? "HIGH" : "LOW");
      else if (fld == 4) what = "Touch pad " + String(n + 1) + (v >= 0 && v < 4 ? " controls relay " + String(v + 1) : String(" does nothing"));
      else if (fld == 5) what = "Touch pad " + String(n + 1) + (v == 1 ? ": ON only while touched" : ": toggles");
      if (what.length()) activity(dn + ": " + what + " (from " + who(r) + ")", false);
    }
    if (cmd == C_SILENCE) activity(dn + ": alarm silenced (from " + who(r) + ")", false);
    if (cmd == C_TANK_SET) {
      static const char* names[] = { "", "full distance", "empty distance", "full alarm level", "low alarm level", "buzzer", "quiet hours from", "quiet hours until", "LED colours", "level LEDs", "daytime display from", "daytime display until", "daytime minimum brightness" };
      char hx[8]; snprintf(hx, sizeof(hx), "#%06lx", (unsigned long)f & 0xFFFFFFUL);
      if (idx >= 13 && idx <= 20) activity(dn + ": LED " + String(idx - 12) + " colour set to " + hx + " (from " + who(r) + ")", false);
      if (idx == 21) activity(dn + ": current-level highlight set to " + String((int)f) + " % (from " + who(r) + ")", false);
      if (idx == 31 || idx == 32) activity(dn + ": light sensor " + (idx == 31 ? "dark" : "daylight") + " reading set to " + String((int)f) + " of 4095 (from " + who(r) + ")", false);
      if (idx == 33) { static const char* bm[] = { "always", "outside quiet hours", "when the room is lit", "outside quiet hours and when the room is lit" }; activity(dn + ": buzzer may sound " + bm[(int)f & 3] + " (from " + who(r) + ")", false); }
      if (idx == 34) activity(dn + ": night LED limit set to " + String((int)f) + " / 255 (from " + who(r) + ")", false);
      if (idx == 44) activity(dn + ": LED simulation " + (f > 0 ? "started" : "stopped") + " (from " + who(r) + ")", false);
      if (idx >= 22 && idx <= 29) activity(dn + ": LED " + String(idx - 21) + " brightness set to " + String((int)f) + " % (from " + who(r) + ")", false);
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
    int ls = j["ledStyle"] | (int)gLedStyle, lp = j["ledPeriod"] | (int)gLedPeriod;
    long okc = j["okColor"] | (long)(((uint32_t)gOk[0] << 16) | (gOk[1] << 8) | gOk[2]);
    int pd = j["priceDay"] | (int)gPriceDay, pn = j["priceNight"] | (int)gPriceNight;
    if (pd < 0 || pd > 5000 || pn < 0 || pn > 5000) { r->send(400, "application/json", "{\"err\":\"price\"}"); return; }
    gPriceDay = pd; gPriceNight = pn;
    if (j["viewOn"].is<bool>()) gViewOn = j["viewOn"].as<bool>();   // read-only tank view on port 8080
    { const char* ks[3] = { "minR", "minG", "minB" };          // colour calibration
      for (int c = 0; c < 3; ++c) { int v = j[ks[c]] | (int)gMin[c]; if (v >= 0 && v <= 80) gMin[c] = v; } }
    if (qf < 0 || qf > 23 || qt < 0 || qt > 23 || df < 0 || df > 23 || dt < 0 || dt > 23 || ld < 0 || ld > 255 || ln < 0 || ln > 255 ||
        lon < 10 || lon > 4095 || loff < 5 || loff >= lon || ls < 0 || ls > 4 || !okPeriod(lp) || okc < 0 || okc > 0xFFFFFF) { r->send(400, "application/json", "{\"err\":\"range\"}"); return; }
    gQuietFrom = qf; gQuietTo = qt; gDayFrom = df; gDayTo = dt; gLedDay = ld; gLedNight = ln; gLitOn = lon; gLitOff = loff;
    gLedStyle = ls; gLedPeriod = lp; gOk[0] = (okc >> 16) & 255; gOk[1] = (okc >> 8) & 255; gOk[2] = okc & 255;
    globalsSave(); stateDirty = true;
    static const char* styles[] = { "breath", "blink", "double blink", "steady", "off" };
    char buf[220]; snprintf(buf, sizeof(buf), "Home settings: quiet %s-%s, daytime %s-%s, status light %d/%d (of 255) %s every %.1f s #%06lx, room bright above %d / dark below %d",
                            hm12(qf * 60).c_str(), hm12(qt * 60).c_str(), hm12(df * 60).c_str(), hm12(dt * 60).c_str(), ld, ln, styles[ls], lp / 1000.0, (unsigned long)okc, lon, loff);
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
  // read-only tank view on port 8080 (nothing else is served there)
  viewServer.on("/", HTTP_GET, [](AsyncWebServerRequest* r) {
    if (!gViewOn) { r->send(404, "text/plain", "Tank view is switched off"); return; }
    AsyncWebServerResponse* res = r->beginResponse(200, "text/html", (const uint8_t*)VIEW_HTML, strlen_P(VIEW_HTML));
    res->addHeader("Cache-Control", "no-cache"); r->send(res);
  });
  viewServer.on("/level", HTTP_GET, [](AsyncWebServerRequest* r) {
    if (!gViewOn) { r->send(404); return; }
    JsonDocument d; d["online"] = false; d["ok"] = false; d["level"] = 0; d["leds"] = 7; d["state"] = "";
    { DevGuard g;
      for (int i = 0; i < MAX_DEV; ++i) { Dev& v = devs[i]; if (!v.used || v.type != DEV_TANK) continue;
        d["online"] = v.lastSeen && millis() - v.lastSeen < OFFLINE_MS; d["ok"] = (bool)v.sensorOk; d["level"] = v.levelPct; d["state"] = v.stateTxt;
        int n = v.tcfgKnown && v.tLedCount ? v.tLedCount : 7; d["leds"] = n;
        JsonArray c = d["colors"].to<JsonArray>();                       // the strip's own colours, bottom first
        for (int k = 0; k < n; ++k) {
          char hx[8]; uint8_t rr, gg, bb; float t = n > 1 ? (float)k / (n - 1) : 1;
          if (v.tPalette == 2 && v.tColorsKnown) { rr = v.tColors[k * 3]; gg = v.tColors[k * 3 + 1]; bb = v.tColors[k * 3 + 2]; }
          else if (v.tPalette == 3) { float h = t * 240, x = 1 - fabsf(fmodf(h / 60, 2) - 1); float R = h < 60 ? 1 : h < 120 ? x : 0, G = h < 60 ? x : h < 180 ? 1 : x, B = h < 120 ? 0 : h < 180 ? x : 1; rr = R * 255; gg = G * 255; bb = B * 255; }
          else { rr = 255 * (1 - t); gg = v.tPalette == 1 ? 255 * t : 0; bb = v.tPalette == 1 ? 0 : 255 * t; }
          snprintf(hx, sizeof(hx), "#%02x%02x%02x", rr, gg, bb); c.add(hx);
        }
        break; } }
    String s; serializeJson(d, s);
    AsyncWebServerResponse* res = r->beginResponse(200, "application/json", s); res->addHeader("Cache-Control", "no-store"); r->send(res);
  });
  viewServer.onNotFound([](AsyncWebServerRequest* r) { r->send(404); });
  viewServer.begin();
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
  gLedStyle = prefs.getUChar("gls", 0); if (gLedStyle > 4) gLedStyle = 0;
  gLedPeriod = prefs.getUShort("glp", 5000); if (!okPeriod(gLedPeriod)) gLedPeriod = 5000;
  prefs.getBytes("gok", gOk, 3);
  gPriceDay = prefs.getUShort("gpd", 616); gPriceNight = prefs.getUShort("gpn", 616);
  prefs.getBytes("gmc", gMin, 3);
  gViewOn = prefs.getBool("gvw", true);
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
    uint8_t k = (millis() / 100) % 2 ? bootGlowLevel() : 0; uint32_t c = ledA.Color(k, k * 3 / 5, k / 4);   // booting: rapid warm flashes
    if (c != shown) { shown = c; ledA.setPixelColor(0, c); ledA.show(); ledB.setPixelColor(0, c); ledB.show(); }
    return;
  }
  uint8_t r, g, b; uint32_t period;
  if (apUp)                          { r = 0; g = 0; b = 1; period = 2000; }
  else if (!staUp)                   { r = 1; g = 1; b = 0; period = 2000; }
  else if (millis() < pairingUntil)  { r = 0; g = 1; b = 1; period = 2000; }
  else                               { r = 255; g = 255; b = 255; period = gLedPeriod; }   // all well: global colour + speed
  bool day = roomLight == 1;                                // room light from the tank's LDR ...
  if (roomLight == 255 && timeValid()) { time_t now = time(nullptr); struct tm tm; localtime_r(&now, &tm); int m = tm.tm_hour * 60 + tm.tm_min, a = gDayFrom * 60, b = gDayTo * 60; day = a < b ? (m >= a && m < b) : (m >= a || m < b); }   // ... else the daytime hours
  uint8_t peak = day ? gLedDay : gLedNight, k;              // global status-light brightness and style
  uint32_t t = millis() % period;
  switch (gLedStyle) {
    case 1: k = t < 120 ? peak : 0; break;                                   // blink
    case 2: k = (t < 100 || (t >= 250 && t < 350)) ? peak : 0; break;        // double blink
    case 3: k = peak; break;                                                 // steady
    case 4: k = 0; break;                                                    // off
    default: { uint32_t len = 800; float s = t < len ? sinf(PI * t / len) : 0; k = (uint8_t)(s * s * peak + 0.5f); }   // breath
  }
  // firmware update (own or an edge's) = rapid cyan flashing; restart coming = rapid white flashing
  bool upd = Update.isRunning() || eota.active, rst = restartAt != 0;
  if (upd || rst) { uint8_t pk = max<uint8_t>(peak, 6); k = (millis() / 100) % 2 ? pk : 0; r = upd ? 0 : 1; g = 1; b = 1; }
  // channel at brightness k, never below the calibrated minimum while that colour is lit
  auto ch = [](uint8_t col, uint8_t k, int c) -> uint8_t { if (!col || !k) return 0; int v = (col * k + 127) / 255; int m = gMin[c] ? gMin[c] : 1; return (uint8_t)min(255, max(v, m)); };
  uint32_t c = r == 255 ? ledA.Color(ch(gOk[0], k, 0), ch(gOk[1], k, 1), ch(gOk[2], k, 2)) : ledA.Color(ch(r * 255, k, 0), ch(g * 255, k, 1), ch(b * 255, k, 2));
  if (hubTestUntil && (int32_t)(hubTestUntil - millis()) > 0) {   // calibration test: test colour + test minimums, day or night
    auto t = [](int q) -> uint8_t { if (!hubTestCol[q]) return 0; int v = (hubTestCol[q] * hubTestK + 127) / 255; return (uint8_t)min(255, max(v, (int)hubTestMin[q])); };
    c = ledA.Color(t(0), t(1), t(2));
  }
  if (c != shown) { shown = c; ledA.setPixelColor(0, c); ledA.show(); ledB.setPixelColor(0, c); ledB.show(); }
}

void loop() {
  esp_task_wdt_reset();
  hubLedTick();
  resetBtnTick();
  if (factoryPending) hubFactoryReset();
  { static uint32_t lastHist = 0; if (millis() - lastHist >= 1000) { lastHist = millis(); histTick(); relayTimerTick(); } }
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
        p.ledStyle = gLedStyle; p.ledPeriod = gLedPeriod; p.okR = gOk[0]; p.okG = gOk[1]; p.okB = gOk[2];
        p.minR = gMin[0]; p.minG = gMin[1]; p.minB = gMin[2];
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
