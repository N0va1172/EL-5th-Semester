/*
  ESP3 - BLIND CAN BUS TAP / SNIFFER / REPLAY NODE
  ---------------------------------------------------
  This node has ZERO built-in knowledge of any CAN ID or what any
  byte means. It does exactly three things, generically, for ANY
  frame on the bus:
    1. Capture every frame the instant it appears (real time)
    2. Store the raw id/dlc/data bytes in a ring buffer
    3. On request from the webpage, retransmit (replay) the exact
       stored bytes

  There is no #define for LED_CTRL_ID, no parsing of any payload
  meaning, no labels. If you change ESP1/ESP2's protocol entirely,
  this code does not need to change at all - that's the point: a
  tap doesn't need to understand a protocol to be dangerous to it.

  HARDWARE: same CAN wiring as ESP1/ESP2 (GPIO21 TX, GPIO22 RX into
  the transceiver, tapped onto the same CAN_H/CAN_L lines).

  NOTE ON MODE: runs TWAI_MODE_NORMAL (not LISTEN_ONLY) so it can
  transmit for replay. It will ACK frames like a real node - that's
  a fine talking point for your presentation (a fully invisible
  listen-only tap could not replay without switching modes).

  LIBRARIES NEEDED: ESPAsyncWebServer, AsyncTCP (ESP32 build)
*/

#include <Arduino.h>
#include <WiFi.h>
#include <ESPAsyncWebServer.h>
#include "driver/twai.h"

#define CAN_TX GPIO_NUM_21
#define CAN_RX GPIO_NUM_22

const char *AP_SSID     = "CAN-TAP-LAB ";
const char *AP_PASSWORD = "sniffmeout"; // 8+ chars required

AsyncWebServer server(80);
AsyncWebSocket ws("/ws");

struct CapturedFrame {
  uint32_t id;
  uint8_t  dlc;
  uint8_t  data[8];
  uint32_t ts;
};

#define MAX_LOG 100
CapturedFrame logBuf[MAX_LOG];
volatile int logCount = 0;
int logHead = 0;

// ---------- Wire protocol: FRAME|<id_hex>|<dlc>|<data_hex_csv>|<ts>
//            browser -> ESP3: REPLAY|<id_hex>|<dlc>|<data_hex_csv>
// No label field anywhere - ESP3 never attaches meaning to anything.

String frameToWireString(const CapturedFrame &f) {
  char hexId[8];
  snprintf(hexId, sizeof(hexId), "0x%03lX", (unsigned long)f.id);

  String dataCsv = "";
  for (int i = 0; i < f.dlc; i++) {
    char b[4];
    snprintf(b, sizeof(b), "%02X", f.data[i]);
    dataCsv += b;
    if (i < f.dlc - 1) dataCsv += ",";
  }

  String out = "FRAME|";
  out += hexId; out += "|";
  out += String(f.dlc); out += "|";
  out += dataCsv; out += "|";
  out += String(f.ts);
  return out;
}

void broadcastFrame(const CapturedFrame &f) {
  ws.textAll(frameToWireString(f));
}

void storeFrame(const CapturedFrame &f) {
  logBuf[logHead] = f;
  logHead = (logHead + 1) % MAX_LOG;
  if (logCount < MAX_LOG) logCount++;
}

// ---------- CAN capture task: pure byte capture, no interpretation ----------
void canCaptureTask(void *param) {
  for (;;) {
    twai_message_t rx;
    if (twai_receive(&rx, pdMS_TO_TICKS(50)) == ESP_OK) {
      if (rx.extd || rx.rtr) continue; // standard data frames only, for this demo

      CapturedFrame f;
      f.id  = rx.identifier;
      f.dlc = rx.data_length_code;
      memcpy(f.data, rx.data, rx.data_length_code);
      f.ts  = millis();

      storeFrame(f);
      broadcastFrame(f);

      Serial.printf("CAPTURED | ID: 0x%03lX | DLC: %u\n", (unsigned long)f.id, f.dlc);
    }
  }
}

// ---------- Replay: blind retransmission of exactly what's asked ----------
void replayFrame(uint32_t id, uint8_t dlc, uint8_t *data) {
  twai_message_t msg = {};
  msg.identifier = id;
  msg.data_length_code = dlc;
  memcpy(msg.data, data, dlc);
  msg.ss = 1;

  esp_err_t res = twai_transmit(&msg, pdMS_TO_TICKS(100));
  Serial.printf("REPLAY %s | ID: 0x%03lX | DLC: %u\n",
                (res == ESP_OK) ? "OK" : "FAILED", (unsigned long)id, dlc);
}

void handleWsMessage(const String &msg) {
  if (!msg.startsWith("REPLAY|")) return;

  int p1 = msg.indexOf('|', 7);
  String idStr  = msg.substring(7, p1);
  int p2 = msg.indexOf('|', p1 + 1);
  String dlcStr = msg.substring(p1 + 1, p2);
  String dataStr = msg.substring(p2 + 1);

  uint32_t id = strtoul(idStr.c_str(), nullptr, 16);
  uint8_t dlc = (uint8_t)dlcStr.toInt();

  uint8_t data[8] = {0};
  int idx = 0, start = 0;
  while (idx < dlc && start < (int)dataStr.length()) {
    int comma = dataStr.indexOf(',', start);
    String byteStr = (comma == -1) ? dataStr.substring(start) : dataStr.substring(start, comma);
    data[idx++] = (uint8_t)strtoul(byteStr.c_str(), nullptr, 16);
    if (comma == -1) break;
    start = comma + 1;
  }

  replayFrame(id, dlc, data);
}

void onWsEvent(AsyncWebSocket *server, AsyncWebSocketClient *client,
               AwsEventType type, void *arg, uint8_t *data, size_t len) {
  if (type == WS_EVT_CONNECT) {
    Serial.printf("WS client connected: %u\n", client->id());
    for (int i = 0; i < logCount; i++) {
      int idx = (logHead - logCount + i + MAX_LOG) % MAX_LOG;
      client->text(frameToWireString(logBuf[idx]));
    }
  } else if (type == WS_EVT_DATA) {
    AwsFrameInfo *info = (AwsFrameInfo *)arg;
    if (info->final && info->index == 0 && info->len == len && info->opcode == WS_TEXT) {
      String msg((char *)data, len);
      handleWsMessage(msg);
    }
  }
}

// ---------- Webpage: shows raw id/dlc/data only, no labels ----------
const char INDEX_HTML[] PROGMEM = R"HTMLPAGE(
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CAN Bus Tap (blind)</title>
<style>
  :root { color-scheme: dark; }
  body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:#0f1115; color:#e6e6e6; margin:0; padding:16px; }
  h1 { font-size: 1.2rem; margin: 0 0 4px; }
  .sub { color:#9aa0a6; font-size:0.85rem; margin-bottom:16px; }
  table { width:100%; border-collapse: collapse; font-size:0.9rem; }
  th, td { text-align:left; padding:6px 8px; border-bottom:1px solid #262a33; }
  th { color:#9aa0a6; font-weight:600; }
  tr:hover { background:#1a1d24; }
  .id { font-family: ui-monospace, Menlo, monospace; color:#7dd3fc; }
  .data { font-family: ui-monospace, Menlo, monospace; }
  button { background:#dc2626; color:white; border:none; border-radius:6px; padding:5px 10px; font-size:0.8rem; cursor:pointer; }
  button:hover { background:#ef4444; }
  #status { font-size:0.8rem; margin-bottom:10px; }
  .ok { color:#86efac; } .bad { color:#f87171; }
</style>
</head>
<body>
  <h1>&#128272; CAN Bus Tap &mdash; raw capture (no decoding)</h1>
  <div class="sub">Every frame shown here is unmodified, unlabeled, raw bytes off the bus. Click Replay to resend it.</div>
  <div id="status">Connecting...</div>
  <table>
    <thead><tr><th>Time</th><th>ID</th><th>DLC</th><th>Data (hex)</th><th></th></tr></thead>
    <tbody id="rows"></tbody>
  </table>

<script>
let ws;
const rows = document.getElementById('rows');
const status = document.getElementById('status');

function connect() {
  ws = new WebSocket('ws://' + location.host + '/ws');
  ws.onopen = () => { status.textContent = 'Connected'; status.className = 'ok'; };
  ws.onclose = () => { status.textContent = 'Disconnected, retrying...'; status.className = 'bad'; setTimeout(connect, 1000); };
  ws.onmessage = (ev) => {
    const parts = ev.data.split('|');
    if (parts[0] !== 'FRAME') return;
    const [, id, dlc, dataCsv, ts] = parts;
    addRow(id, dlc, dataCsv, ts);
  };
}

function addRow(id, dlc, dataCsv, ts) {
  const tr = document.createElement('tr');
  tr.innerHTML = `
    <td>${(ts/1000).toFixed(1)}s</td>
    <td class="id">${id}</td>
    <td>${dlc}</td>
    <td class="data">${dataCsv || '-'}</td>
    <td><button>Replay</button></td>
  `;
  tr.querySelector('button').onclick = () => {
    ws.send(`REPLAY|${id}|${dlc}|${dataCsv}`);
  };
  rows.prepend(tr);
}

connect();
</script>
</body>
</html>
)HTMLPAGE";

void setup() {
  Serial.begin(115200);
  delay(300);

  twai_general_config_t g = TWAI_GENERAL_CONFIG_DEFAULT(CAN_TX, CAN_RX, TWAI_MODE_NORMAL);
  twai_timing_config_t t = TWAI_TIMING_CONFIG_250KBITS();
  twai_filter_config_t f = TWAI_FILTER_CONFIG_ACCEPT_ALL();

  if (twai_driver_install(&g, &t, &f) != ESP_OK || twai_start() != ESP_OK) {
    Serial.println("CAN setup failed");
    while (true) delay(1000);
  }

  WiFi.softAP(AP_SSID, AP_PASSWORD);
  Serial.print("AP started. Connect to SSID: ");
  Serial.println(AP_SSID);
  Serial.print("Then browse to: http://");
  Serial.println(WiFi.softAPIP());

  ws.onEvent(onWsEvent);
  server.addHandler(&ws);

  server.on("/", HTTP_GET, [](AsyncWebServerRequest *request) {
    request->send_P(200, "text/html", INDEX_HTML);
  });

  server.begin();

  xTaskCreatePinnedToCore(canCaptureTask, "canCapture", 4096, nullptr, 1, nullptr, 1);

  Serial.println("ESP3 - BLIND CAN TAP READY");
}

void loop() {
  ws.cleanupClients();
  delay(10);
}
