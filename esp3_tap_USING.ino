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

const char *AP_SSID     = "CAN-TAP-LAB";
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

// ---------- Webpage: raw id/dlc/data only (no decoding), split into
// ID feed + payload feed so they can be freely recombined ("forged")
// into a frame that was never actually sent together on the bus.
const char INDEX_HTML[] PROGMEM = R"HTMLPAGE(
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CAN Bus Traffic Monitor</title>
<style>
  :root {
    --bg: #f5f6f8;
    --panel: #ffffff;
    --border: #e2e4ea;
    --text: #181b22;
    --muted: #6b7180;
    --accent: #2854d6;
    --accent-weak: #e7ecfb;
    --mono: ui-monospace, "SF Mono", "Cascadia Mono", Consolas, monospace;
  }
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, "Segoe UI", Roboto, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    margin: 0;
    padding: 28px 20px 60px;
  }
  .wrap { max-width: 880px; margin: 0 auto; }

  header {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    border-bottom: 1px solid var(--border);
    padding-bottom: 14px;
    margin-bottom: 6px;
  }
  h1 { font-size: 1.15rem; font-weight: 600; margin: 0; }
  .status { display:flex; align-items:center; gap:6px; font-size:0.82rem; color: var(--muted); }
  .dot { width:7px; height:7px; border-radius:50%; background:#c6c9d2; }
  .dot.live { background:#1f9d55; }
  .dot.down { background:#d1453a; }

  .intro { color: var(--muted); font-size: 0.86rem; line-height:1.5; margin: 12px 0 24px; max-width: 62ch; }

  section { margin-bottom: 22px; }
  section > h2 {
    font-size: 0.78rem; font-weight: 600; color: var(--muted);
    margin: 0 0 8px;
  }

  .panel {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 6px;
  }

  /* Frame builder gets a slightly stronger treatment - it's the one
     interactive action on the page, everything else is read-only data */
  .builder {
    border: 1px solid var(--accent);
    border-radius: 6px;
    background: var(--panel);
    padding: 14px 16px;
  }
  .builder-row { display:flex; gap:14px; flex-wrap: wrap; align-items:flex-end; }
  .field { flex: 1; min-width: 180px; }
  .field label { display:block; font-size:0.74rem; color: var(--muted); margin-bottom:4px; }
  .field .value { font-family: var(--mono); font-size: 0.92rem; }
  .field .value.empty { color: var(--muted); font-style: italic; font-family: inherit; font-size: 0.86rem; }

  button {
    font-family: inherit;
    font-size: 0.86rem;
    font-weight: 500;
    padding: 8px 16px;
    border-radius: 5px;
    border: 1px solid var(--accent);
    background: var(--accent);
    color: #fff;
    cursor: pointer;
  }
  button:disabled { background: #e3e5ea; border-color:#e3e5ea; color: var(--muted); cursor: not-allowed; }
  button:hover:not(:disabled) { background:#1f44b8; }

  table { width:100%; border-collapse: collapse; font-size: 0.86rem; }
  th, td { text-align: left; padding: 7px 10px; }
  th { color: var(--muted); font-weight: 500; font-size: 0.76rem; border-bottom: 1px solid var(--border); }
  tbody tr:not(:last-child) td { border-bottom: 1px solid var(--border); }
  td.mono, th.mono { font-family: var(--mono); }
  tbody tr { cursor: pointer; }
  tbody tr:hover td { background: #fafbfc; }
  tbody tr.selected td { background: var(--accent-weak); }

  .empty-row { color: var(--muted); font-size: 0.84rem; padding: 14px 10px; }

  .log { max-height: 260px; overflow-y: auto; }
  .log table { font-size: 0.82rem; }
  .log th, .log td { padding: 5px 10px; }

  @media (max-width: 640px) {
    .builder-row { flex-direction: column; align-items: stretch; }
    table, thead, tbody, th, td, tr { font-size: 0.8rem; }
  }
</style>
</head>
<body>
<div class="wrap">

  <header>
    <h1>CAN Bus Traffic Monitor</h1>
    <div class="status"><span class="dot" id="statusDot"></span><span id="statusText">Connecting</span></div>
  </header>

  <p class="intro">
    Passively captures every frame on the bus. The tap has no prior knowledge of
    message IDs or payload meaning - source IDs and payloads are logged separately
    below, and any combination of the two can be sent as a new frame.
  </p>

  <section>
    <h2>Construct frame</h2>
    <div class="builder">
      <div class="builder-row">
        <div class="field">
          <label>Source ID</label>
          <div class="value empty" id="pickedId">None selected</div>
        </div>
        <div class="field">
          <label>Payload</label>
          <div class="value empty" id="pickedData">None selected</div>
        </div>
        <button id="sendBtn" disabled>Send frame</button>
      </div>
    </div>
  </section>

  <section>
    <h2>Source IDs observed</h2>
    <div class="panel">
      <table>
        <thead><tr><th class="mono">ID</th><th>Last seen</th><th>Count</th></tr></thead>
        <tbody id="idRows"></tbody>
      </table>
      <div class="empty-row" id="idEmpty">No traffic captured yet.</div>
    </div>
  </section>

  <section>
    <h2>Payloads observed</h2>
    <div class="panel">
      <table>
        <thead><tr><th>Length</th><th class="mono">Data (hex)</th><th>Count</th></tr></thead>
        <tbody id="dataRows"></tbody>
      </table>
      <div class="empty-row" id="dataEmpty">No traffic captured yet.</div>
    </div>
  </section>

  <section>
    <h2>Traffic log</h2>
    <div class="panel log">
      <table>
        <thead><tr><th>Time</th><th class="mono">ID</th><th>Len</th><th class="mono">Data</th></tr></thead>
        <tbody id="logRows"></tbody>
      </table>
      <div class="empty-row" id="logEmpty">Waiting for the first frame.</div>
    </div>
  </section>

</div>

<script>
let ws;
const statusDot = document.getElementById('statusDot');
const statusText = document.getElementById('statusText');
const idRows = document.getElementById('idRows');
const dataRows = document.getElementById('dataRows');
const idEmpty = document.getElementById('idEmpty');
const dataEmpty = document.getElementById('dataEmpty');
const logRows = document.getElementById('logRows');
const logEmpty = document.getElementById('logEmpty');
const pickedId = document.getElementById('pickedId');
const pickedData = document.getElementById('pickedData');
const sendBtn = document.getElementById('sendBtn');

const idMap = new Map();   // id -> {hits, el}
const dataMap = new Map(); // "dlc:csv" -> {dlc, csv, hits, el}
let selectedId = null;
let selectedData = null; // {dlc, csv}
let logCount = 0;

function connect() {
  ws = new WebSocket('ws://' + location.host + '/ws');
  ws.onopen = () => { statusDot.className = 'dot live'; statusText.textContent = 'Connected'; };
  ws.onclose = () => { statusDot.className = 'dot down'; statusText.textContent = 'Disconnected - retrying'; setTimeout(connect, 1000); };
  ws.onmessage = (ev) => {
    const parts = ev.data.split('|');
    if (parts[0] !== 'FRAME') return;
    const [, id, dlc, dataCsv, ts] = parts;
    onFrame(id, dlc, dataCsv || '', ts);
  };
}

function onFrame(id, dlc, dataCsv, ts) {
  logFrame(id, dlc, dataCsv, ts);
  upsertId(id, ts);
  upsertData(dlc, dataCsv, ts);
}

function logFrame(id, dlc, dataCsv, ts) {
  if (logCount === 0) logEmpty.style.display = 'none';
  const tr = document.createElement('tr');
  tr.innerHTML = `<td>${(ts/1000).toFixed(1)}s</td><td class="mono">${id}</td><td>${dlc}</td><td class="mono">${dataCsv || '-'}</td>`;
  logRows.prepend(tr);
  logCount++;
  while (logRows.children.length > 60) logRows.removeChild(logRows.lastChild);
}

function upsertId(id, ts) {
  if (!idMap.has(id)) {
    idEmpty.style.display = 'none';
    const tr = document.createElement('tr');
    tr.innerHTML = `<td class="mono">${id}</td><td class="lastTs">${(ts/1000).toFixed(1)}s</td><td class="hits">1</td>`;
    tr.onclick = () => selectId(id);
    idRows.prepend(tr);
    idMap.set(id, { hits: 1, el: tr });
  } else {
    const rec = idMap.get(id);
    rec.hits++;
    rec.el.querySelector('.lastTs').textContent = (ts/1000).toFixed(1) + 's';
    rec.el.querySelector('.hits').textContent = rec.hits;
  }
}

function upsertData(dlc, dataCsv, ts) {
  const key = dlc + ':' + dataCsv;
  if (!dataMap.has(key)) {
    dataEmpty.style.display = 'none';
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${dlc}</td><td class="mono">${dataCsv || '-'}</td><td class="hits">1</td>`;
    tr.onclick = () => selectData(dlc, dataCsv);
    dataRows.prepend(tr);
    dataMap.set(key, { dlc, csv: dataCsv, hits: 1, el: tr });
  } else {
    const rec = dataMap.get(key);
    rec.hits++;
    rec.el.querySelector('.hits').textContent = rec.hits;
  }
}

function selectId(id) {
  selectedId = id;
  document.querySelectorAll('#idRows tr').forEach(r => r.classList.remove('selected'));
  idMap.get(id).el.classList.add('selected');
  pickedId.textContent = id;
  pickedId.classList.remove('empty');
  updateSendState();
}

function selectData(dlc, csv) {
  selectedData = { dlc, csv };
  document.querySelectorAll('#dataRows tr').forEach(r => r.classList.remove('selected'));
  dataMap.get(dlc + ':' + csv).el.classList.add('selected');
  pickedData.textContent = `${csv || '(empty)'}  (len ${dlc})`;
  pickedData.classList.remove('empty');
  updateSendState();
}

function updateSendState() {
  sendBtn.disabled = !(selectedId && selectedData);
}

sendBtn.onclick = () => {
  if (!selectedId || !selectedData) return;
  ws.send(`REPLAY|${selectedId}|${selectedData.dlc}|${selectedData.csv}`);
  const original = sendBtn.textContent;
  sendBtn.textContent = 'Sent';
  setTimeout(() => { sendBtn.textContent = original; }, 600);
};

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
