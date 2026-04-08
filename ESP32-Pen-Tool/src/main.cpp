#include <Arduino.h>
#include <WiFi.h>
#include <AsyncTCP.h>
#include <ESPAsyncWebServer.h>
#include <esp_wifi.h>
#include <set>

AsyncWebServer server(80);

// --- 802.11 STRUCTURES ---
typedef struct {
  int16_t fctl;
  int16_t duration;
  uint8_t addr1[6];
  uint8_t addr2[6];
  uint8_t addr3[6];
  int16_t seqctl;
  unsigned char payload[];
} __attribute__((packed)) mac_header_t;

// Sniffing Globals
uint8_t target_bssid[6];
std::set<String> discovered_clients;
bool is_sniffing = false;
unsigned long sniff_start_time = 0;
const unsigned long SNIFF_DURATION = 10000; // Sniff for 10 seconds

// --- SNIFFER CALLBACK ---
void sniffer_callback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (!is_sniffing || type != WIFI_PKT_DATA) return;

  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  mac_header_t *mac_hdr = (mac_header_t *)pkt->payload;

  bool is_from_ap = memcmp(mac_hdr->addr2, target_bssid, 6) == 0;
  bool is_to_ap = memcmp(mac_hdr->addr1, target_bssid, 6) == 0;

  if (is_from_ap || is_to_ap) {
    uint8_t* client_mac = is_from_ap ? mac_hdr->addr1 : mac_hdr->addr2;
    if (client_mac[0] == 0xFF || (client_mac[0] & 0x01)) return;

    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
             client_mac[0], client_mac[1], client_mac[2], 
             client_mac[3], client_mac[4], client_mac[5]);
    discovered_clients.insert(String(macStr));
  }
}

void parseBytes(const char* str, char sep, byte* bytes, int maxBytes, int base) {
  for (int i = 0; i < maxBytes; i++) {
    bytes[i] = strtoul(str, NULL, base);  
    str = strchr(str, sep);              
    if (str == NULL || *str == '\0') break; 
    str++;                               
  }
}

// --- HTML FRONTEND ---
const char index_html[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>ESP32 Tactical UI</title>
  <style>
    body { background-color: #0d1117; color: #c9d1d9; font-family: monospace; padding: 20px; }
    h1 { color: #58a6ff; border-bottom: 1px solid #30363d; }
    button { background-color: #238636; color: white; padding: 10px; border: none; border-radius: 6px; cursor: pointer; }
    button:disabled { background-color: #30363d; color: #8b949e; }
    table { width: 100%; border-collapse: collapse; margin: 20px 0; background: #161b22; }
    th, td { border: 1px solid #30363d; padding: 12px; text-align: left; }
    .target-btn { background-color: #da3633; }
    #targetPanel { display: none; border: 1px solid #30363d; padding: 15px; margin-top: 20px; }
    .client-item { padding: 8px; border-bottom: 1px solid #30363d; color: #79c0ff; }
  </style>
</head>
<body>
  <h1>Wi-Fi Reconnaissance</h1>
  <button id="scanBtn" onclick="scan()">[ Initiate AP Scan ]</button>
  <div id="status" style="margin: 10px 0;">Ready.</div>

  <table>
    <thead><tr><th>SSID</th><th>BSSID</th><th>Ch</th><th>RSSI</th><th>Action</th></tr></thead>
    <tbody id="netTable"></tbody>
  </table>

  <div id="targetPanel">
    <h2 id="targetTitle">Target</h2>
    <div id="sniffStatus" style="color: #f85149; font-weight: bold;"></div>
    <h3>Connected Clients:</h3>
    <div id="clientList"></div>
  </div>

  <script>
    let sniffInterval;

    function scan() {
      document.getElementById('status').innerText = "Scanning...";
      fetch('/scan').then(r => r.json()).then(data => {
        let html = '';
        data.forEach(n => {
          html += `<tr><td>${n.ssid}</td><td>${n.mac}</td><td>${n.ch}</td><td>${n.rssi}</td>
          <td><button class="target-btn" onclick="startSniff('${n.mac}', ${n.ch}, '${n.ssid}')">Select</button></td></tr>`;
        });
        document.getElementById('netTable').innerHTML = html;
        document.getElementById('status').innerText = "Scan complete.";
      });
    }

    function startSniff(mac, ch, ssid) {
      document.getElementById('targetPanel').style.display = "block";
      document.getElementById('targetTitle').innerText = `Target: ${ssid}`;
      document.getElementById('clientList').innerHTML = "Initializing...";
      
      fetch(`/start_sniff?mac=${mac}&ch=${ch}`).then(() => {
        if(sniffInterval) clearInterval(sniffInterval);
        sniffInterval = setInterval(updateClients, 1000);
      });
    }

    function updateClients() {
      fetch('/get_clients').then(r => r.json()).then(data => {
        let list = data.clients.map(c => `<div class="client-item">MAC: ${c}</div>`).join('');
        document.getElementById('clientList').innerHTML = list || "Searching for packets...";
        document.getElementById('sniffStatus').innerText = data.active ? "STATUS: SNIFFING ACTIVE" : "STATUS: SCAN FINISHED";
        if(!data.active) clearInterval(sniffInterval);
      });
    }
  </script>
</body>
</html>
)rawliteral";

void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP("ESP32_Tactical", "mgmtadmin");

  server.on("/", HTTP_GET, [](AsyncWebServerRequest *r){ r->send_P(200, "text/html", index_html); });

  server.on("/scan", HTTP_GET, [](AsyncWebServerRequest *r){
    int n = WiFi.scanNetworks();
    String json = "[";
    for (int i = 0; i < n; i++) {
      if (i > 0) json += ",";
      json += "{\"ssid\":\""+WiFi.SSID(i)+"\",\"mac\":\""+WiFi.BSSIDstr(i)+"\",\"ch\":"+String(WiFi.channel(i))+",\"rssi\":"+String(WiFi.RSSI(i))+"}";
    }
    json += "]";
    WiFi.scanDelete();
    r->send(200, "application/json", json);
  });

  server.on("/start_sniff", HTTP_GET, [](AsyncWebServerRequest *r){
    if(r->hasParam("mac") && r->hasParam("ch")) {
      parseBytes(r->getParam("mac")->value().c_str(), ':', target_bssid, 6, 16);
      int ch = r->getParam("ch")->value().toInt();
      discovered_clients.clear();
      esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
      esp_wifi_set_promiscuous_rx_cb(&sniffer_callback);
      esp_wifi_set_promiscuous(true);
      is_sniffing = true;
      sniff_start_time = millis();
      r->send(200, "text/plain", "OK");
    }
  });

  server.on("/get_clients", HTTP_GET, [](AsyncWebServerRequest *r){
    String json = "{\"active\":" + String(is_sniffing ? "true" : "false") + ",\"clients\":[";
    bool first = true;
    for (auto const& c : discovered_clients) {
      if (!first) json += ",";
      json += "\"" + c + "\"";
      first = false;
    }
    json += "]}";
    r->send(200, "application/json", json);
  });

  server.begin();
}

void loop() {
  if (is_sniffing && (millis() - sniff_start_time > SNIFF_DURATION)) {
    is_sniffing = false;
    esp_wifi_set_promiscuous(false);
    Serial.println("Sniffing duration ended.");
  }
}