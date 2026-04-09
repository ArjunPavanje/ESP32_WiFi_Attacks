#include <Arduino.h>
#include <WiFi.h>
#include <AsyncTCP.h>
#include <ESPAsyncWebServer.h>
#include <esp_wifi.h>
#include <set>

AsyncWebServer server(80);

// --- 802.11 CONSTANTS ---
#define TO_DS   0x01   // bit 8  of frame control byte[1]
#define FROM_DS 0x02   // bit 9  of frame control byte[1]
#define MIN_PAYLOAD_LEN 26  // Minimum sane payload: 2 (FC) + 2 (duration) + 3×6 (addrs)
#define MIN_RSSI -80   // Ignore weak/noisy signals (dBm)

// 802.11 STRUCTURES
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

// --- UTILITY FUNCTIONS ---
bool macEqual(const uint8_t *a, const uint8_t *b) {
  return memcmp(a, b, 6) == 0;
}

String macToString(const uint8_t *mac) {
  char buf[18];
  snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(buf);
}

void parseBytes(const char* str, char sep, byte* bytes, int maxBytes, int base) {
  for (int i = 0; i < maxBytes; i++) {
    bytes[i] = strtoul(str, NULL, base);  
    str = strchr(str, sep);              
    if (str == NULL || *str == '\0') break; 
    str++;                               
  }
}

void processPacket(const uint8_t *payload, uint16_t len, int8_t rssi) {
  // 1. Sanity-check payload length
  if (len < MIN_PAYLOAD_LEN) return;

  // 2. Drop weak signals
  if (rssi < MIN_RSSI) return;

  // 3. Read frame control DS bits
  uint8_t fc1    = payload[1];
  bool    to_ds   = (fc1 & TO_DS)   != 0;
  bool    from_ds = (fc1 & FROM_DS) != 0;

  uint8_t *addr1 = (uint8_t *)(payload + 4);
  uint8_t *addr2 = (uint8_t *)(payload + 10);
  uint8_t *addr3 = (uint8_t *)(payload + 16);

  uint8_t *client = nullptr;
  uint8_t *ap = nullptr;

  // Determine client and AP based on frame direction
  if (to_ds && !from_ds) {
    // STA -> AP: client is addr2, AP is addr1
    client = addr2;
    ap = addr1;
  } else if (!to_ds && from_ds) {
    // AP -> STA: AP is addr2, client is addr1
    client = addr1;
    ap = addr2;
  } else if (!to_ds && !from_ds) {
    // Ad-hoc or similar
    client = addr2;
    ap = addr3;
  } else {
    return;  // WDS or unsupported
  }

  // **CRITICAL FIX**: Verify this packet is FROM your target AP
  if (!macEqual(ap, target_bssid)) {
    Serial.printf("[SKIP] Packet not from target AP. AP: %s vs Target: %s\n", 
                  macToString(ap).c_str(), macToString(target_bssid).c_str());
    return;
  }

  // Skip the router itself
  if (macEqual(client, target_bssid)) return;

  // Skip multicast / broadcast
  if (client[0] & 0x01) return;

  // Register the client
  String mac = macToString(client);
  discovered_clients.insert(mac);
  Serial.printf("[+] Client from TARGET AP: %s\n", mac.c_str());
}

// --- SNIFFER CALLBACK ---
void sniffer_callback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (!is_sniffing) return;

  wifi_promiscuous_pkt_t *pkt     = (wifi_promiscuous_pkt_t *)buf;
  wifi_pkt_rx_ctrl_t     *rx_ctrl = &pkt->rx_ctrl;
  uint8_t                *payload =  pkt->payload;
  uint16_t                len     =  rx_ctrl->sig_len;

  if(type!=WIFI_PKT_DATA) return; // Only process data frames

  processPacket(payload, len, rx_ctrl->rssi);
  return;

  if (len >= 16) {
    uint8_t *addr1 = payload + 4;
    uint8_t *addr2 = payload + 10;
    uint8_t *addr3 = payload + 16;
    
    // Print ALL addresses to find your target
    Serial.printf("[PKT] Addr1: %02X:%02X:%02X:%02X:%02X:%02X | "
                  "Addr2: %02X:%02X:%02X:%02X:%02X:%02X | "
                  "Addr3: %02X:%02X:%02X:%02X:%02X:%02X | RSSI: %d\n",
                  addr1[0], addr1[1], addr1[2], addr1[3], addr1[4], addr1[5],
                  addr2[0], addr2[1], addr2[2], addr2[3], addr2[4], addr2[5],
                  addr3[0], addr3[1], addr3[2], addr3[3], addr3[4], addr3[5],
                  rx_ctrl->rssi);
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

      Serial.print("Target BSSID: ");
Serial.println(macToString(target_bssid));

      int ch = r->getParam("ch")->value().toInt();
      discovered_clients.clear();
      
      esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
      
      wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_DATA
      };
      esp_wifi_set_promiscuous_filter(&filter);
      esp_wifi_set_promiscuous_rx_cb(&sniffer_callback);
      esp_wifi_set_promiscuous(true);
      
      is_sniffing = true;
      sniff_start_time = millis();
      Serial.printf("Started sniffing on channel %d for BSSID %s\n", ch, macToString(target_bssid).c_str());
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