#include <Arduino.h>
#include <WiFi.h>
#include <AsyncTCP.h>
#include <ESPAsyncWebServer.h>
#include <esp_wifi.h>

AsyncWebServer server(80);

// --- 802.11 CONSTANTS ---
#define TO_DS   0x01   
#define FROM_DS 0x02   
#define MIN_PAYLOAD_LEN 26  
#define MIN_RSSI -80   

// --- SAFE STATIC STORAGE ---
#define MAX_CLIENTS 50
uint8_t discovered_clients[MAX_CLIENTS][6];
volatile int client_count = 0;

// Sniffing Globals
uint8_t target_bssid[6];
String target_ssid_name = "Unknown"; 
uint8_t my_ap_mac[6]; 

// State Management
bool is_sniffing = false;
unsigned long sniff_start_time = 0;
const unsigned long SNIFF_DURATION = 15000; 

// Pending State Management (THE FIX)
bool pending_sniff = false;
unsigned long pending_sniff_time = 0;
int pending_ch = 0;

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

// --- HIGH PRIORITY CALLBACK ---
void processPacket(const uint8_t *payload, uint16_t len, int8_t rssi) {
  if (len < MIN_PAYLOAD_LEN) return;
  if (rssi < MIN_RSSI) return;

  uint8_t *addr1 = (uint8_t *)(payload + 4);
  uint8_t *addr2 = (uint8_t *)(payload + 10);
  uint8_t *addr3 = (uint8_t *)(payload + 16);

  if (macEqual(addr1, my_ap_mac) || macEqual(addr2, my_ap_mac) || macEqual(addr3, my_ap_mac)) {
    return; 
  }

  uint8_t fc1    = payload[1];
  bool    to_ds   = (fc1 & TO_DS)   != 0;
  bool    from_ds = (fc1 & FROM_DS) != 0;

  uint8_t *client = nullptr;
  uint8_t *ap = nullptr;

  if (to_ds && !from_ds) {
    client = addr2; ap = addr1;
  } else if (!to_ds && from_ds) {
    client = addr1; ap = addr2;
  } else if (!to_ds && !from_ds) {
    client = addr2; ap = addr3;
  } else {
    return;  
  }

  if (!macEqual(ap, target_bssid)) return; 
  if (macEqual(client, target_bssid)) return;
  if (client[0] & 0x01) return; 

  for (int i = 0; i < client_count; i++) {
    if (macEqual(client, discovered_clients[i])) return; 
  }

  if (client_count < MAX_CLIENTS) {
    memcpy(discovered_clients[client_count], client, 6);
    client_count++;
  }
}

void sniffer_callback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (!is_sniffing) return;
  if (type != WIFI_PKT_DATA) return; 

  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  processPacket(pkt->payload, pkt->rx_ctrl.sig_len, pkt->rx_ctrl.rssi);
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
    <h2 id="targetTitle">Target AP: None</h2>
    <div id="sniffStatus" style="color: #f85149; font-weight: bold;"></div>
    <h3>Connected Clients:</h3>
    <div id="clientList"></div>
  </div>

  <script>
    window.onload = () => {
      fetch('/get_clients').then(r => r.json()).then(data => {
        if (data.clients.length > 0 || data.active) {
          document.getElementById('targetPanel').style.display = "block";
          document.getElementById('targetTitle').innerText = "Target AP: " + data.ssid;
          updateClientsUI(data);
        }
      }).catch(e => console.log("Fresh load."));
    };

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
      document.getElementById('targetTitle').innerText = "Target AP: " + ssid;
      
      document.getElementById('clientList').innerHTML = "<span style='color:#e3b341;'>Sniffing in progress... The connection will drop temporarily. Please reconnect and refresh this page after 20 seconds.</span>";
      
      let encodedSsid = encodeURIComponent(ssid);
      
      fetch(`/start_sniff?mac=${mac}&ch=${ch}&ssid=${encodedSsid}`).then(() => {
        setTimeout(fetchClients, 20000); 
      }).catch(err => {
        setTimeout(fetchClients, 20000); 
      });
    }

    function fetchClients() {
      document.getElementById('clientList').innerHTML = "Fetching results...";
      fetch('/get_clients').then(r => r.json()).then(data => {
        updateClientsUI(data);
      }).catch(() => {
        document.getElementById('clientList').innerHTML = "<span style='color:red;'>Not connected. Please ensure you are connected to 'ESP32_Tactical' and refresh the page.</span>";
      });
    }

    function updateClientsUI(data) {
      let list = data.clients.map(c => `<div class="client-item">MAC: ${c}</div>`).join('');
      document.getElementById('clientList').innerHTML = list || "No clients found. The network might be empty.";
      document.getElementById('sniffStatus').innerText = "STATUS: SNIFFING FINISHED";
    }
  </script>
</body>
</html>
)rawliteral";

void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_AP_STA);
  
  WiFi.softAP("ESP32_Tactical", "mgmtadmin");
  esp_read_mac(my_ap_mac, ESP_MAC_WIFI_SOFTAP);

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
      pending_ch = r->getParam("ch")->value().toInt();
      
      if(r->hasParam("ssid")) {
        target_ssid_name = r->getParam("ssid")->value();
      } else {
        target_ssid_name = "Unknown";
      }
      
      // DO NOT START SNIFFING HERE.
      // Just set the flags and let the web server safely return the 200 OK response.
      pending_sniff = true;
      pending_sniff_time = millis();
      
      r->send(200, "text/plain", "OK");
    }
  });

  server.on("/get_clients", HTTP_GET, [](AsyncWebServerRequest *r){
    String json = "{\"active\":" + String(is_sniffing || pending_sniff ? "true" : "false") + ",\"ssid\":\"" + target_ssid_name + "\",\"clients\":[";
    for (int i = 0; i < client_count; i++) {
      if (i > 0) json += ",";
      json += "\"" + macToString(discovered_clients[i]) + "\"";
    }
    json += "]}";
    r->send(200, "application/json", json);
  });

  server.begin();
}

void loop() {
  // Check if we have a pending sniff request that has waited for 1 second
  if (pending_sniff && (millis() - pending_sniff_time > 1000)) {
    pending_sniff = false;
    
    // Now that the TCP stack has settled, change the radio state
    esp_wifi_set_promiscuous(false);
    WiFi.softAP("ESP32_Tactical", "mgmtadmin", pending_ch);
    esp_wifi_set_channel(pending_ch, WIFI_SECOND_CHAN_NONE);

    client_count = 0; 
    
    wifi_promiscuous_filter_t filter = {
      .filter_mask = WIFI_PROMIS_FILTER_MASK_DATA
    };
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(&sniffer_callback);
    esp_wifi_set_promiscuous(true);
    
    is_sniffing = true;
    sniff_start_time = millis();
    Serial.println("Sniffing started safely.");
  }

  // Check if sniffing duration has ended
  if (is_sniffing && (millis() - sniff_start_time > SNIFF_DURATION)) {
    is_sniffing = false;
    esp_wifi_set_promiscuous(false);
    Serial.println("Sniffing ended.");
  }
}