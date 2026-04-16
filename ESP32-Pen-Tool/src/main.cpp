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

// Pending State Management
bool pending_sniff = false;
unsigned long pending_sniff_time = 0;
int pending_ch = 0;

// --- BEACON SPAM CONFIGURATION ---
const char ssids[] PROGMEM = {
  "Mom Use This One\n"
  "Abraham Linksys\n"
  "Benjamin FrankLAN\n"
  "Martin Router King\n"
  "John Wilkes Bluetooth\n"
  "Pretty Fly for a Wi-Fi\n"
  "Bill Wi the Science Fi\n"
  "I Believe Wi Can Fi\n"
  "Tell My Wi-Fi Love Her\n"
  "No More Mister Wi-Fi\n"
  "The LAN Before Time\n"
  "Get Off My LAN\n"
  "Router? I Hardly Know Her\n"
  "Wu-Tang LAN\n"
  "Silence of the LANs\n"
  "Loading...\n"
  "Not Your Wi-Fi\n"
  "Definitely Not FBI\n"
  "NSA Surveillance Van 3\n"
  "CIA Listening Post\n"
  "Interpol HQ\n"
  "Very Suspicious Van\n"
  "Skynet Global Defense\n"
  "SkyNet Node 7\n"
  "Winternet Is Coming\n"
  "The Password Is Password\n"
  "IP Freely\n"
  "Dunder Mifflin WiFi\n"
  "The Promised LAN\n"
  "LAN of Milk and Honey\n"
  "Router McRouterface\n"
  "Searching...\n"
  "Please Connect\n"
  "Free Virus Download\n"
  "Hack This If You Can\n"
  "No Internet Access\n"
  "HideYoKidsHideYoWifi\n"
  "The Bandwidth Bandit\n"
  "Yell PASSWORD For Key\n"
  "Click Here For Virus\n"
  "Not Free WiFi\n"
  "Alien Life Form Network\n"
  "2.4 Ghosts Only\n"
  "404 Network Unavailable\n"
  "Nacho Wi-Fi\n"
  "Thou Shalt Not Covet\n"
  "Virus.exe\n"
  "I'm Under Your Bed\n"
  "Your Printer Is On Fire\n"
  "Totally Legit Network\n"
  "Series of Tubes\n"
  "Packet Loss Party\n"
  "The Router About Nothing\n"
  "Bandwidth Court\n"
  "LAN Solo\n"
  "Obi-WAN Kenobi\n"
  "The Dark Net\n"
  "Ping of Death\n"
  "The Network Strikes Back\n"
  "Rogue Access Point\n"
  "Drop It Like Its Hotspot\n"
  "Wifi Art Thou Romeo\n"
  "This Is Not The WiFi\n"
  "Optimus Prime Network\n"
};

// Cached SSID table (parsed once at startup)
#define NUM_SSIDS 64
static int  beacon_ssids_total_len   = 0;
static int  beacon_ssid_offsets[NUM_SSIDS];
static uint8_t beacon_ssid_lengths[NUM_SSIDS];
static uint8_t beacon_ssid_macs[NUM_SSIDS][6];  // fixed MAC per SSID slot
static uint8_t beacon_ssid_actual_count = 0;
static bool beacon_macs_initialized = false;

// Beacon TX state
const bool beacon_wpa2            = false;
const uint8_t BEACON_BATCH_SIZE   = 5;
const uint8_t BEACON_TX_PER_SSID  = 1;
const unsigned long BEACON_TX_INTERVAL_MS = 120;

bool     is_beaconing           = false;
unsigned long beacon_attack_time = 0;
uint8_t  beacon_mac_addr[6];
uint8_t  beacon_wifi_channel    = 1;
char     beacon_empty_ssid[32];
uint16_t beacon_packet_size     = 0;
uint8_t  beacon_current_ssid_index = 0;

// Beacon frame template (802.11 management beacon)
uint8_t beaconPacket[109] = {
  /*  0 - 3  */ 0x80, 0x00, 0x00, 0x00,
  /*  4 - 9  */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  /* 10 - 15 */ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
  /* 16 - 21 */ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
  /* 22 - 23 */ 0x00, 0x00,
  /* 24 - 31 */ 0x83, 0x51, 0xf7, 0x8f, 0x0f, 0x00, 0x00, 0x00,
  /* 32 - 33 */ 0xe8, 0x03,
  /* 34 - 35 */ 0x31, 0x00,
  /* 36 - 37 */ 0x00, 0x20,
  /* 38 - 69 */ 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
               0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
               0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
               0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
  /* 70 - 71 */ 0x01, 0x08,
  /* 72 - 79 */ 0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c,
  /* 80 - 81 */ 0x03, 0x01,
  /* 82      */ 0x01,
  /* 83 - 84 */ 0x30, 0x18,
  /* 85 - 86 */ 0x01, 0x00,
  /* 87 - 90 */ 0x00, 0x0f, 0xac, 0x02,
  /* 91 - 92 */ 0x02, 0x00,
  /* 93 -100 */ 0x00, 0x0f, 0xac, 0x04, 0x00, 0x0f, 0xac, 0x04,
  /*101 -102 */ 0x01, 0x00,
  /*103 -106 */ 0x00, 0x0f, 0xac, 0x02,
  /*107 -108 */ 0x00, 0x00
};

// --- BEACON INIT: parse SSID table + assign fixed MACs ---
void beacon_init_ssid_table() {
  beacon_ssid_actual_count = 0;
  int offset = 0;

  while (offset < beacon_ssids_total_len && beacon_ssid_actual_count < NUM_SSIDS) {
    int start = offset;
    int len   = 0;

    // Measure this SSID and advance offset past its newline
    while (offset < beacon_ssids_total_len) {
      char c = (char)pgm_read_byte(ssids + offset);
      offset++;
      if (c == '\n') break;
      len++;
    }

    if (len == 0) continue;

    uint8_t idx = beacon_ssid_actual_count;
    beacon_ssid_offsets[idx] = start;
    beacon_ssid_lengths[idx] = (uint8_t)min(len, 32);

    // Deterministic locally-administered unicast MAC per slot.
    // Format: 02:E5:32:<slot>:AA:BB  — same across reboots so
    // nearby devices keep seeing the same BSSID and don't age it out.
    beacon_ssid_macs[idx][0] = 0x02;
    beacon_ssid_macs[idx][1] = 0xE5;
    beacon_ssid_macs[idx][2] = 0x32;
    beacon_ssid_macs[idx][3] = idx;
    beacon_ssid_macs[idx][4] = 0xAA;
    beacon_ssid_macs[idx][5] = 0xBB;

    beacon_ssid_actual_count++;
  }

  beacon_macs_initialized = true;
  Serial.printf("[Beacon] Parsed %d SSIDs.\n", beacon_ssid_actual_count);
}

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

// --- PROMISCUOUS SNIFFER CALLBACK ---
void processPacket(const uint8_t *payload, uint16_t len, int8_t rssi) {
  if (len < MIN_PAYLOAD_LEN) return;
  if (rssi < MIN_RSSI) return;

  uint8_t *addr1 = (uint8_t *)(payload + 4);
  uint8_t *addr2 = (uint8_t *)(payload + 10);
  uint8_t *addr3 = (uint8_t *)(payload + 16);

  if (macEqual(addr1, my_ap_mac) || macEqual(addr2, my_ap_mac) || macEqual(addr3, my_ap_mac))
    return;

  uint8_t fc1     = payload[1];
  bool    to_ds   = (fc1 & TO_DS)   != 0;
  bool    from_ds = (fc1 & FROM_DS) != 0;

  uint8_t *client = nullptr;
  uint8_t *ap     = nullptr;

  if      ( to_ds && !from_ds) { client = addr2; ap = addr1; }
  else if (!to_ds &&  from_ds) { client = addr1; ap = addr2; }
  else if (!to_ds && !from_ds) { client = addr2; ap = addr3; }
  else return;

  if (!macEqual(ap, target_bssid)) return;
  if ( macEqual(client, target_bssid)) return;
  if (client[0] & 0x01) return;  // skip multicast

  for (int i = 0; i < client_count; i++)
    if (macEqual(client, discovered_clients[i])) return;

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
  <h1>Wi-Fi Reconnaissance &amp; Beacon Spam</h1>
  <div style="display:flex; gap:10px; margin-bottom:20px;">
    <button id="scanBtn" onclick="scan()">[ Initiate AP Scan ]</button>
    <button id="beaconBtn" onclick="toggleBeacon()" style="background-color:#d29922;">[ Start Beacon Spam ]</button>
  </div>
  <div id="beaconStatus" style="margin:10px 0; color:#1f6feb;"></div>
  <div id="status" style="margin:10px 0;">Ready.</div>

  <table>
    <thead><tr><th>SSID</th><th>BSSID</th><th>Ch</th><th>RSSI</th><th>Action</th></tr></thead>
    <tbody id="netTable"></tbody>
  </table>

  <div id="targetPanel">
    <h2 id="targetTitle">Target AP: None</h2>
    <div id="sniffStatus" style="color:#f85149; font-weight:bold;"></div>
    <h3>Connected Clients:</h3>
    <div id="clientList"></div>
  </div>

  <script>
    let beaconActive = false;

    window.onload = () => {
      checkBeaconStatus();
      fetch('/get_clients').then(r => r.json()).then(data => {
        if (data.clients.length > 0 || data.active) {
          document.getElementById('targetPanel').style.display = "block";
          document.getElementById('targetTitle').innerText = "Target AP: " + data.ssid;
          updateClientsUI(data);
        }
      }).catch(() => {});
    };

    function checkBeaconStatus() {
      fetch('/beacon_status').then(r => r.json()).then(data => {
        beaconActive = data.active;
        updateBeaconUI();
      }).catch(() => {});
    }

    function toggleBeacon() {
      fetch('/toggle_beacon').then(r => r.json()).then(data => {
        beaconActive = data.active;
        updateBeaconUI();
      });
    }

    function updateBeaconUI() {
      const btn    = document.getElementById('beaconBtn');
      const status = document.getElementById('beaconStatus');
      if (beaconActive) {
        btn.innerText = "[ Stop Beacon Spam ]";
        btn.style.backgroundColor = "#da3633";
        status.innerText = "🔴 BEACON SPAM ACTIVE — Broadcasting 64 fake networks...";
      } else {
        btn.innerText = "[ Start Beacon Spam ]";
        btn.style.backgroundColor = "#d29922";
        status.innerText = "";
      }
    }

    function scan() {
      if (beaconActive) { alert("Stop beacon spam before scanning."); return; }
      document.getElementById('status').innerText = "Scanning...";
      fetch('/scan').then(r => r.json()).then(data => {
        let html = '';
        data.forEach(n => {
          html += `<tr>
            <td>${n.ssid}</td><td>${n.mac}</td><td>${n.ch}</td><td>${n.rssi}</td>
            <td><button class="target-btn" onclick="startSniff('${n.mac}',${n.ch},'${n.ssid}')">Select</button></td>
          </tr>`;
        });
        document.getElementById('netTable').innerHTML = html;
        document.getElementById('status').innerText = "Scan complete. " + data.length + " networks found.";
      });
    }

    function startSniff(mac, ch, ssid) {
      document.getElementById('targetPanel').style.display = "block";
      document.getElementById('targetTitle').innerText = "Target AP: " + ssid;
      document.getElementById('clientList').innerHTML =
        "<span style='color:#e3b341;'>Sniffing in progress... Connection will drop temporarily. Reconnect to ESP32_Tactical and refresh after 20 seconds.</span>";
      fetch(`/start_sniff?mac=${mac}&ch=${ch}&ssid=${encodeURIComponent(ssid)}`)
        .finally(() => setTimeout(fetchClients, 20000));
    }

    function fetchClients() {
      document.getElementById('clientList').innerHTML = "Fetching results...";
      fetch('/get_clients').then(r => r.json()).then(updateClientsUI).catch(() => {
        document.getElementById('clientList').innerHTML =
          "<span style='color:red;'>Not connected. Ensure you are on ESP32_Tactical and refresh.</span>";
      });
    }

    function updateClientsUI(data) {
      document.getElementById('clientList').innerHTML =
        data.clients.map(c => `<div class="client-item">MAC: ${c}</div>`).join('') ||
        "No clients found.";
      document.getElementById('sniffStatus').innerText = "STATUS: SNIFFING FINISHED";
    }
  </script>
</body>
</html>
)rawliteral";

// ============================================================
//  SETUP
// ============================================================
void setup() {
  Serial.begin(115200);

  WiFi.mode(WIFI_AP_STA);
  WiFi.setSleep(false);
  esp_wifi_set_ps(WIFI_PS_NONE);

  WiFi.softAP("ESP32_Tactical", "mgmtadmin");
  esp_read_mac(my_ap_mac, ESP_MAC_WIFI_SOFTAP);

  beacon_wifi_channel = WiFi.channel();
  if (beacon_wifi_channel < 1 || beacon_wifi_channel > 14) beacon_wifi_channel = 1;

  // Cache SSID flash length once, then build the lookup table
  beacon_ssids_total_len = strlen_P(ssids);
  beacon_init_ssid_table();

  // Initialise empty SSID buffer used to clear the beacon frame field
  memset(beacon_empty_ssid, 0x20, 32);

  // Pre-configure packet size (open network, no WPA2 IE)
  beacon_packet_size = sizeof(beaconPacket);
  if (!beacon_wpa2) {
    beaconPacket[34]  = 0x21;
    beacon_packet_size -= 26;
  }

  // --- HTTP ROUTES ---
  server.on("/", HTTP_GET, [](AsyncWebServerRequest *r){
    r->send(200, "text/html", index_html);
  });

  server.on("/scan", HTTP_GET, [](AsyncWebServerRequest *r){
    int n = WiFi.scanNetworks();
    String json = "[";
    for (int i = 0; i < n; i++) {
      if (i > 0) json += ",";
      json += "{\"ssid\":\"" + WiFi.SSID(i) +
              "\",\"mac\":\""  + WiFi.BSSIDstr(i) +
              "\",\"ch\":"     + String(WiFi.channel(i)) +
              ",\"rssi\":"     + String(WiFi.RSSI(i)) + "}";
    }
    json += "]";
    WiFi.scanDelete();
    r->send(200, "application/json", json);
  });

  server.on("/start_sniff", HTTP_GET, [](AsyncWebServerRequest *r){
    if (r->hasParam("mac") && r->hasParam("ch")) {
      parseBytes(r->getParam("mac")->value().c_str(), ':', target_bssid, 6, 16);
      pending_ch = r->getParam("ch")->value().toInt();
      target_ssid_name = r->hasParam("ssid") ? r->getParam("ssid")->value() : "Unknown";
      pending_sniff      = true;
      pending_sniff_time = millis();
      r->send(200, "text/plain", "OK");
    } else {
      r->send(400, "text/plain", "Missing params");
    }
  });

  server.on("/get_clients", HTTP_GET, [](AsyncWebServerRequest *r){
    String json = "{\"active\":" +
                  String((is_sniffing || pending_sniff) ? "true" : "false") +
                  ",\"ssid\":\"" + target_ssid_name + "\",\"clients\":[";
    for (int i = 0; i < client_count; i++) {
      if (i > 0) json += ",";
      json += "\"" + macToString(discovered_clients[i]) + "\"";
    }
    json += "]}";
    r->send(200, "application/json", json);
  });

  server.on("/beacon_status", HTTP_GET, [](AsyncWebServerRequest *r){
    r->send(200, "application/json",
            String("{\"active\":") + (is_beaconing ? "true" : "false") + "}");
  });

  server.on("/toggle_beacon", HTTP_GET, [](AsyncWebServerRequest *r){
    is_beaconing = !is_beaconing;

    if (is_beaconing) {
      // Stop any active sniffer before beaconing
      if (is_sniffing) {
        is_sniffing = false;
        esp_wifi_set_promiscuous(false);
      }
      beacon_attack_time        = millis();
      beacon_current_ssid_index = 0;
      beacon_wifi_channel       = WiFi.channel();
      if (beacon_wifi_channel < 1 || beacon_wifi_channel > 14) beacon_wifi_channel = 1;
    }

    r->send(200, "application/json",
            String("{\"active\":") + (is_beaconing ? "true" : "false") + "}");
  });

  server.begin();
  Serial.println("[Setup] Server started. AP: ESP32_Tactical");
}

// ============================================================
//  LOOP
// ============================================================
void loop() {

  // ===== BEACON SPAM =====
  if (is_beaconing && beacon_macs_initialized && beacon_ssid_actual_count > 0) {
    unsigned long now = millis();

    if (now - beacon_attack_time >= BEACON_TX_INTERVAL_MS) {
      beacon_attack_time = now;

      beacon_wifi_channel = WiFi.channel();
      if (beacon_wifi_channel < 1 || beacon_wifi_channel > 14) beacon_wifi_channel = 1;

      // Send BEACON_BATCH_SIZE frames per tick, round-robin across all 64 SSIDs.
      // Each SSID always uses its fixed MAC → devices keep it in their scan list.
      for (uint8_t b = 0; b < BEACON_BATCH_SIZE; b++) {
        uint8_t idx = beacon_current_ssid_index;

        // Read SSID bytes from PROGMEM
        char    ssidBuf[33];
        uint8_t ssidLen = beacon_ssid_lengths[idx];
        for (uint8_t i = 0; i < ssidLen; i++)
          ssidBuf[i] = (char)pgm_read_byte(ssids + beacon_ssid_offsets[idx] + i);
        ssidBuf[ssidLen] = '\0';

        // Inject fixed BSSID / SA for this SSID slot
        memcpy(&beaconPacket[10], beacon_ssid_macs[idx], 6);
        memcpy(&beaconPacket[16], beacon_ssid_macs[idx], 6);

        // Clear then write SSID field
        memcpy(&beaconPacket[38], beacon_empty_ssid, 32);
        memcpy(&beaconPacket[38], ssidBuf, ssidLen);

        // Stamp current channel
        beaconPacket[82] = beacon_wifi_channel;

        // Transmit — if TX queue full, bail early this batch
        esp_err_t tx = esp_wifi_80211_tx(WIFI_IF_STA, beaconPacket, beacon_packet_size, true);
        if (tx != ESP_OK) break;

        // Advance round-robin pointer
        beacon_current_ssid_index++;
        if (beacon_current_ssid_index >= beacon_ssid_actual_count)
          beacon_current_ssid_index = 0;
      }
    }
  }

  // ===== PENDING SNIFF START (deferred 1s after HTTP response) =====
  if (pending_sniff && (millis() - pending_sniff_time > 1000)) {
    pending_sniff = false;

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

    is_sniffing      = true;
    sniff_start_time = millis();
    Serial.printf("[Sniffer] Started on ch %d, target %s\n",
                  pending_ch, target_ssid_name.c_str());
  }

  // ===== SNIFF TIMEOUT =====
  if (is_sniffing && (millis() - sniff_start_time > SNIFF_DURATION)) {
    is_sniffing = false;
    esp_wifi_set_promiscuous(false);
    Serial.printf("[Sniffer] Done. %d client(s) found.\n", client_count);
  }
}