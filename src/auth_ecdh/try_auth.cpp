/*******************************************************
 * Purpose: test repeated or manual ECDH authentication
 * attempts between the ESP32 device and the server.
 *
 * This firmware is used to debug reconnect, rekey, and
 * authentication behavior over Wi-Fi and TCP.
 *******************************************************/
#include <Arduino.h>
#include <WiFi.h>

#include <auth_ecdh.h>

// ----------------- Wi-Fi / TCP -----------------
constexpr const char* SSID      = "RaspberryWiFi";
constexpr const char* PASS      = "12345678";
constexpr const char* SERVER_IP = "192.168.4.1";
constexpr uint16_t    PORT      = 5000;

// ----------------- MASTER KEY -----------------
static const uint8_t MASTER_KEY[] = {
  0x72, 0x13, 0x25, 0x4B, 0x46, 0x7B, 0x23, 0x18,
  0xE1, 0xE7, 0x25, 0x3F, 0x3B, 0x8B, 0x02, 0xAE,
  0xC5, 0x56, 0xFF, 0x9D, 0xAC, 0xBB, 0x73, 0x96,
  0x30, 0xE7, 0x5C, 0x66, 0x7B, 0x1F, 0x32, 0x24
};

// ----------------- Session -----------------
constexpr uint8_t REKEY_REQUEST = 0x10;
constexpr uint32_t RECONNECT_BACKOFF_MS = 1000;

static WiFiClient g_session;
static AuthEcdhConfig g_cfg = {};
static uint8_t g_key96[12];

static bool connect_session() {
  if (g_session.connected()) return true;
  g_session.stop();
  return g_session.connect(SERVER_IP, PORT);
}

static bool run_handshake() {
  if (!connect_session()) {
    Serial.println("[HS] TCP connect failed");
    return false;
  }

  AuthEcdhError err = auth_ecdh_handshake(&g_cfg, g_key96, nullptr);
  if (err != AUTH_ECDH_OK) {
    Serial.printf("[HS] FAILED: %s\n", auth_ecdh_error_str(err));
    g_session.stop();
    return false;
  }

  Serial.println("[HS] DONE");
  return true;
}

void setup() {
  Serial.begin(115200);
  delay(500);
  Serial.printf("Connecting Wi-Fi: %s\n", SSID);
  WiFi.begin(SSID, PASS);
  while (WiFi.status() != WL_CONNECTED) { Serial.print("."); delay(300); }
  Serial.println("\nWi-Fi OK");
  Serial.print("IP: "); Serial.println(WiFi.localIP());
  pinMode(2, INPUT);
  while (digitalRead(2) == LOW) { delay(1); }
  g_cfg.server_ip = SERVER_IP;
  g_cfg.port = PORT;
  g_cfg.master_key = MASTER_KEY;
  g_cfg.master_key_len = sizeof(MASTER_KEY);
  g_cfg.io_timeout_ms = 5000;
  g_cfg.device_id = nullptr;
  g_cfg.client = &g_session;

  run_handshake();
}

void loop() {
  static uint32_t last_try_ms = 0;

  if (!g_session.connected()) {
    uint32_t now = millis();
    if ((now - last_try_ms) >= RECONNECT_BACKOFF_MS) {
      last_try_ms = now;
      run_handshake();
    }
    delay(10);
    return;
  }

  int available = g_session.available();
  if (available <= 0) {
    delay(2);
    return;
  }

  int b = g_session.read();
  if (b == REKEY_REQUEST) {
    Serial.println("[HS] REKEY_REQUEST");
    run_handshake();
  }
}
