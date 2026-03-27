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
constexpr size_t MASTER_KEY_LEN = sizeof(MASTER_KEY);

void setup() {
  Serial.begin(115200);
  delay(500);
  Serial.printf("Connecting Wi-Fi: %s\n", SSID);
  WiFi.begin(SSID, PASS);
  while (WiFi.status() != WL_CONNECTED) { Serial.print("."); delay(300); }
  Serial.println("\nWi-Fi OK");
  Serial.print("IP: "); Serial.println(WiFi.localIP());

  pinMode(2, INPUT);
  while (digitalRead(2) == LOW) delay(1);

  AuthEcdhConfig cfg = {};
  cfg.server_ip = SERVER_IP;
  cfg.port = PORT;
  cfg.master_key = MASTER_KEY;
  cfg.master_key_len = MASTER_KEY_LEN;
  cfg.io_timeout_ms = 5000;
  cfg.device_id = nullptr;

  uint8_t key96[12];
  uint8_t device_id[8];
  AuthEcdhError err = auth_ecdh_handshake(&cfg, key96, device_id);
  if (err != AUTH_ECDH_OK) {
    Serial.printf("[HS] FAILED: %s\n", auth_ecdh_error_str(err));
  } else {
    Serial.println("[HS] DONE");
  }
}

void loop() {}
