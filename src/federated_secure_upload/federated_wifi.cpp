/*******************************************************
 * ESP32-S3 <-> Direct TCP <-> SPECK-64/96
 * Wi-Fi + ECDH authentication + encrypted weights upload.
 *
 * Training logic removed. The device now:
 *  - connects to Wi-Fi
 *  - authenticates with ECDH
 *  - derives a SPECK key
 *  - encrypts weights from weights_q.h
 *  - sends them to the server
 *  - decrypts and validates encrypted replies
 *******************************************************/
#include <Arduino.h>
#include <WiFi.h>

#include "esp_heap_caps.h"
#include "esp_system.h"

#include <auth_ecdh.h>
#include <mbedtls/sha256.h>

#include "weights_q.h"

/* ------------------- Timing helpers ------------------- */
#define TS_START(var) uint32_t var = ESP.getCycleCount()
static inline float cyc2us(uint32_t d) { return d / (float)ESP.getCpuFreqMHz(); }
#define ROTR32(x, r) ((uint32_t)(((x) >> (r)) | ((x) << (32 - (r)))))
#define ROTL32(x, r) ((uint32_t)(((x) << (r)) | ((x) >> (32 - (r)))))

/* ------------------- WiFi / TCP config ------------------- */
constexpr const char* SSID = "RaspberryWiFi";
constexpr const char* PASS = "12345678";
constexpr const char* SERVER_IP = "192.168.4.1";
constexpr uint16_t PORT = 1883;

static const uint8_t MASTER_KEY[] = {
    0x72, 0x13, 0x25, 0x4B, 0x46, 0x7B, 0x23, 0x18,
    0xE1, 0xE7, 0x25, 0x3F, 0x3B, 0x8B, 0x02, 0xAE,
    0xC5, 0x56, 0xFF, 0x9D, 0xAC, 0xBB, 0x73, 0x96,
    0x30, 0xE7, 0x5C, 0x66, 0x7B, 0x1F, 0x32, 0x24
};
constexpr size_t MASTER_KEY_LEN = sizeof(MASTER_KEY);

constexpr uint8_t REKEY_REQUEST = 0x10;
constexpr uint8_t APP_DATA = 0x20;
constexpr uint32_t HS_RETRY_MS = 1000;
constexpr uint32_t HS_TIMEOUT_MS = 5000;
constexpr uint32_t SEND_PERIOD_MS = 15000;
constexpr uint32_t RESEND_TIMEOUT_MS = 60000;
constexpr uint32_t RX_MAX = 131072;
static const uint32_t SERIAL_BAUD = 115200;

/* ------------------- Perf counters ------------------- */
volatile uint32_t enc_pkt_cyc = 0, dec_pkt_cyc = 0;
volatile uint32_t enc_pkt_cnt = 0, dec_pkt_cnt = 0;
volatile uint32_t parse_cyc = 0, parse_cnt = 0;
volatile uint32_t enc_cyc = 0, dec_cyc = 0;
volatile uint32_t enc_cnt = 0, dec_cnt = 0;
volatile uint64_t enc_total_bytes = 0, dec_total_bytes = 0;

/* ------------------- TCP session / auth ------------------- */
WiFiClient net;
static AuthEcdhConfig g_auth_cfg = {};
static uint8_t g_key96[12];
static bool g_key_ready = false;
static uint32_t g_last_hs_try_ms = 0;

/* ------------------- TX state ------------------- */
static bool g_payload_sent = false;
static bool g_waiting_reply = false;
static uint32_t g_last_send_ms = 0;

/* ------------------- SPECK-64/96 ------------------- */
uint32_t RK[26];

void genRK96(const uint32_t k[3]) {
    uint32_t l[2];
    uint32_t rk;
    l[1] = k[2];
    l[0] = k[1];
    rk = k[0];
    RK[0] = rk;
    for (int i = 0; i < 25; i++) {
        uint32_t new_l = (rk + ROTR32(l[i % 2], 8)) ^ i;
        l[i % 2] = new_l;
        rk = ROTL32(rk, 3) ^ new_l;
        RK[i + 1] = rk;
    }
}

inline uint64_t enc64_fast(uint64_t blk) {
    TS_START(t0);
    uint32_t x = (uint32_t)(blk >> 32), y = (uint32_t)blk;
    for (int r = 0; r < 26; ++r) {
        x = (ROTR32(x, 8) + y) ^ RK[r];
        y = ROTL32(y, 3) ^ x;
    }
    uint32_t cyc = ESP.getCycleCount() - t0;
    enc_cyc += cyc;
    ++enc_cnt;
    return ((uint64_t)x << 32) | y;
}

inline uint64_t dec64_fast(uint64_t blk) {
    TS_START(t0);
    uint32_t x = (uint32_t)(blk >> 32), y = (uint32_t)blk;
    for (int r = 25; r >= 0; --r) {
        y = ROTR32(y ^ x, 3);
        x = ROTL32((x ^ RK[r]) - y, 8);
    }
    uint32_t cyc = ESP.getCycleCount() - t0;
    dec_cyc += cyc;
    ++dec_cnt;
    return ((uint64_t)x << 32) | y;
}

static uint32_t load_u32_le(const uint8_t* p) {
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static inline uint32_t read_u32_be(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

static inline void write_u32_be(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void apply_speck_key(const uint8_t key96[12]) {
    uint32_t k[3] = {
        load_u32_le(key96),
        load_u32_le(key96 + 4),
        load_u32_le(key96 + 8)
    };
    genRK96(k);
    g_key_ready = true;
}

static bool connect_session() {
    if (net.connected()) return true;
    net.stop();
    return net.connect(SERVER_IP, PORT);
}

static bool run_handshake() {
    if (!connect_session()) {
        Serial.println("[HS] TCP connect failed");
        g_key_ready = false;
        return false;
    }

    g_auth_cfg.client = &net;
    AuthEcdhError err = auth_ecdh_handshake(&g_auth_cfg, g_key96, nullptr);
    if (err != AUTH_ECDH_OK) {
        Serial.printf("[HS] FAILED: %s\n", auth_ecdh_error_str(err));
        g_key_ready = false;
        return false;
    }

    apply_speck_key(g_key96);
    Serial.println("[HS] DONE");
    return true;
}

static bool ensure_session() {
    if (net.connected() && g_key_ready) return true;
    uint32_t now = millis();
    if (now - g_last_hs_try_ms < HS_RETRY_MS) return false;
    g_last_hs_try_ms = now;
    return run_handshake();
}

/* ------------------- Encrypted weights payload ------------------- */
static constexpr uint8_t WEIGHTS_MAGIC[4] = {'A', 'I', 'F', '1'};

struct EncResult {
    uint8_t* data;
    size_t len;
};

static const uint8_t* local_weights_bytes() {
    return reinterpret_cast<const uint8_t*>(WEIGHTS_Q);
}

static size_t local_weights_len() {
    return sizeof(WEIGHTS_Q);
}

static void print_local_weights_info() {
    Serial.printf("Local quantized weights: count=%d scale=%d bytes=%u\n",
                  WEIGHTS_COUNT, WEIGHTS_SCALE, (unsigned)local_weights_len());
    Serial.print("First 10 weights: ");
    for (int i = 0; i < 10 && i < WEIGHTS_COUNT; ++i) {
        Serial.printf("%ld ", (long)WEIGHTS_Q[i]);
    }
    Serial.println();
}

static EncResult build_and_encrypt_weights_frame() {
    TS_START(pkt_t0);

    const uint8_t* weights = local_weights_bytes();
    const size_t weights_len = local_weights_len();
    if (!weights || weights_len == 0) return {nullptr, 0};
    if (weights_len > 0xFFFFFFFFu - 32u) return {nullptr, 0};

    uint8_t hash[32];
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, weights, weights_len);
    mbedtls_sha256_finish(&ctx, hash);
    mbedtls_sha256_free(&ctx);

    const uint32_t payload_len = (uint32_t)(weights_len + sizeof(hash));
    const size_t plain_len = 4 + 4 + payload_len;
    const size_t padded_len = ((plain_len + 7) / 8) * 8;

    uint8_t* plain = (uint8_t*)heap_caps_malloc(padded_len, MALLOC_CAP_SPIRAM);
    if (!plain) {
        Serial.println("heap_caps_malloc failed for plaintext");
        return {nullptr, 0};
    }

    memcpy(plain, WEIGHTS_MAGIC, 4);
    write_u32_be(plain + 4, payload_len);
    memcpy(plain + 8, weights, weights_len);
    memcpy(plain + 8 + weights_len, hash, sizeof(hash));
    memset(plain + plain_len, 0, padded_len - plain_len);

    uint8_t* cipher = (uint8_t*)heap_caps_malloc(padded_len, MALLOC_CAP_SPIRAM);
    if (!cipher) {
        heap_caps_free(plain);
        return {nullptr, 0};
    }

    for (size_t i = 0; i < padded_len; i += 8) {
        uint64_t blk = 0;
        for (int j = 0; j < 8; ++j) blk = (blk << 8) | plain[i + j];
        uint64_t ct = enc64_fast(blk);
        for (int j = 0; j < 8; ++j) cipher[i + j] = (uint8_t)(ct >> (56 - j * 8));
    }

    enc_total_bytes += plain_len;
    uint32_t cyc_pkt = ESP.getCycleCount() - pkt_t0;
    enc_pkt_cyc += cyc_pkt;
    ++enc_pkt_cnt;

    heap_caps_free(plain);
    return {cipher, padded_len};
}

static bool validate_plaintext_weights(const uint8_t* pt, size_t len) {
    if (!pt || len < 8) {
        Serial.println("RX: payload too short");
        return false;
    }
    if (memcmp(pt, WEIGHTS_MAGIC, 4) != 0) {
        Serial.println("RX: bad magic");
        return false;
    }

    const uint32_t payload_len = read_u32_be(pt + 4);
    if (payload_len < 32) {
        Serial.println("RX: payload_len too small");
        return false;
    }
    if ((size_t)payload_len + 8 > len) {
        Serial.println("RX: payload shorter than header");
        return false;
    }

    const uint32_t weights_len = payload_len - 32;
    const uint8_t* weights_bytes = pt + 8;
    const uint8_t* received_hash = pt + 8 + weights_len;

    uint8_t computed_hash[32];
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, weights_bytes, weights_len);
    mbedtls_sha256_finish(&ctx, computed_hash);
    mbedtls_sha256_free(&ctx);

    if (memcmp(computed_hash, received_hash, sizeof(computed_hash)) != 0) {
        Serial.println("RX: hash mismatch");
        return false;
    }

    Serial.printf("RX: valid encrypted payload with %u bytes of weights\n", (unsigned)weights_len);
    if (weights_len >= sizeof(int32_t)) {
        const int32_t* rx_weights = reinterpret_cast<const int32_t*>(weights_bytes);
        size_t rx_count = weights_len / sizeof(int32_t);
        Serial.print("RX first 10 weights: ");
        for (size_t i = 0; i < 10 && i < rx_count; ++i) {
            Serial.printf("%ld ", (long)rx_weights[i]);
        }
        Serial.println();
    }
    return true;
}

static bool process_response_payload(const uint8_t* pay, size_t len) {
    TS_START(pkt_t0);
    TS_START(parse_t0);

    if (!pay || len == 0) return false;
    if (len % 8 != 0) {
        Serial.println("RX: ciphertext length not multiple of 8");
        return false;
    }

    uint8_t* plain = (uint8_t*)heap_caps_malloc(len, MALLOC_CAP_SPIRAM);
    if (!plain) {
        Serial.println("RX: malloc failed for plaintext");
        return false;
    }

    uint16_t blks = 0;
    for (size_t i = 0; i < len; i += 8) {
        uint64_t ct = 0;
        for (int j = 0; j < 8; ++j) ct = (ct << 8) | pay[i + j];
        uint64_t pt = dec64_fast(ct);
        ++blks;
        for (int j = 7; j >= 0; --j) {
            plain[i + (size_t)(7 - j)] = (uint8_t)((pt >> (j * 8)) & 0xFF);
        }
    }

    uint32_t cyc_pkt = ESP.getCycleCount() - pkt_t0;
    dec_total_bytes += (uint64_t)blks * 8u;
    dec_pkt_cyc += cyc_pkt;
    ++dec_pkt_cnt;
    parse_cyc += ESP.getCycleCount() - parse_t0;
    ++parse_cnt;

    bool ok = validate_plaintext_weights(plain, len);
    heap_caps_free(plain);
    return ok;
}

static bool send_weights_frame() {
    EncResult enc = build_and_encrypt_weights_frame();
    if (!enc.data || enc.len == 0) return false;

    if (!ensure_session()) {
        heap_caps_free(enc.data);
        return false;
    }

    uint8_t type = APP_DATA;
    uint8_t len_be[4];
    write_u32_be(len_be, (uint32_t)enc.len);

    size_t w1 = net.write(&type, 1);
    size_t w2 = net.write(len_be, 4);
    size_t w3 = net.write(enc.data, enc.len);

    heap_caps_free(enc.data);

    if (w1 != 1 || w2 != 4 || w3 != enc.len) {
        Serial.println("TX failed");
        return false;
    }

    Serial.printf("TX: encrypted weights sent (%u plaintext bytes, %u ciphertext bytes)\n",
                  (unsigned)(8 + local_weights_len() + 32),
                  (unsigned)enc.len);
    return true;
}

/* ------------------- RX state machine ------------------- */
enum RxState : uint8_t { RX_WAIT_TYPE = 0, RX_WAIT_LEN, RX_WAIT_PAYLOAD };

static RxState g_rx_state = RX_WAIT_TYPE;
static uint8_t g_rx_len_buf[4];
static uint8_t g_rx_len_pos = 0;
static uint32_t g_rx_payload_len = 0;
static uint8_t* g_rx_payload = nullptr;
static uint32_t g_rx_payload_pos = 0;

static void reset_rx_state() {
    if (g_rx_payload) {
        heap_caps_free(g_rx_payload);
        g_rx_payload = nullptr;
    }
    g_rx_state = RX_WAIT_TYPE;
    g_rx_len_pos = 0;
    g_rx_payload_len = 0;
    g_rx_payload_pos = 0;
}

static void rx_pump() {
    while (net.connected() && net.available() > 0) {
        int b = net.read();
        if (b < 0) return;
        uint8_t byte = (uint8_t)b;

        switch (g_rx_state) {
            case RX_WAIT_TYPE:
                if (byte == REKEY_REQUEST) {
                    Serial.println("[HS] REKEY_REQUEST");
                    g_key_ready = false;
                    run_handshake();
                    g_payload_sent = false;
                    g_waiting_reply = false;
                    reset_rx_state();
                    return;
                }
                if (byte == APP_DATA) {
                    g_rx_state = RX_WAIT_LEN;
                    g_rx_len_pos = 0;
                } else {
                    Serial.printf("RX unknown type: 0x%02X\n", byte);
                }
                break;

            case RX_WAIT_LEN:
                g_rx_len_buf[g_rx_len_pos++] = byte;
                if (g_rx_len_pos == 4) {
                    g_rx_payload_len = read_u32_be(g_rx_len_buf);
                    if (g_rx_payload_len == 0 || g_rx_payload_len > RX_MAX) {
                        Serial.printf("RX bad length: %u\n", (unsigned)g_rx_payload_len);
                        net.stop();
                        reset_rx_state();
                        return;
                    }
                    g_rx_payload_pos = 0;
                    g_rx_payload = (uint8_t*)heap_caps_malloc(g_rx_payload_len, MALLOC_CAP_SPIRAM);
                    if (!g_rx_payload) {
                        Serial.println("RX payload malloc failed, discarding");
                    }
                    g_rx_state = RX_WAIT_PAYLOAD;
                }
                break;

            case RX_WAIT_PAYLOAD:
                if (g_rx_payload && g_rx_payload_pos < g_rx_payload_len) {
                    g_rx_payload[g_rx_payload_pos] = byte;
                }
                g_rx_payload_pos++;
                if (g_rx_payload_pos >= g_rx_payload_len) {
                    if (g_rx_payload) {
                        bool ok = process_response_payload(g_rx_payload, g_rx_payload_len);
                        if (ok) g_waiting_reply = false;
                        heap_caps_free(g_rx_payload);
                        g_rx_payload = nullptr;
                    }
                    g_rx_state = RX_WAIT_TYPE;
                }
                break;
        }
    }
}

/* ------------------- Perf print ------------------- */
static void print_perf() {
    static uint32_t lastMs = 0;
    uint32_t now = millis();
    uint32_t dtMs = now - lastMs;
    if (dtMs < 1000) return;
    lastMs = now;

    uint32_t cryptoCycles = enc_cyc + dec_cyc;
    float cpuPct = (cryptoCycles / (ESP.getCpuFreqMHz() * 1000.0f * dtMs)) * 100.0f;

    bool any = false;
    if (enc_cnt) {
        float avg_us = cyc2us(enc_cyc) / enc_cnt;
        float tot_us = cyc2us(enc_cyc);
        float tot_sec = tot_us / 1e6f;
        float enc_speed_bps = (tot_sec > 0) ? (float)enc_total_bytes / tot_sec : 0.0f;
        float enc_speed_kbps = enc_speed_bps / 1024.0f;
        Serial.printf("enc total time: %.2f us | avg: %.2f us/blk (%u blks)\n",
                      tot_us, avg_us, enc_cnt);
        Serial.printf("enc speed: %.2f KB/s\n", enc_speed_kbps);
        any = true;
    }
    if (dec_cnt) {
        float avg_us = cyc2us(dec_cyc) / dec_cnt;
        float tot_us = cyc2us(dec_cyc);
        float tot_sec = tot_us / 1e6f;
        float dec_speed_bps = (tot_sec > 0) ? (float)dec_total_bytes / tot_sec : 0.0f;
        float dec_speed_kbps = dec_speed_bps / 1024.0f;
        Serial.printf("dec total time: %.2f us | avg: %.2f us/blk (%u blks)\n",
                      tot_us, avg_us, dec_cnt);
        Serial.printf("dec speed: %.2f KB/s\n", dec_speed_kbps);
        any = true;
    }
    if (any) {
        constexpr size_t RAM_BANK = 512 * 1024;
        size_t heapFree = ESP.getFreeHeap();
        size_t ramUsedB = (heapFree < RAM_BANK) ? RAM_BANK - heapFree : 0;
        float ramPct = (float)ramUsedB / RAM_BANK * 100.0f;
        size_t flashUsedB = ESP.getSketchSize();
        size_t flashTotalB = ESP.getFlashChipSize();
        float flashPct = (float)flashUsedB / flashTotalB * 100.0f;
        Serial.printf("RAM used: %u B (%.1f%% of 512 KB) | FLASH used: %u B (%.2f%% of %u KB) | CPU-crypto: %.2f%%\n\n",
                      (unsigned)ramUsedB, ramPct,
                      (unsigned)flashUsedB, flashPct, (unsigned)(flashTotalB / 1024),
                      cpuPct);
    }
    if (enc_pkt_cnt) {
        float avg_us = cyc2us(enc_pkt_cyc) / enc_pkt_cnt;
        float tot_us = cyc2us(enc_pkt_cyc);
        Serial.printf("enc-pkt: %.2f us/pkt | %.2f us total (%u pkts)\n",
                      avg_us, tot_us, enc_pkt_cnt);
    }
    if (dec_pkt_cnt) {
        float avg_us = cyc2us(dec_pkt_cyc) / dec_pkt_cnt;
        float tot_us = cyc2us(dec_pkt_cyc);
        Serial.printf("dec-pkt: %.2f us/pkt | %.2f us total (%u pkts)\n",
                      avg_us, tot_us, dec_pkt_cnt);
    }
    if (parse_cnt) {
        float avg_us = cyc2us(parse_cyc) / parse_cnt;
        float tot_us = cyc2us(parse_cyc);
        Serial.printf("parse: %.2f us/call | %.2f us total (%u calls)\n",
                      avg_us, tot_us, parse_cnt);
    }

    enc_cyc = enc_cnt = 0;
    dec_cyc = dec_cnt = 0;
    enc_pkt_cyc = enc_pkt_cnt = 0;
    dec_pkt_cyc = dec_pkt_cnt = 0;
    parse_cyc = parse_cnt = 0;
    enc_total_bytes = 0;
    dec_total_bytes = 0;
}

/* ------------------- setup & loop ------------------- */
void setup() {
    Serial.begin(SERIAL_BAUD);
    delay(200);

    WiFi.begin(SSID, PASS);
    while (WiFi.status() != WL_CONNECTED) {
        Serial.print('.');
        delay(400);
    }
    Serial.println("\nWi-Fi OK");

    g_auth_cfg.server_ip = SERVER_IP;
    g_auth_cfg.port = PORT;
    g_auth_cfg.master_key = MASTER_KEY;
    g_auth_cfg.master_key_len = MASTER_KEY_LEN;
    g_auth_cfg.io_timeout_ms = HS_TIMEOUT_MS;
    g_auth_cfg.device_id = nullptr;
    g_auth_cfg.client = &net;

    run_handshake();

    Serial.printf("CPU %d MHz\n", ESP.getCpuFreqMHz());
    size_t psram_size = heap_caps_get_total_size(MALLOC_CAP_SPIRAM);
    Serial.printf("PSRAM size: %u bytes\n", (unsigned)psram_size);
    if (psram_size == 0) Serial.println("PSRAM not available!");

    print_local_weights_info();
    g_last_send_ms = millis() - SEND_PERIOD_MS;
}

void loop() {
    if (!ensure_session()) {
        delay(10);
        print_perf();
        return;
    }

    rx_pump();

    unsigned long now = millis();

    if (!g_payload_sent && (now - g_last_send_ms >= SEND_PERIOD_MS)) {
        bool sent = send_weights_frame();
        g_last_send_ms = now;
        if (sent) {
            g_payload_sent = true;
            g_waiting_reply = true;
        }
    }

    if (g_waiting_reply && (now - g_last_send_ms >= RESEND_TIMEOUT_MS)) {
        Serial.println("TX: reply timeout, scheduling resend");
        g_payload_sent = false;
        g_waiting_reply = false;
    }

    print_perf();
    delay(5);
}
