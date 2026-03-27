/*******************************************************
 * ESP32-S3  TLS1.3-like KEX + per-device PSK from MASTER_KEY
 * ECDH P-256 + HMAC auth + TranscriptHash + Finished + HKDF-SHA256
 *
 * Output: KEY96 (12 bytes) for your Speck key (Speck not used here)
 *******************************************************/
#include <WiFi.h>
#include <Arduino.h>

#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/md.h"
#include "mbedtls/bignum.h"

// ----------------- Wi-Fi / TCP -----------------
constexpr const char* SSID      = "RaspberryWiFi";
constexpr const char* PASS      = "12345678";
constexpr const char* SERVER_IP = "192.168.4.1";
constexpr uint16_t    PORT      = 5000;

// ----------------- Protocol -----------------
static const uint8_t PROTO_VER = 0x01;

// ----------------- Device identity (PUBLIC) -----------------
// 8 bytes. Example: GW(2) BR(2) DEV(3) TYPE(1)
static const uint8_t DEVICE_ID[8] = { 0x00,0x0A, 0x00,0x03, 0x00,0x01,0x2F, 0x02 };

// ----------------- MASTER KEY (SECRET) -----------------
// For now in code as requested. MUST be identical on ESP and Raspberry gateway.
static const uint8_t MASTER_KEY[] = "CHANGE_ME_MASTER_KEY_32+_BYTES_LONG_RANDOM";

// ----------------- helpers -----------------
static bool read_exact(WiFiClient& c, uint8_t* dst, size_t n, uint32_t timeout_ms = 5000) {
  size_t got = 0;
  uint32_t t0 = millis();
  while (got < n && (millis() - t0) < timeout_ms) {
    int a = c.available();
    if (a > 0) {
      int r = c.read(dst + got, (int)min((size_t)a, n - got));
      if (r > 0) got += (size_t)r;
    } else {
      delay(1);
    }
  }
  return got == n;
}

static void print_hex(const char* label, const uint8_t* b, size_t n) {
  Serial.print(label);
  for (size_t i = 0; i < n; i++) {
    if (i) Serial.print(' ');
    Serial.printf("%02X", b[i]);
  }
  Serial.println();
}

static bool hmac_sha256(const uint8_t* key, size_t keylen,
                        const uint8_t* msg, size_t msglen,
                        uint8_t out[32]) {
  const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (!md) return false;
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  if (mbedtls_md_setup(&ctx, md, 1) != 0) { mbedtls_md_free(&ctx); return false; }
  if (mbedtls_md_hmac_starts(&ctx, key, keylen) != 0) { mbedtls_md_free(&ctx); return false; }
  if (mbedtls_md_hmac_update(&ctx, msg, msglen) != 0) { mbedtls_md_free(&ctx); return false; }
  if (mbedtls_md_hmac_finish(&ctx, out) != 0) { mbedtls_md_free(&ctx); return false; }
  mbedtls_md_free(&ctx);
  return true;
}
static bool sha256_many(const uint8_t* const* parts, const size_t* lens, size_t count, uint8_t out[32]) {
  const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (!md) return false;
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  if (mbedtls_md_setup(&ctx, md, 0) != 0) { mbedtls_md_free(&ctx); return false; }
  if (mbedtls_md_starts(&ctx) != 0) { mbedtls_md_free(&ctx); return false; }
  for (size_t i = 0; i < count; i++) {
    if (lens[i] && mbedtls_md_update(&ctx, parts[i], lens[i]) != 0) { mbedtls_md_free(&ctx); return false; }
  }
  if (mbedtls_md_finish(&ctx, out) != 0) { mbedtls_md_free(&ctx); return false; }
  mbedtls_md_free(&ctx);
  return true;
}

/*
 * HKDF-SHA256 via HMAC-SHA256 (Extract+Expand)
 */
static bool hkdf_sha256(const uint8_t* salt, size_t salt_len,
                        const uint8_t* ikm,  size_t ikm_len,
                        const uint8_t* info, size_t info_len,
                        uint8_t* okm, size_t okm_len) {
  const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (!md) return false;

  // Extract: PRK = HMAC(salt, IKM)
  uint8_t prk[32];
  {
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    if (mbedtls_md_setup(&ctx, md, 1) != 0) { mbedtls_md_free(&ctx); return false; }
    if (mbedtls_md_hmac_starts(&ctx, salt, salt_len) != 0) { mbedtls_md_free(&ctx); return false; }
    if (mbedtls_md_hmac_update(&ctx, ikm, ikm_len) != 0) { mbedtls_md_free(&ctx); return false; }
    if (mbedtls_md_hmac_finish(&ctx, prk) != 0) { mbedtls_md_free(&ctx); return false; }
    mbedtls_md_free(&ctx);
  }

  // Expand
  uint8_t t[32];
  size_t t_len = 0;
  uint8_t counter = 1;
  size_t pos = 0;

  while (pos < okm_len) {
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    if (mbedtls_md_setup(&ctx, md, 1) != 0) { mbedtls_md_free(&ctx); return false; }

    if (mbedtls_md_hmac_starts(&ctx, prk, sizeof(prk)) != 0) { mbedtls_md_free(&ctx); return false; }
    if (t_len && mbedtls_md_hmac_update(&ctx, t, t_len) != 0) { mbedtls_md_free(&ctx); return false; }
    if (info_len && mbedtls_md_hmac_update(&ctx, info, info_len) != 0) { mbedtls_md_free(&ctx); return false; }
    if (mbedtls_md_hmac_update(&ctx, &counter, 1) != 0) { mbedtls_md_free(&ctx); return false; }
    if (mbedtls_md_hmac_finish(&ctx, t) != 0) { mbedtls_md_free(&ctx); return false; }
    mbedtls_md_free(&ctx);

    t_len = 32;
    size_t take = min((size_t)32, okm_len - pos);
    memcpy(okm + pos, t, take);
    pos += take;

    counter++;
    if (counter == 0) return false;
  }
  return true;
}
// Derive per-device PSK: PSK_device = HMAC(MASTER_KEY, DEVICE_ID)
static bool derive_psk_device(uint8_t out_psk[32]) {
  return hmac_sha256(MASTER_KEY, strlen((const char*)MASTER_KEY),
                     DEVICE_ID, sizeof(DEVICE_ID),
                     out_psk);
}
// ----------------- Handshake -----------------
static bool tls13_like_kex(uint8_t out_key96[12]) {
  WiFiClient c;
  if (!c.connect(SERVER_IP, PORT)) {
    Serial.println("[HS] TCP connect failed");
    return false;
  }
  // RNG init
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr;
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr);
  const char* pers = "esp32_hs";
  if (mbedtls_ctr_drbg_seed(&ctr, mbedtls_entropy_func, &entropy,
                            (const unsigned char*)pers, strlen(pers)) != 0) {
    Serial.println("[HS] ctr_drbg_seed failed");
    return false;
  }
  // Derive PSK_device
  uint8_t psk_device[32];
  if (!derive_psk_device(psk_device)) {
    Serial.println("[HS] derive_psk_device failed");
    return false;
  }
  // ECDH P-256 ephemeral
  mbedtls_ecdh_context ecdh;
  mbedtls_ecdh_init(&ecdh);
  if (mbedtls_ecp_group_load(&ecdh.grp, MBEDTLS_ECP_DP_SECP256R1) != 0) {
    Serial.println("[HS] group_load failed");
    return false;
  }
  if (mbedtls_ecdh_gen_public(&ecdh.grp, &ecdh.d, &ecdh.Q,
                              mbedtls_ctr_drbg_random, &ctr) != 0) {
    Serial.println("[HS] gen_public failed");
    return false;
  }
  uint8_t pubA[100];
  size_t pubA_len = 0;
  if (mbedtls_ecp_point_write_binary(&ecdh.grp, &ecdh.Q,
                                     MBEDTLS_ECP_PF_UNCOMPRESSED,
                                     &pubA_len, pubA, sizeof(pubA)) != 0) {
    Serial.println("[HS] pubA write failed");
    return false;
  }

  uint8_t client_random[32];
  mbedtls_ctr_drbg_random(&ctr, client_random, sizeof(client_random));
  // ---- Build ClientHello without tag ----
  // type|ver|device_id|client_random|pub_len|pubA
  const size_t ch_wo_tag_len = 1 + 1 + 8 + 32 + 2 + pubA_len;
  uint8_t* ch_wo_tag = (uint8_t*)malloc(ch_wo_tag_len);
  if (!ch_wo_tag) { Serial.println("[HS] malloc ch failed"); return false; }
  size_t off = 0;
  ch_wo_tag[off++] = 0x01;
  ch_wo_tag[off++] = PROTO_VER;
  memcpy(ch_wo_tag + off, DEVICE_ID, 8); off += 8;
  memcpy(ch_wo_tag + off, client_random, 32); off += 32;
  ch_wo_tag[off++] = (uint8_t)(pubA_len >> 8);
  ch_wo_tag[off++] = (uint8_t)(pubA_len & 0xFF);
  memcpy(ch_wo_tag + off, pubA, pubA_len); off += pubA_len;
  // tag = HMAC(PSK_device, ch_wo_tag)
  uint8_t ch_tag[32];
  if (!hmac_sha256(psk_device, sizeof(psk_device), ch_wo_tag, ch_wo_tag_len, ch_tag)) {
    free(ch_wo_tag);
    Serial.println("[HS] HMAC(CH) failed");
    return false;
  }

  // Send ClientHello + tag
  c.write(ch_wo_tag, ch_wo_tag_len);
  c.write(ch_tag, 32);

  // ---- Receive ServerHello ----
  uint8_t sh_type = 0, sh_ver = 0;
  if (!read_exact(c, &sh_type, 1) || sh_type != 0x02) { Serial.println("[HS] bad SH type"); free(ch_wo_tag); return false; }
  if (!read_exact(c, &sh_ver, 1) || sh_ver != PROTO_VER) { Serial.println("[HS] bad SH ver"); free(ch_wo_tag); return false; }

  uint8_t server_random[32];
  if (!read_exact(c, server_random, 32)) { Serial.println("[HS] read server_random failed"); free(ch_wo_tag); return false; }

  uint8_t sh_len2[2];
  if (!read_exact(c, sh_len2, 2)) { Serial.println("[HS] read pub len failed"); free(ch_wo_tag); return false; }
  uint16_t pubB_len = ((uint16_t)sh_len2[0] << 8) | sh_len2[1];
  if (pubB_len > 100) { Serial.println("[HS] pubB too long"); free(ch_wo_tag); return false; }

  uint8_t pubB[100];
  if (!read_exact(c, pubB, pubB_len)) { Serial.println("[HS] read pubB failed"); free(ch_wo_tag); return false; }

  uint8_t sh_tag[32];
  if (!read_exact(c, sh_tag, 32)) { Serial.println("[HS] read SH tag failed"); free(ch_wo_tag); return false; }

  // Rebuild ServerHello without tag for verification
  const size_t sh_wo_tag_len = 1 + 1 + 32 + 2 + pubB_len;
  uint8_t* sh_wo_tag = (uint8_t*)malloc(sh_wo_tag_len);
  if (!sh_wo_tag) { free(ch_wo_tag); Serial.println("[HS] malloc sh failed"); return false; }

  off = 0;
  sh_wo_tag[off++] = 0x02;
  sh_wo_tag[off++] = PROTO_VER;
  memcpy(sh_wo_tag + off, server_random, 32); off += 32;
  sh_wo_tag[off++] = (uint8_t)(pubB_len >> 8);
  sh_wo_tag[off++] = (uint8_t)(pubB_len & 0xFF);
  memcpy(sh_wo_tag + off, pubB, pubB_len); off += pubB_len;

  // Expected SH tag = HMAC(PSK_device, CH_wo_tag || SH_wo_tag)
  uint8_t expected_sh_tag[32];
  {
    const uint8_t* parts[] = { ch_wo_tag, sh_wo_tag };
    const size_t   lens[]  = { ch_wo_tag_len, sh_wo_tag_len };
    // compute HMAC over concatenation (do in one buffer for simplicity)
    size_t cat_len = ch_wo_tag_len + sh_wo_tag_len;
    uint8_t* cat = (uint8_t*)malloc(cat_len);
    if (!cat) { free(ch_wo_tag); free(sh_wo_tag); Serial.println("[HS] malloc cat failed"); return false; }
    memcpy(cat, ch_wo_tag, ch_wo_tag_len);
    memcpy(cat + ch_wo_tag_len, sh_wo_tag, sh_wo_tag_len);
    bool ok = hmac_sha256(psk_device, sizeof(psk_device), cat, cat_len, expected_sh_tag);
    free(cat);
    if (!ok) { free(ch_wo_tag); free(sh_wo_tag); Serial.println("[HS] HMAC(SH) compute failed"); return false; }
  }

  if (memcmp(expected_sh_tag, sh_tag, 32) != 0) {
    free(ch_wo_tag); free(sh_wo_tag);
    Serial.println("[HS] ServerHello auth FAILED (wrong master_key/device_id or MITM)");
    return false;
  }

  // Transcript hash TH = SHA256(CH_wo_tag || SH_wo_tag)
  uint8_t th[32];
  {
    const uint8_t* parts[] = { ch_wo_tag, sh_wo_tag };
    const size_t   lens[]  = { ch_wo_tag_len, sh_wo_tag_len };
    if (!sha256_many(parts, lens, 2, th)) {
      free(ch_wo_tag); free(sh_wo_tag);
      Serial.println("[HS] transcript sha256 failed");
      return false;
    }
  }

  // Parse peer pubB
  if (mbedtls_ecp_point_read_binary(&ecdh.grp, &ecdh.Qp, pubB, pubB_len) != 0) {
    free(ch_wo_tag); free(sh_wo_tag);
    Serial.println("[HS] peer pub parse failed");
    return false;
  }

  // Compute shared secret
  if (mbedtls_ecdh_compute_shared(&ecdh.grp, &ecdh.z, &ecdh.Qp, &ecdh.d,
                                  mbedtls_ctr_drbg_random, &ctr) != 0) {
    free(ch_wo_tag); free(sh_wo_tag);
    Serial.println("[HS] compute_shared failed");
    return false;
  }
  uint8_t shared[32];
  if (mbedtls_mpi_write_binary(&ecdh.z, shared, sizeof(shared)) != 0) {
    free(ch_wo_tag); free(sh_wo_tag);
    Serial.println("[HS] export shared failed");
    return false;
  }

  // salt = SHA256(client_random || server_random)
  uint8_t salt[32];
  {
    const uint8_t* parts[] = { client_random, server_random };
    const size_t   lens[]  = { 32, 32 };
    if (!sha256_many(parts, lens, 2, salt)) {
      free(ch_wo_tag); free(sh_wo_tag);
      Serial.println("[HS] salt sha256 failed");
      return false;
    }
  }

  // info = "session-v1" || TH
  uint8_t info[32 + 10];
  memcpy(info, "session-v1", 10);
  memcpy(info + 10, th, 32);

  // OKM 76 bytes = srv_finished_key(32) + cli_finished_key(32) + key96(12)
  uint8_t okm[76];
  if (!hkdf_sha256(salt, sizeof(salt), shared, sizeof(shared), info, sizeof(info), okm, sizeof(okm))) {
    free(ch_wo_tag); free(sh_wo_tag);
    Serial.println("[HS] hkdf failed");
    return false;
  }
  const uint8_t* srv_finished_key = okm + 0;
  const uint8_t* cli_finished_key = okm + 32;
  memcpy(out_key96, okm + 64, 12);

  // ---- Receive ServerFinished ----
  uint8_t sf_type;
  if (!read_exact(c, &sf_type, 1) || sf_type != 0x03) {
    free(ch_wo_tag); free(sh_wo_tag);
    Serial.println("[HS] bad ServerFinished type");
    return false;
  }
  uint8_t sf_verify[32];
  if (!read_exact(c, sf_verify, 32)) {
    free(ch_wo_tag); free(sh_wo_tag);
    Serial.println("[HS] read ServerFinished verify failed");
    return false;
  }
  uint8_t exp_sf[32];
  if (!hmac_sha256(srv_finished_key, 32, th, 32, exp_sf) || memcmp(exp_sf, sf_verify, 32) != 0) {
    free(ch_wo_tag); free(sh_wo_tag);
    Serial.println("[HS] ServerFinished verify FAILED");
    return false;
  }

  // ---- Send ClientFinished ----
  uint8_t cf[1 + 32];
  cf[0] = 0x04;
  if (!hmac_sha256(cli_finished_key, 32, th, 32, cf + 1)) {
    free(ch_wo_tag); free(sh_wo_tag);
    Serial.println("[HS] ClientFinished HMAC failed");
    return false;
  }
  c.write(cf, sizeof(cf));

  // Debug prints
  Serial.println("[HS] OK");
  print_hex("[HS] device_id:", DEVICE_ID, 8);
  print_hex("[HS] client_random:", client_random, 32);
  print_hex("[HS] server_random:", server_random, 32);
  print_hex("[HS] transcript_hash:", th, 32);
  print_hex("[HS] KEY96:", out_key96, 12);

  // cleanup
  free(ch_wo_tag);
  free(sh_wo_tag);
  c.stop();
  mbedtls_ecdh_free(&ecdh);
  mbedtls_ctr_drbg_free(&ctr);
  mbedtls_entropy_free(&entropy);
  return true;
}

// ----------------- Arduino entry -----------------
void setup() {

}

void loop() {
  Serial.begin(115200);
  delay(500);

  Serial.printf("Connecting Wi-Fi: %s\n", SSID);
  WiFi.begin(SSID, PASS);
  while (WiFi.status() != WL_CONNECTED) { Serial.print("."); delay(300); }
  Serial.println("\nWi-Fi OK");
  Serial.print("IP: "); Serial.println(WiFi.localIP());
  pinMode(2, INPUT);
  while (digitalRead(2) == LOW) { delay(1); }
  uint8_t key96[12];
  const size_t count = 200;
  uint32_t sred = 0;
  for (size_t i = 0; i < count; i++)
  {
  uint32_t start_time = millis();
  bool ok = tls13_like_kex(key96);
  uint32_t end_time = millis();
  uint32_t duration_ms = end_time - start_time;
  if (!ok) {
    Serial.println("[HS] FAILED");
    Serial.printf("[HS] Duration: %u ms\n", duration_ms);
  } else {
    Serial.println("[HS] DONE");
    Serial.printf("[HS] Duration: %u ms\n", duration_ms);
    sred += duration_ms;
  }
  }
  Serial.printf("[HS] Average Duration: %u ms\n", sred);
  Serial.printf("[HS] Average Duration: %u ms\n", sred / count);
}
