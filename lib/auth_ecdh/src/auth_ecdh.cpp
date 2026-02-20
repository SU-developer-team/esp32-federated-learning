#include <Arduino.h>
#include <WiFi.h>
#include <string.h>

#include "auth_ecdh.h"

#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/md.h"
#include "mbedtls/bignum.h"

#ifndef AUTH_ECDH_ENABLE_LOGS
#define AUTH_ECDH_ENABLE_LOGS 1
#endif

#if AUTH_ECDH_ENABLE_LOGS
#define AUTH_ECDH_LOG(msg) Serial.println(msg)
#define AUTH_ECDH_LOGF(...) Serial.printf(__VA_ARGS__)
#else
#define AUTH_ECDH_LOG(msg) do {} while (0)
#define AUTH_ECDH_LOGF(...) do {} while (0)
#endif

// ----------------- Protocol -----------------
static const uint8_t PROTO_VER = 0x01;

// ----------------- Device identity -----------------
// Fallback static ID (used only if efuse MAC cannot be read).
static const uint8_t DEVICE_ID_FALLBACK[8] = { 0x00,0x0A, 0x00,0x03, 0x00,0x01,0x2F, 0x02 };

// ----------------- Sizes -----------------
constexpr size_t PUB_KEY_LEN   = 65;   // 0x04 + 32x + 32y
constexpr size_t CH_WO_TAG_LEN = 1 + 1 + 8 + 32 + 2 + PUB_KEY_LEN;  // 109
constexpr size_t SH_WO_TAG_LEN = 1 + 1 + 32 + 2 + PUB_KEY_LEN;      // 101
constexpr size_t INFO_LEN      = 10 + 32;                           // "session-v1" + TH
constexpr size_t OKM_LEN       = 76;
constexpr uint32_t DEFAULT_TIMEOUT_MS = 5000;

// ----------------- RNG -----------------
static mbedtls_entropy_context g_entropy;
static mbedtls_ctr_drbg_context g_ctr;
static bool g_rng_ready = false;

static bool rng_init_once() {
  if (g_rng_ready) return true;
  mbedtls_entropy_init(&g_entropy);
  mbedtls_ctr_drbg_init(&g_ctr);
  const char* pers = "esp32_hs";
  int rc = mbedtls_ctr_drbg_seed(&g_ctr, mbedtls_entropy_func, &g_entropy,
                                 (const unsigned char*)pers, strlen(pers));
  g_rng_ready = (rc == 0);
  return g_rng_ready;
}

// ----------------- Helpers -----------------
static const mbedtls_md_info_t* sha256_md_info() {
  static const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  return md;
}

static bool read_exact(WiFiClient& c, uint8_t* dst, size_t n, uint32_t timeout_ms) {
  size_t got = 0;
  uint32_t t0 = millis();
  while (got < n && (millis() - t0) < timeout_ms) {
    int a = c.available();
    if (a > 0) {
      int r = c.read(dst + got, (int)min((size_t)a, n - got));
      if (r > 0) got += (size_t)r;
    } else {
      yield();
    }
  }
  return got == n;
}

static void print_hex(const char* label, const uint8_t* b, size_t n) {
#if AUTH_ECDH_ENABLE_LOGS
  Serial.print(label);
  for (size_t i = 0; i < n; i++) {
    if (i) Serial.print(' ');
    Serial.printf("%02X", b[i]);
  }
  Serial.println();
#else
  (void)label;
  (void)b;
  (void)n;
#endif
}

static bool hmac_sha256(const uint8_t* key, size_t keylen,
                        const uint8_t* msg, size_t msglen,
                        uint8_t out[32]) {
  const mbedtls_md_info_t* md = sha256_md_info();
  if (!md) return false;

  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  if (mbedtls_md_setup(&ctx, md, 1) != 0) goto err;
  if (mbedtls_md_hmac_starts(&ctx, key, keylen) != 0) goto err;
  if (mbedtls_md_hmac_update(&ctx, msg, msglen) != 0) goto err;
  if (mbedtls_md_hmac_finish(&ctx, out) != 0) goto err;
  mbedtls_md_free(&ctx);
  return true;
err:
  mbedtls_md_free(&ctx);
  return false;
}

// ----------------- HKDF-SHA256 (manual implementation) -----------------
static bool hkdf_sha256(const uint8_t* salt, size_t salt_len,
                        const uint8_t* ikm, size_t ikm_len,
                        const uint8_t* info, size_t info_len,
                        uint8_t* okm, size_t okm_len) {
  const mbedtls_md_info_t* md = sha256_md_info();
  if (!md) return false;

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

static void fill_device_id(uint8_t out[8], const uint8_t* override_id) {
  if (override_id) {
    memcpy(out, override_id, 8);
    return;
  }

  uint64_t mac = ESP.getEfuseMac();
  if (mac == 0) {
    memcpy(out, DEVICE_ID_FALLBACK, 8);
    return;
  }
  out[0] = (uint8_t)((mac >> 56) & 0xFF);
  out[1] = (uint8_t)((mac >> 48) & 0xFF);
  out[2] = (uint8_t)((mac >> 40) & 0xFF);
  out[3] = (uint8_t)((mac >> 32) & 0xFF);
  out[4] = (uint8_t)((mac >> 24) & 0xFF);
  out[5] = (uint8_t)((mac >> 16) & 0xFF);
  out[6] = (uint8_t)((mac >> 8)  & 0xFF);
  out[7] = (uint8_t)((mac >> 0)  & 0xFF);
}

static bool derive_psk_device(const uint8_t* master_key, size_t master_key_len,
                              const uint8_t device_id[8], uint8_t out_psk[32]) {
  return hmac_sha256(master_key, master_key_len, device_id, 8, out_psk);
}

// ----------------- Handshake -----------------
AuthEcdhError auth_ecdh_handshake(const AuthEcdhConfig* cfg,
                                  uint8_t out_key96[12],
                                  uint8_t out_device_id[8]) {
  if (!cfg || !cfg->master_key || cfg->master_key_len == 0 || !out_key96) {
    return AUTH_ECDH_ERR_BAD_ARGS;
  }
  if (!cfg->client && (!cfg->server_ip || cfg->port == 0)) {
    return AUTH_ECDH_ERR_BAD_ARGS;
  }

  if (!rng_init_once()) {
    AUTH_ECDH_LOG("[HS] RNG init failed");
    return AUTH_ECDH_ERR_RNG_INIT;
  }

  const uint32_t timeout_ms = (cfg->io_timeout_ms == 0) ? DEFAULT_TIMEOUT_MS : cfg->io_timeout_ms;
  AuthEcdhError err = AUTH_ECDH_OK;

  WiFiClient local_client;
  WiFiClient* c = cfg->client ? cfg->client : &local_client;
  mbedtls_ecdh_context ecdh;
  mbedtls_ecdh_init(&ecdh);

  uint8_t psk_device[32];
  uint8_t device_id[8];
  uint8_t pubA[PUB_KEY_LEN];
  size_t pubA_len = 0;
  uint8_t client_random[32];
  uint8_t ch_wo_tag[CH_WO_TAG_LEN];
  uint8_t ch_tag[32];
  uint8_t sh_type = 0, sh_ver = 0;
  uint8_t server_random[32];
  uint8_t sh_len2[2];
  uint16_t pubB_len = 0;
  uint8_t pubB[PUB_KEY_LEN];
  uint8_t sh_tag[32];
  uint8_t sh_wo_tag[SH_WO_TAG_LEN];
  uint8_t expected_sh_tag[32];
  uint8_t th[32];
  uint8_t shared[32];
  uint8_t salt[32];
  uint8_t info[INFO_LEN];
  uint8_t okm[OKM_LEN];
  const uint8_t* srv_finished_key = nullptr;
  const uint8_t* cli_finished_key = nullptr;
  uint8_t sf_type = 0;
  uint8_t sf_verify[32];
  uint8_t exp_sf[32];
  uint8_t cf[33];

  if (!cfg->client) {
    if (!c->connect(cfg->server_ip, cfg->port)) {
      AUTH_ECDH_LOG("[HS] TCP connect failed");
      err = AUTH_ECDH_ERR_TCP_CONNECT;
      goto cleanup;
    }
  } else if (!c->connected()) {
    AUTH_ECDH_LOG("[HS] TCP not connected");
    err = AUTH_ECDH_ERR_TCP_CONNECT;
    goto cleanup;
  }

  fill_device_id(device_id, cfg->device_id);
  if (out_device_id) memcpy(out_device_id, device_id, 8);

  if (!derive_psk_device(cfg->master_key, cfg->master_key_len, device_id, psk_device)) {
    AUTH_ECDH_LOG("[HS] derive_psk_device failed");
    err = AUTH_ECDH_ERR_PSK_DERIVE;
    goto cleanup;
  }

  if (mbedtls_ecp_group_load(&ecdh.grp, MBEDTLS_ECP_DP_SECP256R1) != 0) {
    AUTH_ECDH_LOG("[HS] group_load failed");
    err = AUTH_ECDH_ERR_ECP_GROUP;
    goto cleanup;
  }
  if (mbedtls_ecdh_gen_public(&ecdh.grp, &ecdh.d, &ecdh.Q,
                              mbedtls_ctr_drbg_random, &g_ctr) != 0) {
    AUTH_ECDH_LOG("[HS] gen_public failed");
    err = AUTH_ECDH_ERR_ECP_KEYGEN;
    goto cleanup;
  }

  if (mbedtls_ecp_point_write_binary(&ecdh.grp, &ecdh.Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                     &pubA_len, pubA, sizeof(pubA)) != 0 ||
      pubA_len != PUB_KEY_LEN) {
    AUTH_ECDH_LOG("[HS] pubA write failed");
    err = AUTH_ECDH_ERR_PUB_WRITE;
    goto cleanup;
  }

  mbedtls_ctr_drbg_random(&g_ctr, client_random, sizeof(client_random));

  // ClientHello
  ch_wo_tag[0] = 0x01;
  ch_wo_tag[1] = PROTO_VER;
  memcpy(&ch_wo_tag[2], device_id, 8);
  memcpy(&ch_wo_tag[10], client_random, 32);
  ch_wo_tag[42] = (uint8_t)(pubA_len >> 8);
  ch_wo_tag[43] = (uint8_t)(pubA_len & 0xFF);
  memcpy(&ch_wo_tag[44], pubA, pubA_len);

  if (!hmac_sha256(psk_device, sizeof(psk_device), ch_wo_tag, CH_WO_TAG_LEN, ch_tag)) {
    AUTH_ECDH_LOG("[HS] HMAC(CH) failed");
    err = AUTH_ECDH_ERR_SH_HMAC;
    goto cleanup;
  }

  if (c->write(ch_wo_tag, CH_WO_TAG_LEN) != CH_WO_TAG_LEN ||
      c->write(ch_tag, 32) != 32) {
    AUTH_ECDH_LOG("[HS] send ClientHello failed");
    err = AUTH_ECDH_ERR_IO_SEND_CH;
    goto cleanup;
  }

  // ServerHello
  if (!read_exact(*c, &sh_type, 1, timeout_ms) || sh_type != 0x02) {
    AUTH_ECDH_LOG("[HS] bad SH type");
    err = AUTH_ECDH_ERR_IO_READ_SH;
    goto cleanup;
  }
  if (!read_exact(*c, &sh_ver, 1, timeout_ms) || sh_ver != PROTO_VER) {
    AUTH_ECDH_LOG("[HS] bad SH ver");
    err = AUTH_ECDH_ERR_IO_READ_SH;
    goto cleanup;
  }

  if (!read_exact(*c, server_random, 32, timeout_ms)) {
    AUTH_ECDH_LOG("[HS] read server_random failed");
    err = AUTH_ECDH_ERR_IO_READ_SH;
    goto cleanup;
  }

  if (!read_exact(*c, sh_len2, 2, timeout_ms)) {
    AUTH_ECDH_LOG("[HS] read pub len failed");
    err = AUTH_ECDH_ERR_IO_READ_SH;
    goto cleanup;
  }
  pubB_len = ((uint16_t)sh_len2[0] << 8) | sh_len2[1];
  if (pubB_len != PUB_KEY_LEN) {
    AUTH_ECDH_LOG("[HS] pubB len mismatch");
    err = AUTH_ECDH_ERR_IO_READ_SH;
    goto cleanup;
  }

  if (!read_exact(*c, pubB, PUB_KEY_LEN, timeout_ms)) {
    AUTH_ECDH_LOG("[HS] read pubB failed");
    err = AUTH_ECDH_ERR_IO_READ_SH;
    goto cleanup;
  }

  if (!read_exact(*c, sh_tag, 32, timeout_ms)) {
    AUTH_ECDH_LOG("[HS] read SH tag failed");
    err = AUTH_ECDH_ERR_IO_READ_SH;
    goto cleanup;
  }

  // ServerHello without tag
  sh_wo_tag[0] = 0x02;
  sh_wo_tag[1] = PROTO_VER;
  memcpy(&sh_wo_tag[2], server_random, 32);
  sh_wo_tag[34] = (uint8_t)(pubB_len >> 8);
  sh_wo_tag[35] = (uint8_t)(pubB_len & 0xFF);
  memcpy(&sh_wo_tag[36], pubB, pubB_len);

  // SH tag verification (HMAC over CH || SH)
  {
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    if (mbedtls_md_setup(&ctx, sha256_md_info(), 1) != 0) {
      mbedtls_md_free(&ctx);
      err = AUTH_ECDH_ERR_SH_HMAC;
      goto cleanup;
    }
    if (mbedtls_md_hmac_starts(&ctx, psk_device, sizeof(psk_device)) != 0) goto cleanup_hmac;
    if (mbedtls_md_hmac_update(&ctx, ch_wo_tag, CH_WO_TAG_LEN) != 0) goto cleanup_hmac;
    if (mbedtls_md_hmac_update(&ctx, sh_wo_tag, SH_WO_TAG_LEN) != 0) goto cleanup_hmac;
    if (mbedtls_md_hmac_finish(&ctx, expected_sh_tag) != 0) goto cleanup_hmac;
    mbedtls_md_free(&ctx);
    goto hmac_done;
  cleanup_hmac:
    mbedtls_md_free(&ctx);
    AUTH_ECDH_LOG("[HS] HMAC(SH) compute failed");
    err = AUTH_ECDH_ERR_SH_HMAC;
    goto cleanup;
  }
hmac_done:

  if (memcmp(expected_sh_tag, sh_tag, 32) != 0) {
    AUTH_ECDH_LOG("[HS] ServerHello auth FAILED");
    err = AUTH_ECDH_ERR_SH_AUTH;
    goto cleanup;
  }

  // Transcript hash
  {
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    if (mbedtls_md_setup(&ctx, sha256_md_info(), 0) != 0) goto cleanup;
    if (mbedtls_md_starts(&ctx) != 0) goto cleanup_th;
    if (mbedtls_md_update(&ctx, ch_wo_tag, CH_WO_TAG_LEN) != 0) goto cleanup_th;
    if (mbedtls_md_update(&ctx, sh_wo_tag, SH_WO_TAG_LEN) != 0) goto cleanup_th;
    if (mbedtls_md_finish(&ctx, th) != 0) goto cleanup_th;
    mbedtls_md_free(&ctx);
    goto th_done;
  cleanup_th:
    mbedtls_md_free(&ctx);
    AUTH_ECDH_LOG("[HS] transcript sha256 failed");
    err = AUTH_ECDH_ERR_TRANSCRIPT;
    goto cleanup;
  }
th_done:

  if (mbedtls_ecp_point_read_binary(&ecdh.grp, &ecdh.Qp, pubB, PUB_KEY_LEN) != 0) {
    AUTH_ECDH_LOG("[HS] peer pub parse failed");
    err = AUTH_ECDH_ERR_PEER_PUB;
    goto cleanup;
  }

  if (mbedtls_ecdh_compute_shared(&ecdh.grp, &ecdh.z, &ecdh.Qp, &ecdh.d,
                                  mbedtls_ctr_drbg_random, &g_ctr) != 0) {
    AUTH_ECDH_LOG("[HS] compute_shared failed");
    err = AUTH_ECDH_ERR_SHARED;
    goto cleanup;
  }
  if (mbedtls_mpi_write_binary(&ecdh.z, shared, sizeof(shared)) != 0) {
    AUTH_ECDH_LOG("[HS] export shared failed");
    err = AUTH_ECDH_ERR_SHARED_EXPORT;
    goto cleanup;
  }

  // salt = SHA256(client_random || server_random)
  {
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    if (mbedtls_md_setup(&ctx, sha256_md_info(), 0) != 0) goto cleanup;
    if (mbedtls_md_starts(&ctx) != 0) goto cleanup_salt;
    if (mbedtls_md_update(&ctx, client_random, 32) != 0) goto cleanup_salt;
    if (mbedtls_md_update(&ctx, server_random, 32) != 0) goto cleanup_salt;
    if (mbedtls_md_finish(&ctx, salt) != 0) goto cleanup_salt;
    mbedtls_md_free(&ctx);
    goto salt_done;
  cleanup_salt:
    mbedtls_md_free(&ctx);
    AUTH_ECDH_LOG("[HS] salt sha256 failed");
    err = AUTH_ECDH_ERR_SALT;
    goto cleanup;
  }
salt_done:

  memcpy(info, "session-v1", 10);
  memcpy(info + 10, th, 32);

  if (!hkdf_sha256(salt, sizeof(salt), shared, sizeof(shared), info, INFO_LEN, okm, OKM_LEN)) {
    AUTH_ECDH_LOG("[HS] hkdf failed");
    err = AUTH_ECDH_ERR_HKDF;
    goto cleanup;
  }

  srv_finished_key = okm;
  cli_finished_key = okm + 32;
  memcpy(out_key96, okm + 64, 12);

  // ServerFinished
  if (!read_exact(*c, &sf_type, 1, timeout_ms) || sf_type != 0x03) {
    AUTH_ECDH_LOG("[HS] bad ServerFinished type");
    err = AUTH_ECDH_ERR_IO_READ_SF;
    goto cleanup;
  }
  if (!read_exact(*c, sf_verify, 32, timeout_ms)) {
    AUTH_ECDH_LOG("[HS] read ServerFinished verify failed");
    err = AUTH_ECDH_ERR_IO_READ_SF;
    goto cleanup;
  }
  if (!hmac_sha256(srv_finished_key, 32, th, 32, exp_sf) ||
      memcmp(exp_sf, sf_verify, 32) != 0) {
    AUTH_ECDH_LOG("[HS] ServerFinished verify FAILED");
    err = AUTH_ECDH_ERR_SF_VERIFY;
    goto cleanup;
  }

  // ClientFinished
  cf[0] = 0x04;
  if (!hmac_sha256(cli_finished_key, 32, th, 32, cf + 1)) {
    AUTH_ECDH_LOG("[HS] ClientFinished HMAC failed");
    err = AUTH_ECDH_ERR_CF_HMAC;
    goto cleanup;
  }
  if (c->write(cf, sizeof(cf)) != sizeof(cf)) {
    AUTH_ECDH_LOG("[HS] send ClientFinished failed");
    err = AUTH_ECDH_ERR_IO_SEND_CF;
    goto cleanup;
  }

  AUTH_ECDH_LOG("[HS] OK");
  print_hex("[HS] device_id:", device_id, 8);
  print_hex("[HS] client_random:", client_random, 32);
  print_hex("[HS] server_random:", server_random, 32);
  print_hex("[HS] transcript_hash:", th, 32);
  print_hex("[HS] KEY96:", out_key96, 12);

cleanup:
  if (!cfg->client) {
    c->stop();
  }
  mbedtls_ecdh_free(&ecdh);
  return err;
}

const char* auth_ecdh_error_str(AuthEcdhError err) {
  switch (err) {
    case AUTH_ECDH_OK: return "OK";
    case AUTH_ECDH_ERR_BAD_ARGS: return "bad args";
    case AUTH_ECDH_ERR_RNG_INIT: return "rng init failed";
    case AUTH_ECDH_ERR_TCP_CONNECT: return "tcp connect failed";
    case AUTH_ECDH_ERR_PSK_DERIVE: return "psk derive failed";
    case AUTH_ECDH_ERR_ECP_GROUP: return "ecp group load failed";
    case AUTH_ECDH_ERR_ECP_KEYGEN: return "ecdh keygen failed";
    case AUTH_ECDH_ERR_PUB_WRITE: return "public key write failed";
    case AUTH_ECDH_ERR_IO_SEND_CH: return "send ClientHello failed";
    case AUTH_ECDH_ERR_IO_READ_SH: return "read ServerHello failed";
    case AUTH_ECDH_ERR_SH_HMAC: return "ServerHello HMAC failed";
    case AUTH_ECDH_ERR_SH_AUTH: return "ServerHello auth failed";
    case AUTH_ECDH_ERR_TRANSCRIPT: return "transcript hash failed";
    case AUTH_ECDH_ERR_PEER_PUB: return "peer public key parse failed";
    case AUTH_ECDH_ERR_SHARED: return "shared secret failed";
    case AUTH_ECDH_ERR_SHARED_EXPORT: return "shared secret export failed";
    case AUTH_ECDH_ERR_SALT: return "salt hash failed";
    case AUTH_ECDH_ERR_HKDF: return "hkdf failed";
    case AUTH_ECDH_ERR_IO_READ_SF: return "read ServerFinished failed";
    case AUTH_ECDH_ERR_SF_VERIFY: return "ServerFinished verify failed";
    case AUTH_ECDH_ERR_CF_HMAC: return "ClientFinished HMAC failed";
    case AUTH_ECDH_ERR_IO_SEND_CF: return "send ClientFinished failed";
    default: return "unknown error";
  }
}
