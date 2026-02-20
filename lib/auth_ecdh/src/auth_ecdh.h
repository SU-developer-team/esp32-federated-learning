#pragma once

#include <stddef.h>
#include <stdint.h>

class WiFiClient;

typedef enum AuthEcdhError {
  AUTH_ECDH_OK = 0,
  AUTH_ECDH_ERR_BAD_ARGS,
  AUTH_ECDH_ERR_RNG_INIT,
  AUTH_ECDH_ERR_TCP_CONNECT,
  AUTH_ECDH_ERR_PSK_DERIVE,
  AUTH_ECDH_ERR_ECP_GROUP,
  AUTH_ECDH_ERR_ECP_KEYGEN,
  AUTH_ECDH_ERR_PUB_WRITE,
  AUTH_ECDH_ERR_IO_SEND_CH,
  AUTH_ECDH_ERR_IO_READ_SH,
  AUTH_ECDH_ERR_SH_HMAC,
  AUTH_ECDH_ERR_SH_AUTH,
  AUTH_ECDH_ERR_TRANSCRIPT,
  AUTH_ECDH_ERR_PEER_PUB,
  AUTH_ECDH_ERR_SHARED,
  AUTH_ECDH_ERR_SHARED_EXPORT,
  AUTH_ECDH_ERR_SALT,
  AUTH_ECDH_ERR_HKDF,
  AUTH_ECDH_ERR_IO_READ_SF,
  AUTH_ECDH_ERR_SF_VERIFY,
  AUTH_ECDH_ERR_CF_HMAC,
  AUTH_ECDH_ERR_IO_SEND_CF
} AuthEcdhError;

typedef struct AuthEcdhConfig {
  const char* server_ip;
  uint16_t port;
  const uint8_t* master_key;
  size_t master_key_len;
  uint32_t io_timeout_ms;
  const uint8_t* device_id;
  // Optional: if set, must be connected; handshake will not connect/stop it.
  WiFiClient* client;
} AuthEcdhConfig;

AuthEcdhError auth_ecdh_handshake(const AuthEcdhConfig* cfg,
                                  uint8_t out_key96[12],
                                  uint8_t out_device_id[8]);

const char* auth_ecdh_error_str(AuthEcdhError err);
