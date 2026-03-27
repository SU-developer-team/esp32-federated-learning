#!/usr/bin/env python3
# Minimal RLHABC aggregation server (double each block: C + C)

from __future__ import annotations

import os
import socket
import struct
import threading
import time
import numpy as np
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ---------------- Network / Protocol ----------------
HOST = "0.0.0.0"
PORT = 1883
PROTO_VER = 0x01

MSG_CLIENT_HELLO     = 0x01
MSG_SERVER_HELLO     = 0x02
MSG_SERVER_FINISHED  = 0x03
MSG_CLIENT_FINISHED  = 0x04

MSG_APP_DATA         = 0x20   # [0x20][len:u32 BE][hdr][ciphertext][mac]
MSG_APP_STATS        = 0x21   # [0x21][len:u32 BE][hdr][stats][mac]

NORMAL_TIMEOUT_S = 2000000000.0

# MUST match ESP32
MASTER_KEY = bytes([
    0x72, 0x13, 0x25, 0x4B, 0x46, 0x7B, 0x23, 0x18,
    0xE1, 0xE7, 0x25, 0x3F, 0x3B, 0x8B, 0x02, 0xAE,
    0xC5, 0x56, 0xFF, 0x9D, 0xAC, 0xBB, 0x73, 0x96,
    0x30, 0xE7, 0x5C, 0x66, 0x7B, 0x1F, 0x32, 0x24
])

# ---------------- RLHABC ----------------
RLHABC_N = 65537 * 65521
RLHABC_BLOCK_BYTES = 9 * 4  # 9 x u32 (big-endian)
APP_HDR_LEN = 8 + 4 + 4     # device_id(8) + seq(u32) + block_count(u32)
APP_MAC_LEN = 32

# ---------------- Logging ----------------
LOG_ROOT = Path("log_homofrov")

def _now_ts() -> str:
    return time.strftime("%Y%m%d_%H%M%S")

def _save_payload_txt(device_id_hex: str, payload: bytes):
    LOG_ROOT.mkdir(parents=True, exist_ok=True)
    name = f"rx_{device_id_hex}_{_now_ts()}_{len(payload)}.txt"
    # store hex for reliable text output
    text = payload.hex()
    (LOG_ROOT / name).write_text(text, encoding="utf-8")

def _save_stats_txt(device_id_hex: str, stats: str):
    LOG_ROOT.mkdir(parents=True, exist_ok=True)
    name = f"stats_{device_id_hex}_{_now_ts()}.txt"
    (LOG_ROOT / name).write_text(stats, encoding="utf-8")

# -------------------------------------------------
# Low-level helpers
# -------------------------------------------------
def recv_exact(conn: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Disconnected")
        data += chunk
    return data

def sha256_bytes(*parts: bytes) -> bytes:
    d = hashes.Hash(hashes.SHA256())
    for p in parts:
        d.update(p)
    return d.finalize()

def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    h_ = hmac.HMAC(key, hashes.SHA256())
    h_.update(msg)
    return h_.finalize()

def derive_psk_device(device_id: bytes) -> bytes:
    return hmac_sha256(MASTER_KEY, device_id)

def hkdf_session(shared: bytes, client_random: bytes, server_random: bytes, transcript_hash: bytes) -> bytes:
    salt = sha256_bytes(client_random, server_random)
    info = b"session-v1" + transcript_hash
    return HKDF(
        algorithm=hashes.SHA256(),
        length=76,
        salt=salt,
        info=info,
    ).derive(shared)

# -------------------------------------------------
# Framing helpers
# -------------------------------------------------
def recv_frame(conn: socket.socket):
    t = recv_exact(conn, 1)[0]
    if t in (MSG_APP_DATA, MSG_APP_STATS):
        ln = struct.unpack(">I", recv_exact(conn, 4))[0]
        if ln > 50_000_000:
            raise RuntimeError(f"Too large frame: {ln}")
        payload = recv_exact(conn, ln) if ln > 0 else b""
        return t, payload
    return t, None

def send_app_data(conn: socket.socket, payload: bytes):
    conn.sendall(bytes([MSG_APP_DATA]) + struct.pack(">I", len(payload)) + payload)

# -------------------------------------------------
# Handshake (auth_ecdh compatible)
# -------------------------------------------------
def do_handshake(conn: socket.socket):
    t = recv_exact(conn, 1)[0]
    if t != MSG_CLIENT_HELLO:
        raise RuntimeError(f"Bad ClientHello type: 0x{t:02x}")
    ver = recv_exact(conn, 1)[0]
    if ver != PROTO_VER:
        raise RuntimeError("Bad CH version")
    device_id = recv_exact(conn, 8)
    client_random = recv_exact(conn, 32)
    pub_len = struct.unpack(">H", recv_exact(conn, 2))[0]
    pubA = recv_exact(conn, pub_len)
    ch_tag = recv_exact(conn, 32)

    ch_wo_tag = (
        bytes([MSG_CLIENT_HELLO]) +
        bytes([PROTO_VER]) +
        device_id +
        client_random +
        struct.pack(">H", pub_len) +
        pubA
    )

    psk_device = derive_psk_device(device_id)
    exp_ch_tag = hmac_sha256(psk_device, ch_wo_tag)
    if exp_ch_tag != ch_tag:
        raise RuntimeError("ClientHello auth FAILED")

    server_random = os.urandom(32)
    srv_priv = ec.generate_private_key(ec.SECP256R1())
    pubB = srv_priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    pubB_len = len(pubB)

    sh_wo_tag = (
        bytes([MSG_SERVER_HELLO]) +
        bytes([PROTO_VER]) +
        server_random +
        struct.pack(">H", pubB_len) +
        pubB
    )

    sh_tag = hmac_sha256(psk_device, ch_wo_tag + sh_wo_tag)
    th = sha256_bytes(ch_wo_tag, sh_wo_tag)

    cli_pub_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pubA)
    shared = srv_priv.exchange(ec.ECDH(), cli_pub_key)

    okm = hkdf_session(shared, client_random, server_random, th)
    srv_finished_key = okm[0:32]
    cli_finished_key = okm[32:64]
    key96 = okm[64:76]
    mac_key = sha256_bytes(key96, b"mac")

    conn.sendall(sh_wo_tag + sh_tag)
    sf_verify = hmac_sha256(srv_finished_key, th)
    conn.sendall(bytes([MSG_SERVER_FINISHED]) + sf_verify)

    cf_type = recv_exact(conn, 1)[0]
    if cf_type != MSG_CLIENT_FINISHED:
        raise RuntimeError("Bad ClientFinished type")
    cf_verify = recv_exact(conn, 32)
    exp_cf = hmac_sha256(cli_finished_key, th)
    if cf_verify != exp_cf:
        raise RuntimeError("ClientFinished verify FAILED")

    return device_id, mac_key

# -------------------------------------------------
# RLHABC aggregation: double each block (C + C)
# -------------------------------------------------
def rlhabc_double_blocks(ciphertext_bytes: bytes, block_count: int) -> bytes:
    expected_len = block_count * RLHABC_BLOCK_BYTES
    if len(ciphertext_bytes) != expected_len:
        raise ValueError("RLHABC ciphertext length mismatch")
    if block_count == 0:
        return b""
    blocks = np.frombuffer(ciphertext_bytes, dtype=">u4").reshape(block_count, 9).astype(np.uint64)
    out = (blocks + blocks) % RLHABC_N
    return out.astype(">u4").tobytes()

# -------------------------------------------------
# Session loop
# -------------------------------------------------
def session_loop(conn: socket.socket, addr):
    addr_str = f"{addr[0]}:{addr[1]}"
    device_id, mac_key = do_handshake(conn)
    print(f"[HS] OK {addr_str} device_id={device_id.hex()}")

    while True:
        t_rx = time.perf_counter()
        msg_type, payload = recv_frame(conn)
        if msg_type not in (MSG_APP_DATA, MSG_APP_STATS):
            raise RuntimeError(f"Unexpected message type: 0x{msg_type:02x}")
        if payload is None:
            continue

        if len(payload) < (APP_HDR_LEN + APP_MAC_LEN):
            print(f"[APP] Bad length: {len(payload)} (must be >= {APP_HDR_LEN + APP_MAC_LEN})")
            continue
        hdr = payload[:APP_HDR_LEN]
        dev_hdr = hdr[:8]
        seq = struct.unpack(">I", hdr[8:12])[0]
        block_count = struct.unpack(">I", hdr[12:16])[0]
        if block_count == 0:
            print("[APP] block_count=0")
            continue
        body = payload[APP_HDR_LEN:-APP_MAC_LEN]
        mac = payload[-APP_MAC_LEN:]
        exp_mac = hmac_sha256(mac_key, hdr + body)
        if exp_mac != mac:
            print("[APP] HMAC mismatch")
            continue
        if dev_hdr != device_id:
            print("[APP] device_id mismatch")
            continue

        if msg_type == MSG_APP_STATS:
            stats_text = body.decode("utf-8", errors="replace")
            _save_stats_txt(device_id.hex(), stats_text)
            print(f"[STATS] {device_id.hex()} seq={seq} {stats_text}")
            continue

        ciphertext = body
        if len(ciphertext) != block_count * RLHABC_BLOCK_BYTES:
            print(f"[APP] Bad length: {len(ciphertext)} (expected {block_count * RLHABC_BLOCK_BYTES})")
            continue

        _save_payload_txt(device_id.hex(), payload)

        t0 = time.perf_counter()
        out = rlhabc_double_blocks(ciphertext, block_count)
        out_mac = hmac_sha256(mac_key, hdr + out)
        dt_ms = (time.perf_counter() - t0) * 1000.0
        total_ms = (time.perf_counter() - t_rx) * 1000.0
        print(f"[APP] RX {len(ciphertext)} B ({block_count} blocks) seq={seq} -> TX {len(out)} B | sum {dt_ms:.3f} ms | total {total_ms:.3f} ms")
        send_app_data(conn, hdr + out + out_mac)

# -------------------------------------------------
# TCP server
# -------------------------------------------------
def handle_client(conn: socket.socket, addr):
    with conn:
        conn.settimeout(NORMAL_TIMEOUT_S)
        session_loop(conn, addr)

def safe_handle(conn, addr):
    try:
        handle_client(conn, addr)
    except Exception as e:
        print(f"[TCP] DROP {addr[0]}:{addr[1]}: {e}")
        try:
            conn.close()
        except Exception:
            pass

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    server.bind((HOST, PORT))
    server.listen(50)

    print(f"Server on {HOST}:{PORT}")
    print(f"RLHABC block size: {RLHABC_BLOCK_BYTES} bytes")

    while True:
        conn, addr = server.accept()
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        th = threading.Thread(target=lambda: safe_handle(conn, addr), daemon=True)
        th.start()

if __name__ == "__main__":
    main()
