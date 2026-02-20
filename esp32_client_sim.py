#!/usr/bin/env python3
"""
ESP32 client simulator:
- ECDH P-256 + HMAC auth + HKDF-SHA256
- Speck-64/96 for payload encryption
- Framed protocol: [type][len][ciphertext]

Dependencies:
  pip install cryptography
  Optional (to build payload from .tflite):
    pip install tflite-runtime numpy
"""
from __future__ import annotations

import argparse
import hmac
import hashlib
import os
import socket
import struct
import time
from typing import Optional, Tuple

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
except Exception as exc:  # pragma: no cover
    raise SystemExit("Missing dependency: pip install cryptography") from exc


PROTO_VER = 0x01
CH_TYPE = 0x01
SH_TYPE = 0x02
SF_TYPE = 0x03
CF_TYPE = 0x04

REKEY_REQUEST = 0x10
APP_DATA = 0x20

DEFAULT_MASTER_KEY_HEX = (
    "7213254B467B2318E1E7253F3B8B02AE"
    "C556FF9DACBB739630E75C667B1F3224"
)
DEFAULT_DEVICE_ID_HEX = "000A000300012F02"


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def hkdf_sha256(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    prk = hmac_sha256(salt, ikm)
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac_sha256(prk, t + info + bytes([counter]))
        okm += t
        counter += 1
        if counter == 0:
            raise ValueError("HKDF counter wrapped")
    return okm[:length]


def read_exact(sock: socket.socket, n: int, timeout: float) -> Optional[bytes]:
    end = time.time() + timeout
    buf = b""
    while len(buf) < n:
        remaining = end - time.time()
        if remaining <= 0:
            return None
        sock.settimeout(remaining)
        try:
            chunk = sock.recv(n - len(buf))
        except socket.timeout:
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


def do_handshake(sock: socket.socket, master_key: bytes, device_id: bytes, timeout: float) -> bytes:
    if len(device_id) != 8:
        raise ValueError("device_id must be 8 bytes")

    psk_device = hmac_sha256(master_key, device_id)

    # ECDH P-256
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    if len(pub) != 65:
        raise ValueError("Unexpected P-256 public key length")

    client_random = os.urandom(32)
    ch_wo_tag = (
        bytes([CH_TYPE, PROTO_VER]) +
        device_id +
        client_random +
        struct.pack(">H", len(pub)) +
        pub
    )
    ch_tag = hmac_sha256(psk_device, ch_wo_tag)
    sock.sendall(ch_wo_tag + ch_tag)

    # ServerHello
    sh_type = read_exact(sock, 1, timeout)
    if not sh_type or sh_type[0] != SH_TYPE:
        raise RuntimeError("Bad ServerHello type")
    sh_ver = read_exact(sock, 1, timeout)
    if not sh_ver or sh_ver[0] != PROTO_VER:
        raise RuntimeError("Bad ServerHello version")

    server_random = read_exact(sock, 32, timeout)
    if not server_random:
        raise RuntimeError("Server random missing")

    pub_len_raw = read_exact(sock, 2, timeout)
    if not pub_len_raw:
        raise RuntimeError("Server pub len missing")
    pub_len = struct.unpack(">H", pub_len_raw)[0]

    pubB = read_exact(sock, pub_len, timeout)
    if not pubB:
        raise RuntimeError("Server pub missing")

    sh_tag = read_exact(sock, 32, timeout)
    if not sh_tag:
        raise RuntimeError("ServerHello tag missing")

    sh_wo_tag = (
        bytes([SH_TYPE, PROTO_VER]) +
        server_random +
        struct.pack(">H", pub_len) +
        pubB
    )

    expected_sh_tag = hmac_sha256(psk_device, ch_wo_tag + sh_wo_tag)
    if expected_sh_tag != sh_tag:
        raise RuntimeError("ServerHello auth failed")

    th = hashlib.sha256(ch_wo_tag + sh_wo_tag).digest()

    peer_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pubB)
    shared = priv.exchange(ec.ECDH(), peer_pub)

    salt = hashlib.sha256(client_random + server_random).digest()
    info = b"session-v1" + th
    okm = hkdf_sha256(salt, shared, info, 76)

    srv_finished_key = okm[:32]
    cli_finished_key = okm[32:64]
    key96 = okm[64:76]

    # ServerFinished
    sf_type = read_exact(sock, 1, timeout)
    if not sf_type or sf_type[0] != SF_TYPE:
        raise RuntimeError("Bad ServerFinished type")
    sf_verify = read_exact(sock, 32, timeout)
    if not sf_verify:
        raise RuntimeError("ServerFinished verify missing")

    exp_sf = hmac_sha256(srv_finished_key, th)
    if exp_sf != sf_verify:
        raise RuntimeError("ServerFinished verify failed")

    # ClientFinished
    cf = bytes([CF_TYPE]) + hmac_sha256(cli_finished_key, th)
    sock.sendall(cf)

    return key96


def speck_key_schedule(key96: bytes) -> list[int]:
    if len(key96) != 12:
        raise ValueError("key96 must be 12 bytes")
    k0, k1, k2 = struct.unpack("<III", key96)
    l = [k1, k2]
    rk = k0
    rks = [rk]
    for i in range(25):
        new_l = ((rk + rotr32(l[i % 2], 8)) & 0xFFFFFFFF) ^ i
        l[i % 2] = new_l
        rk = rotl32(rk, 3) ^ new_l
        rks.append(rk & 0xFFFFFFFF)
    return rks


def rotr32(x: int, r: int) -> int:
    return ((x >> r) | ((x << (32 - r)) & 0xFFFFFFFF)) & 0xFFFFFFFF


def rotl32(x: int, r: int) -> int:
    return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF


def speck_encrypt_block(block: int, rks: list[int]) -> int:
    x = (block >> 32) & 0xFFFFFFFF
    y = block & 0xFFFFFFFF
    for rk in rks:
        x = (rotr32(x, 8) + y) & 0xFFFFFFFF
        x ^= rk
        y = rotl32(y, 3) ^ x
    return ((x << 32) | y) & 0xFFFFFFFFFFFFFFFF


def speck_decrypt_block(block: int, rks: list[int]) -> int:
    x = (block >> 32) & 0xFFFFFFFF
    y = block & 0xFFFFFFFF
    for rk in reversed(rks):
        y = rotr32(y ^ x, 3)
        x = (rotl32((x ^ rk) - y, 8)) & 0xFFFFFFFF
    return ((x << 32) | y) & 0xFFFFFFFFFFFFFFFF


def encrypt_payload(plaintext: bytes, rks: list[int]) -> bytes:
    out = bytearray()
    for i in range(0, len(plaintext), 8):
        chunk = plaintext[i:i + 8]
        if len(chunk) < 8:
            chunk = chunk + b"\x00" * (8 - len(chunk))
        block = int.from_bytes(chunk, "big")
        ct = speck_encrypt_block(block, rks)
        out += ct.to_bytes(8, "little")
    return bytes(out)


def decrypt_payload(ciphertext: bytes, rks: list[int]) -> bytes:
    out = bytearray()
    for i in range(0, len(ciphertext), 8):
        chunk = ciphertext[i:i + 8]
        if len(chunk) < 8:
            break
        ct = int.from_bytes(chunk, "little")
        pt = speck_decrypt_block(ct, rks)
        out += pt.to_bytes(8, "big")
    return bytes(out)


def build_payload_from_model(model_path: str, free_heap: int, cpu_freq: int) -> Optional[bytes]:
    try:
        import numpy as np
        try:
            from tflite_runtime.interpreter import Interpreter  # type: ignore
        except Exception:
            from tensorflow.lite import Interpreter  # type: ignore
    except Exception:
        return None

    interpreter = Interpreter(model_path=model_path)
    interpreter.allocate_tensors()
    details = interpreter.get_tensor_details()

    payload = bytearray()
    total_weights = 0

    for d in details:
        if d.get("dtype") != np.float32:
            continue
        try:
            data = interpreter.get_tensor(d["index"])
        except Exception:
            continue
        if data is None:
            continue
        raw = data.tobytes()
        if len(raw) == 0 or len(raw) > 0xFFFF:
            continue
        idx = d["index"] & 0xFF
        payload += bytes([idx, 0x01]) + struct.pack(">H", len(raw)) + raw
        total_weights += len(raw)

    meta = struct.pack(">BBHIII", 0xFF, 0x00, 12, free_heap, cpu_freq, total_weights)
    payload += meta
    return bytes(payload)


def build_dummy_payload() -> bytes:
    data = b"hello"
    payload = bytearray()
    payload += bytes([0x00, 0x01]) + struct.pack(">H", len(data)) + data
    meta = struct.pack(">BBHIII", 0xFF, 0x00, 12, 0, 0, len(data))
    payload += meta
    return bytes(payload)


def build_payload(model_path: Optional[str], payload_path: Optional[str], free_heap: int, cpu_freq: int) -> bytes:
    if payload_path:
        return open(payload_path, "rb").read()
    if model_path:
        payload = build_payload_from_model(model_path, free_heap, cpu_freq)
        if payload is not None:
            return payload
    return build_dummy_payload()


def recv_frame(sock: socket.socket, timeout: float) -> Optional[Tuple[int, Optional[bytes]]]:
    t = read_exact(sock, 1, timeout)
    if not t:
        return None
    msg_type = t[0]
    if msg_type == REKEY_REQUEST:
        return (msg_type, None)
    if msg_type != APP_DATA:
        return (msg_type, None)
    len4 = read_exact(sock, 4, timeout)
    if not len4:
        return None
    length = struct.unpack(">I", len4)[0]
    payload = read_exact(sock, length, timeout)
    if not payload:
        return None
    return (msg_type, payload)


def parse_hex(s: str, expected_len: Optional[int] = None) -> bytes:
    s = s.replace(":", "").replace(" ", "").strip()
    b = bytes.fromhex(s)
    if expected_len is not None and len(b) != expected_len:
        raise ValueError(f"Expected {expected_len} bytes, got {len(b)}")
    return b


def main() -> None:
    parser = argparse.ArgumentParser(description="ESP32 client simulator")
    parser.add_argument("--host", default="192.168.4.1")
    parser.add_argument("--port", type=int, default=1883)
    parser.add_argument("--master-key", default=DEFAULT_MASTER_KEY_HEX)
    parser.add_argument("--device-id", default=DEFAULT_DEVICE_ID_HEX)
    parser.add_argument("--model", help="Path to .tflite model")
    parser.add_argument("--payload", help="Path to prebuilt plaintext payload")
    parser.add_argument("--period", type=float, default=15.0)
    parser.add_argument("--free-heap", type=int, default=0)
    parser.add_argument("--cpu-freq", type=int, default=0)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--print-plaintext", action="store_true")
    args = parser.parse_args()

    master_key = parse_hex(args.master_key, expected_len=32)
    device_id = parse_hex(args.device_id, expected_len=8)

    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.connect((args.host, args.port))

        try:
            key96 = do_handshake(sock, master_key, device_id, args.timeout)
            rks = speck_key_schedule(key96)
            print("[HS] OK")

            next_send = time.time()
            while True:
                # Read any incoming frame
                sock.settimeout(0.1)
                try:
                    peek = sock.recv(1, socket.MSG_PEEK)
                except Exception:
                    peek = b""
                if peek:
                    frame = recv_frame(sock, args.timeout)
                    if frame:
                        msg_type, payload = frame
                        if msg_type == REKEY_REQUEST:
                            print("[HS] REKEY_REQUEST")
                            key96 = do_handshake(sock, master_key, device_id, args.timeout)
                            rks = speck_key_schedule(key96)
                            print("[HS] OK")
                        elif msg_type == APP_DATA and payload:
                            if args.print_plaintext:
                                pt = decrypt_payload(payload, rks)
                                print("[RX] plaintext:", pt[:256])
                            else:
                                print("[RX] payload:", len(payload), "bytes")
                        else:
                            print("[RX] unknown type:", hex(msg_type))

                now = time.time()
                if now >= next_send:
                    plaintext = build_payload(args.model, args.payload, args.free_heap, args.cpu_freq)
                    ciphertext = encrypt_payload(plaintext, rks)
                    frame = bytes([APP_DATA]) + struct.pack(">I", len(ciphertext)) + ciphertext
                    sock.sendall(frame)
                    print("[TX] sent", len(ciphertext), "bytes")
                    next_send = now + args.period
                    if args.once:
                        return
                time.sleep(0.01)
        except Exception as exc:
            print("[ERR]", exc)
            time.sleep(1.0)
        finally:
            try:
                sock.close()
            except Exception:
                pass


if __name__ == "__main__":
    main()
