#!/usr/bin/env python3
# ---------------------------------------------------------
# secure_federated_server.py (HUMAN-READABLE LOGS ONLY)
#
# ✅ ВАЖНО: bin НЕ создаём вообще
# - RX/TX plaintext (после расшифровки) -> .txt
# - RX/TX веса (float32) -> .csv (idx,weight)
# - Метрики -> .csv
# - meta -> .json (как было)
#
# LOG STRUCTURE:
# server_logs/YYYY-MM-DD/<GROUP_ID>/devices/<device_id>/round_<NNN>/
#   session.log
#   rx/...
#   tx/...
#
# Staging:
# server_logs/YYYY-MM-DD/_staging/agg_<agg_round_id>/devices/<device_id>/
#
# Metrics:
# если пришли до AIF1 -> server_logs/YYYY-MM-DD/_metrics_orphans/devices/<device_id>/
# потом переносятся в нужный round_XXX
# ---------------------------------------------------------

from __future__ import annotations

import os
import socket
import struct
import threading
import time
import sqlite3
import json
import datetime
import shutil
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

MSG_REKEY_REQUEST    = 0x10
MSG_APP_DATA         = 0x20   # [0x20][len:u32 BE][ciphertext]

SESSION_LIFETIME_S = 7200000
REKEY_ADVANCE_S    = 5.0
REKEY_GRACE_S      = 10.0
NORMAL_TIMEOUT_S   = 2.0

# ---------------- Federated aggregation ----------------
AGG_MIN_UPDATES = 1
AGG_TIMEOUT_S = 1000000000000

# ✅ ждём ровно столько устройств
AGG_EXACT_DEVICES = 1

# ✅ ограничение количества агрегированных раундов
MAX_AGG_ROUNDS = None

# (опционально) лимит round_XXX внутри одной группы участников
MAX_GROUP_ROUNDS = None  # например 10

# ---------------- Storage (SQLite) ----------------
DB_PATH = "sessions.db"
DB_LOCK = threading.Lock()

EVENTS_KEEP_DAYS = 7
EVENTS_MAX_ROWS  = 20000
EVENTS_CLEAN_EVERY = 50

# ---------------- File logging ----------------
LOG_ROOT = Path("server_logs")
STAGING_NAME = "_staging"
FALLBACK_NAME = "_metrics_orphans"

LOG_SAVE_CIPHERTEXT = False
LOG_SAVE_PLAINTEXT  = True
LOG_SAVE_AIF1_WEIGHTS = False
LOG_SAVE_JSON_META = True
LOG_MAX_BYTES_PLAINTEXT = 5_000_000

_file_lock_global = threading.Lock()
_file_locks: dict[str, threading.Lock] = {}

def _get_dev_lock(device_id_hex: str) -> threading.Lock:
    with _file_lock_global:
        lk = _file_locks.get(device_id_hex)
        if lk is None:
            lk = threading.Lock()
            _file_locks[device_id_hex] = lk
        return lk

def _now_date_str() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d")

def _now_ts_str() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def _ms_id() -> str:
    return str(int(time.time() * 1000))

def append_text(path: Path, line: str, *, device_id_hex: str):
    lk = _get_dev_lock(device_id_hex)
    with lk:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")

def write_json(path: Path, obj: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)

def write_text(path: Path, text: str, *, device_id_hex: str):
    lk = _get_dev_lock(device_id_hex)
    with lk:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", errors="ignore")

def bytes_to_readable_text(b: bytes, *, max_bytes: int | None = None) -> str:
    if max_bytes is not None and len(b) > max_bytes:
        b = b[:max_bytes]
    try:
        s = b.decode("utf-8")
        bad = sum(1 for ch in s[:2000] if ch == "\x00")
        if bad < 5:
            return s
    except Exception:
        pass
    hex_str = b.hex()
    preview = []
    for x in b[:256]:
        preview.append(chr(x) if 32 <= x <= 126 else ".")
    ascii_preview = "".join(preview)
    return (
        f"[BINARY DATA]\n"
        f"len={len(b)}\n"
        f"hex(first {min(len(b), 4096)} bytes)={hex_str[:8192]}\n"
        f"ascii_preview(first 256)={ascii_preview}\n"
    )

def write_weights_csv(path: Path, weights_bytes: bytes, *, device_id_hex: str):
    lk = _get_dev_lock(device_id_hex)
    with lk:
        path.parent.mkdir(parents=True, exist_ok=True)
        arr = np.frombuffer(weights_bytes, dtype=np.float32)
        with path.open("w", encoding="utf-8", newline="\n") as f:
            f.write("idx,weight\n")
            for i, w in enumerate(arr):
                f.write(f"{i},{w:.10g}\n")

def flog_event(base_dir: Path | None, device_id_hex: str, level: str, msg: str, extra: dict | None = None):
    if base_dir is None:
        return
    line = f"[{_now_ts_str()}] [{level}] {msg}"
    append_text(base_dir / "session.log", line, device_id_hex=device_id_hex)
    if extra and LOG_SAVE_JSON_META:
        write_json(base_dir / "session_meta.json", {"ts": _now_ts_str(), "level": level, "msg": msg, "extra": extra})

# MUST match ESP32
MASTER_KEY = bytes([
    0x72, 0x13, 0x25, 0x4B, 0x46, 0x7B, 0x23, 0x18,
    0xE1, 0xE7, 0x25, 0x3F, 0x3B, 0x8B, 0x02, 0xAE,
    0xC5, 0x56, 0xFF, 0x9D, 0xAC, 0xBB, 0x73, 0x96,
    0x30, 0xE7, 0x5C, 0x66, 0x7B, 0x1F, 0x32, 0x24
])

# -------------------------------------------------
# DB helpers
# -------------------------------------------------
_db_event_counter = 0

def db_init():
    with DB_LOCK:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        with conn:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS device_state (
                device_id         TEXT PRIMARY KEY,
                addr              TEXT,
                state             TEXT NOT NULL,
                epoch             INTEGER NOT NULL,
                session_id        TEXT,
                connected_at      REAL,
                expires_at        REAL,
                last_seen         REAL,
                last_close_reason TEXT
            )
            """)
            conn.execute("""
            CREATE TABLE IF NOT EXISTS session_events (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                ts         REAL NOT NULL,
                device_id  TEXT NOT NULL,
                event      TEXT NOT NULL,
                session_id TEXT,
                epoch      INTEGER,
                details    TEXT
            )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_device_ts ON session_events(device_id, ts)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON session_events(ts)")
        conn.close()

def db_upsert_device_active(*, device_id: str, addr: str, epoch: int, session_id: str,
                            connected_at: float, expires_at: float):
    with DB_LOCK:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        with conn:
            conn.execute("""
                INSERT INTO device_state(device_id, addr, state, epoch, session_id, connected_at, expires_at, last_seen, last_close_reason)
                VALUES (?, ?, 'ACTIVE', ?, ?, ?, ?, ?, NULL)
                ON CONFLICT(device_id) DO UPDATE SET
                    addr=excluded.addr,
                    state='ACTIVE',
                    epoch=excluded.epoch,
                    session_id=excluded.session_id,
                    connected_at=excluded.connected_at,
                    expires_at=excluded.expires_at,
                    last_seen=excluded.last_seen,
                    last_close_reason=NULL
            """, (device_id, addr, epoch, session_id, connected_at, expires_at, time.time()))
        conn.close()

def db_update_device_closed(*, device_id: str, reason: str):
    with DB_LOCK:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        with conn:
            conn.execute("""
                UPDATE device_state
                SET state='CLOSED',
                    last_close_reason=?,
                    last_seen=?
                WHERE device_id=?
            """, (reason, time.time(), device_id))
        conn.close()

def db_touch_last_seen(*, device_id: str):
    with DB_LOCK:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        with conn:
            conn.execute("""
                UPDATE device_state
                SET last_seen=?
                WHERE device_id=?
            """, (time.time(), device_id))
        conn.close()

def db_add_event(*, device_id: str, event: str, session_id: str | None, epoch: int | None, details: dict | None):
    global _db_event_counter
    _db_event_counter += 1
    details_str = None
    if details is not None:
        details_str = json.dumps(details, separators=(",", ":"), ensure_ascii=False)
    with DB_LOCK:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        with conn:
            conn.execute("""
                INSERT INTO session_events(ts, device_id, event, session_id, epoch, details)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (time.time(), device_id, event, session_id, epoch, details_str))
        conn.close()
    if _db_event_counter % EVENTS_CLEAN_EVERY == 0:
        db_cleanup_events()

def db_cleanup_events():
    cutoff_ts = time.time() - (EVENTS_KEEP_DAYS * 86400.0)
    with DB_LOCK:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        with conn:
            conn.execute("DELETE FROM session_events WHERE ts < ?", (cutoff_ts,))
            conn.execute(f"""
                DELETE FROM session_events
                WHERE id NOT IN (
                    SELECT id FROM session_events
                    ORDER BY id DESC
                    LIMIT {int(EVENTS_MAX_ROWS)}
                )
            """)
        conn.close()

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

def summary(a: np.ndarray) -> dict:
    if a.size == 0:
        return {"n": 0}
    return {
        "n": a.size,
        "min": float(a.min()),
        "max": float(a.max()),
        "mean": float(a.mean()),
        "std": float(a.std()),
    }

# -------------------------------------------------
# Framing helpers
# -------------------------------------------------
def recv_frame(conn: socket.socket):
    t = recv_exact(conn, 1)[0]
    if t == MSG_APP_DATA:
        ln = struct.unpack(">I", recv_exact(conn, 4))[0]
        if ln > 10_000_000:
            raise RuntimeError(f"Too large frame: {ln}")
        payload = recv_exact(conn, ln) if ln > 0 else b""
        return t, payload
    return t, None

def send_app_data(conn: socket.socket, payload: bytes):
    conn.sendall(bytes([MSG_APP_DATA]) + struct.pack(">I", len(payload)) + payload)

def _drain_app_data_until_clienthello(conn: socket.socket, *, timeout_s: float) -> int:
    deadline = time.monotonic() + timeout_s
    ignored = 0
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout("rekey: timeout waiting for ClientHello")
        old_timeout = conn.gettimeout()
        conn.settimeout(min(1.0, remaining))
        try:
            t = recv_exact(conn, 1)[0]
        finally:
            conn.settimeout(old_timeout)
        if t == MSG_CLIENT_HELLO:
            if ignored:
                print(f"[REKEY] Drained {ignored} frame(s) before ClientHello")
            return t
        if t == MSG_APP_DATA:
            ln = struct.unpack(">I", recv_exact(conn, 4))[0]
            if ln > 10_000_000:
                raise RuntimeError(f"Too large frame while draining: {ln}")
            if ln:
                _ = recv_exact(conn, ln)
            ignored += 1
            continue
        ignored += 1

def _short_id(hexstr: str | None, n: int = 8) -> str:
    if not hexstr:
        return "?"
    return hexstr[:n]

def log_stat(*, addr: str, device_id_hex: str, epoch: int, session_id_hex: str | None,
             rx_bytes: int, dec_ms: float, proc_ms: float,
             meta: dict | None = None, warn: str | None = None):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    sid = _short_id(session_id_hex, 8)
    hdr = f"[{ts}] [APP] {addr} dev={device_id_hex} epoch={epoch} sid={sid}"
    print("\n" + hdr)
    print(f"  RX: {rx_bytes} B  ({rx_bytes//8} blocks)")
    print(f"  time: dec={dec_ms:.3f} ms  proc={proc_ms:.3f} ms")
    if meta:
        print(f"  meta: {meta}")
    if warn:
        print(f"  ⚠️ {warn}")

# -------------------------------------------------
# Handshake
# -------------------------------------------------
def do_handshake(conn: socket.socket, expected_device_id: bytes | None = None, first_byte: int | None = None):
    if first_byte is None:
        t = recv_exact(conn, 1)[0]
    else:
        t = first_byte
    if t != MSG_CLIENT_HELLO:
        raise RuntimeError(f"Bad ClientHello type: 0x{t:02x}")
    ver = recv_exact(conn, 1)[0]
    if ver != PROTO_VER:
        raise RuntimeError("Bad CH version")
    device_id = recv_exact(conn, 8)
    if expected_device_id is not None and device_id != expected_device_id:
        raise RuntimeError("Unexpected device_id during rekey")
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

    session_id = os.urandom(8)
    return {"device_id": device_id, "session_id": session_id, "key96": key96, "created_at": time.time()}

# -------------------------------------------------
# Speck-64/96
# -------------------------------------------------
MASK32 = 0xFFFFFFFF

def ror32(v, r):
    return ((v >> r) | (v << (32 - r))) & MASK32

def rol32(v, r):
    return ((v << r) | (v >> (32 - r))) & MASK32

def speck_gen_round_keys_from_key96(key96: bytes):
    if len(key96) != 12:
        raise ValueError("key96 must be 12 bytes")
    k0 = struct.unpack("<I", key96[0:4])[0]
    k1 = struct.unpack("<I", key96[4:8])[0]
    k2 = struct.unpack("<I", key96[8:12])[0]
    KEY = [k0, k1, k2]
    ROUNDS = 26
    l = [0] * 2
    l[1] = KEY[2]
    l[0] = KEY[1]
    rk = KEY[0]
    rks = [rk]
    for i in range(ROUNDS - 1):
        new_l = (rk + ror32(l[i % 2], 8)) & MASK32
        new_l ^= i
        l[i % 2] = new_l
        rk = rol32(rk, 3) ^ new_l
        rks.append(rk)
    return rks

def speck_encrypt_u64(pt_num: int, RK):
    x = (pt_num >> 32) & MASK32
    y = pt_num & MASK32
    for k in RK:
        x = ((ror32(x, 8) + y) & MASK32) ^ k
        y = rol32(y, 3) ^ x
    return ((x << 32) | y) & 0xFFFFFFFFFFFFFFFF

def speck_decrypt_u64(ct_num: int, RK):
    x = (ct_num >> 32) & MASK32
    y = ct_num & MASK32
    for k in reversed(RK):
        y = ror32(y ^ x, 3)
        x = rol32(((x ^ k) - y) & MASK32, 8)
    return ((x << 32) | y) & 0xFFFFFFFFFFFFFFFF

# ✅ FIX: единый порядок байт с ESP32 (big-endian блоки 8 байт)
def speck_decrypt_bytes(ciphertext: bytes, RK) -> bytes:
    if len(ciphertext) % 8 != 0:
        raise ValueError("Ciphertext length must be multiple of 8")
    out = bytearray()
    for i in range(0, len(ciphertext), 8):
        ct_num = int.from_bytes(ciphertext[i:i+8], byteorder="big", signed=False)
        pt_num = speck_decrypt_u64(ct_num, RK)
        out += pt_num.to_bytes(8, byteorder="big", signed=False)
    return bytes(out)

def speck_encrypt_bytes(plaintext: bytes, RK) -> bytes:
    out = bytearray()
    for i in range(0, len(plaintext), 8):
        chunk = plaintext[i:i+8]
        chunk = chunk.ljust(8, b"\x00")  # padding нулями
        plain_num = int.from_bytes(chunk, byteorder="big", signed=False)
        ct_num = speck_encrypt_u64(plain_num, RK)
        out += ct_num.to_bytes(8, byteorder="big", signed=False)
    return bytes(out)

# -------------------------------------------------
# Grouped log manager + staging
# -------------------------------------------------
_group_lock = threading.RLock()
_group_state = {}         # day -> {"current_key": frozenset, "group_id": str, "round_no": int}
_aggid_to_group = {}      # agg_round_id -> {"day","group_id","round_no","participants"}
_group_counter = {}       # day -> int (next group number)

_dev_last_round_lock = threading.Lock()
_dev_last_round = {}      # device_id_hex -> {"day": str, "agg_round_id": int}

def _participants_key(participants: list[str]) -> frozenset:
    return frozenset(participants)

def _make_group_id(day: str, participants: list[str]) -> str:
    counter = _group_counter.get(day, 0) + 1
    _group_counter[day] = counter
    return f"group_{counter}"

def _staging_dir(day: str, agg_round_id: int, device_id_hex: str) -> Path:
    return LOG_ROOT / day / STAGING_NAME / f"agg_{agg_round_id:06d}" / "devices" / device_id_hex

def _final_round_dir(day: str, group_id: str, device_id_hex: str, round_no: int) -> Path:
    return LOG_ROOT / day / f"{group_id}" / "devices" / device_id_hex / f"round_{round_no:03d}"

def _fallback_metrics_dir(day: str, device_id_hex: str) -> Path:
    return LOG_ROOT / day / FALLBACK_NAME / "devices" / device_id_hex

def _ensure_round_dirs(base: Path):
    (base / "rx").mkdir(parents=True, exist_ok=True)
    (base / "tx").mkdir(parents=True, exist_ok=True)

def _assign_group_for_completed_round(day: str, participants: list[str], agg_round_id: int) -> dict:
    key = _participants_key(participants)
    with _group_lock:
        st = _group_state.get(day)
        if st is None or st["current_key"] != key:
            gid = _make_group_id(day, participants)
            round_no = 1
            _group_state[day] = {"current_key": key, "group_id": gid, "round_no": round_no}
        else:
            gid = st["group_id"]
            round_no = st["round_no"] + 1
            if MAX_GROUP_ROUNDS is not None and round_no > MAX_GROUP_ROUNDS:
                raise RuntimeError(f"MAX_GROUP_ROUNDS reached ({MAX_GROUP_ROUNDS}) for group {gid}")
            st["round_no"] = round_no

        info = {"day": day, "group_id": gid, "round_no": round_no, "participants": sorted(participants)}
        _aggid_to_group[agg_round_id] = info
        return info

def _move_staging_to_final(day: str, agg_round_id: int, participants: list[str], group_info: dict):
    for dev in participants:
        src = _staging_dir(day, agg_round_id, dev)
        if not src.exists():
            continue
        dst = _final_round_dir(day, group_info["group_id"], dev, group_info["round_no"])
        dst.parent.mkdir(parents=True, exist_ok=True)
        if dst.exists():
            shutil.copytree(src, dst, dirs_exist_ok=True)
            shutil.rmtree(src, ignore_errors=True)
        else:
            shutil.move(str(src), str(dst))

def _set_dev_last_round(device_id_hex: str, day: str, agg_round_id: int):
    with _dev_last_round_lock:
        _dev_last_round[device_id_hex] = {"day": day, "agg_round_id": agg_round_id}

def _get_dev_last_round(device_id_hex: str):
    with _dev_last_round_lock:
        return _dev_last_round.get(device_id_hex)

def _metrics_target_dir_for_device(device_id_hex: str) -> Path | None:
    info = _get_dev_last_round(device_id_hex)
    if not info:
        return None
    day = info["day"]
    agg_round_id = info["agg_round_id"]

    g = _aggid_to_group.get(agg_round_id)
    if g and g.get("day") == day:
        return _final_round_dir(day, g["group_id"], device_id_hex, g["round_no"])

    return _staging_dir(day, agg_round_id, device_id_hex)

def _try_rehome_fallback_metrics(device_id_hex: str):
    info = _get_dev_last_round(device_id_hex)
    if not info:
        return
    day = info["day"]
    src = _fallback_metrics_dir(day, device_id_hex)
    if not src.exists():
        return
    dst = _metrics_target_dir_for_device(device_id_hex)
    if dst is None:
        return

    _ensure_round_dirs(dst)

    if (src / "rx").exists():
        for p in (src / "rx").glob("*"):
            try:
                target = dst / "rx" / p.name
                if target.exists():
                    target = dst / "rx" / (p.stem + "_moved" + p.suffix)
                shutil.move(str(p), str(target))
            except Exception:
                pass

    try:
        for sub in [src / "rx", src / "tx", src]:
            if sub.exists() and sub.is_dir():
                try:
                    sub.rmdir()
                except OSError:
                    pass
    except Exception:
        pass

# -------------------------------------------------
# Aggregation state + pending
# -------------------------------------------------
_agg_lock = threading.Lock()
_agg_round = 1
_agg_weights = {}        # device_id_hex -> {"arr": np.ndarray, "rx_sha256": str, "rx_fid": str}
_agg_weights_len = None
_agg_last_ts = 0.0

_pending_lock = threading.Lock()
_pending_payloads = {}   # device_id_hex -> {"payload": bytes, "agg_round_id": int, "participants": list[str]}

def _maybe_reset_round(now_ts: float):
    global _agg_round, _agg_weights, _agg_weights_len, _agg_last_ts
    if _agg_weights and (now_ts - _agg_last_ts) > AGG_TIMEOUT_S:
        print(f"[AGG] Timeout: drop round {_agg_round} ({len(_agg_weights)} updates)")
        _agg_round += 1
        _agg_weights = {}
        _agg_weights_len = None
        _agg_last_ts = now_ts

def _get_current_agg_round_id() -> int:
    with _agg_lock:
        return _agg_round

def _aggregate_update(device_id_hex: str, weights_bytes: bytes, rx_fid: str) -> tuple[bytes, list[str], int] | None:
    global _agg_round, _agg_weights, _agg_weights_len, _agg_last_ts

    if len(weights_bytes) % 4 != 0:
        raise ValueError("weights length is not multiple of 4 (float32)")

    now_ts = time.time()
    with _agg_lock:
        _maybe_reset_round(now_ts)
        current_round = _agg_round

        if _agg_weights_len is None:
            _agg_weights_len = len(weights_bytes)
        elif _agg_weights_len != len(weights_bytes):
            print(f"[AGG] Drop update (size mismatch) dev={device_id_hex} len={len(weights_bytes)} expected={_agg_weights_len}")
            return None

        arr = np.frombuffer(weights_bytes, dtype=np.float32).copy()
        rx_sha256 = sha256_bytes(weights_bytes).hex()
        _agg_weights[device_id_hex] = {"arr": arr, "rx_sha256": rx_sha256, "rx_fid": rx_fid}
        _agg_last_ts = now_ts

        count = len(_agg_weights)
        print(f"[AGG] Round {current_round}: {count}/{AGG_MIN_UPDATES} updates | devices={list(_agg_weights.keys())}")

        if AGG_EXACT_DEVICES is not None:
            if count != AGG_EXACT_DEVICES:
                return None
        else:
            if count < AGG_MIN_UPDATES:
                return None

        participants = list(_agg_weights.keys())
        summaries = {dev: summary(meta["arr"]) for dev, meta in _agg_weights.items()}

        stacked = np.stack([meta["arr"] for meta in _agg_weights.values()], axis=0).astype(np.float64)
        mean = stacked.mean(axis=0).astype(np.float32)
        out = mean.tobytes()

        agg_log = {
            "round_id": current_round,
            "timestamp": now_ts,
            "participants": sorted(participants),
            "weights_len": _agg_weights_len,
            "per_device": {
                dev: {
                    "rx_sha256": meta["rx_sha256"],
                    "rx_fid": meta["rx_fid"],
                    "summary": summaries[dev]
                } for dev, meta in _agg_weights.items()
            },
            "agg_summary": summary(mean),
            "agg_sha256": sha256_bytes(out).hex(),
        }

        day = _now_date_str()
        agg_meta_path = LOG_ROOT / day / STAGING_NAME / f"agg_{current_round:06d}" / "agg_round.json"
        write_json(agg_meta_path, agg_log)

        _agg_round += 1
        _agg_weights = {}
        _agg_weights_len = None
        _agg_last_ts = now_ts

        if MAX_AGG_ROUNDS is not None and current_round >= MAX_AGG_ROUNDS:
            print(f"[AGG] Reached MAX_AGG_ROUNDS={MAX_AGG_ROUNDS}. Stopping server.")
            os._exit(0)

        return out, participants, current_round

def _queue_pending_for(devices: list[str], payload_plain: bytes, agg_round_id: int, participants: list[str]):
    with _pending_lock:
        for dev in devices:
            _pending_payloads[dev] = {"payload": payload_plain, "agg_round_id": agg_round_id, "participants": participants}

def _pop_pending_for(device_id_hex: str):
    with _pending_lock:
        return _pending_payloads.pop(device_id_hex, None)

def _build_aif1_payload(weights_bytes: bytes) -> bytes:
    hash_bytes = sha256_bytes(weights_bytes)
    payload = weights_bytes + hash_bytes
    return b"AIF1" + struct.pack(">I", len(payload)) + payload

# -------------------------------------------------
# SAVE (NO BIN): RX/TX to txt + weights to csv
# -------------------------------------------------
def _save_rx(base_dir: Path | None, device_id_hex: str,
             ciphertext: bytes, plaintext: bytes | None, aif1_weights: bytes | None,
             meta: dict, train_metrics_text: str | None = None, test_metrics_text: str | None = None):
    if base_dir is None:
        return None

    fid = _ms_id()
    _ensure_round_dirs(base_dir)

    if plaintext is not None and LOG_SAVE_PLAINTEXT:
        txt = bytes_to_readable_text(plaintext, max_bytes=LOG_MAX_BYTES_PLAINTEXT)
        write_text(base_dir / "rx" / f"rx_plain_{fid}.txt", txt, device_id_hex=device_id_hex)

    if aif1_weights is not None:
        write_weights_csv(base_dir / "rx" / f"rx_weights_{fid}.csv", aif1_weights, device_id_hex=device_id_hex)

    if train_metrics_text is not None:
        with open(base_dir / "rx" / f"rx_train_metrics_{fid}.csv", "w", encoding="utf-8") as f:
            f.write(train_metrics_text)

    if test_metrics_text is not None:
        with open(base_dir / "rx" / f"rx_test_metrics_{fid}.csv", "w", encoding="utf-8") as f:
            f.write(test_metrics_text)

    if LOG_SAVE_JSON_META:
        write_json(base_dir / "rx" / f"rx_meta_{fid}.json", meta)

    return fid

def _save_tx(base_dir: Path | None, device_id_hex: str, ciphertext: bytes, plaintext: bytes | None, meta: dict):
    if base_dir is None:
        return None

    fid = _ms_id()
    _ensure_round_dirs(base_dir)

    if plaintext is not None and LOG_SAVE_PLAINTEXT:
        txt = bytes_to_readable_text(plaintext, max_bytes=LOG_MAX_BYTES_PLAINTEXT)
        write_text(base_dir / "tx" / f"tx_plain_{fid}.txt", txt, device_id_hex=device_id_hex)

        if len(plaintext) >= 8 and plaintext[0:4] == b"AIF1":
            try:
                ln = struct.unpack(">I", plaintext[4:8])[0]
                if ln >= 32 and 8 + ln <= len(plaintext):
                    payload = plaintext[8:8+ln]
                    w = payload[:-32]
                    if sha256_bytes(w) == payload[-32:]:
                        write_weights_csv(base_dir / "tx" / f"tx_weights_{fid}.csv", w, device_id_hex=device_id_hex)
            except Exception:
                pass

    if LOG_SAVE_JSON_META:
        write_json(base_dir / "tx" / f"tx_meta_{fid}.json", meta)

    return fid

# -------------------------------------------------
# Payload processing
# -------------------------------------------------
METRICS_HEADER = "EPOCH,ms,train_loss,val_loss,train_acc,val_acc"

def process_payload(ciphertext_bytes: bytes, RK,
                    *, addr_str: str, device_id_hex: str, epoch: int, session_id_hex: str | None) -> bytes | None:

    t_cycle_start = time.perf_counter()

    if len(ciphertext_bytes) % 8 != 0:
        proc_ms = (time.perf_counter() - t_cycle_start) * 1000
        log_stat(addr=addr_str, device_id_hex=device_id_hex, epoch=epoch, session_id_hex=session_id_hex,
                 rx_bytes=len(ciphertext_bytes), dec_ms=0.0, proc_ms=proc_ms,
                 warn="Payload length is not multiple of 8")
        return None

    t_dec_start = time.perf_counter()
    try:
        decrypted = speck_decrypt_bytes(ciphertext_bytes, RK)
    except Exception as e:
        dec_ms = (time.perf_counter() - t_dec_start) * 1000
        proc_ms = (time.perf_counter() - t_cycle_start) * 1000
        log_stat(addr=addr_str, device_id_hex=device_id_hex, epoch=epoch, session_id_hex=session_id_hex,
                 rx_bytes=len(ciphertext_bytes), dec_ms=dec_ms, proc_ms=proc_ms,
                 warn=f"Decrypt error: {e}")
        return None

    decryption_time_ms = (time.perf_counter() - t_dec_start) * 1000

    try:
        train_metrics_text = None
        test_metrics_text = None
        metrics_bytes = b""
        if len(decrypted) >= 8 and decrypted[0:4] == b"AIF1":
            payload_type = "AIF1"
            weights_len = struct.unpack(">I", decrypted[4:8])[0] - 32
            pos = 8
            weights_bytes = decrypted[pos:pos + weights_len + 32]
            received_hash = weights_bytes[-32:]
            weights_bytes = weights_bytes[:-32]
            computed_hash = sha256_bytes(weights_bytes)
            if computed_hash != received_hash:
                raise ValueError("Hash mismatch")
            metrics_len = 0

        elif len(decrypted) >= 12 and decrypted[0:4] == b"AIF2":
            payload_type = "AIF2"
            weights_len = struct.unpack(">I", decrypted[4:8])[0]
            metrics_len = struct.unpack(">I", decrypted[8:12])[0]
            pos = 12
            if pos + weights_len + metrics_len + 32 > len(decrypted):
                raise ValueError("AIF2 payload truncated")
            weights_bytes = decrypted[pos:pos + weights_len]
            pos += weights_len
            metrics_bytes = decrypted[pos:pos + metrics_len]
            pos += metrics_len
            received_hash = decrypted[pos:pos + 32]
            computed_hash = sha256_bytes(weights_bytes)
            if computed_hash != received_hash:
                raise ValueError("Hash mismatch")
            if metrics_len > 0:
                metrics_str = metrics_bytes.decode("utf-8", errors="ignore")
                if not metrics_str.startswith(METRICS_HEADER):
                    print("Warning: bad metrics header in AIF2")
                # Разделяем на train и test
                parts = metrics_str.split("\n# Test Results\n", 1)
                train_metrics_text = parts[0].strip()
                test_metrics_text = parts[1].strip() if len(parts) > 1 else None

        elif decrypted.decode("utf-8", errors="ignore").startswith(METRICS_HEADER):
            payload_type = "metrics"
            metrics_text = decrypted.decode("utf-8", errors="ignore")
            weights_len = 0
            weights_bytes = b""
            metrics_len = len(decrypted)
        else:
            raise ValueError("Unknown payload type")

        if weights_len > 0:
            agg_round_id = _get_current_agg_round_id()
            day = _now_date_str()

            _set_dev_last_round(device_id_hex, day, agg_round_id)
            _try_rehome_fallback_metrics(device_id_hex)

            base_dir = _staging_dir(day, agg_round_id, device_id_hex)
            _ensure_round_dirs(base_dir)

            proc_time_ms = (time.perf_counter() - t_cycle_start) * 1000
            log_stat(addr=addr_str, device_id_hex=device_id_hex, epoch=epoch, session_id_hex=session_id_hex,
                     rx_bytes=len(ciphertext_bytes), dec_ms=decryption_time_ms, proc_ms=proc_time_ms,
                     meta={"type": payload_type, "agg_round_id": agg_round_id, "weights_len": weights_len, "metrics_len": metrics_len})

            rx_meta = {
                "type": payload_type,
                "ok": True,
                "epoch": epoch,
                "sid": session_id_hex,
                "addr": addr_str,
                "agg_round_id": agg_round_id,
                "cipher_len": len(ciphertext_bytes),
                "plain_len": len(decrypted),
                "weights_len": weights_len,
                "metrics_len": metrics_len,
                "weights_sha256": computed_hash.hex(),
                "hash_ok": True,
                "dec_ms": round(decryption_time_ms, 3),
                "proc_ms": round(proc_time_ms, 3),
            }

            rx_fid = _save_rx(
                base_dir, device_id_hex,
                ciphertext=ciphertext_bytes,
                plaintext=decrypted,
                aif1_weights=weights_bytes,
                meta=rx_meta,
                train_metrics_text=train_metrics_text,
                test_metrics_text=test_metrics_text
            ) or "?"
            flog_event(base_dir, device_id_hex, "RX", f"{payload_type} received agg_round_id={agg_round_id} fid={rx_fid}",
                       extra={"agg_round_id": agg_round_id, "rx_fid": rx_fid})

            aggregated = _aggregate_update(device_id_hex, weights_bytes, rx_fid=rx_fid)
            if aggregated is None:
                return None

            agg_bytes, participants, finished_round_id = aggregated

            group_info = _assign_group_for_completed_round(day, participants, finished_round_id)
            _move_staging_to_final(day, finished_round_id, participants, group_info)

            resp_plain = _build_aif1_payload(agg_bytes)
            _queue_pending_for(participants, resp_plain, finished_round_id, participants)

            db_add_event(
                device_id=device_id_hex,
                event="agg_complete",
                session_id=session_id_hex,
                epoch=epoch,
                details={
                    "agg_round_id": finished_round_id,
                    "group_id": group_info["group_id"],
                    "group_round_no": group_info["round_no"],
                    "participants": sorted(participants),
                    "agg_sha256": sha256_bytes(agg_bytes).hex()
                },
            )

            pending = _pop_pending_for(device_id_hex)
            payload_to_send = pending["payload"] if pending else resp_plain
            resp_ct = speck_encrypt_bytes(payload_to_send, RK)

            final_dir = _final_round_dir(day, group_info["group_id"], device_id_hex, group_info["round_no"])
            tx_meta = {
                "type": "AIF1",
                "epoch": epoch,
                "sid": session_id_hex,
                "addr": addr_str,
                "agg_round_id": finished_round_id,
                "group_id": group_info["group_id"],
                "group_round_no": group_info["round_no"],
                "participants": sorted(participants),
                "agg_weights_len": len(agg_bytes),
                "agg_weights_sha256": sha256_bytes(agg_bytes).hex(),
                "plain_len": len(payload_to_send),
                "cipher_len": len(resp_ct),
            }
            _save_tx(final_dir, device_id_hex, ciphertext=resp_ct, plaintext=payload_to_send, meta=tx_meta)
            flog_event(final_dir, device_id_hex, "TX", f"AIF1 sent agg_round_id={finished_round_id}", extra=tx_meta)

            return resp_ct

        elif train_metrics_text is not None:
            target_dir = _metrics_target_dir_for_device(device_id_hex)
            if target_dir is None:
                day = _now_date_str()
                target_dir = _fallback_metrics_dir(day, device_id_hex)

            _ensure_round_dirs(target_dir)

            last_info = _get_dev_last_round(device_id_hex) or {}
            agg_round_id = last_info.get("agg_round_id")
            day_att = last_info.get("day")

            proc_time_ms = (time.perf_counter() - t_cycle_start) * 1000
            log_stat(addr=addr_str, device_id_hex=device_id_hex, epoch=epoch, session_id_hex=session_id_hex,
                     rx_bytes=len(ciphertext_bytes), dec_ms=decryption_time_ms, proc_ms=proc_time_ms,
                     meta={"type": "metrics", "attached_agg_round_id": agg_round_id, "lines": train_metrics_text.count("\n")})

            rx_meta = {
                "type": "metrics",
                "ok": True,
                "epoch": epoch,
                "sid": session_id_hex,
                "addr": addr_str,
                "attached_day": day_att,
                "attached_agg_round_id": agg_round_id,
                "cipher_len": len(ciphertext_bytes),
                "plain_len": len(decrypted),
                "dec_ms": round(decryption_time_ms, 3),
                "proc_ms": round(proc_time_ms, 3),
            }

            fid = _save_rx(
                target_dir, device_id_hex,
                ciphertext=ciphertext_bytes,
                plaintext=decrypted,
                aif1_weights=None,
                meta=rx_meta,
                train_metrics_text=train_metrics_text.strip(),
                test_metrics_text=test_metrics_text.strip() if test_metrics_text else None
            )
            flog_event(target_dir, device_id_hex, "RX", f"metrics received fid={fid}", extra=rx_meta)
            return None

        return None

    except Exception as e:
        proc_time_ms = (time.perf_counter() - t_cycle_start) * 1000
        log_stat(addr=addr_str, device_id_hex=device_id_hex, epoch=epoch, session_id_hex=session_id_hex,
                 rx_bytes=len(ciphertext_bytes), dec_ms=decryption_time_ms, proc_ms=proc_time_ms,
                 warn=f"Parse error: {e}")
        return None

# -------------------------------------------------
# Session loop
# -------------------------------------------------
def session_loop(conn: socket.socket, addr):
    addr_str = f"{addr[0]}:{addr[1]}"

    device_id_hex = None
    epoch = 0
    RK = None
    session_id_hex = None
    device_id = None

    try:
        sess = do_handshake(conn, expected_device_id=None)
        device_id = sess["device_id"]
        device_id_hex = device_id.hex()
        epoch = 1

        RK = speck_gen_round_keys_from_key96(sess["key96"])
        session_id_hex = sess["session_id"].hex()
        key96_hash = sha256_bytes(sess["key96"]).hex()

        connected_at = time.time()
        expires_at_wall = connected_at + SESSION_LIFETIME_S

        db_upsert_device_active(
            device_id=device_id_hex,
            addr=addr_str,
            epoch=epoch,
            session_id=session_id_hex,
            connected_at=connected_at,
            expires_at=expires_at_wall,
        )

        db_add_event(
            device_id=device_id_hex,
            event="connect",
            session_id=session_id_hex,
            epoch=epoch,
            details={"addr": addr_str, "key96_sha256": key96_hash},
        )

        print(f"[HS] OK {addr_str} device_id={device_id_hex} session_id={session_id_hex}")

        expires_at = time.monotonic() + SESSION_LIFETIME_S

        while True:
            now = time.monotonic()
            rekey_at = expires_at - REKEY_ADVANCE_S

            if now >= rekey_at:
                conn.sendall(bytes([MSG_REKEY_REQUEST]))
                print(f"[REKEY] Request sent to {addr_str} dev={device_id_hex} epoch={epoch}")

                first = _drain_app_data_until_clienthello(conn, timeout_s=REKEY_GRACE_S)
                new_sess = do_handshake(conn, expected_device_id=device_id, first_byte=first)

                epoch += 1
                sess = new_sess
                session_id_hex = sess["session_id"].hex()
                RK = speck_gen_round_keys_from_key96(sess["key96"])
                key96_hash = sha256_bytes(sess["key96"]).hex()

                now_wall = time.time()
                expires_at = time.monotonic() + SESSION_LIFETIME_S

                db_upsert_device_active(
                    device_id=device_id_hex,
                    addr=addr_str,
                    epoch=epoch,
                    session_id=session_id_hex,
                    connected_at=now_wall,
                    expires_at=now_wall + SESSION_LIFETIME_S,
                )

                db_add_event(
                    device_id=device_id_hex,
                    event="rekey",
                    session_id=session_id_hex,
                    epoch=epoch,
                    details={"key96_sha256": key96_hash},
                )

                print(f"[REKEY] OK {addr_str} dev={device_id_hex} new_session_id={session_id_hex} epoch={epoch}")
                continue

            wait_s = max(0.05, min(NORMAL_TIMEOUT_S, rekey_at - now))
            old_timeout = conn.gettimeout()
            conn.settimeout(wait_s)
            try:
                msg_type, payload = recv_frame(conn)
            except socket.timeout:
                if device_id_hex is not None:
                    db_touch_last_seen(device_id=device_id_hex)

                    pending = _pop_pending_for(device_id_hex)
                    if pending is not None:
                        resp_ct = speck_encrypt_bytes(pending["payload"], RK)
                        send_app_data(conn, resp_ct)

                        day = _now_date_str()
                        g = _aggid_to_group.get(pending["agg_round_id"])
                        if g:
                            final_dir = _final_round_dir(day, g["group_id"], device_id_hex, g["round_no"])
                            tx_meta = {"type": "pending_push", "agg_round_id": pending["agg_round_id"], **g}
                            _save_tx(final_dir, device_id_hex, ciphertext=resp_ct, plaintext=pending["payload"], meta=tx_meta)
                            flog_event(final_dir, device_id_hex, "TX", "pending_push sent", extra=tx_meta)
                continue
            finally:
                conn.settimeout(old_timeout)

            if msg_type == MSG_APP_DATA:
                if payload is None:
                    continue
                if device_id_hex is not None:
                    db_touch_last_seen(device_id=device_id_hex)

                response_ct = process_payload(
                    payload, RK,
                    addr_str=addr_str,
                    device_id_hex=device_id_hex,
                    epoch=epoch,
                    session_id_hex=session_id_hex,
                )

                if response_ct is not None:
                    send_app_data(conn, response_ct)
                else:
                    pending = _pop_pending_for(device_id_hex)
                    if pending is not None:
                        resp_ct = speck_encrypt_bytes(pending["payload"], RK)
                        send_app_data(conn, resp_ct)

                        day = _now_date_str()
                        g = _aggid_to_group.get(pending["agg_round_id"])
                        if g:
                            final_dir = _final_round_dir(day, g["group_id"], device_id_hex, g["round_no"])
                            tx_meta = {"type": "pending_after_none", "agg_round_id": pending["agg_round_id"], **g}
                            _save_tx(final_dir, device_id_hex, ciphertext=resp_ct, plaintext=pending["payload"], meta=tx_meta)
                            flog_event(final_dir, device_id_hex, "TX", "pending_after_none sent", extra=tx_meta)
                continue

            raise RuntimeError(f"Unexpected message type in app loop: 0x{msg_type:02x}")

    except Exception as e:
        if device_id_hex is not None:
            db_add_event(
                device_id=device_id_hex,
                event="error",
                session_id=session_id_hex,
                epoch=epoch if epoch else None,
                details={"error": str(e), "addr": addr_str},
            )
        raise
    finally:
        if device_id_hex is not None:
            db_update_device_closed(device_id=device_id_hex, reason="disconnect")
            db_add_event(
                device_id=device_id_hex,
                event="disconnect",
                session_id=session_id_hex,
                epoch=epoch if epoch else None,
                details={"addr": addr_str},
            )

# -------------------------------------------------
# TCP server
# -------------------------------------------------
def handle_client(conn: socket.socket, addr):
    with conn:
        addr_str = f"{addr[0]}:{addr[1]}"
        print(f"\n{'='*60}\n[TCP] Client connected: {addr_str}")
        session_loop(conn, addr)

def safe_handle(conn, addr):
    try:
        handle_client(conn, addr)
    except Exception as e:
        print(f"[TCP] DROP {addr[0]}:{addr[1]}: {e}")
        import traceback
        traceback.print_exc()
        try:
            conn.close()
        except Exception:
            pass

def main():
    db_init()
    LOG_ROOT.mkdir(parents=True, exist_ok=True)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    server.bind((HOST, PORT))
    server.listen(50)

    print(f"🚀 Unified server on {HOST}:{PORT} (DB: {DB_PATH})")
    print(f"📝 File logs: {LOG_ROOT.resolve()}")
    print("✅ Logging mode: NO BIN, only TXT/CSV/JSON")
    print(f"✅ MAX_AGG_ROUNDS={MAX_AGG_ROUNDS}")
    print(f"✅ MAX_GROUP_ROUNDS={MAX_GROUP_ROUNDS}")

    while True:
        conn, addr = server.accept()
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        conn.settimeout(NORMAL_TIMEOUT_S)
        th = threading.Thread(target=lambda: safe_handle(conn, addr), daemon=True)
        th.start()

if __name__ == "__main__":
    main()
