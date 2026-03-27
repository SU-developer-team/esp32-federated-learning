#!/usr/bin/env python3
import re
import numpy as np

# ============================================================
# НАСТРОЙКИ — УКАЖИ ТУТ СВОИ ФАЙЛЫ
# ============================================================
PY_WEIGHTS_PATH  = "/home/admin/saved_weights/weights_000a000300012f02_epoch_1.txt"
ESP_WEIGHTS_PATH = "/home/admin/saved_weights/weights_0000ecf4a1453ab4_epoch_1.txt"

# Размеры сети (ДОЛЖНЫ совпадать с ESP и Python моделью)
F=39; H1=64; H2=64; H3=32; K=16

EXPECTED_FLOATS = (H1*F + H1) + (H2*H1 + H2) + (H3*H2 + H3) + (K*H3 + K)  # = 2332

# ============================================================

W_RE = re.compile(r"w\[(\d+)\]\s*=\s*([+-]?(?:\d+\.\d*|\d*\.\d+|\d+)(?:[eE][+-]?\d+)?)")

def read_weights_txt(path: str) -> np.ndarray:
    """
    Reads lines like: w[123]=0.123
    Returns float32 array with size = max_index+1, missing indices => error
    """
    idx_to_val = {}
    max_i = -1
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = W_RE.search(line)
            if not m:
                continue
            i = int(m.group(1))
            v = float(m.group(2))
            idx_to_val[i] = v
            if i > max_i:
                max_i = i

    if max_i < 0:
        raise SystemExit(f"No weights found in: {path} (expected lines like w[0]=...)")

    arr = np.full(max_i + 1, np.nan, dtype=np.float32)
    for i, v in idx_to_val.items():
        arr[i] = np.float32(v)

    if np.isnan(arr).any():
        missing = np.where(np.isnan(arr))[0]
        raise SystemExit(f"{path}: missing {missing.size} indices (example: {missing[:10].tolist()})")

    return arr


def split_layers(flat: np.ndarray):
    p = 0
    w1 = flat[p:p+H1*F].reshape(H1, F); p += H1*F
    b1 = flat[p:p+H1]; p += H1

    w2 = flat[p:p+H2*H1].reshape(H2, H1); p += H2*H1
    b2 = flat[p:p+H2]; p += H2

    w3 = flat[p:p+H3*H2].reshape(H3, H2); p += H3*H2
    b3 = flat[p:p+H3]; p += H3

    w4 = flat[p:p+K*H3].reshape(K, H3); p += K*H3
    b4 = flat[p:p+K]; p += K

    if p != flat.size:
        raise SystemExit(f"split_layers size mismatch: consumed={p} floats, flat.size={flat.size}")
    return (w1,b1,w2,b2,w3,b3,w4,b4)


def best_align(W_py, W_esp):
    if W_py.shape == W_esp.shape:
        err0 = float(np.mean(np.abs(W_py - W_esp)))
    else:
        err0 = float("inf")

    if W_py.shape == W_esp.T.shape:
        err1 = float(np.mean(np.abs(W_py - W_esp.T)))
    else:
        err1 = float("inf")

    if err1 < err0:
        return W_esp.T, True, err1
    return W_esp, False, err0


def align_and_flatten(py_flat, esp_flat):
    py = split_layers(py_flat)
    esp = split_layers(esp_flat)

    out = []
    info = []

    # fc1
    W, tr, e = best_align(py[0], esp[0]); info.append(("fc1", tr, e))
    out += [W.ravel(), esp[1]]

    # fc2
    W, tr, e = best_align(py[2], esp[2]); info.append(("fc2", tr, e))
    out += [W.ravel(), esp[3]]

    # fc3
    W, tr, e = best_align(py[4], esp[4]); info.append(("fc3", tr, e))
    out += [W.ravel(), esp[5]]

    # fc4
    W, tr, e = best_align(py[6], esp[6]); info.append(("fc4", tr, e))
    out += [W.ravel(), esp[7]]

    aligned_esp = np.concatenate(out).astype(np.float32)
    return aligned_esp, info


def cosine(a, b):
    a = a.astype(np.float64); b = b.astype(np.float64)
    na = np.linalg.norm(a); nb = np.linalg.norm(b)
    if na == 0 or nb == 0:
        return 0.0
    return float(np.dot(a, b) / (na * nb))


def summary(py, esp):
    diff = py - esp
    ad = np.abs(diff)
    max_abs = float(np.max(ad))
    mean_abs = float(np.mean(ad))
    p95 = float(np.percentile(ad, 95))
    denom = np.maximum(np.abs(py), 1e-12)
    mean_rel = float(np.mean(ad / denom))
    cos = cosine(py, esp)
    return max_abs, mean_abs, p95, mean_rel, cos


def main():
    print("Reading:")
    print("  PY :", PY_WEIGHTS_PATH)
    print("  ESP:", ESP_WEIGHTS_PATH)

    py_w = read_weights_txt(PY_WEIGHTS_PATH)
    esp_w = read_weights_txt(ESP_WEIGHTS_PATH)

    print("PY floats:", py_w.size, "ESP floats:", esp_w.size)
    if py_w.size != esp_w.size:
        raise SystemExit("Different vector sizes. Fix your logs so both contain same indices 0..N-1.")

    if py_w.size != EXPECTED_FLOATS:
        print(f"[WARN] floats={py_w.size}, expected={EXPECTED_FLOATS}. If dims differ, update F,H1,H2,H3,K.")

    # BEFORE
    max_abs, mean_abs, p95, mean_rel, cos = summary(py_w, esp_w)
    print("\nBefore alignment:")
    print(f"  max_abs_diff = {max_abs:.6f}")
    print(f"  mean_abs_diff = {mean_abs:.6f}")
    print(f"  p95_abs_diff = {p95:.6f}")
    print(f"  mean_rel_diff = {mean_rel:.6f}")
    print(f"  cosine_sim = {cos:.6f}")

    # AFTER
    aligned_esp, info = align_and_flatten(py_w, esp_w)
    max_abs, mean_abs, p95, mean_rel, cos = summary(py_w, aligned_esp)

    print("\nLayer transpose decisions (name, transposed?, mean_abs_err):")
    for name, tr, e in info:
        print(f"  {name}: transposed={tr}  err={e:.6f}")

    print("\nAfter alignment:")
    print(f"  max_abs_diff = {max_abs:.6f}")
    print(f"  mean_abs_diff = {mean_abs:.6f}")
    print(f"  p95_abs_diff = {p95:.6f}")
    print(f"  mean_rel_diff = {mean_rel:.6f}")
    print(f"  cosine_sim = {cos:.6f}")


if __name__ == "__main__":
    main()
