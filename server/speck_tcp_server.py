#!/usr/bin/env python3
# ---------------------------------------------------------
# speck_server.py – ОПТИМИЗИРОВАННЫЙ TCP-сервер
# ---------------------------------------------------------

import json, time, numpy as np
import struct
import datetime
import socket

# ───────── конфигурация ─────────
PORT = 1883
SCALE_COEF = 0.5

# ───────── Speck-64/96 параметры ─────────
ROUNDS = 26
KEY = [0x03020100, 0x07060504, 0x0B0A0908]
MASK32 = 0xFFFFFFFF
ROR = lambda v, r: ((v >> r) | (v << (32 - r))) & MASK32
ROL = lambda v, r: ((v << r) | (v >> (32 - r))) & MASK32

def gen_round_keys(k):
    l = [0] * 2
    l[1] = k[2]
    l[0] = k[1]
    rk = k[0]
    rks = [rk]
    for i in range(25):
        new_l = (rk + ROR(l[i % 2], 8)) & MASK32
        new_l ^= i
        l[i % 2] = new_l
        rk = ROL(rk, 3) ^ new_l
        rks.append(rk)
    return rks

RK = gen_round_keys(KEY)

def speck_encrypt(plain_num: int) -> int:
    x = (plain_num >> 32) & MASK32
    y = plain_num & MASK32
    for k in RK:
        x = ((ROR(x, 8) + y) & MASK32) ^ k
        y = ROL(y, 3) ^ x
    return (x << 32) | y

def speck_decrypt(ct_num: int) -> int:
    x = (ct_num >> 32) & MASK32
    y = ct_num & MASK32
    for k in reversed(RK):
        y = ROR(y ^ x, 3)
        x = ROL(((x ^ k) - y) & MASK32, 8)
    return (x << 32) | y

# ───────── обработка входящего payload ─────────
def process_payload(payload_bytes):
    t_cycle_start = time.perf_counter()

    byte_count = len(payload_bytes)
    if byte_count % 8 != 0:
        print("⛔ Payload не кратен 8 байтам")
        return None

    # ───── дешифровка ─────
    t_dec_start = time.perf_counter()
    decrypted_bytes = bytearray()
    block_count = byte_count // 8
    for i in range(block_count):
        ct_bytes = payload_bytes[i*8:(i+1)*8]
        ct_num = struct.unpack('<Q', ct_bytes)[0]
        pt_num = speck_decrypt(ct_num)
        for shift in range(56, -1, -8):
            decrypted_bytes.append((pt_num >> shift) & 0xFF)

    decryption_time_ms = (time.perf_counter() - t_dec_start) * 1000
    decrypt_speed = byte_count / (decryption_time_ms / 1000) if decryption_time_ms > 0 else 0

    proc_time_ms = (time.perf_counter() - t_cycle_start) * 1000

    print(f"\n=== Статистика ===")
    print(f"Получено блоков: {block_count}")
    print(f"Получено байт: {byte_count}")
    print(f"Время дешифровки: {decryption_time_ms:.3f} мс")
    print(f"Скорость дешифровки: {decrypt_speed:.2f} байт/с")
    print(f"Время обработки: {proc_time_ms:.3f} мс")

    # ───── парсинг бинарного формата от ESP32 ─────────
    try:
        offset = 0
        tensors = {}
        total_weights_bytes = 0

        while offset < len(decrypted_bytes):
            if offset + 4 > len(decrypted_bytes):
                raise ValueError("Недостаточно байт для заголовка")

            idx = decrypted_bytes[offset]
            flag = decrypted_bytes[offset + 1]
            size = struct.unpack('>H', decrypted_bytes[offset + 2:offset + 4])[0]

            if flag == 0x01:  # тензор весов
                if offset + 4 + size > len(decrypted_bytes):
                    raise ValueError(f"Overflow для тензора {idx}")
                raw_data = decrypted_bytes[offset + 4:offset + 4 + size]
                weights_flat = np.frombuffer(raw_data, dtype=np.float32)
                tensors[idx] = weights_flat
                total_weights_bytes += size
                offset += 4 + size

            elif idx == 0xFF and flag == 0x00:  # мета в конце
                if size != 12:
                    raise ValueError(f"Неверный размер meta: {size}")
                meta_bytes = decrypted_bytes[offset + 4:offset + 4 + size]
                free_heap, cpu_freq_mhz, parsed_total_weights = struct.unpack('>III', meta_bytes)

                if parsed_total_weights != total_weights_bytes:
                    print("⚠️ Meta total_weights не совпадает с реальным!")

                packet = {
                    "esp_info": {
                        "free_heap": free_heap,
                        "cpu_freq_mhz": cpu_freq_mhz,
                        "total_weights_bytes": total_weights_bytes
                    }
                }
                offset += 4 + size
                break
            else:
                raise ValueError(f"Неизвестная метка: {idx:02x} {flag:02x}")

        # ───── запись в лог ─────────
        log_file = 'parsed_log.txt'
        timestamp = datetime.datetime.now().isoformat()
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(f"[{timestamp}] Статистика + Meta:\n")
            f.write(json.dumps(packet, indent=4, ensure_ascii=False) + "\n")
            f.write(f"Тензоров получено: {len(tensors)}\n")
            f.write(f"Обработка заняла: {proc_time_ms:.3f} мс\n")
            f.write("-" * 50 + "\n\n")

        print("\nesp_info:", json.dumps(packet["esp_info"], ensure_ascii=False))

        # ───── МАЛЕНЬКИЙ ОТВЕТ ─────────
        response = {
            "status": "ok",
            "scaled": True,
            "weights_received_bytes": total_weights_bytes,
            "tensors_count": len(tensors),
            "srv_proc_ms": round(proc_time_ms, 3)
        }

        resp_str = json.dumps(response, separators=(',', ':'))
        resp_bytes = resp_str.encode("utf-8")

        print("\n=== ОТВЕТ СЕРВЕРА (маленький JSON) ===")
        print(resp_str)
        print(f"Длина ответа: {len(resp_bytes)} байт")

        # Шифруем ответ
        t_enc_start = time.perf_counter()
        ct_bytes = b''
        for i in range(0, len(resp_bytes), 8):
            chunk = resp_bytes[i:i+8]
            plain_num = 0
            for b in chunk:
                plain_num = (plain_num << 8) | b
            plain_num <<= 8 * (8 - len(chunk))
            ct_num = speck_encrypt(plain_num)
            ct_bytes += struct.pack('<Q', ct_num)

        enc_time_ms = (time.perf_counter() - t_enc_start) * 1000
        print(f"✓ Зашифровано {len(ct_bytes)//8} блоков за {enc_time_ms:.3f} мс")
        return ct_bytes

    except Exception as e:
        print("💥 Ошибка парсинга:", e)
        import traceback
        traceback.print_exc()
        return None

# ───────── ОПТИМИЗИРОВАННЫЙ TCP сервер ─────────
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# ✅ КРИТИЧНО: Отключаем Nagle algorithm для низкой задержки
server.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
server.bind(('0.0.0.0', PORT))
server.listen(5)  # Увеличена очередь подключений
print(f"🚀 Сервер запущен на порту {PORT} (оптимизированная версия)")

while True:
    try:
        conn, addr = server.accept()
        print(f"\n{'='*60}")
        print(f"Подключение от {addr}")

        # ✅ Настройка таймаутов и параметров соединения
        conn.settimeout(5.0)  # 5 секунд таймаут
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        # ✅ ОПТИМИЗИРОВАННОЕ ЧТЕНИЕ: большой буфер + таймаут
        t_rx_start = time.perf_counter()
        data = b''
        expected_size = 40000  # ~36-40 KB ожидаем

        # Читаем данные большими кусками
        while len(data) < expected_size:
            try:
                # ✅ КЛЮЧЕВОЕ ИЗМЕНЕНИЕ: буфер 32 KB вместо 4 KB!
                chunk = conn.recv(32768)
                if not chunk:
                    break
                data += chunk

                # Если получили данные и больше ничего не приходит 100ms - выходим
                conn.settimeout(0.1)

            except socket.timeout:
                # Таймаут - значит данные закончились
                if len(data) > 0:
                    break
                else:
                    print("⚠️ Таймаут без данных")
                    break

        rx_time_ms = (time.perf_counter() - t_rx_start) * 1000

        if len(data) > 0:
            rx_speed_kbps = (len(data) / (rx_time_ms / 1000)) / 1024
            rx_speed_mbps = rx_speed_kbps * 8 / 1024
            print(f"📥 RX: {len(data)} байт за {rx_time_ms:.3f} мс ({rx_speed_kbps:.2f} KB/s | {rx_speed_mbps:.3f} Mbit/s)")

            # Обработка
            t_process_start = time.perf_counter()
            response = process_payload(data)
            process_time_ms = (time.perf_counter() - t_process_start) * 1000

            if response:
                # ✅ Отправка ответа одним куском
                t_tx_start = time.perf_counter()
                conn.sendall(response)
                tx_time_ms = (time.perf_counter() - t_tx_start) * 1000

                tx_speed_kbps = (len(response) / (tx_time_ms / 1000)) / 1024 if tx_time_ms > 0 else 0
                tx_speed_mbps = tx_speed_kbps * 8 / 1024
                print(f"📤 TX: {len(response)} байт за {tx_time_ms:.3f} мс ({tx_speed_kbps:.2f} KB/s | {tx_speed_mbps:.3f} Mbit/s)")

                # Итоговая статистика
                total_time_ms = rx_time_ms + process_time_ms + tx_time_ms
                total_data_kb = (len(data) + len(response)) / 1024
                total_speed_kbps = total_data_kb / (total_time_ms / 1000)
                total_speed_mbps = total_speed_kbps * 8 / 1024

                print(f"\n📊 ИТОГО:")
                print(f"  RX: {rx_time_ms:.1f} мс | Process: {process_time_ms:.1f} мс | TX: {tx_time_ms:.1f} мс")
                print(f"  Всего: {total_time_ms:.1f} мс | {total_speed_kbps:.2f} KB/s | {total_speed_mbps:.3f} Mbit/s")
                print(f"{'='*60}\n")
        else:
            print("⚠️ Получены пустые данные")

        conn.close()

    except Exception as e:
        print(f"💥 Ошибка обработки соединения: {e}")
        import traceback
        traceback.print_exc()
        try:
            conn.close()
        except:
            pass
