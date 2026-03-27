#!/usr/bin/env python3
# ---------------------------------------------------------
#  speck_server.py   –   MQTT-сервис для пакетов Speck-64/96
# ---------------------------------------------------------
#  • Подписывается на  iot/enc (binary payload от ESP32)
#  • Дешифрует последовательные 64-битные блоки (без HEX/индексов)
#  • Парсит binary: метки тензоров (idx + 0x01 + size16 BE + float32 data) + meta в конце (0xFF 0x00 + size16 + fields)
#  • Масштабирует веса на 0.5 с точностью до 4 знаков (flat array → reshape если нужно)
#  • Формирует ответ  {weights, srv_info}  → шифрует  → iot/raw (как HEX с индексами)
#  • Выводит дешифрованные данные, статистику, ответный JSON и блоки
#
#  Запуск:   python3 speck_server.py
# ---------------------------------------------------------

import json, time, numpy as np, paho.mqtt.client as mqtt
import struct  # Для unpack big-endian/short
import datetime  # Добавлено для timestamp в логе

# ───────── конфигурация ─────────
BROKER      = "broker.hivemq.com"
TOPIC_ENC   = "iot/enc"     # ESP32 ➜ сервер (подписка, binary)
TOPIC_RAW   = "iot/raw"     # сервер ➜ ESP32 (публикация, HEX)
SCALE_COEF  = 0.5           # коэффициент масштабирования

# ───────── Speck-64/96 параметры ─────────
ROUNDS = 26
KEY = [0x03020100, 0x07060504, 0x0B0A0908]  # k0, k1, k2 (как в ESP32)
MASK32 = 0xFFFFFFFF
ROR = lambda v, r: ((v >> r) | (v << (32 - r))) & MASK32
ROL = lambda v, r: ((v << r) | (v >> (32 - r))) & MASK32

def gen_round_keys(k):
    """Key-schedule для Speck-64/96, как в коде ESP32"""
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
    """Шифрует 64-битный блок (числовой)"""
    x = (plain_num >> 32) & MASK32
    y = plain_num & MASK32
    for k in RK:
        x = ((ROR(x, 8) + y) & MASK32) ^ k
        y = ROL(y, 3) ^ x
    return (x << 32) | y

def speck_decrypt(ct_num: int) -> int:
    """Дешифрует 64-битный блок (числовой)"""
    x = (ct_num >> 32) & MASK32
    y = ct_num & MASK32
    for k in reversed(RK):
        y = ROR(y ^ x, 3)
        x = ROL(((x ^ k) - y) & MASK32, 8)
    return (x << 32) | y

# ───────── MQTT обработка ─────────
t_cycle_start = 0.0

def on_connect(client, userdata, flags, rc):
    print("Соединено с брокером.")
    client.subscribe(TOPIC_ENC)

def on_message(client, userdata, msg):
    global t_cycle_start
    t_cycle_start = time.perf_counter()

    # ───── приём binary payload ─────
    payload_bytes = msg.payload  # bytes, без decode
    byte_count = len(payload_bytes)
    if byte_count % 8 != 0:
        print("⛔ Payload не кратен 8 байтам (невалидный шифртекст)")
        return

    # ───── дешифровка блоков ─────
    t_dec_start = time.perf_counter()
    decrypted_bytes = bytearray()
    block_count = byte_count // 8
    for i in range(block_count):
        # Извлечь 8 байт как little-endian uint64 (ESP32 LE)
        ct_bytes = payload_bytes[i*8:(i+1)*8]
        ct_num = struct.unpack('<Q', ct_bytes)[0]  # < для little-endian
        pt_num = speck_decrypt(ct_num)
        # Разбить pt_num на 8 байт (big-endian, как в ESP dec)
        for shift in range(56, -1, -8):
            ch = (pt_num >> shift) & 0xFF
            decrypted_bytes.append(ch)
    decryption_time_ms = (time.perf_counter() - t_dec_start) * 1000
    if decryption_time_ms > 0:
        decrypt_speed_bytes_per_sec = byte_count / (decryption_time_ms / 1000)
    else:
        decrypt_speed_bytes_per_sec = 0

    # ───── статистика ─────
    proc_time_ms = (time.perf_counter() - t_cycle_start) * 1000
    print(f"\n=== Статистика ===")
    print(f"Получено блоков: {block_count}")
    print(f"Получено байт: {byte_count}")
    print(f"Время дешифровки: {decryption_time_ms:.3f} мс")
    print(f"Скорость дешифровки: {decrypt_speed_bytes_per_sec:.2f} байт/с")
    print(f"Время обработки: {proc_time_ms:.3f} мс")

    try:
        # ───── парсинг binary формата от ESP32 ─────
        offset = 0
        tensors = {}  # {tensor_idx: np.array(weights)}
        total_weights_bytes = 0

        while offset < len(decrypted_bytes):
            if offset + 4 > len(decrypted_bytes):
                raise ValueError("Недостаточно байт для заголовка")

            idx = decrypted_bytes[offset]
            flag = decrypted_bytes[offset + 1]
            size = struct.unpack('>H', decrypted_bytes[offset + 2:offset + 4])[0]  # > для big-endian uint16

            if flag == 0x01:  # Тензор весов
                if offset + 4 + size > len(decrypted_bytes):
                    raise ValueError(f"Overflow для тензора {idx}")
                raw_data = decrypted_bytes[offset + 4:offset + 4 + size]
                weights_flat = np.frombuffer(raw_data, dtype=np.float32)  # LE, как в TFLite/ESP
                tensors[idx] = weights_flat
                total_weights_bytes += size
                offset += 4 + size
            elif idx == 0xFF and flag == 0x00:  # Meta
                if size != 12:
                    raise ValueError(f"Неверный размер meta: {size}")
                if offset + 4 + size > len(decrypted_bytes):
                    raise ValueError("Overflow для meta")
                meta_bytes = decrypted_bytes[offset + 4:offset + 4 + size]
                free_heap, cpu_freq_mhz, parsed_total_weights = struct.unpack('>III', meta_bytes)  # > BE uint32 x3
                if parsed_total_weights != total_weights_bytes:
                    raise ValueError(f"Meta total_weights mismatch: {parsed_total_weights} vs {total_weights_bytes}")
                packet = {
                    "esp_info": {
                        "free_heap": free_heap,
                        "cpu_freq_mhz": cpu_freq_mhz,
                        "total_weights_bytes": total_weights_bytes
                    }
                }
                offset += 4 + size
                break  # Meta в конце
            else:
                raise ValueError(f"Неизвестная метка: {idx:02x} {flag:02x}")

        if not tensors:
            raise ValueError("Нет тензоров в данных")

        print("\n=== Дешифрованные данные (meta) ===")
        print(json.dumps(packet, ensure_ascii=False))

        # ───── логирование parsed данных в TXT файл (понятный формат) ─────
        log_file = 'parsed_log.txt'
        timestamp = datetime.datetime.now().isoformat()
        with open(log_file, 'a') as f:
            f.write(f"[{timestamp}] Статистика:\n")
            f.write(f"Получено блоков: {block_count}\n")
            f.write(f"Получено байт: {byte_count}\n")
            f.write(f"Время дешифровки: {decryption_time_ms:.3f} мс\n")
            f.write(f"Скорость дешифровки: {decrypt_speed_bytes_per_sec:.2f} байт/с\n")
            f.write(f"Время обработки: {proc_time_ms:.3f} мс\n\n")
            f.write(f"[{timestamp}] Parsed Meta:\n")
            f.write(json.dumps(packet, indent=4, ensure_ascii=False) + "\n\n")
            f.write(f"[{timestamp}] Parsed Weights (тензоры):\n")
            for tensor_idx, tensor_weights in tensors.items():
                # Выводим как список floats с точностью .4f для читаемости
                weights_list = [f"{w}" for w in tensor_weights]
                f.write(f"Tensor {tensor_idx} (size: {len(weights_list)}):\n")
                f.write(", ".join(weights_list) + "\n\n")  # Полный список, разделённый запятыми
            f.write("--- End of entry ---\n\n")

        # ─── обработка весов (для примера, все конкатенируем в один flat) ───
        # Если multiple tensors, обработайте отдельно; здесь flat всех
        all_weights_flat = np.concatenate(list(tensors.values()))
        all_weights_flat *= SCALE_COEF

        # Reshape: адаптируйте под модель! Пример dummy 4D
        weights = all_weights_flat.reshape((1, 1, 1, len(all_weights_flat)))

        # tolist с formatting (4 уровня nested, точность .9f как в orig)
        weights = [[[[float(f"{w:}") for w in subsubsub] for subsubsub in subsub] for subsub in sub] for sub in weights.tolist()]

    except Exception as e:
        print("💥 Не распарсен binary:", e)
        print("Первые 32 байта decrypted:", decrypted_bytes[:32].hex(" "))
        return

    # ─── вывод esp_info ───
    if "esp_info" in packet:
        print("\nesp_info:", json.dumps(packet["esp_info"], ensure_ascii=False))

    print(f"Входной binary (meta + weights): {len(decrypted_bytes)} байт")

    # ─── формируем ответный JSON (компактный) ───
    response = {
        "weights": weights,
        "srv_info": {
            "scale_coef": SCALE_COEF,
            "srv_proc_ms": round(proc_time_ms, 3)
        }
    }
    resp_str = json.dumps(response, separators=(',', ':'))
    resp_bytes = resp_str.encode("utf-8")
    
    # ─── вывод парсенного ответного JSON ───
    print("\n=== Ответный JSON (перед шифрованием) ===")
    print(json.dumps(response, ensure_ascii=False))
    print(f"Выходной JSON: {len(resp_str)} байт")

    # ─── шифруем и публикуем (как HEX с индексами) ───
    parts = []
    for i in range(0, len(resp_bytes), 8):
        chunk = resp_bytes[i:i+8]
        plain_num = 0
        for b in chunk:
            plain_num = (plain_num << 8) | b
        plain_num <<= 8 * (8 - len(chunk))  # Паддинг слева (big-endian)
        ct_num = speck_encrypt(plain_num)
        parts.append(f"{i//8}:{ct_num:016x}")

    # ─── вывод отправляемых блоков ───
    blocks_str = ",".join(parts)
    print("\n=== Отправляемые блоки ===")
    print(blocks_str[:100] + "..." if len(blocks_str) > 100 else blocks_str)

    client.publish(TOPIC_RAW, blocks_str)
    print(f"✓ Обработано и отправлено {len(parts)} блоков.\n")

# ───────── запуск клиента ─────────
client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message
client.connect(BROKER, 1883, 60)
client.loop_forever()



# admin@raspberrypi:~/server/rinat $ wpa_passphrase "raspi" "12345678"
# network={
#         ssid="raspi"
#         #psk="12345678"
#         psk=9442a2831661a3cdab5b4d1b970592cdb0bb39c6934f37efd95010cce7dca3e9
# }
# admin@raspberrypi:~/server/rinat $
