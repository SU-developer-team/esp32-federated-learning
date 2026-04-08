/*******************************************************
 * Purpose: measure execution speed of the SIMON
 * implementation on the ESP32 platform.
 *
 * This firmware is used for encryption performance
 * benchmarking under repeated workloads.
 *******************************************************/
#include <Arduino.h>
#include <cstdint>

/* РџР°СЂР°РјРµС‚СЂС‹ SIMON 64/96 */
#define ROTR32(x, r) ((x >> r) | (x << (32 - r)))
#define ROTL32(x, r) ((x << r) | (x >> (32 - r)))

int N = 32; // СЂР°Р·РјРµСЂ СЃР»РѕРІР° РІ Р±РёС‚Р°С…
int const BLOCK_SIZE = 2 * N; // СЂР°Р·РјРµСЂ Р±Р»РѕРєР° РІ Р±РёС‚Р°С…
int const T = 42; // С‡РёСЃР»Рѕ СЂР°СѓРЅРґРѕРІ

/* Z2 РєРѕРЅСЃС‚Р°РЅС‚Р° РґР»СЏ SIMON 64/96 */
static const uint64_t z2 = 0b10101111011100000011010010011000101000010001111110010110110011ULL;

/* Round keys */
uint32_t RK[T];

/* f-С„СѓРЅРєС†РёСЏ */
IRAM_ATTR inline uint32_t simon_f(uint32_t x) {
    return (ROTL32(x, 1) & ROTL32(x, 8)) ^ ROTL32(x, 2);
}

/* РЁРёС„СЂРѕРІР°РЅРёРµ Р±Р»РѕРєР° (64 Р±РёС‚Р°) */
IRAM_ATTR uint64_t simon_encrypt(uint64_t blk) {
    uint32_t left = uint32_t(blk >> 32);
    uint32_t right = uint32_t(blk);
    for (int i = 0; i <= T - 1; i++) {
        uint32_t tmp = left;
        left = right ^ simon_f(tmp) ^ RK[i];
        right = tmp;
    }
    return (uint64_t(left) << 32) | right;
}

/* Р”РµС€РёС„СЂРѕРІР°РЅРёРµ Р±Р»РѕРєР° (64 Р±РёС‚Р°) */
IRAM_ATTR uint64_t simon_decrypt(uint64_t blk) {
    uint32_t left = uint32_t(blk >> 32);
    uint32_t right = uint32_t(blk);
    for (int i = T - 1; i >= 0; --i) {
        uint32_t tmp = right;
        right = left ^ simon_f(tmp) ^ RK[i];
        left = tmp;
    }
    return (uint64_t(left) << 32) | right;
}

/* РљР»СЋС‡РµРІРѕР№ РіСЂР°С„РёРє (Key schedule) */
void simon_key_schedule_64_96(const uint32_t key[3]) {
    const uint32_t c = 0xFFFFFFFC;
    RK[0] = key[0];
    RK[1] = key[1];
    RK[2] = key[2];

    for (int i = 3; i <= T - 1; i++) {
        uint32_t tmp = ROTR32(RK[i - 1], 3);
        tmp ^= ROTR32(tmp, 1);
        uint32_t z_bit = (z2 >> (61 - ((i - 3) % 62))) & 1;
        RK[i] = RK[i - 3] ^ tmp ^ c ^ z_bit;
    }
}

void setup() {
    Serial.begin(115200);
    delay(10000); // Р—Р°РґРµСЂР¶РєР° 10 СЃРµРєСѓРЅРґ РґР»СЏ РёРЅРёС†РёР°Р»РёР·Р°С†РёРё Serial

    Serial.println("=== Starting SIMON 64/96 test ===");
    const uint32_t KEY96[3] = {0x03020100, 0x0B0A0908, 0x13121110};
    simon_key_schedule_64_96(KEY96);

    uint64_t pt = 0x6f7220676e696c63; // plaintext
    size_t data_size = sizeof(pt); // СЂР°Р·РјРµСЂ РІ Р±Р°Р№С‚Р°С…
    uint32_t data_bits = data_size * 8; // СЂР°Р·РјРµСЂ РІ Р±РёС‚Р°С…

    Serial.print("Plaintext (PT) = 0x");
    Serial.println(pt, HEX);
    Serial.print("Data size: ");
    Serial.print(data_size);
    Serial.print(" bytes (");
    Serial.print(data_bits);
    Serial.println(" bits)");

    // РР·РјРµСЂРµРЅРёРµ РІСЂРµРјРµРЅРё РѕРґРЅРѕР№ РёС‚РµСЂР°С†РёРё С€РёС„СЂРѕРІР°РЅРёСЏ
    Serial.println("=== Measuring single encryption ===");
    volatile uint64_t ct = 0; // volatile РґР»СЏ РїСЂРµРґРѕС‚РІСЂР°С‰РµРЅРёСЏ РѕРїС‚РёРјРёР·Р°С†РёРё
    noInterrupts();
    uint32_t start_cycles = ESP.getCycleCount();
    ct = simon_encrypt(pt);
    uint32_t enc_cycles = ESP.getCycleCount() - start_cycles;
    interrupts();
    float enc_time_us = enc_cycles / (float)ESP.getCpuFreqMHz();

    Serial.print("Encrypted text (CT) = 0x");
    Serial.println(ct, HEX);
    Serial.print("CPU Frequency: ");
    Serial.print(ESP.getCpuFreqMHz());
    Serial.println(" MHz");
    Serial.print("Cycles for 1 encryption: ");
    Serial.println(enc_cycles);
    Serial.print("Time for 1 encryption: ");
    Serial.print(enc_time_us, 4);
    Serial.println(" microseconds");

    // РР·РјРµСЂРµРЅРёРµ РІСЂРµРјРµРЅРё РѕРґРЅРѕР№ РёС‚РµСЂР°С†РёРё РґРµС€РёС„СЂРѕРІР°РЅРёСЏ
    Serial.println("=== Measuring single decryption ===");
    volatile uint64_t dec = 0;
    noInterrupts();
    start_cycles = ESP.getCycleCount();
    dec = simon_decrypt(ct);
    uint32_t dec_cycles = ESP.getCycleCount() - start_cycles;
    interrupts();
    float dec_time_us = dec_cycles / (float)ESP.getCpuFreqMHz();

    Serial.print("Decrypted text (DEC) = 0x");
    Serial.println(dec, HEX);
    Serial.print("Cycles for 1 decryption: ");
    Serial.println(dec_cycles);
    Serial.print("Time for 1 decryption: ");
    Serial.print(dec_time_us, 4);
    Serial.println(" microseconds");

    // РР·РјРµСЂРµРЅРёРµ РІСЂРµРјРµРЅРё 5000 РёС‚РµСЂР°С†РёР№ С€РёС„СЂРѕРІР°РЅРёСЏ (ESP.getCycleCount)
    Serial.println("\n=== Measuring 5000 encryptions (ESP.getCycleCount) ===");
    volatile uint64_t dummy = 0;
    const size_t ITERATIONS = 5000;
    noInterrupts();
    start_cycles = ESP.getCycleCount();
    for (size_t i = 0; i < ITERATIONS; i++) {
        ct = simon_encrypt(pt);
        
    }
    dummy += ct;
    enc_cycles = ESP.getCycleCount() - start_cycles;
    interrupts();
    enc_time_us = enc_cycles / (float)ESP.getCpuFreqMHz();

    Serial.print("Total cycles for 5000 encryptions: ");
    Serial.println(enc_cycles);
    Serial.print("Total time for 5000 encryptions: ");
    Serial.print(enc_time_us, 4);
    Serial.println(" microseconds");
    Serial.print("Average time per encryption: ");
    Serial.print(enc_time_us / ITERATIONS, 4);
    Serial.println(" microseconds");

    // РР·РјРµСЂРµРЅРёРµ РІСЂРµРјРµРЅРё 5000 РёС‚РµСЂР°С†РёР№ РґРµС€РёС„СЂРѕРІР°РЅРёСЏ (ESP.getCycleCount)
    Serial.println("\n=== Measuring 5000 decryptions (ESP.getCycleCount) ===");
    dummy = 0;
    noInterrupts();
    start_cycles = ESP.getCycleCount();
    for (size_t i = 0; i < ITERATIONS; i++) {
        dec = simon_decrypt(ct);
        dummy += dec;
    }
    dec_cycles = ESP.getCycleCount() - start_cycles;
    interrupts();
    dec_time_us = dec_cycles / (float)ESP.getCpuFreqMHz();

    Serial.print("Total cycles for 5000 decryptions: ");
    Serial.println(dec_cycles);
    Serial.print("Total time for 5000 decryptions: ");
    Serial.print(dec_time_us, 4);
    Serial.println(" microseconds");
    Serial.println("=== Encryption ===");
    Serial.print(enc_time_us / (ITERATIONS * data_size), 4);
    Serial.println(" mc/byte");
    Serial.print((data_size * ITERATIONS) / (enc_time_us / 1000000), 4);
    Serial.println(" bytes/c");
    Serial.println("=== Decryption ===");
    Serial.print(dec_time_us / (ITERATIONS * data_size), 4);
    Serial.println(" mc/byte");
    Serial.print((data_size * ITERATIONS) / (dec_time_us / 1000000), 4);
    Serial.println(" bytes/c");
    Serial.println("=== Test completed ===");
}

void loop() {
    // РџСѓСЃС‚РѕР№ С†РёРєР»
}