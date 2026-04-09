/*******************************************************
 * Purpose: measure execution speed of the SPECK
 * implementation on the ESP32 platform.
 *
 * This firmware is used for encryption performance
 * benchmarking under repeated workloads.
 *******************************************************/
#include <Arduino.h>
#include <cstdint>

#define ROTR32(x, r) ((uint32_t)(((x) >> (r)) | ((x) << (32 - (r)))))
#define ROTL32(x, r) ((uint32_t)(((x) << (r)) | ((x) >> (32 - (r)))))

uint32_t RK[26];
uint64_t ctBuf[600];

void genRK96(const uint32_t k[3]) {
    uint32_t l[2];
    uint32_t rk;

    l[1] = k[2];
    l[0] = k[1];
    rk = k[0];

    RK[0] = rk;

    for (int i = 0; i < 25; i++) {
        uint32_t new_l = (rk + ROTR32(l[i % 2], 8)) ^ i;
        l[i % 2] = new_l;
        rk = ROTL32(rk, 3) ^ new_l;
        RK[i + 1] = rk;
    }
}

inline uint64_t enc64_fast(uint64_t blk)
{

    uint32_t x = (uint32_t)(blk >> 32), y = (uint32_t)blk;
    for (int r = 0; r < 26; ++r) {
        x = (ROTR32(x, 8) + y) ^ RK[r];
        y = ROTL32(y, 3) ^ x;
    }
    return ((uint64_t)x << 32) | y;
}

inline uint64_t dec64_fast(uint64_t blk)
{
    uint32_t s = 0;
    uint32_t x = (uint32_t)(blk >> 32), y = (uint32_t)blk;
    for (int r = 25; r >= 0; --r) {
        s = x ^ y;
        y = ROTR32(y ^ x, 3);
        x = ROTL32((x ^ RK[r]) - y, 8);
    }
    return ((uint64_t)x << 32) | y;
}
void test_vectors() {
    
    Serial.begin(115200);
    delay(10000);

    Serial.println("=== Starting SPECK 64/96 test ===");
    const uint32_t KEY96[3] = { 0x03020100, 0x0B0A0908, 0x13121110 };
    genRK96(KEY96);

    uint64_t pt = ((uint64_t)0x74614620 << 32) | 0x736e6165;
    size_t data_size = sizeof(pt);
    uint32_t data_bits = data_size * 8;

    Serial.print("Plaintext (PT) = 0x");
    Serial.println(pt, HEX);
    Serial.print("Data size: ");
    Serial.print(data_size);
    Serial.print(" bytes (");
    Serial.print(data_bits);
    Serial.println(" bits)");

    Serial.println("=== Measuring single encryption ===");
    volatile uint64_t ct = 0;
    noInterrupts();
    uint32_t start_cycles = ESP.getCycleCount();
    ct = enc64_fast(pt);
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

    Serial.println("=== Measuring single decryption ===");
    volatile uint64_t dec = 0;
    noInterrupts();
    start_cycles = ESP.getCycleCount();
    dec = dec64_fast(ct);
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

    Serial.println("\n=== Measuring 5000 encryptions (ESP.getCycleCount) ===");
    volatile uint64_t dummy = 0;
    const size_t ITERATIONS = 5000;
    noInterrupts();
    start_cycles = ESP.getCycleCount();
    for (size_t i = 0; i < ITERATIONS; i++) {
        ct = enc64_fast(pt);
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

    Serial.println("\n=== Measuring 5000 decryptions (ESP.getCycleCount) ===");
    dummy = 0;
    noInterrupts();
    start_cycles = ESP.getCycleCount();
    for (size_t i = 0; i < ITERATIONS; i++) {
        dec = dec64_fast(ct);
    }
    dummy += dec;
    dec_cycles = ESP.getCycleCount() - start_cycles;
    interrupts();
    dec_time_us = dec_cycles / (float)ESP.getCpuFreqMHz();

    Serial.print("Total cycles for 5000 decryptions: ");
    Serial.println(dec_cycles);
    Serial.print("Total time for 5000 decryptions: ");
    Serial.print(dec_time_us, 4);
    Serial.println(" microseconds");
    Serial.print("Average time per decryption: ");
    Serial.print(dec_time_us / ITERATIONS, 4);
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
void setup(){
    Serial.begin(115200);
    test_vectors();
}
void loop() {
}
