/*******************************************************
 * Purpose: measure execution speed of the PRESENT
 * implementation on the ESP32 platform.
 *
 * This firmware is used for encryption performance
 * benchmarking under repeated workloads.
 *******************************************************/
#include <Arduino.h>
#include <cstdint>

/* -------------------- PRESENT-80 -------------------- */

static const uint8_t SBOX[16] = {
    0xC, 0x5, 0x6, 0xB,
    0x9, 0x0, 0xA, 0xD,
    0x3, 0xE, 0xF, 0x8,
    0x4, 0x7, 0x1, 0x2
};

static const uint8_t SBOX_INV[16] = {
    0x5, 0xE, 0xF, 0x8,
    0xC, 0x1, 0x2, 0xD,
    0xB, 0x4, 0x6, 0x3,
    0x0, 0x7, 0x9, 0xA
};

uint64_t round_keys[32];

void present80_key_schedule(const uint8_t *key) {
    uint64_t k_hi = 0;
    uint16_t k_lo = 0;
    
    for (int i = 0; i < 8; i++) {
        k_hi = (k_hi << 8) | key[i];
    }
    k_lo = ((uint16_t)key[8] << 8) | key[9];
    
    for (int i = 0; i < 32; i++) {
        round_keys[i] = k_hi;
        
        uint64_t temp_hi = k_hi;
        uint16_t temp_lo = k_lo;
        
        k_hi = (temp_hi >> 19) | ((uint64_t)temp_lo << 45) | ((uint64_t)(temp_hi & 0x07) << 61);
        k_lo = (uint16_t)(temp_hi >> 3) & 0xFFFF;
        
        uint8_t s = (k_hi >> 60) & 0xF;
        k_hi = (k_hi & 0x0FFFFFFFFFFFFFFFULL) | ((uint64_t)SBOX[s] << 60);
        
        uint8_t counter = (i + 1) & 0x1F;
        k_hi ^= ((uint64_t)(counter >> 1) & 0x0F);
        k_lo ^= (uint16_t)((counter & 0x01) << 15);
    }
}

uint64_t present_pbox(uint64_t s) {
    uint64_t t = 0;
    for (int i = 0; i < 64; i++) {
        int pos = (16 * i) % 63;
        if (i == 63) pos = 63;
        t |= ((s >> i) & 1ULL) << pos;
    }
    return t;
}

uint64_t present_pbox_inv(uint64_t s) {
    uint64_t t = 0;
    for (int i = 0; i < 64; i++) {
        int pos = (i == 63) ? 63 : (16 * i) % 63;
        t |= ((s >> pos) & 1ULL) << i;
    }
    return t;
}

IRAM_ATTR uint64_t present80_encrypt(uint64_t block) {
    uint64_t state = block;
    
    for (int i = 0; i < 31; i++) {
        // AddRoundKey
        state ^= round_keys[i];
        
        uint64_t tmp = 0;
        for (int n = 0; n < 16; n++) {
            tmp |= (uint64_t)SBOX[(state >> (n * 4)) & 0xF] << (n * 4);
        }
        
        state = present_pbox(tmp);
    }
    
    state ^= round_keys[31];
    
    return state;
}

IRAM_ATTR uint64_t present80_decrypt(uint64_t block) {
    uint64_t state = block ^ round_keys[31];
    
    for (int r = 30; r >= 0; r--) {
        state = present_pbox_inv(state);
        
        uint64_t tmp = 0;
        for (int n = 0; n < 16; n++) {
            tmp |= (uint64_t)SBOX_INV[(state >> (n * 4)) & 0xF] << (n * 4);
        }
        
        state = tmp ^ round_keys[r];
    }
    
    return state;
}

void setup() {
    Serial.begin(115200);
    delay(10000);
    uint8_t key[10] = {0x00, 0x00, 0x00, 0x00, 0x00, 
                       0x00, 0x00, 0x00, 0x00, 0x00};

    Serial.println("=== Starting PRESENT-80 test ===");
    present80_key_schedule(key);
    uint64_t pt = 0x6f7220676e696c63; // plaintext
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
    ct = present80_encrypt(pt);
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
    dec = present80_decrypt(ct);
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
    const size_t CHUNKS = 20;
    const size_t PER_CHUNK = 250;
    noInterrupts();
    start_cycles = ESP.getCycleCount();
    int a = 0;
    for (size_t chunk = 0; chunk < CHUNKS; chunk++) {
        for (size_t i = 0; i < PER_CHUNK; i++) {
            ct = present80_encrypt(pt);
        }
        interrupts();
        yield();
        noInterrupts();
    }

    dummy += ct;
    enc_cycles = ESP.getCycleCount() - start_cycles;
    interrupts();
    enc_time_us = enc_cycles / (float)ESP.getCpuFreqMHz();
    const size_t ITERATIONS = CHUNKS * PER_CHUNK;

    Serial.println();
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
    for (size_t chunk = 0; chunk < CHUNKS; chunk++) {
        for (size_t i = 0; i < PER_CHUNK; i++) {
            dec = present80_decrypt(ct);
            dummy += dec;
        }
        interrupts();
        yield();
        noInterrupts();
    }
    dec_cycles = ESP.getCycleCount() - start_cycles;
    interrupts();
    dec_time_us = dec_cycles / (float)ESP.getCpuFreqMHz();

    Serial.println();
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

void loop() {
}
