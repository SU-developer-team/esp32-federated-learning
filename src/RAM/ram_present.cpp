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

/* Генерация раундовых ключей (80 бит) */
void present80_key_schedule(const uint8_t *key) {
    // Загружаем 80-битный ключ: key[0..9] (10 байт)
    uint64_t k_hi = 0;
    uint16_t k_lo = 0;
    
    // k_hi содержит биты [79:16]
    for (int i = 0; i < 8; i++) {
        k_hi = (k_hi << 8) | key[i];
    }
    // k_lo содержит биты [15:0]
    k_lo = ((uint16_t)key[8] << 8) | key[9];
    
    for (int i = 0; i < 32; i++) {
        // Извлекаем раундовый ключ (биты [79:16])
        round_keys[i] = k_hi;
        
        // 1. Циклический сдвиг влево на 61 бит (эквивалентно сдвигу вправо на 19)
        // Для 80-битного регистра: [k_hi(64 bits) | k_lo(16 bits)]
        uint64_t temp_hi = k_hi;
        uint16_t temp_lo = k_lo;
        
        k_hi = (temp_hi >> 19) | ((uint64_t)temp_lo << 45) | ((uint64_t)(temp_hi & 0x07) << 61);
        k_lo = (uint16_t)(temp_hi >> 3) & 0xFFFF;
        
        // 2. S-box на старшие 4 бита (биты [79:76])
        uint8_t s = (k_hi >> 60) & 0xF;
        k_hi = (k_hi & 0x0FFFFFFFFFFFFFFFULL) | ((uint64_t)SBOX[s] << 60);
        
        // 3. XOR раундового номера в биты [19:15] 80-битного ключа
        uint8_t counter = (i + 1) & 0x1F;
        k_hi ^= ((uint64_t)(counter >> 1) & 0x0F);
        k_lo ^= (uint16_t)((counter & 0x01) << 15);
    }
}

/* Перестановка битов */
uint64_t present_pbox(uint64_t s) {
    uint64_t t = 0;
    for (int i = 0; i < 64; i++) {
        int pos = (16 * i) % 63;
        if (i == 63) pos = 63;
        t |= ((s >> i) & 1ULL) << pos;
    }
    return t;
}

/* Шифрование блока */
IRAM_ATTR uint64_t present80_encrypt(uint64_t block) {
    uint64_t state = block;
    
    for (int i = 0; i < 31; i++) {
        // AddRoundKey
        state ^= round_keys[i];
        
        // S-box слой
        uint64_t tmp = 0;
        for (int n = 0; n < 16; n++) {
            tmp |= (uint64_t)SBOX[(state >> (n * 4)) & 0xF] << (n * 4);
        }
        
        // P-box слой
        state = present_pbox(tmp);
    }
    
    // Последний AddRoundKey (31-й раунд)
    state ^= round_keys[31];
    
    return state;
}

void setup() {
    Serial.begin(115200);
    delay(1000);
    
    // Ключ: 00000000000000000000 (80 бит = 10 байт)
    uint8_t key[10] = {0x00, 0x00, 0x00, 0x00, 0x00, 
                       0x00, 0x00, 0x00, 0x00, 0x00};
    present80_key_schedule(key);
    uint64_t plaintext = 0x0000000000000000ULL;
    uint64_t ciphertext = present80_encrypt(plaintext);
}

void loop() {
    // Пустой цикл
}