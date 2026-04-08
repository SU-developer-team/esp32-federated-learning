/*******************************************************
 * Purpose: measure RAM usage of the PRESENT
 * implementation on the ESP32 platform.
 *
 * This firmware is used for runtime memory benchmarking
 * of the cipher implementation.
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

/* Р“РµРЅРµСЂР°С†РёСЏ СЂР°СѓРЅРґРѕРІС‹С… РєР»СЋС‡РµР№ (80 Р±РёС‚) */
void present80_key_schedule(const uint8_t *key) {
    // Р—Р°РіСЂСѓР¶Р°РµРј 80-Р±РёС‚РЅС‹Р№ РєР»СЋС‡: key[0..9] (10 Р±Р°Р№С‚)
    uint64_t k_hi = 0;
    uint16_t k_lo = 0;
    
    // k_hi СЃРѕРґРµСЂР¶РёС‚ Р±РёС‚С‹ [79:16]
    for (int i = 0; i < 8; i++) {
        k_hi = (k_hi << 8) | key[i];
    }
    // k_lo СЃРѕРґРµСЂР¶РёС‚ Р±РёС‚С‹ [15:0]
    k_lo = ((uint16_t)key[8] << 8) | key[9];
    
    for (int i = 0; i < 32; i++) {
        // РР·РІР»РµРєР°РµРј СЂР°СѓРЅРґРѕРІС‹Р№ РєР»СЋС‡ (Р±РёС‚С‹ [79:16])
        round_keys[i] = k_hi;
        
        // 1. Р¦РёРєР»РёС‡РµСЃРєРёР№ СЃРґРІРёРі РІР»РµРІРѕ РЅР° 61 Р±РёС‚ (СЌРєРІРёРІР°Р»РµРЅС‚РЅРѕ СЃРґРІРёРіСѓ РІРїСЂР°РІРѕ РЅР° 19)
        // Р”Р»СЏ 80-Р±РёС‚РЅРѕРіРѕ СЂРµРіРёСЃС‚СЂР°: [k_hi(64 bits) | k_lo(16 bits)]
        uint64_t temp_hi = k_hi;
        uint16_t temp_lo = k_lo;
        
        k_hi = (temp_hi >> 19) | ((uint64_t)temp_lo << 45) | ((uint64_t)(temp_hi & 0x07) << 61);
        k_lo = (uint16_t)(temp_hi >> 3) & 0xFFFF;
        
        // 2. S-box РЅР° СЃС‚Р°СЂС€РёРµ 4 Р±РёС‚Р° (Р±РёС‚С‹ [79:76])
        uint8_t s = (k_hi >> 60) & 0xF;
        k_hi = (k_hi & 0x0FFFFFFFFFFFFFFFULL) | ((uint64_t)SBOX[s] << 60);
        
        // 3. XOR СЂР°СѓРЅРґРѕРІРѕРіРѕ РЅРѕРјРµСЂР° РІ Р±РёС‚С‹ [19:15] 80-Р±РёС‚РЅРѕРіРѕ РєР»СЋС‡Р°
        uint8_t counter = (i + 1) & 0x1F;
        k_hi ^= ((uint64_t)(counter >> 1) & 0x0F);
        k_lo ^= (uint16_t)((counter & 0x01) << 15);
    }
}

/* РџРµСЂРµСЃС‚Р°РЅРѕРІРєР° Р±РёС‚РѕРІ */
uint64_t present_pbox(uint64_t s) {
    uint64_t t = 0;
    for (int i = 0; i < 64; i++) {
        int pos = (16 * i) % 63;
        if (i == 63) pos = 63;
        t |= ((s >> i) & 1ULL) << pos;
    }
    return t;
}

/* РЁРёС„СЂРѕРІР°РЅРёРµ Р±Р»РѕРєР° */
IRAM_ATTR uint64_t present80_encrypt(uint64_t block) {
    uint64_t state = block;
    
    for (int i = 0; i < 31; i++) {
        // AddRoundKey
        state ^= round_keys[i];
        
        // S-box СЃР»РѕР№
        uint64_t tmp = 0;
        for (int n = 0; n < 16; n++) {
            tmp |= (uint64_t)SBOX[(state >> (n * 4)) & 0xF] << (n * 4);
        }
        
        // P-box СЃР»РѕР№
        state = present_pbox(tmp);
    }
    
    // РџРѕСЃР»РµРґРЅРёР№ AddRoundKey (31-Р№ СЂР°СѓРЅРґ)
    state ^= round_keys[31];
    
    return state;
}

void setup() {
    Serial.begin(115200);
    delay(1000);
    
    // РљР»СЋС‡: 00000000000000000000 (80 Р±РёС‚ = 10 Р±Р°Р№С‚)
    uint8_t key[10] = {0x00, 0x00, 0x00, 0x00, 0x00, 
                       0x00, 0x00, 0x00, 0x00, 0x00};
    present80_key_schedule(key);
    uint64_t plaintext = 0x0000000000000000ULL;
    uint64_t ciphertext = present80_encrypt(plaintext);
}

void loop() {
    // РџСѓСЃС‚РѕР№ С†РёРєР»
}