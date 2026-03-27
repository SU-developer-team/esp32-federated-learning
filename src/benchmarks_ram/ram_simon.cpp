#include <Arduino.h>
#include <cstdint>

/* Параметры SIMON 64/96 */
#define ROTR32(x, r) ((x >> r) | (x << (32 - r)))
#define ROTL32(x, r) ((x << r) | (x >> (32 - r)))

int const BLOCK_SIZE = 64; // размер блока в битах
int const T = 42; // число раундов

/* Z2 константа для SIMON 64/96 */
static const uint64_t z2 = 0b10101111011100000011010010011000101000010001111110010110110011ULL;

/* Round keys */
uint32_t RK[T];

/* f-функция */
IRAM_ATTR inline uint32_t simon_f(uint32_t x) {
    return (ROTL32(x, 1) & ROTL32(x, 8)) ^ ROTL32(x, 2);
}

/* Шифрование блока (64 бита) */
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

/* Ключевой график (Key schedule) */
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
    const uint32_t KEY96[3] = {0x03020100, 0x0B0A0908, 0x13121110};
    simon_key_schedule_64_96(KEY96);
    uint64_t pt = 0x6f7220676e696c63; // plaintext
    simon_encrypt(pt);
}

void loop() {
    // Пустой цикл
}