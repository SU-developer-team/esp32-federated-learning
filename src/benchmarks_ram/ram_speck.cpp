/*******************************************************
 * Purpose: measure RAM usage of the SPECK
 * implementation on the ESP32 platform.
 *
 * This firmware is used for runtime memory benchmarking
 * of the cipher implementation.
 *******************************************************/
#include <Arduino.h>

#define ROTR32(x, r) ((uint32_t)(((x) >> (r)) | ((x) << (32 - (r)))))
#define ROTL32(x, r) ((uint32_t)(((x) << (r)) | ((x) >> (32 - (r)))))

uint32_t RK[26];
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
void setup(){
    Serial.begin(115200);
    const uint32_t KEY96[3] = { 0x03020100, 0x0B0A0908, 0x13121110 };
    genRK96(KEY96);
    uint64_t pt = ((uint64_t)0x74614620 << 32) | 0x736e6165;
    enc64_fast(pt);
}
void loop(){

}