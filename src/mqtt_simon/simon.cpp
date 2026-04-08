/*******************************************************
 * Purpose: demonstrate MQTT communication protected with
 * the SIMON block cipher on the ESP32 device.
 *
 * This firmware publishes and receives encrypted payloads
 * and is used to study secure MQTT behavior and overhead.
 *******************************************************/
#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <esp_attr.h>
#include "esp_heap_caps.h"
#include "esp_system.h"

volatile uint32_t enc_pkt_cyc = 0, dec_pkt_cyc = 0;
volatile uint32_t enc_pkt_cnt = 0, dec_pkt_cnt = 0;
volatile uint32_t parse_cyc = 0, parse_cnt = 0;

/* в”Ђв”Ђв”Ђв”Ђв”Ђ helpers & timer в”Ђв”Ђв”Ђв”Ђв”Ђ */
#define TS_START(var) uint32_t var = ESP.getCycleCount()
static inline float cyc2us(uint32_t d){ return d / (float)ESP.getCpuFreqMHz(); }

#define ROTR32(x, r) ((x >> r) | (x << (32 - r)))
#define ROTL32(x, r) ((x << r) | (x >> (32 - r)))

/* ------------------------------------------------------------------
 *            CONSTANTS
 * -----------------------------------------------------------------*/
constexpr const char* SSID   = "Wi-Fi 4G";
constexpr const char* PASS   = "'dffhAO&&S4G'";
constexpr const char* BROKER = "broker.hivemq.com";
constexpr uint16_t    PORT   = 1883;

constexpr const char* TOPIC_RAW = "iot/raw";
constexpr const char* TOPIC_ENC = "iot/enc";
constexpr const char* CLIENT_ID = "esp32-client";
constexpr size_t      MQTT_BUF  = 8192;

/* Round-keys РґР»СЏ SIMON 64/96 */
int const T = 42; // С‡РёСЃР»Рѕ СЂР°СѓРЅРґРѕРІ
uint32_t RK[T];

/* РњРёРЅРё-РїСЂРёРјРµСЂ РІРµСЃРѕРІ */
const char WEIGHTS[] PROGMEM = R"RAW([[[[-0.22269929945468903, -0.0020684152841567993, -0.028627386316657066, -0.04175390675663948, 0.02046719379723072, 0.08776327967643738, -0.06972722709178925, -0.0024031028151512146, -0.1369350701570511, 0.07604920864105225, -0.15909017622470856, -0.11621670424938202, 0.01977522112429142, 0.05549396574497223, -0.006383150815963745, -0.38754409551620483, 0.019943036139011383, -0.1304830014705658, 0.09386514127254486, 0.08403369039297104, 0.04103871434926987, 0.001162276603281498, -0.21528294682502747, 0.08617235720157623, -0.0812213271856308, 0.10415084660053253, -0.047551874071359634, -0.10483313351869583, 0.04774774610996246, -0.11372575163841248, 0.032191865146160126, 0.047332197427749634, 0.05957270786166191, -0.003320351243019104, -0.19130374491214752, -0.5056506395339966, 0.0594739094376564, 0.09424041211605072, -0.005374163389205933, -0.09813196212053299, 0.06058444082736969, -0.012654859572649002, -0.20923274755477905, -0.029386963695287704, 0.03915838152170181, 0.03987979143857956, 0.118799589574337, -0.1517963707447052, -0.12310691177845001, 0.02752935327589512, -0.07804187387228012, 0.0912553071975708, -0.028958793729543686, 0.01714150607585907, 0.06191866844892502, -0.13848546147346497, -0.03784804418683052, -0.09685277193784714, -0.13155832886695862, 0.04564664885401726, -0.12638293206691742, -0.4195791482925415, -0.07618607580661774, -0.06411894410848618]], [[-0.38721707463264465, 0.10108035802841187, -0.547479510307312, -0.142031729221344, -0.25518128275871277, 0.08117641508579254, 0.032983507961034775, -0.017013398930430412, 0.007050002459436655, -0.054755937308073044, 0.020490612834692, -0.49241167306900024, 0.0165400467813015, 0.06026015430688858, 0.0010598376393318176, -0.5442346334457397, 0.0368630550801754, -0.03570526838302612, -0.038232430815696716, -0.07469354569911957, 0.025067295879125595, -0.015666861087083817, 0.018609998747706413, -0.3061330318450928, 0.05790018290281296, 0.048334307968616486, -0.24385195970535278, -0.07935438305139542, -0.1819179654121399, 0.11193083971738815, 0.026050634682178497, -0.016550563275814056, 0.06019206717610359, -0.36496007442474365, -0.02235141023993492, 0.008374023251235485, 0.024556607007980347, -0.05442333221435547, -0.6205769777297974, -0.2319582849740982, -0.1597018837928772, 0.11711525917053223, -0.08185379207134247, 0.03631089627742767, -0.11780697852373123, 0.07119498401880264, 0.00010193139314651489, -0.2678371071815491, 0.03866139054298401, -0.42356234788894653, 0.09636807441711426, -0.01641259714961052, -0.12778903543949127, -1.0513049364089966, -0.04323035851120949, 0.08268750458955765, -0.31393373012542725, 0.02999350056052208, -0.08584080636501312, -0.23677249252796173, -0.02576761692762375, -0.2608223557472229, -0.1403527706861496, -0.007824636995792389]]]])RAW";

/* Р‘СѓС„РµСЂС‹ */
StaticJsonDocument<4096> doc;
char            jsonBuf[4096];
uint64_t        ctBuf[600];

volatile uint32_t enc_cyc=0, dec_cyc=0;
volatile uint32_t enc_cnt=0, dec_cnt=0;

/* MQTT */
WiFiClient   net;
PubSubClient mqtt(net);

/* РРЎРџР РђР’Р›Р•РќРћ: РљР»СЋС‡ РґР»СЏ SIMON 64/96 РІ РїСЂР°РІРёР»СЊРЅРѕРј С„РѕСЂРјР°С‚Рµ */
const uint32_t KEY96[3] = { 0x03020100, 0x0B0A0908, 0x13121110 };// const uint32_t KEY96[3] = { 0x03020100, 0x0B0A0908, 0x13121110 };

/* в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ SIMON IMPLEMENTATION в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ */

/* РРЎРџР РђР’Р›Р•РќРћ: z2 РїРѕСЃР»РµРґРѕРІР°С‚РµР»СЊРЅРѕСЃС‚СЊ РґР»СЏ SIMON 64/96 РїРѕ СЃС‚Р°РЅРґР°СЂС‚Сѓ */
static const uint64_t z2 = 0b10101111011100000011010010011000101000010001111110010110110011ULL;

/* РРЎРџР РђР’Р›Р•РќРћ: SIMON key schedule РґР»СЏ SIMON 64/96 - СЃС‚СЂРѕРіРѕ РїРѕ СЃС‚Р°РЅРґР°СЂС‚Сѓ */
void simon_key_schedule_64_96(const uint32_t key[3]) {
    const uint32_t c = 0xFFFFFFFC;  // c = 2^n - 4
    
    // РџРµСЂРІС‹Рµ 3 РєР»СЋС‡Р° СЂР°СѓРЅРґР° - СЌС‚Рѕ РёСЃС…РѕРґРЅС‹Р№ РєР»СЋС‡
    RK[0] = key[0];
    RK[1] = key[1]; 
    RK[2] = key[2];
    
    // Р“РµРЅРµСЂРёСЂСѓРµРј РѕСЃС‚Р°РІС€РёРµСЃСЏ РєР»СЋС‡Рё (42 СЂР°СѓРЅРґР° РґР»СЏ SIMON 64/96)
    for (int i = 3; i <= T-1; i++) {
        uint32_t tmp = ROTR32(RK[i-1], 3);     // S^-3(k[i-1])                        // S^-3(k[i-1]) XOR k[i-3]
        tmp ^= ROTR32(tmp, 1);                 // (I XOR S^-1)(S^-3(k[i-1]) XOR k[i-3])
        uint32_t z_bit = (z2 >> (61 - ((i - 3) % 62))) & 1;
        RK[i] = RK[i - 3] ^ tmp ^ c ^ z_bit;
    }
}


/* SIMON f С„СѓРЅРєС†РёСЏ - РїСЂР°РІРёР»СЊРЅР°СЏ РїРѕ СЃС‚Р°РЅРґР°СЂС‚Сѓ */
inline uint32_t simon_f(uint32_t x) {
    return (ROTL32(x, 1) & ROTL32(x, 8)) ^ ROTL32(x, 2);
}

#define DEBUG_BLOCK_TIMING

/* РРЎРџР РђР’Р›Р•РќРћ: РЁРёС„СЂРѕРІР°РЅРёРµ SIMON-64/96 РїРѕ СЃС‚Р°РЅРґР°СЂС‚Сѓ */
inline uint64_t enc64_fast(uint64_t blk) {
    TS_START(t0);
    uint32_t x = uint32_t(blk >> 32);        // РјР»Р°РґС€РёРµ 32 Р±РёС‚Р° (РїСЂР°РІР°СЏ РїРѕР»РѕРІРёРЅР°)
    uint32_t y = uint32_t(blk);  // СЃС‚Р°СЂС€РёРµ 32 Р±РёС‚Р° (Р»РµРІР°СЏ РїРѕР»РѕРІРёРЅР°)

    // SIMON Feistel: (x,y) -> (y XOR f(x) XOR k, x)
    for (int i = 0; i <= T - 1; i++) {
    uint32_t tmp = x;
    x = y ^ simon_f(tmp) ^ RK[i];
    y = tmp;
    }

    uint32_t cyc = ESP.getCycleCount() - t0;
    enc_cyc += cyc;  ++enc_cnt;

#ifdef DEBUG_BLOCK_TIMING
    Serial.printf("ENC  P=0x%016llX -> C=0x%016llX  |  %u cyc  (%.2f Вµs)\n",
                  (unsigned long long)blk,
                  (unsigned long long)((uint64_t(x) << 32) | y),
                  cyc, cyc2us(cyc));
#endif
    return (uint64_t(x) << 32) | y;
}

/* РРЎРџР РђР’Р›Р•РќРћ: Р”РµС€РёС„СЂРѕРІР°РЅРёРµ SIMON-64/96 РїРѕ СЃС‚Р°РЅРґР°СЂС‚Сѓ */
inline uint64_t dec64_fast(uint64_t blk) {
    TS_START(t0);
    uint32_t x = uint32_t(blk >> 32);        // РјР»Р°РґС€РёРµ 32 Р±РёС‚Р°
    uint32_t y = uint32_t(blk);  // СЃС‚Р°СЂС€РёРµ 32 Р±РёС‚Р°

    // РћР±СЂР°С‚РЅС‹Р№ SIMON Feistel: (x,y) -> (y, x XOR f(y) XOR k)
    for (int i = T - 1; i >= 0; --i) {
    uint32_t tmp = y;
    y = x ^ simon_f(tmp) ^ RK[i];
    x = tmp;
    }

    uint32_t cyc = ESP.getCycleCount() - t0;
    dec_cyc += cyc;  ++dec_cnt;

#ifdef DEBUG_BLOCK_TIMING
    Serial.printf("DEC  C=0x%016llX -> P=0x%016llX  |  %u cyc  (%.2f Вµs)\n",
                  (unsigned long long)blk,
                  (unsigned long long)((uint64_t(x) << 32) | y),
                  cyc, cyc2us(cyc));
#endif
    return (uint64_t(x) << 32) | y;
}
void test_vectors() {
    // РўРµСЃС‚РѕРІС‹Р№ РєР»СЋС‡ (РёР· СЃС‚Р°С‚СЊРё, Simon 64/96)
    const uint32_t KEY96_test[3] = { 0x03020100, 0x0B0A0908, 0x13121110 };
    simon_key_schedule_64_96(KEY96_test);

    // Plaintext (РёР· СЃС‚Р°С‚СЊРё)
    uint64_t pt = 0x6f7220676e696c63; // plaintext

    // РћР¶РёРґР°РµРјС‹Р№ ciphertext
    uint64_t ct_expected = 0x5ca2e27f111a8fc8ULL;
    // РЁРёС„СЂСѓРµРј
    uint64_t ct = enc64_fast(pt);

    // Р”РµС€РёС„СЂСѓРµРј РѕР±СЂР°С‚РЅРѕ
    uint64_t dec = dec64_fast(ct);

    Serial.printf("\n=== SIMON 64/96 TEST VECTOR ===\n");
    Serial.printf("Key: 13121110 0b0a0908 03020100\n");
    Serial.printf("PT : %016llX\n", (unsigned long long)pt);
    Serial.printf("CT : %016llX  (expected %016llX)\n", 
                  (unsigned long long)ct, (unsigned long long)ct_expected);
    Serial.printf("DEC: %016llX  (should equal PT)\n\n", 
                  (unsigned long long)dec);
}

/* MQTT callback (decrypt & pretty-print) */
void cb(char*, byte* pay, unsigned len)
{
    TS_START(pkt_t0);
    TS_START(parse_t0);
    String msg((char*)pay, len);

    uint16_t blks = 0;  String json;
    while (msg.length()) {
        int col = msg.indexOf(':');
        if (col < 0) break;
        int com = msg.indexOf(',', col + 1);

        uint64_t ct = strtoull(msg.substring(col + 1,
                              com < 0 ? msg.length() : com).c_str(), nullptr, 16);
        uint64_t pt = dec64_fast(ct);
        ++blks;

        for (int i = 7; i >= 0; --i) {
            char ch = (pt >> (i * 8)) & 0xFF;
            if (ch >= 32 && ch <= 126) json += ch;
        }
        if (com < 0) break;
        msg = msg.substring(com + 1);
    }

    uint32_t cyc_pkt = ESP.getCycleCount() - pkt_t0;
    Serial.printf("DEC packet: %u cyc  (%.2f Вµs)  |  %u blocks  (%.2f Вµs/blk)\n",
                  cyc_pkt, cyc2us(cyc_pkt), blks,
                  blks ? cyc2us(cyc_pkt) / blks : 0.0f);
    Serial.printf("Decrypted JSON: %s\n\n", json.c_str());

    dec_pkt_cyc += cyc_pkt;
    ++dec_pkt_cnt;

    parse_cyc += ESP.getCycleCount() - parse_t0;
    ++parse_cnt;
}

/* Build JSON в†’ encrypt в†’ MQTT string */
String buildAndEncrypt()
{
    TS_START(pkt_t0);
    
    /* Р¤РѕСЂРјРёСЂСѓРµРј JSON */
    doc.clear();
    deserializeJson(doc["weights"], FPSTR(WEIGHTS));
    JsonObject meta = doc.createNestedObject("esp_info");
    meta["free_heap"] = ESP.getFreeHeap();
    meta["cpu_freq_mhz"] = ESP.getCpuFreqMHz();
    meta["timestamp"] = millis();

    uint16_t jsonLen = serializeJson(doc, jsonBuf);
    uint16_t blocks = (jsonLen + 7) / 8;

    Serial.printf("Plaintext size: %u bytes (%u bits)\n", jsonLen, jsonLen * 8);

    /* РЁРёС„СЂСѓРµРј */
    TS_START(t0);
    for (uint16_t i = 0; i < blocks; ++i) {
        uint64_t blk = 0;
        for (int j = 0; j < 8; ++j) {
            int idx = i * 8 + j;
            blk = (blk << 8) | (idx < jsonLen ? (uint8_t)jsonBuf[idx] : 0);
        }
        ctBuf[i] = enc64_fast(blk);
    }

    uint32_t ciphertextBits = blocks * 64;
    Serial.printf("Ciphertext size: %u blocks (%u bits)\n", blocks, ciphertextBits);

    uint32_t cyc_pkt = ESP.getCycleCount() - t0;
    float us_pkt = cyc2us(cyc_pkt);

    Serial.printf("ENC packet: %u cyc  (%.2f Вµs)  |  %u blocks  (%.2f Вµs/blk)\n",
                  cyc_pkt, us_pkt, blocks, us_pkt / blocks);

    enc_pkt_cyc += ESP.getCycleCount() - pkt_t0;
    ++enc_pkt_cnt;

    /* РЎРєР»РµРёРІР°РµРј РІ "i:HEX,..." */
    String out; out.reserve(blocks * 20);
    for (uint16_t i = 0; i < blocks; ++i) {
        out += String(i);
        out += ':'; 
        char hex[17];
        sprintf(hex, "%016llX", (unsigned long long)ctBuf[i]);
        out += hex;
        if (i < blocks - 1) out += ',';
    } 
    return out;
}

/* РџРµС‡Р°С‚СЊ РїСЂРѕРёР·РІРѕРґРёС‚РµР»СЊРЅРѕСЃС‚Рё */
void printPerf()
{
    static uint32_t lastMs = 0;
    uint32_t now = millis();
    uint32_t dtMs = now - lastMs;
    if (dtMs < 5000) return;  // РєР°Р¶РґС‹Рµ 5 СЃРµРєСѓРЅРґ
    lastMs = now;

    uint32_t cryptoCycles = enc_cyc + dec_cyc;
    float cpuPct = (cryptoCycles / (ESP.getCpuFreqMHz() * 1000.0f * dtMs)) * 100.0f;

    size_t heapFree = ESP.getFreeHeap();
    size_t heapMin = esp_get_minimum_free_heap_size();

    bool any = false;

    if (enc_cnt) {
        float avg_us = cyc2us(enc_cyc) / enc_cnt;
        float tot_us = cyc2us(enc_cyc);
        Serial.printf("enc : %.2f Вµs/blk  |  %.2f Вµs total  (%u blks)\n",
                      avg_us, tot_us, enc_cnt);
        any = true;
    }

    if (dec_cnt) {
        float avg_us = cyc2us(dec_cyc) / dec_cnt;
        float tot_us = cyc2us(dec_cyc);
        Serial.printf("dec : %.2f Вµs/blk  |  %.2f Вµs total  (%u blks)\n",
                      avg_us, tot_us, dec_cnt);
        any = true;
    }

    if (any) {
        constexpr size_t RAM_BANK = 512 * 1024;
        size_t ramUsedB = (heapFree < RAM_BANK) ? RAM_BANK - heapFree : 0;
        float ramPct = (float)ramUsedB / RAM_BANK * 100.0f;

        size_t flashUsedB = ESP.getSketchSize();
        size_t flashTotalB = ESP.getFlashChipSize();
        float flashPct = (float)flashUsedB / flashTotalB * 100.0f;

        Serial.printf("RAM used: %u B (%.1f %% of 512 KB) | "
                      "FLASH used: %u B (%.2f %% of %u KB) | "
                      "CPU-crypto: %.2f %%\n",
                      ramUsedB, ramPct,
                      flashUsedB, flashPct, flashTotalB / 1024,
                      cpuPct);
        Serial.printf("Heap: %u B free, %u B minimum\n\n", heapFree, heapMin);
        test_vectors();
    }

    /* РЎР±СЂР°СЃС‹РІР°РµРј СЃС‡С‘С‚С‡РёРєРё */
    enc_cyc = enc_cnt = 0;
    dec_cyc = dec_cnt = 0;
    enc_pkt_cyc = enc_pkt_cnt = 0;
    dec_pkt_cyc = dec_pkt_cnt = 0;
    parse_cyc = parse_cnt = 0;
}

void setup() {
    Serial.begin(115200);
    Serial.println("\nStarting SIMON ESP32 implementation...");
    
    WiFi.begin(SSID, PASS);
    while (WiFi.status() != WL_CONNECTED) { 
        Serial.print('.'); 
        delay(400); 
    }
    Serial.println("\nWi-Fi connected");

    simon_key_schedule_64_96(KEY96);
    Serial.printf("CPU %d MHz  |  SIMON 64/96 key schedule ready\n", ESP.getCpuFreqMHz());
    // РџРµС‡Р°С‚Р°РµРј РїРµСЂРІС‹Рµ РЅРµСЃРєРѕР»СЊРєРѕ round keys РґР»СЏ РїСЂРѕРІРµСЂРєРё
    Serial.print("First round keys: ");
    for(int i = 0; i < 6; i++) {
        Serial.printf("RK[%d]=0x%08X ", i, RK[i]);
    }
    Serial.println();
    mqtt.setServer(BROKER, PORT);
    mqtt.setCallback(cb);
    mqtt.setBufferSize(MQTT_BUF);
}

const unsigned long PERIOD = 15000;
unsigned long lastSend = 0;

void loop() {
    mqtt.loop();
    
    if (!mqtt.connected()) {
        Serial.print("MQTT connecting...");
        if (mqtt.connect(CLIENT_ID)) { 
            Serial.println("OK"); 
            mqtt.subscribe(TOPIC_RAW);
        } else { 
            Serial.printf("failed, rc=%d\n", mqtt.state()); 
            delay(3000); 
        }
    }

    unsigned long now = millis();
    if (now - lastSend >= PERIOD && mqtt.connected()) {
        String payload = buildAndEncrypt();
        mqtt.publish(TOPIC_ENC, payload.c_str(), false);
        Serial.printf("Published %u bytes to %s\n", payload.length(), TOPIC_ENC);
        lastSend = now;
    }

    printPerf();
    delay(100);
}