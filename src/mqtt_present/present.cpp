/*******************************************************
 *  ESP32-S3  ↔  MQTT  ↔  PRESENT-80   (fast LUT, no-IRAM)
 *  2025-07-11  – исправленный вывод и полный пример
 *******************************************************/
#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <esp_attr.h>   // DRAM_ATTR
#include "esp_heap_caps.h"      // esp_get_minimum_free_heap_size()      
#include "esp_system.h"   // ESP.getFreePsram()

volatile uint32_t enc_pkt_cyc = 0, dec_pkt_cyc = 0;   // cycles на пакет
volatile uint32_t enc_pkt_cnt = 0, dec_pkt_cnt = 0;   // кол-во пакетов
volatile uint32_t parse_cyc = 0, parse_cnt = 0;   
/* ───── helpers & timer ───── */
#define TS_START(var) uint32_t var = ESP.getCycleCount()
static inline float cyc2us(uint32_t d){ return d / (float)ESP.getCpuFreqMHz(); }

/* ------------------------------------------------------------------
 *            CONSTANTS
 * -----------------------------------------------------------------*/
constexpr const char* SSID   = "Wi-Fi 4G";
constexpr const char* PASS   = "'dffhAO&&S4G'";
constexpr const char* BROKER = "broker.hivemq.com";
constexpr uint16_t    PORT   = 1883;

constexpr const char* TOPIC_RAW = "iot/raw";   // не используется, оставлен на будущее
constexpr const char* TOPIC_ENC = "iot/enc";   // публикация + подписка!
constexpr const char* CLIENT_ID = "esp32-client";
constexpr size_t      MQTT_BUF  = 8192;

/* PRESENT S-box / P-layer */
const uint8_t SBOX[16] = {0xC,0x5,0x6,0xB,0x9,0x0,0xA,0xD,0x3,0xE,0xF,0x8,0x4,0x7,0x1,0x2};
uint8_t       ISBOX[16];
const uint8_t PBOX[64] = {
   0,16,32,48, 1,17,33,49, 2,18,34,50, 3,19,35,51,
   4,20,36,52, 5,21,37,53, 6,22,38,54, 7,23,39,55,
   8,24,40,56, 9,25,41,57,10,26,42,58,11,27,43,59,
  12,28,44,60,13,29,45,61,14,30,46,62,15,31,47,63};

/* 80-битный мастер-ключ */
const uint8_t KEY80[10] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,0x01,0x23};

/* Round-keys */
uint64_t RK[32];

/* LUT  (S-box + P) и inverse  — держим в быстрой DRAM */
DRAM_ATTR uint64_t SP_LUT [16][16];
DRAM_ATTR uint64_t ISP_LUT[16][16];

/* Мини-пример весов, чтобы не грузить Flash */
const char WEIGHTS[] PROGMEM = R"RAW([[[[-0.22269929945468903, -0.0020684152841567993, -0.028627386316657066, -0.04175390675663948, 0.02046719379723072, 0.08776327967643738, -0.06972722709178925, -0.0024031028151512146, -0.1369350701570511, 0.07604920864105225, -0.15909017622470856, -0.11621670424938202, 0.01977522112429142, 0.05549396574497223, -0.006383150815963745, -0.38754409551620483, 0.019943036139011383, -0.1304830014705658, 0.09386514127254486, 0.08403369039297104, 0.04103871434926987, 0.001162276603281498, -0.21528294682502747, 0.08617235720157623, -0.0812213271856308, 0.10415084660053253, -0.047551874071359634, -0.10483313351869583, 0.04774774610996246, -0.11372575163841248, 0.032191865146160126, 0.047332197427749634, 0.05957270786166191, -0.003320351243019104, -0.19130374491214752, -0.5056506395339966, 0.0594739094376564, 0.09424041211605072, -0.005374163389205933, -0.09813196212053299, 0.06058444082736969, -0.012654859572649002, -0.20923274755477905, -0.029386963695287704, 0.03915838152170181, 0.03987979143857956, 0.118799589574337, -0.1517963707447052, -0.12310691177845001, 0.02752935327589512, -0.07804187387228012, 0.0912553071975708, -0.028958793729543686, 0.01714150607585907, 0.06191866844892502, -0.13848546147346497, -0.03784804418683052, -0.09685277193784714, -0.13155832886695862, 0.04564664885401726, -0.12638293206691742, -0.4195791482925415, -0.07618607580661774, -0.06411894410848618]], [[-0.38721707463264465, 0.10108035802841187, -0.547479510307312, -0.142031729221344, -0.25518128275871277, 0.08117641508579254, 0.032983507961034775, -0.017013398930430412, 0.007050002459436655, -0.054755937308073044, 0.020490612834692, -0.49241167306900024, 0.0165400467813015, 0.06026015430688858, 0.0010598376393318176, -0.5442346334457397, 0.0368630550801754, -0.03570526838302612, -0.038232430815696716, -0.07469354569911957, 0.025067295879125595, -0.015666861087083817, 0.018609998747706413, -0.3061330318450928, 0.05790018290281296, 0.048334307968616486, -0.24385195970535278, -0.07935438305139542, -0.1819179654121399, 0.11193083971738815, 0.026050634682178497, -0.016550563275814056, 0.06019206717610359, -0.36496007442474365, -0.02235141023993492, 0.008374023251235485, 0.024556607007980347, -0.05442333221435547, -0.6205769777297974, -0.2319582849740982, -0.1597018837928772, 0.11711525917053223, -0.08185379207134247, 0.03631089627742767, -0.11780697852373123, 0.07119498401880264, 0.00010193139314651489, -0.2678371071815491, 0.03866139054298401, -0.42356234788894653, 0.09636807441711426, -0.01641259714961052, -0.12778903543949127, -1.0513049364089966, -0.04323035851120949, 0.08268750458955765, -0.31393373012542725, 0.02999350056052208, -0.08584080636501312, -0.23677249252796173, -0.02576761692762375, -0.2608223557472229, -0.1403527706861496, -0.007824636995792389]]]])RAW";   // урезано для примера

/* Буферы */
StaticJsonDocument<4096> doc;
char            jsonBuf[4096];
uint64_t        ctBuf[600];

volatile uint32_t enc_cyc=0, dec_cyc=0;
volatile uint32_t enc_cnt=0, dec_cnt=0;

/* MQTT */
WiFiClient   net;
PubSubClient mqtt(net);

/* ───────────────────── 1. Key-schedule ───────────────────── */
void genRK80(const uint8_t k0[10])
{
  uint8_t k[10]; memcpy(k,k0,10);
  for(int r=0;r<32;++r){
    uint64_t rk=0; for(int i=0;i<8;++i) rk=(rk<<8)|k[i];
    RK[r]=rk;

    /* <<< 61 (7 bytes + 5 bits) */
    uint8_t tmp[10];
    for(int i=0;i<10;++i) tmp[i]=k[(i+7)%10];
    for(int i=0;i<10;++i){
      uint16_t pair = (tmp[i]<<8)|tmp[(i+1)%10];
      k[i]=(pair<<5)|(pair>>11);
    }
    /* S-box старших 4 бит */
    k[0]=(SBOX[k[0]>>4]<<4)|(k[0]&0x0F);
    /* XOR round-counter (K19..K15) */
    uint8_t rc=r+1;
    k[7]^=rc>>1;
    k[8]^=rc<<7;
  }
}

/* ───────────────────── 2.  LUT builder ───────────────────── */
uint64_t perm64(uint64_t t){
  uint64_t s=0;
  for(int i=0;i<64;++i) if(t>>i & 1) s |= 1ULL<<PBOX[i];
  return s;
}
void buildLUT()
{
    for (int i = 0; i < 256; ++i) {
        int pos = i >> 4;      // верхние 4 бита = позиция
        int v   = i & 0x0F;    // нижние 4 бита = значение

        if (pos == 0)                // первые 16 итераций
            ISBOX[SBOX[v]] = v;      // сразу строим инверсию

        uint64_t t = uint64_t(SBOX[v])  << (pos * 4);
        SP_LUT [pos][v] = perm64(t);

        uint64_t ti = uint64_t(ISBOX[v]) << (pos * 4);
        ISP_LUT[pos][v] = perm64(ti);
    }
}


/* ───────────── 3.  fast round / inverse round ───────────── */
static   uint64_t round64(uint64_t st,uint64_t rk){
  st ^= rk;
  uint64_t o=0;
  o|=SP_LUT[ 0][ st      &0xF];
  o|=SP_LUT[ 1][(st>> 4) &0xF];
  o|=SP_LUT[ 2][(st>> 8) &0xF];
  o|=SP_LUT[ 3][(st>>12) &0xF];
  o|=SP_LUT[ 4][(st>>16) &0xF];
  o|=SP_LUT[ 5][(st>>20) &0xF];
  o|=SP_LUT[ 6][(st>>24) &0xF];
  o|=SP_LUT[ 7][(st>>28) &0xF];
  o|=SP_LUT[ 8][(st>>32) &0xF];
  o|=SP_LUT[ 9][(st>>36) &0xF];
  o|=SP_LUT[10][(st>>40) &0xF];
  o|=SP_LUT[11][(st>>44) &0xF];
  o|=SP_LUT[12][(st>>48) &0xF];
  o|=SP_LUT[13][(st>>52) &0xF];
  o|=SP_LUT[14][(st>>56) &0xF];
  o|=SP_LUT[15][(st>>60) &0xF];
  return o;
}
static   uint64_t iround64(uint64_t st,uint64_t rk){
  uint64_t o=0;
  o|=ISP_LUT[ 0][ st      &0xF];
  o|=ISP_LUT[ 1][(st>> 4) &0xF];
  o|=ISP_LUT[ 2][(st>> 8) &0xF];
  o|=ISP_LUT[ 3][(st>>12) &0xF];
  o|=ISP_LUT[ 4][(st>>16) &0xF];
  o|=ISP_LUT[ 5][(st>>20) &0xF];
  o|=ISP_LUT[ 6][(st>>24) &0xF];
  o|=ISP_LUT[ 7][(st>>28) &0xF];
  o|=ISP_LUT[ 8][(st>>32) &0xF];
  o|=ISP_LUT[ 9][(st>>36) &0xF];
  o|=ISP_LUT[10][(st>>40) &0xF];
  o|=ISP_LUT[11][(st>>44) &0xF];
  o|=ISP_LUT[12][(st>>48) &0xF];
  o|=ISP_LUT[13][(st>>52) &0xF];
  o|=ISP_LUT[14][(st>>56) &0xF];
  o|=ISP_LUT[15][(st>>60) &0xF];
  return o ^ rk;
}

/* 31 раунд */
IRAM_ATTR inline uint64_t enc64_fast(uint64_t p)
{ 
    TS_START(t0);                               // старт таймера
    uint64_t s = p;
    for (int r = 0; r < 31; ++r)
        s = round64(s, RK[r]);

    uint32_t cyc   = ESP.getCycleCount() - t0;   // такты на шифр
    uint32_t f_cpu = ESP.getCpuFreqMHz();        // частота, МГц

    enc_cyc += cyc;  ++enc_cnt;

    Serial.printf(
        "ENC  P=0x%016llX  |  %u cyc  (%.2f µs @ %u MHz)\n",
        (unsigned long long)p,
        cyc,
        cyc2us(cyc),     // µs = cyc / f_cpu
        f_cpu);

    return s ^ RK[31];
}


IRAM_ATTR inline uint64_t dec64_fast(uint64_t c){
  TS_START(t0);
  uint64_t s=c ^ RK[31];
  for(int r=30;r>=0;--r) s=iround64(s,RK[r]);
  dec_cyc += ESP.getCycleCount()-t0;  ++dec_cnt;
  return s;
}

/* ───────── 4. MQTT callback  (decrypt & pretty-print) ───────── */
/* ───────── 4. MQTT callback  (decrypt & pretty-print) ───────── */
void cb(char*, byte* pay, unsigned len)
{
    TS_START(pkt_t0);                // ← таймер ВСЕГО пакета

    TS_START(parse_t0);
    String msg((char*)pay, len);

    uint16_t blks = 0;  String json;
    while (msg.length()) {
        int col = msg.indexOf(':');
        if (col < 0) break;
        int com = msg.indexOf(',', col + 1);

        uint64_t ct = strtoull(msg.substring(col + 1,
                              com < 0 ? msg.length() : com).c_str(), nullptr, 16);
        uint64_t pt = dec64_fast(ct);      // один блок
        ++blks;

        for (int i = 7; i >= 0; --i) {
            char ch = (pt >> (i * 8)) & 0xFF;
            if (ch >= 32 && ch <= 126) json += ch;
        }
        if (com < 0) break;
        msg = msg.substring(com + 1);
    }

    /* -------- вывод итогового времени пакета -------- */
    uint32_t cyc_pkt = ESP.getCycleCount() - pkt_t0;
    Serial.printf("DEC packet: %u cyc  (%.2f µs)  |  %u blocks  (%.2f µs/blk)\n",
                  cyc_pkt, cyc2us(cyc_pkt), blks,
                  blks ? cyc2us(cyc_pkt) / blks : 0.0f);

    /* статистика для CPU-crypto, если нужна */
    dec_pkt_cyc += cyc_pkt;
    ++dec_pkt_cnt;

    /* таймер парсинга, если продолжаете его вести */
    parse_cyc += ESP.getCycleCount() - parse_t0;
    ++parse_cnt;
}


/* ─────── 5. Build JSON → encrypt → MQTT string ─────── */
String buildAndEncrypt()
{
  TS_START(pkt_t0);
  /* 5.1 формируем JSON */
  doc.clear();
  deserializeJson(doc["weights"],FPSTR(WEIGHTS));
  JsonObject meta=doc.createNestedObject("esp_info");
  meta["free_heap"]=ESP.getFreeHeap();
  meta["cpu_freq_mhz"]=ESP.getCpuFreqMHz();

  uint16_t jsonLen = serializeJson(doc,jsonBuf);
  uint16_t blocks  = (jsonLen+7)/8;

  /* 5.2 шифруем */
  TS_START(t0);
  for(uint16_t i=0;i<blocks;++i){
    uint64_t blk=0;
    for(int j=0;j<8;++j){
      int idx=i*8+j;
      blk=(blk<<8)|(idx<jsonLen?(uint8_t)jsonBuf[idx]:0);
    }
    ctBuf[i]=enc64_fast(blk);
  }
  float blk_us = cyc2us(ESP.getCycleCount()-t0)/blocks;
  enc_pkt_cyc += ESP.getCycleCount() - pkt_t0;   // общие циклы
  ++enc_pkt_cnt;                                 // +1 пакет
  /* 5.3 склеиваем в "i:HEX,..."  */
  uint32_t cyc_pkt = ESP.getCycleCount() - t0;      // ВСЕ циклы шифрования
  float     us_pkt = cyc2us(cyc_pkt);               // те же микросекунды

  Serial.printf("ENC packet: %u cyc  (%.2f µs)  |  %u blocks  (%.2f µs/blk)\n",
                cyc_pkt, us_pkt, blocks, us_pkt / blocks);


  String out; out.reserve(blocks*20);
  for(uint16_t i=0;i<blocks;++i){
    out += String(i);          // <─ главная правка!
    out += ':'; out += String((unsigned long long)ctBuf[i],HEX);
    if(i<blocks-1) out += ',';
  } 
  return out;
}

/* ───────────────  печать производительности ─────────────── */
/* ───────────────  печать производительности ─────────────── */
void printPerf()
{
    static uint32_t lastMs = 0;
    uint32_t now   = millis();
    uint32_t dtMs  = now - lastMs;          // длительность интервала
    if (dtMs < 1000) return;                // не чаще 1 р/с
    lastMs = now;

    /* ---------- CPU-и RAM-метрики этого интервала ---------- */
    uint32_t cryptoCycles = enc_cyc + dec_cyc;
    float cpuPct = (cryptoCycles / (ESP.getCpuFreqMHz() * 1000.0f * dtMs)) * 100.0f;

    size_t heapFree = ESP.getFreeHeap();
    size_t heapMin  = esp_get_minimum_free_heap_size();

    /* ---------- тайминги ---------- */
    bool any = false;

    if (enc_cnt) {
        float avg_us = cyc2us(enc_cyc) / enc_cnt;      // µs на блок
        float tot_us = cyc2us(enc_cyc);                // µs на все blks
        Serial.printf("enc : %.2f µs/blk  |  %.2f µs total  (%u blks)\n",
                      avg_us, tot_us, enc_cnt);
        any = true;
    }

    if (dec_cnt) {
        float avg_us = cyc2us(dec_cyc) / dec_cnt;
        float tot_us = cyc2us(dec_cyc);
        Serial.printf("dec : %.2f µs/blk  |  %.2f µs total  (%u blks)\n",
                      avg_us, tot_us, dec_cnt);
        any = true;
    }

    /* ---------- ресурсы: выводим, если было что печатать ---------- */
    /* ---------- ресурсы: выводим, если было что печатать ---------- */
      /* ---------- ресурсы: выводим, если было шифрование/дешифрование ---------- */
    if (any) {
        /* ---------- RAM ---------- */
        constexpr size_t RAM_BANK = 512 * 1024;                // 512 КБ
        size_t  ramUsedB = (heapFree < RAM_BANK) ? RAM_BANK - heapFree : 0;
        float   ramPct   = (float)ramUsedB / RAM_BANK * 100.0f;

        /* ---------- FLASH (ROM) ---------- */
        size_t flashUsedB  = ESP.getSketchSize();              // прошивка
        size_t flashTotalB = ESP.getFlashChipSize();           // объём микросхемы
        float  flashPct    = (float)flashUsedB / flashTotalB * 100.0f;

        /* ---------- вывод ---------- */
        Serial.printf("RAM used: %u B (%.1f %% of 512 KB) | "
                      "FLASH used: %u B (%.2f %% of %u KB) | "
                      "CPU-crypto: %.2f %%\n\n",
                      ramUsedB,  ramPct,
                      flashUsedB, flashPct, flashTotalB / 1024,
                      cpuPct);
    }



    /* сбрасываем счётчики на следующий интервал */
    enc_cyc = enc_cnt = 0;
    dec_cyc = dec_cnt = 0;
}



/* ─────────────── 6.  setup & loop ─────────────── */
void setup(){
  Serial.begin(115200);
  WiFi.begin(SSID,PASS);
  while(WiFi.status()!=WL_CONNECTED){ Serial.print('.'); delay(400);}
  Serial.println("\nWi-Fi OK");

  genRK80(KEY80);
  buildLUT();
  Serial.printf("CPU %d MHz  |  LUT ready (no-IRAM)\n",ESP.getCpuFreqMHz());

  mqtt.setServer(BROKER,PORT);
  mqtt.setCallback(cb);
  mqtt.setBufferSize(MQTT_BUF);
}

const unsigned long PERIOD = 15000;
unsigned long lastSend=0;

void loop() {
  mqtt.loop();
  if(!mqtt.connected()) {
    Serial.print("MQTT…");
    if(mqtt.connect(CLIENT_ID)){ Serial.println("OK"); mqtt.subscribe(TOPIC_RAW);}
    else { Serial.printf("fail rc=%d\n",mqtt.state()); delay(3000);}
  }

  unsigned long now=millis();
  if(now-lastSend>=PERIOD && mqtt.connected()) {
    String payload = buildAndEncrypt();
    mqtt.publish(TOPIC_ENC, payload.c_str(), false);
    lastSend = now;
  }
  printPerf();
}