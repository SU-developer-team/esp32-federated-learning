/*******************************************************
 * Purpose: run centralized training on the full dataset
 * for comparison with the federated learning devices.
 *
 * This firmware trains and evaluates the same model in a
 * single node setup to provide a baseline experiment.
 *******************************************************/
#include <Arduino.h>
#include <WiFi.h>
#include "esp_heap_caps.h"
#include "esp_system.h"

#include <aifes.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include <auth_ecdh.h>

#include "federated_train_centr/dataset_embedded.h"
#include "federated_train_centr/dataset_test.h"

#include <mbedtls/sha256.h>

/* ------------------- Timing helpers ------------------- */
#define TS_START(var) uint32_t var = ESP.getCycleCount()
static inline float cyc2us(uint32_t d) { return d / (float)ESP.getCpuFreqMHz(); }
#define ROTR32(x, r) ((uint32_t)(((x) >> (r)) | ((x) << (32 - (r)))))
#define ROTL32(x, r) ((uint32_t)(((x) << (r)) | ((x) >> (32 - (r)))))

/* ------------------- WiFi / TCP config ------------------- */
constexpr const char* SSID = "RaspberryWiFi";
constexpr const char* PASS = "12345678";
constexpr const char* SERVER_IP = "192.168.4.1";
constexpr uint16_t PORT = 1883;

static const uint8_t MASTER_KEY[] = {
    0x72, 0x13, 0x25, 0x4B, 0x46, 0x7B, 0x23, 0x18,
    0xE1, 0xE7, 0x25, 0x3F, 0x3B, 0x8B, 0x02, 0xAE,
    0xC5, 0x56, 0xFF, 0x9D, 0xAC, 0xBB, 0x73, 0x96,
    0x30, 0xE7, 0x5C, 0x66, 0x7B, 0x1F, 0x32, 0x24
};
constexpr size_t MASTER_KEY_LEN = sizeof(MASTER_KEY);

constexpr uint8_t REKEY_REQUEST = 0x10;
constexpr uint8_t APP_DATA = 0x20;
constexpr uint32_t HS_RETRY_MS = 1000;
constexpr uint32_t HS_TIMEOUT_MS = 5000;

/* ------------------- Perf counters ------------------- */
volatile uint32_t enc_pkt_cyc = 0, dec_pkt_cyc = 0;
volatile uint32_t enc_pkt_cnt = 0, dec_pkt_cnt = 0;
volatile uint32_t parse_cyc = 0, parse_cnt = 0;
volatile uint32_t enc_cyc = 0, dec_cyc = 0;
volatile uint32_t enc_cnt = 0, dec_cnt = 0;
volatile uint64_t enc_total_bytes = 0, dec_total_bytes = 0;

/* ------------------- TCP session / auth ------------------- */
WiFiClient net;
static AuthEcdhConfig g_auth_cfg = {};
static uint8_t g_key96[12];
static bool g_key_ready = false;
static uint32_t g_last_hs_try_ms = 0;

/* ------------------- SPECK-64/96 ------------------- */
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

inline uint64_t enc64_fast(uint64_t blk) {
    TS_START(t0);
    uint32_t x = (uint32_t)(blk >> 32), y = (uint32_t)blk;
    for (int r = 0; r < 26; ++r) {
        x = (ROTR32(x, 8) + y) ^ RK[r];
        y = ROTL32(y, 3) ^ x;
    }
    uint32_t cyc = ESP.getCycleCount() - t0;
    enc_cyc += cyc; ++enc_cnt;
    return ((uint64_t)x << 32) | y;
}

inline uint64_t dec64_fast(uint64_t blk) {
    TS_START(t0);
    uint32_t x = (uint32_t)(blk >> 32), y = (uint32_t)blk;
    for (int r = 25; r >= 0; --r) {
        y = ROTR32(y ^ x, 3);
        x = ROTL32((x ^ RK[r]) - y, 8);
    }
    uint32_t cyc = ESP.getCycleCount() - t0;
    dec_cyc += cyc; ++dec_cnt;
    return ((uint64_t)x << 32) | y;
}

static uint32_t load_u32_le(const uint8_t* p) {
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void apply_speck_key(const uint8_t key96[12]) {
    uint32_t k[3] = {
        load_u32_le(key96),
        load_u32_le(key96 + 4),
        load_u32_le(key96 + 8)
    };
    genRK96(k);
    g_key_ready = true;
}

static bool connect_session() {
    if (net.connected()) return true;
    net.stop();
    return net.connect(SERVER_IP, PORT);
}

static bool run_handshake() {
    if (!connect_session()) {
        Serial.println("[HS] TCP connect failed");
        g_key_ready = false;
        return false;
    }

    g_auth_cfg.client = &net;
    AuthEcdhError err = auth_ecdh_handshake(&g_auth_cfg, g_key96, nullptr);
    if (err != AUTH_ECDH_OK) {
        Serial.printf("[HS] FAILED: %s\n", auth_ecdh_error_str(err));
        g_key_ready = false;
        return false;
    }

    apply_speck_key(g_key96);
    Serial.println("[HS] DONE");
    return true;
}

static bool ensure_session() {
    if (net.connected() && g_key_ready) return true;
    uint32_t now = millis();
    if (now - g_last_hs_try_ms < HS_RETRY_MS) return false;
    g_last_hs_try_ms = now;
    return run_handshake();
}

/* ------------------- AIfES training config ------------------- */
static const uint32_t SERIAL_BAUD = 115200;

static const uint16_t H1 = 64;
static const uint16_t H2 = 64;
static const uint16_t H3 = 32;

static const float    LEARNING_RATE = 0.001f;
static const float    VAL_SPLIT     = 0.20f;
static const uint32_t SHUFFLE_SEED  = 42;

static const uint32_t BATCH_SIZE = 32;

static const uint16_t MAX_EPOCHS = 1;
static const uint16_t PATIENCE  = 15;
static const float    MIN_DELTA = 1e-4f;
static const uint16_t TRAIN_ROUNDS = 20;

static const float ADAM_BETA1 = 0.9f;
static const float ADAM_BETA2 = 0.999f;
static const float ADAM_EPS   = 1e-7f;

static const uint32_t TRAIN_TASK_STACK_WORDS = 45000;
static const UBaseType_t TRAIN_TASK_PRIORITY = 1;
static const BaseType_t TRAIN_TASK_CORE = 1;

static uint16_t INPUT_SHAPE[2] = {1, DS_F};

static_assert(TDS_F == DS_F, "Test dataset must have same feature count");
static_assert(TDS_K == DS_K, "Test dataset must have same class count");
static_assert(DS_K <= 32, "Increase outK buffer if classes > 32");

/* ------------------- AIfES model ------------------- */
aimodel_t model;

ailayer_input_f32_t   in_layer = AILAYER_INPUT_F32_A(2, INPUT_SHAPE);
ailayer_dense_f32_t   d1_layer;
ailayer_relu_f32_t    r1_layer;
ailayer_dense_f32_t   d2_layer;
ailayer_relu_f32_t    r2_layer;
ailayer_dense_f32_t   d3_layer;
ailayer_relu_f32_t    r3_layer;
ailayer_dense_f32_t   dout_layer;
ailayer_softmax_f32_t sm_layer;

ailoss_crossentropy_f32_t ce_loss;

aiopti_adam_f32_t opt_adam;
aiopti_t* optimizer = nullptr;

void* pmem = nullptr;   uint32_t psize = 0;
void* tmem = nullptr;   uint32_t tsize = 0;

void* best_pmem = nullptr;
float best_val_loss = 1e30f;

/* ------------------- Train/val split ------------------- */
static inline uint8_t argmax32(const float* v, uint8_t k) {
    uint8_t best = 0;
    float bestv = v[0];
    for (uint8_t i = 1; i < k; i++) {
        if (v[i] > bestv) { bestv = v[i]; best = i; }
    }
    return best;
}

static uint16_t* idx_all = nullptr;
static uint16_t N_TRAIN = 0;
static uint16_t N_VAL   = 0;

static float*   x_train_data = nullptr;
static uint8_t* y_train_data = nullptr;
static float*   x_val_data   = nullptr;
static uint8_t* y_val_data   = nullptr;

static uint16_t x_train_shape[2];
static uint16_t y_train_shape[2];
static uint16_t x_val_shape[2];
static uint16_t y_val_shape[2];

static aitensor_t x_train;
static aitensor_t y_train;
static aitensor_t x_val;
static aitensor_t y_val;

static void make_train_val_tensors() {
    idx_all = (uint16_t*)malloc(sizeof(uint16_t) * DS_N);
    if (!idx_all) { Serial.println("FATAL: idx_all malloc failed"); while(true) delay(1000); }

    for (uint16_t i = 0; i < DS_N; i++) idx_all[i] = i;

    N_VAL = (uint16_t)((float)DS_N * VAL_SPLIT);
    if (N_VAL < 1) N_VAL = 1;
    if (N_VAL >= DS_N) N_VAL = DS_N - 1;
    N_TRAIN = DS_N - N_VAL;

    x_train_data = (float*)malloc((size_t)N_TRAIN * DS_F * sizeof(float));
    y_train_data = (uint8_t*)malloc((size_t)N_TRAIN * sizeof(uint8_t));
    x_val_data   = (float*)malloc((size_t)N_VAL   * DS_F * sizeof(float));
    y_val_data   = (uint8_t*)malloc((size_t)N_VAL   * sizeof(uint8_t));

    if (!x_train_data || !y_train_data || !x_val_data || !y_val_data) {
        Serial.println("FATAL: dataset buffers malloc failed");
        while(true) delay(1000);
    }

    for (uint16_t t = 0; t < N_TRAIN; t++) {
        uint16_t i = idx_all[t];
        memcpy(&x_train_data[(size_t)t * DS_F], DS_X[i], sizeof(float) * DS_F);
        y_train_data[t] = DS_Y[i];
    }

    for (uint16_t v = 0; v < N_VAL; v++) {
        uint16_t i = idx_all[N_TRAIN + v];
        memcpy(&x_val_data[(size_t)v * DS_F], DS_X[i], sizeof(float) * DS_F);
        y_val_data[v] = DS_Y[i];
    }

    x_train_shape[0] = N_TRAIN; x_train_shape[1] = DS_F;
    y_train_shape[0] = N_TRAIN; y_train_shape[1] = 1;
    x_val_shape[0]   = N_VAL;   x_val_shape[1]   = DS_F;
    y_val_shape[0]   = N_VAL;   y_val_shape[1]   = 1;

    x_train = AITENSOR_2D_F32(x_train_shape, x_train_data);
    y_train = AITENSOR_2D_U8 (y_train_shape, y_train_data);
    x_val   = AITENSOR_2D_F32(x_val_shape,   x_val_data);
    y_val   = AITENSOR_2D_U8 (y_val_shape,   y_val_data);

    Serial.printf("Split done: train=%u val=%u (VAL_SPLIT=%.2f)\n",
                  (unsigned)N_TRAIN, (unsigned)N_VAL, (double)VAL_SPLIT);
}

static void build_model() {
    d1_layer   = AILAYER_DENSE_F32_A(H1);
    r1_layer   = AILAYER_RELU_F32_A();
    d2_layer   = AILAYER_DENSE_F32_A(H2);
    r2_layer   = AILAYER_RELU_F32_A();
    d3_layer   = AILAYER_DENSE_F32_A(H3);
    r3_layer   = AILAYER_RELU_F32_A();
    dout_layer = AILAYER_DENSE_F32_A(DS_K);
    sm_layer   = AILAYER_SOFTMAX_F32_A();

    ailayer_t* x;
    model.input_layer = ailayer_input_f32_default(&in_layer);
    x = ailayer_dense_f32_default(&d1_layer, model.input_layer);
    x = ailayer_relu_f32_default(&r1_layer, x);
    x = ailayer_dense_f32_default(&d2_layer, x);
    x = ailayer_relu_f32_default(&r2_layer, x);
    x = ailayer_dense_f32_default(&d3_layer, x);
    x = ailayer_relu_f32_default(&r3_layer, x);
    x = ailayer_dense_f32_default(&dout_layer, x);
    x = ailayer_softmax_f32_default(&sm_layer, x);
    model.output_layer = x;

    model.loss = ailoss_crossentropy_sparse8_f32_default(
        (ailoss_crossentropy_f32_t*)&ce_loss, model.output_layer);

    aialgo_compile_model(&model);

    psize = aialgo_sizeof_parameter_memory(&model);
    pmem = malloc(psize);
    if (!pmem) { Serial.printf("FATAL: pmem malloc failed (%u)\n", (unsigned)psize); while(true) delay(1000); }
    aialgo_distribute_parameter_memory(&model, pmem, psize);
    aialgo_initialize_parameters_model(&model);

    opt_adam = AIOPTI_ADAM_F32(LEARNING_RATE, ADAM_BETA1, ADAM_BETA2, ADAM_EPS);
    optimizer = aiopti_adam_f32_default(&opt_adam);

    tsize = aialgo_sizeof_training_memory(&model, optimizer);
    tmem = malloc(tsize);
    if (!tmem) { Serial.printf("FATAL: tmem malloc failed (%u)\n", (unsigned)tsize); while(true) delay(1000); }
    aialgo_schedule_training_memory(&model, optimizer, tmem, tsize);
    aialgo_init_model_for_training(&model, optimizer);

    best_pmem = malloc(psize);
    if (!best_pmem) { Serial.printf("FATAL: best_pmem malloc failed (%u)\n", (unsigned)psize); while(true) delay(1000); }
    memcpy(best_pmem, pmem, psize);

    Serial.printf("Model built. param_mem=%u train_mem=%u\n", (unsigned)psize, (unsigned)tsize);
}

static float eval_acc_tensor(const float* Xflat, const uint8_t* Y, uint16_t N) {
    float x1[DS_F];
    uint16_t x1_shape[2] = {1, DS_F};
    aitensor_t x1_tensor = AITENSOR_2D_F32(x1_shape, x1);

    float outK[32];
    uint16_t out_shape[2] = {1, DS_K};
    aitensor_t out_tensor = AITENSOR_2D_F32(out_shape, outK);

    uint32_t correct = 0;
    for (uint16_t i = 0; i < N; i++) {
        memcpy(x1, &Xflat[(size_t)i * DS_F], sizeof(float) * DS_F);
        aialgo_inference_model(&model, &x1_tensor, &out_tensor);
        uint8_t pred = argmax32(outK, DS_K);
        if (pred == Y[i]) correct++;
    }
    return 100.0f * (float)correct / (float)N;
}

static void train_with_early_stopping(String& metrics_log) {
    Serial.println("EPOCH,ms,train_loss,val_loss,train_acc,val_acc");
    metrics_log = "EPOCH,ms,train_loss,val_loss,train_acc,val_acc\n";

    uint16_t no_improve = 0;
    best_val_loss = 1e30f;

    for (uint16_t epoch = 1; epoch <= MAX_EPOCHS; epoch++) {
        uint32_t t0 = millis();

        aialgo_train_model(&model, &x_train, &y_train, optimizer, BATCH_SIZE);

        uint32_t dt = millis() - t0;

        float train_loss = 0.0f;
        float val_loss   = 0.0f;
        aialgo_calc_loss_model_f32(&model, &x_train, &y_train, &train_loss);
        aialgo_calc_loss_model_f32(&model, &x_val,   &y_val,   &val_loss);

        float train_acc = eval_acc_tensor(x_train_data, y_train_data, N_TRAIN);
        float val_acc   = eval_acc_tensor(x_val_data,   y_val_data,   N_VAL);

        char line[128];
        snprintf(line, sizeof(line), "%u,%lu,%.6f,%.6f,%.2f,%.2f\n",
                 (unsigned)epoch, (unsigned long)dt,
                 (double)train_loss, (double)val_loss,
                 (double)train_acc, (double)val_acc);
        Serial.print(line);
        metrics_log += line;

        if (val_loss < (best_val_loss - MIN_DELTA)) {
            best_val_loss = val_loss;
            no_improve = 0;
            memcpy(best_pmem, pmem, psize);
        } else {
            no_improve++;
        }
    }

}

static float eval_test_plain(const float (*X)[DS_F], const uint8_t* Y, uint16_t N, String& test_csv) {
    float x1[DS_F];
    uint16_t x1_shape[2] = {1, DS_F};
    aitensor_t x1_tensor = AITENSOR_2D_F32(x1_shape, x1);

    float outK[32];
    uint16_t out_shape[2] = {1, DS_K};
    aitensor_t out_tensor = AITENSOR_2D_F32(out_shape, outK);

    test_csv.reserve(200 * (size_t)N + 512);

    test_csv = "Sample,True_Label,Predicted_Label,Correct";
    for (uint8_t k = 0; k < DS_K; k++) {
        test_csv += ",Prob";
        test_csv += String(k);
    }
    test_csv += "\n";

    uint32_t correct = 0;

    char line_buf[1024];

    for (uint16_t i = 0; i < N; i++) {
        for (uint16_t j = 0; j < DS_F; j++) x1[j] = X[i][j];
        aialgo_inference_model(&model, &x1_tensor, &out_tensor);
        uint8_t pred = argmax32(outK, DS_K);
        bool is_correct = (pred == Y[i]);
        if (is_correct) correct++;

        int len = snprintf(line_buf, sizeof(line_buf),
                           "%u,%u,%u,%s",
                           (unsigned)i, (unsigned)Y[i], (unsigned)pred,
                           is_correct ? "Yes" : "No");

        if (len < 0 || len >= (int)sizeof(line_buf)) {
            Serial.println("ERROR: line_buf overflow in test_csv!");
            continue;
        }

        char* ptr = line_buf + len;

        for (uint8_t k = 0; k < DS_K; k++) {
            int prob_len = snprintf(ptr, sizeof(line_buf) - (ptr - line_buf),
                                    ",%.6f", (double)outK[k]);
            if (prob_len < 0 || prob_len >= (int)(sizeof(line_buf) - (ptr - line_buf))) {
                Serial.println("ERROR: prob overflow in test_csv!");
                break;
            }
            ptr += prob_len;
        }

        if (ptr - line_buf + 2 <= (int)sizeof(line_buf)) {
            *ptr++ = '\n';
            *ptr = '\0';
        } else {
            Serial.println("ERROR: final \n overflow!");
        }

        test_csv += line_buf;
    }

    float acc = 100.0f * (float)correct / (float)N;

    char acc_line[128];
    snprintf(acc_line, sizeof(acc_line), "\n# Overall Test Accuracy: %.2f\n", (double)acc);
    test_csv += acc_line;

    return acc;
}

/* ------------------- Federated state ------------------- */
static bool g_training_started = false;
static volatile bool g_weights_ready = false;
static volatile bool g_waiting_global = false;
static bool g_sent_once = false;
static uint16_t g_rounds_done = 0;
static bool g_model_built = false;
static bool g_data_ready = false;

static uint32_t g_last_send_ms = 0;
constexpr uint32_t SEND_PERIOD_MS = 15000;
constexpr uint32_t RESEND_TIMEOUT_MS = 60000;
constexpr uint32_t TX_SOCKET_TIMEOUT_SEC = 5;
constexpr uint8_t TX_RETRY_ATTEMPTS = 2;
constexpr size_t METRICS_LOG_CAPACITY = 256 + ((size_t)MAX_EPOCHS * 128);
constexpr size_t TEST_CSV_CAPACITY = ((size_t)TDS_N * 200) + 512;
constexpr size_t METRICS_PENDING_CAPACITY = METRICS_LOG_CAPACITY + 32 + TEST_CSV_CAPACITY;

// Metrics now combined with weights
static String g_metrics_pending;
static String g_metrics_log_buf;
static String g_test_csv_buf;
static uint8_t* g_tx_buf = nullptr;
static size_t g_tx_buf_size = 0;

static constexpr uint8_t WEIGHTS_MAGIC[4] = {'A', 'I', 'F', '2'};  // Use AIF2 for combined

struct EncResult {
    uint8_t* data;
    size_t len;
};

static void log_mem_snapshot(const char* tag) {
    size_t psram_free = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    size_t psram_largest = heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM);
    size_t heap_free = ESP.getFreeHeap();
    size_t heap_largest = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);

    Serial.printf("MEM %s: heap_free=%u heap_largest=%u psram_free=%u psram_largest=%u\n",
                  tag,
                  (unsigned)heap_free,
                  (unsigned)heap_largest,
                  (unsigned)psram_free,
                  (unsigned)psram_largest);
}

static size_t padded_payload_len(size_t weights_len, size_t metrics_len) {
    const size_t header_len = 4 + 4 + 4;
    const size_t data_len = header_len + weights_len + metrics_len + 32;
    return ((data_len + 7) / 8) * 8;
}

static void prepare_runtime_buffers() {
    if (!g_metrics_log_buf.reserve(METRICS_LOG_CAPACITY)) {
        Serial.printf("WARN: metrics_log reserve failed (%u)\n", (unsigned)METRICS_LOG_CAPACITY);
    }
    if (!g_test_csv_buf.reserve(TEST_CSV_CAPACITY)) {
        Serial.printf("WARN: test_csv reserve failed (%u)\n", (unsigned)TEST_CSV_CAPACITY);
    }
    if (!g_metrics_pending.reserve(METRICS_PENDING_CAPACITY)) {
        Serial.printf("WARN: metrics_pending reserve failed (%u)\n", (unsigned)METRICS_PENDING_CAPACITY);
    }

    size_t required_tx_buf = padded_payload_len(psize, METRICS_PENDING_CAPACITY);
    if (!g_tx_buf || g_tx_buf_size < required_tx_buf) {
        if (g_tx_buf) {
            heap_caps_free(g_tx_buf);
            g_tx_buf = nullptr;
            g_tx_buf_size = 0;
        }
        g_tx_buf = (uint8_t*)heap_caps_malloc(required_tx_buf, MALLOC_CAP_SPIRAM);
        if (!g_tx_buf) {
            Serial.printf("FATAL: g_tx_buf alloc failed (%u)\n", (unsigned)required_tx_buf);
            log_mem_snapshot("g_tx_buf_alloc_failed");
            while (true) delay(1000);
        }
        g_tx_buf_size = required_tx_buf;
        Serial.printf("TX buffer allocated once: %u bytes\n", (unsigned)g_tx_buf_size);
        log_mem_snapshot("g_tx_buf_ready");
    }
}

static inline uint32_t read_u32_be(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |
           (uint32_t)p[3];
}

static inline void write_u32_be(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v);
}

static EncResult buildAndEncryptCombined(const uint8_t* weights, size_t weights_len, const char* metrics, size_t metrics_len) {
    TS_START(pkt_t0);
    if (!weights || weights_len == 0) return {nullptr, 0};

    if (weights_len > 0xFFFFFFFFu - 40 || metrics_len > 0xFFFFFFFFu - 40) return {nullptr, 0};

    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);  // SHA-256
    mbedtls_sha256_update(&ctx, weights, weights_len);
    uint8_t hash[32];
    mbedtls_sha256_finish(&ctx, hash);
    mbedtls_sha256_free(&ctx);

    const size_t header_len = 4 + 4 + 4;  // AIF2 + u32 weights_len + u32 metrics_len
    const size_t dataLen = header_len + weights_len + metrics_len + 32;
    const size_t paddedLen = padded_payload_len(weights_len, metrics_len);

    Serial.printf("TX buffer plan: header=%u plain=%u padded=%u hash=32\n",
                  (unsigned)header_len, (unsigned)dataLen, (unsigned)paddedLen);
    log_mem_snapshot("before_encrypt_alloc");

    if (!g_tx_buf || g_tx_buf_size < paddedLen) {
        Serial.printf("TX buffer too small: need=%u have=%u\n",
                      (unsigned)paddedLen, (unsigned)g_tx_buf_size);
        log_mem_snapshot("tx_buf_too_small");
        return {nullptr, 0};
    }

    uint8_t* dataBuf = g_tx_buf;
    dataBuf[0] = WEIGHTS_MAGIC[0];
    dataBuf[1] = WEIGHTS_MAGIC[1];
    dataBuf[2] = WEIGHTS_MAGIC[2];
    dataBuf[3] = WEIGHTS_MAGIC[3];
    write_u32_be(dataBuf + 4, (uint32_t)weights_len);
    write_u32_be(dataBuf + 8, (uint32_t)metrics_len);
    memcpy(dataBuf + header_len, weights, weights_len);
    memcpy(dataBuf + header_len + weights_len, metrics, metrics_len);
    memcpy(dataBuf + header_len + weights_len + metrics_len, hash, 32);
    memset(dataBuf + dataLen, 0, paddedLen - dataLen);

    for (size_t i = 0; i < paddedLen; i += 8) {
        uint64_t blk = 0;
        for (int j = 0; j < 8; ++j) {
            blk = (blk << 8) | dataBuf[i + j];
        }
        uint64_t ct = enc64_fast(blk);
        for (int j = 0; j < 8; ++j) {
            dataBuf[i + j] = (uint8_t)(ct >> (56 - j * 8));
        }
    }

    enc_total_bytes += dataLen;
    uint32_t cyc_pkt = ESP.getCycleCount() - pkt_t0;
    enc_pkt_cyc += cyc_pkt;
    ++enc_pkt_cnt;

    log_mem_snapshot("after_encrypt_inplace");
    return {dataBuf, paddedLen};
}

/* ----------- ADAM FIX helper: reset optimizer state after global ----------- */
static void reset_adam_state_after_global() {
    if (tmem && tsize && optimizer) {
        aialgo_schedule_training_memory(&model, optimizer, tmem, tsize);
        aialgo_init_model_for_training(&model, optimizer);
    }
    Serial.println("ADAM FIX: optimizer state reset after applying global weights");
}

static bool apply_weights_from_plaintext(const uint8_t* pt, size_t len) {
    if (len < 8) {
        Serial.println("RX: payload too short");
        return false;
    }
    if (memcmp(pt, "AIF1", 4) != 0) {
        Serial.println("RX: bad magic");
        return false;
    }
    uint32_t payload_len = read_u32_be(pt + 4);
    if (payload_len < 32) {
        Serial.println("RX: payload_len too small for hash");
        return false;
    }
    uint32_t weights_len = payload_len - 32;
    if (weights_len != psize) {
        Serial.printf("RX: weight size mismatch (rx=%u expected=%u)\n",
                      (unsigned)weights_len, (unsigned)psize);
        return false;
    }
    if ((size_t)payload_len + 8 > len) {
        Serial.println("RX: payload shorter than header");
        return false;
    }

    const uint8_t* weights_bytes = pt + 8;
    const uint8_t* received_hash = pt + 8 + weights_len;

    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, weights_bytes, weights_len);
    uint8_t computed_hash[32];
    mbedtls_sha256_finish(&ctx, computed_hash);
    mbedtls_sha256_free(&ctx);

    if (memcmp(computed_hash, received_hash, 32) != 0) {
        Serial.println("RX: hash mismatch");
        return false;
    }

    memcpy(pmem, weights_bytes, weights_len);
    if (best_pmem) memcpy(best_pmem, pmem, psize);

    // ADAM FIX: reset optimizer moments after weights jump
    reset_adam_state_after_global();

    Serial.printf("Applied global weights: %u bytes (hash OK)\n", (unsigned)weights_len);
    return true;
}

static bool process_response_apply_weights(const uint8_t* pay, size_t len) {
    TS_START(pkt_t0);
    TS_START(parse_t0);

    if (!pay || len == 0) return false;
    if (len % 8 != 0) {
        Serial.println("RX: ciphertext length not multiple of 8");
        return false;
    }

    uint8_t* plain = (uint8_t*)heap_caps_malloc(len, MALLOC_CAP_SPIRAM);
    if (!plain) {
        Serial.println("RX: malloc failed for plaintext");
        return false;
    }

    uint16_t blks = 0;
    for (size_t i = 0; i < len; i += 8) {
        uint64_t ct = 0;
        for (int j = 0; j < 8; ++j) {
            ct = (ct << 8) | pay[i + j];
        }
        uint64_t pt = dec64_fast(ct);
        ++blks;
        for (int j = 7; j >= 0; --j) {
            plain[i + (size_t)(7 - j)] = (uint8_t)((pt >> (j * 8)) & 0xFF);
        }
    }

    uint32_t cyc_pkt = ESP.getCycleCount() - pkt_t0;
    dec_total_bytes += blks * 8;
    dec_pkt_cyc += cyc_pkt;
    ++dec_pkt_cnt;
    parse_cyc += ESP.getCycleCount() - parse_t0;
    ++parse_cnt;

    bool ok = apply_weights_from_plaintext(plain, len);
    heap_caps_free(plain);
    return ok;
}

static bool send_combined_frame() {
    if (!pmem || psize == 0) {
        Serial.println("TX skipped: model weights are not ready");
        return false;
    }
    if (g_metrics_pending.length() == 0) {
        Serial.println("TX skipped: metrics payload is empty");
        return false;
    }

    size_t metrics_len = g_metrics_pending.length();
    Serial.printf("TX prepare: weights=%u metrics=%u bytes\n",
                  (unsigned)psize, (unsigned)metrics_len);
    log_mem_snapshot("before_tx_prepare");

    EncResult enc = buildAndEncryptCombined((const uint8_t*)pmem, psize, g_metrics_pending.c_str(), metrics_len);
    if (!enc.data || enc.len == 0) {
        Serial.println("TX prepare failed: encryption buffer was not created");
        log_mem_snapshot("tx_prepare_failed");
        return false;
    }

    Serial.printf("TX encrypted payload ready: ciphertext=%u bytes\n", (unsigned)enc.len);
    log_mem_snapshot("tx_payload_ready");

    uint8_t type = APP_DATA;
    uint8_t len_be[4];
    write_u32_be(len_be, (uint32_t)enc.len);

    for (uint8_t attempt = 1; attempt <= TX_RETRY_ATTEMPTS; ++attempt) {
        Serial.printf("TX attempt %u/%u: start\n",
                      (unsigned)attempt, (unsigned)TX_RETRY_ATTEMPTS);

        if (!ensure_session()) {
            Serial.printf("TX attempt %u/%u aborted: session is not ready\n",
                          (unsigned)attempt, (unsigned)TX_RETRY_ATTEMPTS);
            return false;
        }

        if (net.setTimeout(TX_SOCKET_TIMEOUT_SEC) < 0) {
            Serial.println("TX socket timeout setup failed");
        }

        size_t w1 = net.write(&type, 1);
        size_t w2 = net.write(len_be, 4);
        size_t w3 = net.write(enc.data, enc.len);

        if (w1 == 1 && w2 == 4 && w3 == enc.len) {
            Serial.printf("Combined sent: weights=%u metrics=%u ciphertext=%u bytes\n",
                          (unsigned)psize, (unsigned)metrics_len, (unsigned)enc.len);
            log_mem_snapshot("tx_sent_ok");
            return true;
        }

        Serial.printf("TX failed on attempt %u/%u (w1=%u w2=%u w3=%u expected=%u)\n",
                      (unsigned)attempt, (unsigned)TX_RETRY_ATTEMPTS,
                      (unsigned)w1, (unsigned)w2, (unsigned)w3, (unsigned)enc.len);
        log_mem_snapshot("tx_attempt_failed");
        net.stop();
        g_key_ready = false;
        delay(50);
    }

    Serial.println("TX failed: combined payload was not sent after all attempts");
    return false;
}

/* ------------------- RX state machine ------------------- */
enum RxState : uint8_t { RX_WAIT_TYPE = 0, RX_WAIT_LEN, RX_WAIT_PAYLOAD };

static RxState g_rx_state = RX_WAIT_TYPE;
static uint8_t g_rx_len_buf[4];
static uint8_t g_rx_len_pos = 0;
static uint32_t g_rx_payload_len = 0;
static uint8_t* g_rx_payload = nullptr;
static uint32_t g_rx_payload_pos = 0;

constexpr uint32_t RX_MAX = 131072;

static void reset_rx_state() {
    if (g_rx_payload) {
        heap_caps_free(g_rx_payload);
        g_rx_payload = nullptr;
    }
    g_rx_state = RX_WAIT_TYPE;
    g_rx_len_pos = 0;
    g_rx_payload_len = 0;
    g_rx_payload_pos = 0;
}

static void rx_pump() {
    while (net.connected() && net.available() > 0) {
        int b = net.read();
        if (b < 0) return;
        uint8_t byte = (uint8_t)b;

        switch (g_rx_state) {
            case RX_WAIT_TYPE:
                if (byte == REKEY_REQUEST) {
                    Serial.println("[HS] REKEY_REQUEST");
                    g_key_ready = false;
                    run_handshake();
                    reset_rx_state();
                    return;
                }
                if (byte == APP_DATA) {
                    g_rx_state = RX_WAIT_LEN;
                    g_rx_len_pos = 0;
                } else {
                    Serial.printf("RX unknown type: 0x%02X\n", byte);
                }
                break;

            case RX_WAIT_LEN:
                g_rx_len_buf[g_rx_len_pos++] = byte;
                if (g_rx_len_pos == 4) {
                    g_rx_payload_len = read_u32_be(g_rx_len_buf);
                    if (g_rx_payload_len == 0 || g_rx_payload_len > RX_MAX) {
                        Serial.printf("RX bad length: %u\n", (unsigned)g_rx_payload_len);
                        net.stop();
                        reset_rx_state();
                        return;
                    }
                    g_rx_payload_pos = 0;
                    g_rx_payload = (uint8_t*)heap_caps_malloc(g_rx_payload_len, MALLOC_CAP_SPIRAM);
                    if (!g_rx_payload) {
                        Serial.println("RX payload malloc failed, discarding");
                    }
                    g_rx_state = RX_WAIT_PAYLOAD;
                }
                break;

            case RX_WAIT_PAYLOAD:
                if (g_rx_payload && g_rx_payload_pos < g_rx_payload_len) {
                    g_rx_payload[g_rx_payload_pos] = byte;
                }
                g_rx_payload_pos++;
                if (g_rx_payload_pos >= g_rx_payload_len) {
                    if (g_rx_payload) {
                        bool applied = process_response_apply_weights(g_rx_payload, g_rx_payload_len);
                        if (applied) {
                            // received new global weights -> next training round can start
                            g_waiting_global = false;
                            g_weights_ready = false;
                            g_sent_once = false;
                        }
                        heap_caps_free(g_rx_payload);
                        g_rx_payload = nullptr;
                    }
                    g_rx_state = RX_WAIT_TYPE;
                }
                break;
        }
    }
}

/* ------------------- Perf print ------------------- */
static void printPerf() {
    heap_caps_check_integrity_all(true);
    
    static uint32_t lastMs = 0;
    uint32_t now = millis();
    uint32_t dtMs = now - lastMs;
    if (dtMs < 1000) return;
    lastMs = now;

    uint32_t cryptoCycles = enc_cyc + dec_cyc;
    float cpuPct = (cryptoCycles / (ESP.getCpuFreqMHz() * 1000.0f * dtMs)) * 100.0f;

    bool any = false;
    if (enc_cnt) {
        float avg_us = cyc2us(enc_cyc) / enc_cnt;
        float tot_us = cyc2us(enc_cyc);
        float tot_sec = tot_us / 1e6f;
        float enc_speed_bps = (tot_sec > 0) ? enc_total_bytes / tot_sec : 0.0f;
        float enc_speed_kbps = enc_speed_bps / 1024.0f;
        Serial.printf("enc total time: %.2f us | avg: %.2f us/blk (%u blks)\n",
                      tot_us, avg_us, enc_cnt);
        Serial.printf("enc speed: %.2f KB/s\n", enc_speed_kbps);
        any = true;
    }
    if (dec_cnt) {
        float avg_us = cyc2us(dec_cyc) / dec_cnt;
        float tot_us = cyc2us(dec_cyc);
        float tot_sec = tot_us / 1e6f;
        float dec_speed_bps = (tot_sec > 0) ? dec_total_bytes / tot_sec : 0.0f;
        float dec_speed_kbps = dec_speed_bps / 1024.0f;
        Serial.printf("dec total time: %.2f us | avg: %.2f us/blk (%u blks)\n",
                      tot_us, avg_us, dec_cnt);
        Serial.printf("dec speed: %.2f KB/s\n", dec_speed_kbps);
        any = true;
    }
    if (any) {
        constexpr size_t RAM_BANK = 512 * 1024;
        size_t heapFree = ESP.getFreeHeap();
        size_t ramUsedB = (heapFree < RAM_BANK) ? RAM_BANK - heapFree : 0;
        float ramPct = (float)ramUsedB / RAM_BANK * 100.0f;
        size_t flashUsedB = ESP.getSketchSize();
        size_t flashTotalB = ESP.getFlashChipSize();
        float flashPct = (float)flashUsedB / flashTotalB * 100.0f;
        Serial.printf("RAM used: %u B (%.1f%% of 512 KB) | FLASH used: %u B (%.2f%% of %u KB) | CPU-crypto: %.2f%%\n\n",
                      (unsigned)ramUsedB, ramPct,
                      (unsigned)flashUsedB, flashPct, (unsigned)(flashTotalB / 1024),
                      cpuPct);
    }
    if (enc_pkt_cnt) {
        float avg_us = cyc2us(enc_pkt_cyc) / enc_pkt_cnt;
        float tot_us = cyc2us(enc_pkt_cyc);
        Serial.printf("enc-pkt: %.2f us/pkt | %.2f us total (%u pkts)\n",
                      avg_us, tot_us, enc_pkt_cnt);
    }
    if (dec_pkt_cnt) {
        float avg_us = cyc2us(dec_pkt_cyc) / dec_pkt_cnt;
        float tot_us = cyc2us(dec_pkt_cyc);
        Serial.printf("dec-pkt: %.2f us/pkt | %.2f us total (%u pkts)\n",
                      avg_us, tot_us, dec_pkt_cnt);
    }
    if (parse_cnt) {
        float avg_us = cyc2us(parse_cyc) / parse_cnt;
        float tot_us = cyc2us(parse_cyc);
        Serial.printf("parse: %.2f us/call | %.2f us total (%u calls)\n",
                      avg_us, tot_us, parse_cnt);
    }

    enc_cyc = enc_cnt = 0;
    dec_cyc = dec_cnt = 0;
    enc_pkt_cyc = enc_pkt_cnt = 0;
    dec_pkt_cyc = dec_pkt_cnt = 0;
    parse_cyc = parse_cnt = 0;
    enc_total_bytes = 0;
    dec_total_bytes = 0;
}

/* ------------------- Training task ------------------- */
static void training_task(void* pv) {
    (void)pv;

    randomSeed(SHUFFLE_SEED);

    Serial.println("\nAIfES training + CSV logging + early stopping");
    if (!g_data_ready) {
        make_train_val_tensors();
        g_data_ready = true;
    }
    if (!g_model_built) {
        build_model();
        prepare_runtime_buffers();
        g_model_built = true;
    } else {
        if (best_pmem) memcpy(best_pmem, pmem, psize);
    }

    float tr0 = 0.0f, va0 = 0.0f;
    aialgo_calc_loss_model_f32(&model, &x_train, &y_train, &tr0);
    aialgo_calc_loss_model_f32(&model, &x_val,   &y_val,   &va0);
    Serial.printf("Initial train_loss=%.6f val_loss=%.6f\n", (double)tr0, (double)va0);

    g_metrics_log_buf = "";
    g_test_csv_buf = "";

    String& metrics_log = g_metrics_log_buf;
    train_with_early_stopping(metrics_log);

    String& test_csv = g_test_csv_buf;
    float test_acc = eval_test_plain(TDS_X, TDS_Y, TDS_N, test_csv);
    Serial.printf("FINAL_TEST_ACC=%.2f\n", (double)test_acc);
    Serial.printf("TEST CSV size=%u bytes\n", (unsigned)test_csv.length());
    log_mem_snapshot("after_test_eval");

    Serial.println("\nFirst 10 rows of test_csv:");
    int line_count = 0;
    int pos = 0;
    while (line_count < 10 && pos < test_csv.length()) {
        int next_pos = test_csv.indexOf('\n', pos);
        if (next_pos == -1) next_pos = test_csv.length();
        String line = test_csv.substring(pos, next_pos);
        Serial.println(line);
        pos = next_pos + 1;
        line_count++;
    }
    if (line_count < 10) {
        Serial.println("(Less than 10 lines available)");
    }

    Serial.println("First 10 rows of weights (10 per row):");
    float* weights = (float*)pmem;
    uint32_t num_weights = psize / sizeof(float);
    for (uint32_t row = 0; row < 10; row++) {
        for (uint32_t col = 0; col < 10; col++) {
            uint32_t idx = row * 10 + col;
            if (idx < num_weights) Serial.printf("%.6f ", weights[idx]);
            else break;
        }
        Serial.println();
    }

    g_metrics_pending = metrics_log + "\n# Test Results\n" + test_csv;
    Serial.printf("METRICS pending assembled: metrics_log=%u test_csv=%u combined=%u bytes\n",
                  (unsigned)metrics_log.length(),
                  (unsigned)test_csv.length(),
                  (unsigned)g_metrics_pending.length());
    log_mem_snapshot("after_metrics_concat");

    g_weights_ready = true;
    g_waiting_global = false;
    g_last_send_ms = millis() - SEND_PERIOD_MS;

    Serial.printf("Local training done. Weights ready (%u bytes).\n", (unsigned)psize);
    g_rounds_done++;
    Serial.printf("Round %u/%u completed.\n", (unsigned)g_rounds_done, (unsigned)TRAIN_ROUNDS);
    Serial.printf("TX queued after round %u: metrics_pending=%u bytes\n",
                  (unsigned)g_rounds_done, (unsigned)g_metrics_pending.length());

    g_training_started = false;
    vTaskDelay(pdMS_TO_TICKS(10));
    vTaskDelete(nullptr);
}

static bool start_training_task() {
    if (g_training_started) return true;
    if (g_rounds_done >= TRAIN_ROUNDS) return true;

    BaseType_t ok = xTaskCreatePinnedToCore(
        training_task,
        "trainTask",
        TRAIN_TASK_STACK_WORDS,
        nullptr,
        TRAIN_TASK_PRIORITY,
        nullptr,
        TRAIN_TASK_CORE);

    if (ok != pdPASS) {
        Serial.println("FATAL: failed to create training task");
        return false;
    }
    g_training_started = true;
    return true;
}

/* ------------------- setup & loop ------------------- */
void setup() {
    Serial.begin(SERIAL_BAUD);
    delay(200);
    
    WiFi.begin(SSID, PASS);
    while (WiFi.status() != WL_CONNECTED) { Serial.print('.'); delay(400); }
    Serial.println("\nWi-Fi OK");

    g_auth_cfg.server_ip = SERVER_IP;
    g_auth_cfg.port = PORT;
    g_auth_cfg.master_key = MASTER_KEY;
    g_auth_cfg.master_key_len = MASTER_KEY_LEN;
    g_auth_cfg.io_timeout_ms = HS_TIMEOUT_MS;
    g_auth_cfg.device_id = nullptr;
    g_auth_cfg.client = &net;

    run_handshake();

    Serial.printf("CPU %d MHz\n", ESP.getCpuFreqMHz());
    size_t psram_size = heap_caps_get_total_size(MALLOC_CAP_SPIRAM);
    Serial.printf("PSRAM size: %u bytes\n", (unsigned)psram_size);
    if (psram_size == 0) Serial.println("PSRAM not available!");

    if (g_key_ready) start_training_task();
}

void loop() {
    if (!ensure_session()) {
        delay(10);
        printPerf();
        return;
    }

    // Start training when we have a key and we are not holding local weights ready
    if (!g_training_started && g_key_ready && !g_weights_ready) {
        start_training_task();
    }

    rx_pump();

    unsigned long now = millis();

    // Send combined when ready
    if (!g_sent_once && g_weights_ready && !g_waiting_global && (now - g_last_send_ms >= SEND_PERIOD_MS)) {
        Serial.printf("TX trigger: round=%u weights_ready=1 waiting_global=0 sent_once=0\n",
                      (unsigned)g_rounds_done);
        bool sent = send_combined_frame();
        g_last_send_ms = now;

        if (sent) {
            g_metrics_pending = "";
            g_waiting_global = true;
            g_sent_once = true;
            Serial.println("TX state: upload completed, waiting for global weights");
        } else {
            Serial.println("TX state: upload did not complete, next retry will be visible in logs");
        }
    }

    // Resend window for combined
    if (g_waiting_global && (now - g_last_send_ms >= RESEND_TIMEOUT_MS)) {
        g_waiting_global = false;
    }

    printPerf();
    vTaskDelay(pdMS_TO_TICKS(5));
}
