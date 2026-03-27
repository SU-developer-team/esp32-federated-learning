/*******************************************************
 * aifes_init_dump_test.ino
 * Purpose: dump initial weights from AIfES (ESP32)
 *******************************************************/
#include <Arduino.h>
#include <aifes.h>

#include "federated_train_device_4/dataset_embedded.h"   // DS_F, DS_K

static const uint32_t SERIAL_BAUD = 115200;

static const uint16_t H1 = 64;
static const uint16_t H2 = 64;
static const uint16_t H3 = 32;

static uint16_t INPUT_SHAPE[2] = {1, DS_F};

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

void* pmem = nullptr;
uint32_t psize = 0;

static void build_model_and_init() {
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

  aialgo_compile_model(&model);

  psize = aialgo_sizeof_parameter_memory(&model);
  pmem = malloc(psize);
  if (!pmem) {
    Serial.printf("FATAL: pmem malloc failed (%u)\n", (unsigned)psize);
    while (true) delay(1000);
  }
  aialgo_distribute_parameter_memory(&model, pmem, psize);

  // This calls default init for each layer that has init_params
  aialgo_initialize_parameters_model(&model);

  Serial.printf("Model built. psize=%u bytes => %u float32\n",
                (unsigned)psize, (unsigned)(psize / 4));
}

static void dump_stats_and_head(uint32_t head_n = 200) {
  float* w = (float*)pmem;
  uint32_t n = psize / 4;

  float mn = w[0], mx = w[0];
  double sum = 0.0, sum2 = 0.0;

  Serial.printf("=== AIfES INIT DUMP TEST ===\nDS_F=%u DS_K=%u\n",
                (unsigned)DS_F, (unsigned)DS_K);

  Serial.println("INIT_WEIGHTS first 200:");
  for (uint32_t i = 0; i < n; i++) {
    float v = w[i];
    if (v < mn) mn = v;
    if (v > mx) mx = v;
    sum += (double)v;
    sum2 += (double)v * (double)v;

    if (i < head_n) {
      Serial.printf("%u: %.9f\n", (unsigned)i, (double)v);
    }
  }

  double mean = sum / (double)n;
  double var = (sum2 / (double)n) - mean * mean;
  double stdv = (var > 0) ? sqrt(var) : 0;

  Serial.printf("STATS over %u floats: min=%.9f max=%.9f mean=%.9f std=%.9f\n",
                (unsigned)n, (double)mn, (double)mx, mean, stdv);
}

void setup() {
  Serial.begin(SERIAL_BAUD);
  delay(300);

  Serial.printf("DS_F=%u DS_K=%u\n", (unsigned)DS_F, (unsigned)DS_K);

  build_model_and_init();
  dump_stats_and_head(200);
}

void loop() {
  delay(2000);
}
