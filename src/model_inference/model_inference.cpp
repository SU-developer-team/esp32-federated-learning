#include <Arduino.h>
#include "federated_global_model_float32.h"

// TensorFlow Lite Micro (из твоей библиотеки TensorFlowLite_ESP32)
#include "tensorflow/lite/micro/all_ops_resolver.h"
#include "tensorflow/lite/micro/micro_interpreter.h"
#include "tensorflow/lite/schema/schema_generated.h"
#include "tensorflow/lite/micro/micro_error_reporter.h"

// ======== Память под тензоры ========
constexpr int kTensorArenaSize = 256 * 1024;  // Увеличил — веса могут быть большими
static uint8_t tensor_arena[kTensorArenaSize] __attribute__((aligned(16)));

// ======== Глобальные переменные ========
tflite::MicroErrorReporter micro_error_reporter;
tflite::ErrorReporter* error_reporter = &micro_error_reporter;
const tflite::Model* model = nullptr;
tflite::AllOpsResolver resolver;
tflite::MicroInterpreter* interpreter = nullptr;

void setup() {
  Serial.begin(115200);
  delay(2000);
  Serial.println("\n=== Вывод весов модели (float32) ===");

  // === Загружаем модель ===
  model = tflite::GetModel(federated_global_model_float32_tflite);
  if (!model) {
    Serial.println("Ошибка: не удалось загрузить модель!");
    while (true) delay(100);
  }

  if (model->version() != TFLITE_SCHEMA_VERSION) {
    Serial.printf("Ошибка: версия модели %lu ≠ %d\n", model->version(), TFLITE_SCHEMA_VERSION);
    while (true) delay(100);
  }
  Serial.println("Модель успешно загружена.");

  // === Создаём интерпретатор ===
  static tflite::MicroInterpreter static_interpreter(
      model, resolver, tensor_arena, kTensorArenaSize, error_reporter);
  interpreter = &static_interpreter;

  if (interpreter->AllocateTensors() != kTfLiteOk) {
    Serial.println("Ошибка: не хватило памяти под тензоры! Увеличь kTensorArenaSize.");
    while (true) delay(100);
  }

  // === Получаем подграф (обычно 0) ===
  const auto* subgraph = model->subgraphs()->Get(0);
  if (!subgraph) {
    Serial.println("Ошибка: подграф не найден!");
    while (true) delay(100);
  }

  auto* tensors = subgraph->tensors();
  int tensor_count = tensors->size();
  Serial.printf("Найдено тензоров: %d\n", tensor_count);

  // === Проходим по всем тензорам и ищем веса (float32) ===
  for (int i = 0; i < tensor_count; ++i) {
    const auto* t = tensors->Get(i);

    // Пропускаем, если нет буфера (не веса)
    if (!t->buffer()) continue;

    // Проверяем тип — только float32
    if (t->type() != tflite::TensorType_FLOAT32) continue;

    int32_t buffer_idx = t->buffer();
    const auto* buffer = model->buffers()->Get(buffer_idx);
    if (!buffer || !buffer->data()) continue;

    const uint8_t* raw_data = buffer->data()->data();
    int num_elements = buffer->data()->size() / sizeof(float);
    const float* weights = reinterpret_cast<const float*>(raw_data);

    const char* name = t->name() ? t->name()->c_str() : "unnamed";

    Serial.printf("\n--- Тензор #%d: %s ---\n", i, name);
    Serial.printf("    Элементов: %d (%.2f KB)\n", num_elements, num_elements * 4.0 / 1024.0);

    // Выводим по 8 значений в строке
    for (int j = 0; j < num_elements; ++j) {
      Serial.printf("%.6f ", weights[j]);
      if ((j + 1) % 8 == 0) Serial.println();
    }
    if (num_elements % 8 != 0) Serial.println();
  }

  Serial.println("\n=== Вывод весов завершён ===");
}

void loop() {
  // Ничего не делаем
}




