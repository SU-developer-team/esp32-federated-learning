# ESP32 Federated Learning Experiments

This repository contains ESP32-S3 firmware and Python-side tooling for federated learning experiments, secure weight transfer over Wi-Fi, and lightweight crypto benchmarking.

The project combines:
- ESP32-S3 client firmware for local training and weight upload
- ESP32-S3 centralized training firmware for baseline comparison
- ECDH + PSK authentication and key exchange
- Python server code for receiving, aggregating, and analyzing model updates
- LabVIEW measurement assets used during power and energy experiments
- RAM, flash, and speed benchmarks for lightweight ciphers

## Repository Layout

### Root
- [platformio.ini](/d:/esp32_federated/platformio.ini) defines all PlatformIO environments.
- [esp32-s3-devkitc-1-n16r8v.json](/d:/esp32_federated/esp32-s3-devkitc-1-n16r8v.json) is the board manifest that should be used for this project.
- [src](/d:/esp32_federated/src) contains all firmware sources.
- [lib/auth_ecdh](/d:/esp32_federated/lib/auth_ecdh) contains the local authentication library.
- [server](/d:/esp32_federated/server) contains the Python server code, metric analysis scripts, and related utilities.
- [labview](/d:/esp32_federated/labview) contains the LabVIEW project file used to measure power and energy consumption during the experiments.
- [server/graph](/d:/esp32_federated/server/graph) stores generated experiment graphs, including power and energy plots.

### Firmware in `src`
- [federated_train_device_1](/d:/esp32_federated/src/federated_train_device_1), [federated_train_device_2](/d:/esp32_federated/src/federated_train_device_2), and [federated_train_device_3](/d:/esp32_federated/src/federated_train_device_3) are federated learning firmware variants for different devices.
- [federated_train_centr](/d:/esp32_federated/src/federated_train_centr) contains the centralized training firmware and datasets used as a single-node baseline for comparison against the federated setup.
- [auth_ecdh](/d:/esp32_federated/src/auth_ecdh) contains firmware used to test the `auth_ecdh` library.
- [ecdh_handshake](/d:/esp32_federated/src/ecdh_handshake) contains a manual ECDH handshake implementation.
- [ecdh_handshake_speed](/d:/esp32_federated/src/ecdh_handshake_speed) measures handshake performance.
- [aifes_init_dump](/d:/esp32_federated/src/aifes_init_dump) dumps initial AIfES model weights.
- [benchmarks_ram](/d:/esp32_federated/src/benchmarks_ram), [benchmarks_flash](/d:/esp32_federated/src/benchmarks_flash), and [benchmarks_speed](/d:/esp32_federated/src/benchmarks_speed) contain benchmark firmware.
- [weights_q.h](/d:/esp32_federated/src/weights_q.h) stores embedded quantized model weights used by some firmware.

## Authentication Library

The local authentication library is stored in [lib/auth_ecdh](/d:/esp32_federated/lib/auth_ecdh).

Main API:
- [auth_ecdh.h](/d:/esp32_federated/lib/auth_ecdh/src/auth_ecdh.h) defines `AuthEcdhConfig`.
- `auth_ecdh_handshake(...)` performs the authenticated handshake.
- `auth_ecdh_error_str(...)` returns human-readable error text.

This library is part of the repository and should stay tracked by Git.

## Python Server Folder

The [server](/d:/esp32_federated/server) folder contains the Python-side server code and analysis tools.

Important files:
- [secure_federated_server.py](/d:/esp32_federated/server/secure_federated_server.py) is the main secure TCP server for federated weight exchange.
- [speck_tcp_server.py](/d:/esp32_federated/server/speck_tcp_server.py) is a simpler TCP server variant.
- [analyze_test_metrics.py](/d:/esp32_federated/server/analyze_test_metrics.py) analyzes test metrics and builds confusion matrices and accuracy plots.
- [compare_saved_weights.py](/d:/esp32_federated/server/saved_weights/compare_saved_weights.py) compares saved weight dumps.
- [requirements.txt](/d:/esp32_federated/server/requirements.txt) lists Python dependencies for the server-side scripts.

Experiment logs, exported metrics, and generated plots are stored in [server_logs](/d:/esp32_federated/server/server_logs).

Additional saved measurement graphs, such as power, current, voltage, and cumulative energy plots, are stored in [graph](/d:/esp32_federated/server/graph).

The `server/server_logs`, `server/saved_weights/*.txt`, and similar generated artifacts are local outputs and should not be committed.

## PlatformIO Environments

The full list is in [platformio.ini](/d:/esp32_federated/platformio.ini). The most important environments are:

### Secure transfer and training
- `federated_train_device_1`
- `federated_train_device_2`
- `federated_train_device_3`
- `federated_train_centr`

### Authentication and handshake
- `auth_ecdh_once`
- `auth_ecdh_rekey`
- `ecdh_handshake`
- `ecdh_handshake_speed`

### Benchmarks
- `bench_ram_present`, `bench_ram_simon`, `bench_ram_speck`
- `bench_flash_present`, `bench_flash_simon`, `bench_flash_speck`
- `bench_speed_present`, `bench_speed_simon`, `bench_speed_speck`

### Utility firmware
- `aifes_init_dump`

## Build and Upload

Examples:

```bash
pio run -e federated_train_device_1 -t upload
pio device monitor -b 115200
```

Run a benchmark build:

```bash
pio run -e bench_speed_speck -t upload
```

## Notes

- The project is intended to use the local board manifest [esp32-s3-devkitc-1-n16r8v.json](/d:/esp32_federated/esp32-s3-devkitc-1-n16r8v.json).
- The board ID used in [platformio.ini](/d:/esp32_federated/platformio.ini) is `esp32-s3-devkitc-1-n16r8v`.
- PSRAM is enabled in [platformio.ini](/d:/esp32_federated/platformio.ini).
- Some firmware keeps Wi-Fi credentials, server IPs, and keys directly in source files.
- The training firmware uses embedded datasets stored in header files.
- The federated training flows depend on the Python server code in [server](/d:/esp32_federated/server).
- The [labview/labview.vi](/d:/esp32_federated/labview/labview.vi) file is the measurement workflow used to capture energy and power consumption during the hardware experiments.
- A repository scan found no files larger than `150 MB` at the moment.

## Project Status

This is an experimental research repository.

- Some firmware targets are intended for active use.
- Some targets are standalone tests or benchmarks.
- The repository structure has been cleaned up, but the project still contains experimental code paths and hardcoded settings.
