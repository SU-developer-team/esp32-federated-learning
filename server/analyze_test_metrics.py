import glob
import os
from io import StringIO

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay

# ------------------- SETTINGS -------------------
date = 'server_logs/2026-02-23'
group = 'group_1'
base_path = os.path.join(date, group, 'devices')

CLASS_NAMES = [
    "Benign",
    "No DDoS",
    "DDoS icmp flood",
    "DDoS UDP flood",
    "DDoS TCP flood",
    "DDoS PSHACK",
    "DDoS Syn flood",
    "DDoS RSTFIN flood",
    "DDoS Synonymous ip flood",
    "DDoS ICMP fragmentation",
    "DDoS UDP fragmentation",
    "DDoS ACK Fragmentation",
    "Mirai",
    "MITM",
    "Reconnaissance",
    "Vulnerability scan",
]
LABELS = list(range(len(CLASS_NAMES)))


def parse_csv(file_path: str):
    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        lines = f.readlines()

    accuracy = None
    if lines and lines[-1].startswith('# Overall Test Accuracy:'):
        try:
            accuracy = float(lines[-1].split(':')[-1].strip())
        except Exception:
            accuracy = None
        content_lines = lines[:-1]
    else:
        content_lines = lines

    df = pd.read_csv(StringIO(''.join(content_lines)))
    true_labels = df['True_Label'].astype(int).values
    pred_labels = df['Predicted_Label'].astype(int).values
    return true_labels, pred_labels, accuracy


def save_confusion_matrix(true_labels, pred_labels, save_path: str, title: str):
    cm = confusion_matrix(true_labels, pred_labels, labels=LABELS)
    save_confusion_matrix_from_array(cm, save_path, title, values_format='d')


def save_confusion_matrix_from_array(
    cm: np.ndarray,
    save_path: str,
    title: str,
    values_format='d',
    im_kw=None,
):
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=CLASS_NAMES)
    fig, ax = plt.subplots(figsize=(12, 10))
    disp.plot(
        ax=ax,
        cmap='Blues',
        values_format=values_format,
        colorbar=True,
        im_kw=im_kw,
    )
    ax.set_title(title)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("True")
    plt.setp(ax.get_xticklabels(), rotation=45, ha='right')
    plt.setp(ax.get_yticklabels(), rotation=0)
    fig.tight_layout()
    fig.savefig(save_path, dpi=300)
    plt.close(fig)


def save_accuracy_plot(round_nums, accuracies, device_path: str):
    plt.figure(figsize=(8, 6))
    plt.plot(round_nums, accuracies, marker='o')
    plt.xlabel('Round Number')
    plt.ylabel('Test Accuracy')
    plt.title('Test Accuracy per Round')
    plt.ylim(0, 100)
    plt.grid(True)
    save_path = os.path.join(device_path, 'accuracy_per_round.png')
    plt.tight_layout()
    plt.savefig(save_path, dpi=300)
    plt.close()


def save_avg_accuracy_plot(round_nums, avg_accuracies, save_path: str):
    plt.figure(figsize=(8, 6))
    plt.plot(round_nums, avg_accuracies, marker='o')
    plt.xlabel('Round Number')
    plt.ylabel('Avg Test Accuracy (all devices)')
    plt.title('Average Test Accuracy per Round (All Devices)')
    plt.ylim(0, 100)
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(save_path, dpi=300)
    plt.close()


def save_all_devices_accuracy_plot(device_to_rounds_accs: dict, save_path: str):
    plt.figure(figsize=(10, 7))

    for idx, (_, data) in enumerate(sorted(device_to_rounds_accs.items()), start=1):
        rounds = data.get("rounds", [])
        accs = data.get("accs", [])
        if not rounds or not accs:
            continue
        plt.plot(rounds, accs, marker='o', linewidth=1, markersize=3, label=f"Device {idx}")

    plt.xlabel('Round Number')
    plt.ylabel('Test Accuracy')
    plt.title('Test Accuracy per Round (Each Device)')
    plt.ylim(0, 100)
    plt.grid(True)
    plt.legend(loc='best', fontsize=8, ncol=2, frameon=True)
    plt.tight_layout()
    plt.savefig(save_path, dpi=300)
    plt.close()


def avg_classification_reports(report_dicts: list[dict]) -> dict:
    keys_to_avg = CLASS_NAMES + ['macro avg', 'weighted avg']
    metrics = ['precision', 'recall', 'f1-score', 'support']
    out = {}

    for key in keys_to_avg:
        out[key] = {}
        for metric in metrics:
            vals = []
            for report in report_dicts:
                if key in report and metric in report[key]:
                    vals.append(report[key][metric])
            out[key][metric] = float(np.mean(vals)) if vals else float('nan')

    acc_vals = [
        report.get('accuracy')
        for report in report_dicts
        if isinstance(report.get('accuracy'), (int, float))
    ]
    out['accuracy'] = float(np.mean(acc_vals)) if acc_vals else float('nan')
    return out


def report_dict_to_dataframe(report_avg: dict) -> pd.DataFrame:
    rows = []
    idx = []

    for name in CLASS_NAMES:
        idx.append(name)
        rows.append([
            report_avg[name]['precision'],
            report_avg[name]['recall'],
            report_avg[name]['f1-score'],
            report_avg[name]['support'],
        ])

    idx.append('accuracy')
    rows.append([
        np.nan,
        np.nan,
        report_avg.get('accuracy', np.nan),
        report_avg.get('weighted avg', {}).get('support', np.nan),
    ])

    for name in ['macro avg', 'weighted avg']:
        idx.append(name)
        rows.append([
            report_avg[name]['precision'],
            report_avg[name]['recall'],
            report_avg[name]['f1-score'],
            report_avg[name]['support'],
        ])

    return pd.DataFrame(rows, index=idx, columns=['precision', 'recall', 'f1-score', 'support'])


def find_last_round_number(devices_root: str):
    round_numbers = []

    for device in os.listdir(devices_root):
        device_path = os.path.join(devices_root, device)
        if not os.path.isdir(device_path):
            continue

        for round_folder in os.listdir(device_path):
            round_path = os.path.join(device_path, round_folder)
            if round_folder.startswith('round_') and os.path.isdir(round_path):
                round_numbers.append(int(round_folder.split('_')[-1]))

    if not round_numbers:
        return None
    return max(round_numbers)


def load_confusion_matrix_for_round(device_path: str, round_num: int):
    round_path = None
    for round_folder in os.listdir(device_path):
        candidate_path = os.path.join(device_path, round_folder)
        if not (round_folder.startswith('round_') and os.path.isdir(candidate_path)):
            continue
        if int(round_folder.split('_')[-1]) == round_num:
            round_path = candidate_path
            break

    if round_path is None:
        return None

    rx_path = os.path.join(round_path, 'rx')
    if not os.path.isdir(rx_path):
        return None

    csv_files = glob.glob(os.path.join(rx_path, 'rx_test_metrics_*.csv'))
    if not csv_files:
        return None

    true_labels, pred_labels, _ = parse_csv(csv_files[0])
    return confusion_matrix(true_labels, pred_labels, labels=LABELS).astype(float)


def normalize_confusion_matrix(cm: np.ndarray) -> np.ndarray:
    row_sums = cm.sum(axis=1, keepdims=True)
    return np.divide(
        cm,
        row_sums,
        out=np.zeros_like(cm, dtype=float),
        where=row_sums != 0,
    )


def save_combined_confusion_matrix_versions(base_dir: str, round_num: int, cm_sum: np.ndarray, used_devices: int):
    raw_save_path = os.path.join(
        base_dir,
        f'confusion_matrix_round_{round_num:03d}_{used_devices}_devices.png',
    )
    save_confusion_matrix_from_array(
        cm_sum.astype(int),
        raw_save_path,
        f'Combined Confusion Matrix for Round {round_num} | devices={used_devices}',
        values_format='d',
    )

    normalized_cm = normalize_confusion_matrix(cm_sum)
    normalized_save_path = os.path.join(
        base_dir,
        f'confusion_matrix_round_{round_num:03d}_{used_devices}_devices_normalized.png',
    )
    save_confusion_matrix_from_array(
        normalized_cm,
        normalized_save_path,
        f'Normalized Combined Confusion Matrix for Round {round_num} | devices={used_devices}',
        values_format='.2f',
        im_kw={'vmin': 0.0, 'vmax': 1.0},
    )


if not os.path.isdir(base_path):
    raise FileNotFoundError(f"Base path not found: {base_path}")

devices = [
    d for d in os.listdir(base_path)
    if os.path.isdir(os.path.join(base_path, d))
]

last_round_num_global = find_last_round_number(base_path)
if last_round_num_global is None:
    raise FileNotFoundError(f"No round folders found in {base_path}")

round_to_accs: dict[int, list[float]] = {}
device_to_rounds_accs = {}
last_round_accuracies = []
last_round_report_dicts = []
devices_used_last = 0

for device in devices:
    device_path = os.path.join(base_path, device)
    round_folders = sorted(
        [
            r for r in os.listdir(device_path)
            if r.startswith('round_') and os.path.isdir(os.path.join(device_path, r))
        ],
        key=lambda x: int(x.split('_')[-1]),
    )

    accuracies = []
    round_nums = []
    last_valid = None

    for round_folder in round_folders:
        round_path = os.path.join(device_path, round_folder)
        rx_path = os.path.join(round_path, 'rx')
        if not os.path.exists(rx_path):
            continue

        csv_files = glob.glob(os.path.join(rx_path, 'rx_test_metrics_*.csv'))
        if not csv_files:
            continue

        csv_file = csv_files[0]
        true_labels, pred_labels, accuracy = parse_csv(csv_file)
        round_num = int(round_folder.split('_')[-1])

        if accuracy is None:
            continue

        round_nums.append(round_num)
        accuracies.append(accuracy)
        round_to_accs.setdefault(round_num, []).append(accuracy)

        cm_save_path = os.path.join(round_path, f'confusion_matrix_round_{round_num:03d}.png')
        save_confusion_matrix(true_labels, pred_labels, cm_save_path, f'Confusion Matrix for Round {round_num}')

        report_txt = classification_report(
            true_labels,
            pred_labels,
            labels=LABELS,
            target_names=CLASS_NAMES,
            digits=4,
            zero_division=0,
        )
        report_path = os.path.join(round_path, f'classification_report_round_{round_num:03d}.txt')
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report_txt)

        last_valid = (round_num, true_labels, pred_labels, accuracy)

    if round_nums:
        save_accuracy_plot(round_nums, accuracies, device_path)
        device_to_rounds_accs[device] = {"rounds": round_nums, "accs": accuracies}

    if last_valid is not None:
        _, last_true, last_pred, last_acc = last_valid
        devices_used_last += 1
        last_round_accuracies.append(last_acc)
        rep_dict = classification_report(
            last_true,
            last_pred,
            labels=LABELS,
            target_names=CLASS_NAMES,
            digits=6,
            zero_division=0,
            output_dict=True,
        )
        last_round_report_dicts.append(rep_dict)

if device_to_rounds_accs:
    save_all_devices_accuracy_plot(
        device_to_rounds_accs,
        os.path.join(base_path, 'all_devices_accuracy_per_round.png'),
    )

if round_to_accs:
    all_rounds_sorted = sorted(round_to_accs.keys())
    avg_accs = [float(np.mean(round_to_accs[r])) for r in all_rounds_sorted]
    save_avg_accuracy_plot(
        all_rounds_sorted,
        avg_accs,
        os.path.join(base_path, 'avg_accuracy_per_round.png'),
    )

combined_last_round_cms = []
for device in devices:
    device_path = os.path.join(base_path, device)
    cm = load_confusion_matrix_for_round(device_path, last_round_num_global)
    if cm is not None:
        combined_last_round_cms.append(cm)

if combined_last_round_cms:
    combined_cm = np.sum(combined_last_round_cms, axis=0)
    save_combined_confusion_matrix_versions(
        base_path,
        last_round_num_global,
        combined_cm,
        len(combined_last_round_cms),
    )

if devices_used_last > 0 and last_round_report_dicts:
    report_avg = avg_classification_reports(last_round_report_dicts)
    summary_row = {
        "num_devices": devices_used_last,
        "avg_test_accuracy": float(np.mean(last_round_accuracies)) if last_round_accuracies else float('nan'),
        "avg_macro_precision": report_avg["macro avg"]["precision"],
        "avg_macro_recall": report_avg["macro avg"]["recall"],
        "avg_macro_f1": report_avg["macro avg"]["f1-score"],
        "avg_weighted_precision": report_avg["weighted avg"]["precision"],
        "avg_weighted_recall": report_avg["weighted avg"]["recall"],
        "avg_weighted_f1": report_avg["weighted avg"]["f1-score"],
    }

    df_summary = pd.DataFrame([summary_row])
    df_summary.to_csv(os.path.join(base_path, 'devices_summary_last_round.csv'), index=False)

    df_report_avg = report_dict_to_dataframe(report_avg)
    df_report_avg.to_csv(os.path.join(base_path, 'classification_report_avg_last_round.csv'))
else:
    warn_path = os.path.join(base_path, 'AGGREGATION_WARNING.txt')
    with open(warn_path, 'w', encoding='utf-8') as f:
        f.write(
            "No valid last-round metrics found for devices. "
            "Check that rx_test_metrics_*.csv exists and has accuracy line.\n"
        )

print("Done.")
print(f"Devices found: {len(devices)}")
print(f"Devices used (last round valid): {devices_used_last}")
print(f"Last common round used for combined confusion matrix: {last_round_num_global}")
print(f"Outputs saved into: {base_path}")
