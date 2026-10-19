"""
SentinelML V2 — Empirical Evaluation Benchmark Harness
========================================================
Executes a reproducible evaluation of the Random Forest model and StandardScaler
across defined benign workloads, synthetic ransomware-like behavioral vectors,
and failure edge cases.

NOTE ON BENCHMARK FIDELITY:
This evaluation measures the classifier against controlled synthetic profiles and
functional system states. It is labeled as a FUNCTIONAL EVALUATION BENCHMARK,
not an unconstrained real-world malware dataset benchmark (such as EMBER or VirusShare).
"""

import time
import json
import logging
import sys
from pathlib import Path
from typing import List, Dict, Tuple, Any

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np

from ml.predictor import MLPredictor, FEATURE_NAMES

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("sentinel.eval.benchmark")


def generate_evaluation_dataset() -> List[Dict[str, Any]]:
    """
    Generate 40 balanced, labeled evaluation samples:
    - 20 Benign System Scenarios (Label: 0)
    - 20 Synthetic Ransomware-like Behavioral Scenarios (Label: 1)
    """
    dataset = []

    # ─────────────────────────────────────────────────────────────────
    # 20 BENIGN SCENARIOS (Ground Truth = 0: SAFE)
    # ─────────────────────────────────────────────────────────────────
    benign_templates = [
        ("Clean Desktop Idle", [150, 0, 3.2, 4.8, 0, 0, 1, 0, 15, 2, 4200, 2, 0, 0, 0, 0, 0, 0, 0]),
        ("Developer Web Server Running", [220, 0, 3.8, 5.2, 0, 0, 2, 0, 85, 8, 8500, 4, 1, 1, 0, 0, 0, 0, 0]),
        ("Bulk Photo Album Browsing", [180, 0, 4.1, 5.5, 2, 0, 1, 0, 25, 3, 6200, 3, 0, 0, 0, 0, 0, 0, 0]),
        ("Video Conferencing & Streaming", [260, 0, 3.6, 5.0, 0, 0, 3, 0, 120, 14, 9800, 6, 2, 0, 0, 1, 0, 0, 0]),
        ("Compilation / Gradle Build", [310, 1, 4.0, 5.8, 1, 0, 2, 0, 45, 5, 14000, 8, 3, 2, 1, 2, 0, 1, 0]),
        ("Windows System Update in Progress", [240, 1, 3.9, 5.4, 0, 0, 3, 0, 60, 6, 11000, 7, 1, 1, 0, 0, 0, 0, 0]),
        ("Heavy Database Querying", [200, 0, 3.5, 5.1, 0, 0, 2, 0, 75, 4, 16000, 12, 1, 0, 0, 3, 1, 1, 0]),
        ("Office Suite (Word, Excel, PPT)", [190, 0, 3.4, 5.0, 0, 0, 2, 0, 30, 4, 5400, 3, 0, 0, 0, 0, 0, 0, 0]),
        ("Music Production / DAW Project", [215, 0, 4.2, 5.9, 1, 0, 2, 0, 20, 2, 8900, 4, 0, 0, 0, 2, 0, 0, 0]),
        ("Virtual Machine Guest Running", [250, 0, 3.7, 5.3, 0, 0, 2, 0, 50, 5, 12500, 5, 1, 0, 0, 1, 0, 0, 0]),
        ("Web Browser with 30 Tabs", [280, 0, 3.6, 5.2, 0, 0, 3, 0, 160, 18, 13000, 8, 2, 0, 0, 2, 0, 0, 0]),
        ("Docker Container Spin-up", [270, 0, 3.8, 5.4, 0, 0, 2, 0, 90, 10, 11500, 6, 2, 1, 0, 1, 0, 0, 0]),
        ("Antivirus Background Definitions Update", [210, 0, 3.5, 5.0, 0, 0, 3, 0, 40, 4, 7800, 5, 0, 0, 0, 0, 0, 0, 0]),
        ("CAD 3D Modeling Session", [230, 0, 3.9, 5.6, 1, 0, 2, 0, 35, 3, 9200, 5, 1, 0, 0, 2, 0, 1, 0]),
        ("Audio Podcast Rendering", [175, 0, 3.7, 5.3, 0, 0, 1, 0, 18, 2, 4900, 3, 0, 0, 0, 1, 0, 0, 0]),
        ("Data Science Jupyter Lab Session", [240, 0, 4.0, 5.7, 1, 0, 2, 0, 55, 6, 10200, 6, 1, 1, 0, 1, 0, 0, 0]),
        ("Network File Transfer (SMB)", [195, 0, 3.5, 5.1, 0, 0, 1, 0, 40, 2, 7100, 4, 0, 0, 0, 0, 0, 0, 0]),
        ("Graphic Design Vector Export", [205, 0, 3.8, 5.4, 0, 0, 2, 0, 28, 3, 6500, 4, 0, 0, 0, 0, 0, 0, 0]),
        ("Gaming Client with Anti-Cheat Service", [235, 1, 3.6, 5.2, 0, 0, 2, 0, 65, 8, 8800, 5, 1, 0, 0, 2, 0, 0, 0]),
        ("Code Editor & Git Repository Rebase", [185, 0, 3.4, 4.9, 0, 0, 1, 0, 22, 3, 5600, 3, 0, 1, 0, 0, 0, 0, 0]),
    ]

    for name, vec in benign_templates:
        dataset.append({
            "name": name,
            "features": np.array([vec], dtype=np.float64),
            "label": 0,
            "category": "BENIGN"
        })

    # ─────────────────────────────────────────────────────────────────
    # 20 SYNTHETIC RANSOMWARE-LIKE SCENARIOS (Ground Truth = 1: THREAT)
    # Characterized by elevated Shannon entropy, shadow copy deletion,
    # crypto DLL loads, abnormal handle exhaustion, or Defender tampering.
    # ─────────────────────────────────────────────────────────────────
    ransom_templates = [
        ("Simulated LockBit 3.0 Profile", [160, 4, 7.85, 7.99, 45, 3, 6, 3, 85, 18, 1800, 280, 8, 4, 6, 4, 4, 35, 2]),
        ("Simulated WannaCry Propagation", [180, 6, 7.92, 8.00, 60, 5, 8, 4, 140, 32, 2200, 350, 12, 6, 8, 6, 6, 50, 3]),
        ("Simulated Conti Bulk Encryption", [150, 5, 7.88, 7.98, 50, 4, 7, 2, 95, 20, 1950, 310, 9, 3, 7, 5, 5, 42, 2]),
        ("Simulated BlackCat (ALPHV) Execution", [170, 7, 7.94, 8.00, 55, 6, 9, 5, 110, 25, 2400, 390, 14, 5, 9, 7, 7, 55, 4]),
        ("Simulated Ryuk Active Directory Strike", [190, 8, 7.90, 7.99, 52, 5, 8, 4, 125, 28, 2100, 340, 11, 7, 8, 6, 6, 48, 3]),
        ("Simulated REvil/Sodinokibi High-Thread", [165, 5, 7.86, 7.97, 48, 4, 6, 3, 90, 19, 1850, 290, 8, 4, 6, 5, 5, 40, 2]),
        ("Simulated DarkSide Infrastructure Lock", [175, 6, 7.89, 7.98, 54, 5, 7, 3, 105, 22, 2050, 330, 10, 5, 7, 6, 6, 45, 3]),
        ("Simulated Hive Rapid Symmetric Encryptor", [185, 7, 7.91, 8.00, 58, 6, 8, 4, 115, 26, 2300, 370, 13, 6, 8, 6, 6, 52, 3]),
        ("Simulated Babuk Multi-threaded Linux/Win", [155, 4, 7.84, 7.96, 44, 3, 5, 2, 80, 16, 1750, 270, 7, 3, 5, 4, 4, 38, 2]),
        ("Simulated Maze Dual-Extortion Setup", [195, 8, 7.93, 8.00, 62, 7, 9, 5, 135, 30, 2500, 410, 15, 7, 9, 7, 7, 58, 4]),
        ("Simulated Phobos Ransomware Traversal", [145, 4, 7.82, 7.95, 42, 3, 6, 2, 75, 15, 1650, 260, 7, 3, 5, 4, 4, 36, 2]),
        ("Simulated Dharma Endpoint Disruption", [150, 5, 7.85, 7.97, 46, 4, 7, 3, 85, 18, 1800, 280, 8, 4, 6, 5, 5, 40, 2]),
        ("Simulated MedusaLocker Service Disabler", [160, 6, 7.88, 7.98, 50, 5, 8, 4, 100, 22, 2000, 320, 10, 5, 7, 6, 6, 46, 3]),
        ("Simulated NetWalker Fast Memory Injector", [170, 7, 7.90, 7.99, 53, 6, 8, 3, 110, 24, 2150, 350, 12, 6, 8, 6, 6, 49, 3]),
        ("Simulated Avaddon Script-Driven Dropper", [180, 6, 7.87, 7.98, 49, 5, 7, 3, 105, 21, 1950, 310, 9, 8, 7, 5, 5, 44, 2]),
        ("Simulated BianLian Go-compiled Burst", [165, 5, 7.86, 7.97, 47, 4, 6, 3, 90, 19, 1850, 290, 8, 4, 6, 5, 5, 41, 2]),
        ("Simulated Play Ransomware Volume Stripper", [175, 7, 7.89, 7.99, 55, 6, 8, 4, 115, 25, 2250, 360, 11, 5, 8, 6, 6, 51, 3]),
        ("Simulated Royal Ransomware High-IOPS", [190, 8, 7.92, 8.00, 60, 6, 9, 4, 130, 29, 2450, 400, 14, 6, 9, 7, 7, 56, 4]),
        ("Simulated Akira File Tampering Pattern", [155, 5, 7.84, 7.96, 45, 4, 6, 3, 85, 17, 1750, 275, 8, 4, 6, 4, 4, 39, 2]),
        ("Simulated Clop Shadow Copy Annihilator", [200, 9, 7.95, 8.00, 65, 7, 9, 5, 145, 34, 2600, 430, 16, 7, 9, 8, 8, 62, 4]),
    ]

    for name, vec in ransom_templates:
        dataset.append({
            "name": name,
            "features": np.array([vec], dtype=np.float64),
            "label": 1,
            "category": "RANSOMWARE_SIM"
        })

    return dataset


def run_benchmark() -> Dict[str, Any]:
    """Execute evaluation benchmark across all dataset samples."""
    predictor = MLPredictor()
    if not predictor.load_model():
        raise RuntimeError("Failed to load model/scaler artifacts for benchmark!")

    dataset = generate_evaluation_dataset()
    results = []
    latencies_ms = []

    tp = 0
    fp = 0
    tn = 0
    fn = 0

    log.info("Starting evaluation across %d test cases...", len(dataset))

    for idx, sample in enumerate(dataset):
        t_start = time.perf_counter()
        pred_res = predictor.predict(sample["features"])
        t_elapsed = (time.perf_counter() - t_start) * 1000.0  # ms
        latencies_ms.append(t_elapsed)

        threat_level, prob = pred_res if pred_res else ("ERROR", 0.0)
        # Operational classification: >= 0.50 is positive (WARNING or CRITICAL)
        predicted_positive = 1 if prob >= 0.50 else 0
        actual_positive = sample["label"]

        if actual_positive == 1 and predicted_positive == 1:
            tp += 1
            status = "TP"
        elif actual_positive == 0 and predicted_positive == 0:
            tn += 1
            status = "TN"
        elif actual_positive == 0 and predicted_positive == 1:
            fp += 1
            status = "FP"
        else:
            fn += 1
            status = "FN"

        results.append({
            "index": idx + 1,
            "name": sample["name"],
            "category": sample["category"],
            "ground_truth": actual_positive,
            "predicted_label": predicted_positive,
            "threat_level": threat_level,
            "probability": round(prob, 4),
            "outcome": status,
            "latency_ms": round(t_elapsed, 3)
        })

    total = len(dataset)
    accuracy = (tp + tn) / total
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    summary = {
        "benchmark_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_samples": total,
        "benign_samples": 20,
        "ransomware_sim_samples": 20,
        "confusion_matrix": {
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn,
        },
        "metrics": {
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
        },
        "latency_stats_ms": {
            "mean": round(float(np.mean(latencies_ms)), 3),
            "p50": round(float(np.median(latencies_ms)), 3),
            "p95": round(float(np.percentile(latencies_ms, 95)), 3),
            "max": round(float(np.max(latencies_ms)), 3),
        },
        "sample_results": results
    }

    # Save to json file
    out_path = Path(__file__).resolve().parent / "benchmark_results.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    log.info("Benchmark complete! TP=%d, TN=%d, FP=%d, FN=%d, Acc=%.4f, F1=%.4f, Mean Latency=%.3f ms",
             tp, tn, fp, fn, accuracy, f1, summary["latency_stats_ms"]["mean"])
    return summary


if __name__ == "__main__":
    res = run_benchmark()
    print("\n" + "=" * 70)
    print("SENTINELML V2 — BENCHMARK RESULTS")
    print("=" * 70)
    print(f"Total Test Cases:    {res['total_samples']}")
    print(f"True Positives (TP): {res['confusion_matrix']['true_positives']}")
    print(f"True Negatives (TN): {res['confusion_matrix']['true_negatives']}")
    print(f"False Positives(FP): {res['confusion_matrix']['false_positives']}")
    print(f"False Negatives(FN): {res['confusion_matrix']['false_negatives']}")
    print(f"Accuracy:            {res['metrics']['accuracy'] * 100:.2f}%")
    print(f"Precision:           {res['metrics']['precision'] * 100:.2f}%")
    print(f"Recall:              {res['metrics']['recall'] * 100:.2f}%")
    print(f"F1-Score:            {res['metrics']['f1_score'] * 100:.2f}%")
    print(f"Mean Latency:        {res['latency_stats_ms']['mean']:.3f} ms")
    print(f"p95 Latency:         {res['latency_stats_ms']['p95']:.3f} ms")
    print("=" * 70)
