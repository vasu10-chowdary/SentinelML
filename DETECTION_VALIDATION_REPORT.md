# SENTINELML V2 — DETECTION PERFORMANCE VALIDATION REPORT

**Document Type:** Empirical Benchmark & Scientific Provenance Audit  
**Target System:** SentinelML V2 (`RandomForestClassifier`, 100 Trees, 19 Features)  
**Evaluation Script:** `tests/run_evaluation_benchmark.py`  
**Raw Results Output:** `tests/benchmark_results.json`  
**Execution Environment:** Windows 11 AMD64 | Python 3.14.3 | Scikit-Learn 1.6+  
**Audit Date:** October 19, 2026  

---

## 1. Executive Summary

This report documents the empirical evaluation of SentinelML V2's machine learning inference pipeline. Testing was executed using a reproducible benchmark harness across **40 controlled, labeled test cases** (20 benign operational workloads and 20 synthetic ransomware-like behavioral profiles).

### Key Performance Findings
- **Functional Accuracy:** 100.00% across the controlled functional benchmark suite (40/40 correct classifications).
- **Precision:** 100.00% (Zero false positives in tested benign business and development workloads).
- **Recall:** 100.00% (Zero false negatives in synthetic high-threat ransomware profiles).
- **F1-Score:** 1.0000.
- **Inference Latency:** Mean of **9.833 ms** per sample ($p95 = 14.615\text{ ms}$), easily satisfying real-time desktop monitoring requirements.

> **Crucial Academic Disclaimer:**  
> This benchmark validates the classifier's mathematical consistency and functional separation between benign host activity and ransomware behavioral vectors. It is designated as a **Controlled Functional Evaluation Benchmark**. It does **not** represent an unconstrained real-world malware test on active in-the-wild ransomware binaries.

---

## 2. Confusion Matrix & Benchmark Metrics

The 40 evaluated cases were categorized using the verified operational threshold:
$$\text{Class} = \begin{cases} \text{SAFE} & p < 0.50 \\ \text{WARNING / THREAT} & p \ge 0.50 \end{cases}$$

### 2.1 Confusion Matrix

```
                        Actual Negative (Benign)    Actual Positive (Ransomware Sim)
Predicted Negative (0)           20 (TN)                         0 (FN)
Predicted Positive (1)            0 (FP)                        20 (TP)
```

| Metric | Formula | Evaluated Value |
|---|---|:---:|
| **True Positives (TP)** | Correctly flagged high-threat profiles | **20** |
| **True Negatives (TN)** | Correctly cleared benign workloads | **20** |
| **False Positives (FP)** | Benign workloads erroneously flagged | **0** |
| **False Negatives (FN)** | Ransomware profiles missed | **0** |
| **Accuracy** | $\frac{TP + TN}{TP + TN + FP + FN}$ | **100.00%** |
| **Precision** | $\frac{TP}{TP + FP}$ | **100.00%** |
| **Recall (Sensitivity)** | $\frac{TP}{TP + FN}$ | **100.00%** |
| **F1-Score** | $2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$ | **1.0000** |

---

## 3. Latency & Computational Overhead

Inference latency was measured on an AMD64 architecture over 40 consecutive evaluations:

| Metric | Measured Value (Milliseconds) |
|---|:---:|
| **Minimum Latency** | **7.120 ms** |
| **Median (p50) Latency** | **8.840 ms** |
| **Mean Latency** | **9.833 ms** |
| **95th Percentile (p95)** | **14.615 ms** |
| **Maximum Latency** | **18.720 ms** |

**Assessment:** With a sub-15ms $p95$ latency, the Random Forest inference overhead is negligible compared to the underlying I/O of process enumeration and filesystem header sampling (3–5 seconds).

---

## 4. Evaluated Workload Profiles

### 4.1 Benign Operational Profiles (Ground Truth: SAFE)
Each benign scenario was constructed from realistic desktop telemetry:

| Scenario Index | Workload Description | Probability ($p$) | Classification | Status |
|:---:|:---|:---:|:---:|:---:|
| 01 | Clean Desktop Idle State | 0.1000 | SAFE | TN |
| 02 | Developer Local Web Server | 0.2400 | SAFE | TN |
| 03 | Bulk Photo Album Browsing | 0.1000 | SAFE | TN |
| 04 | Video Conferencing & Streaming | 0.2100 | SAFE | TN |
| 05 | Heavy Compilation / Gradle Build | 0.2900 | SAFE | TN |
| 06 | Windows System Update in Progress | 0.2200 | SAFE | TN |
| 07 | Heavy Database Queries & Handles | 0.2200 | SAFE | TN |
| 08 | Standard Office Suite (Word, PPT) | 0.0800 | SAFE | TN |
| 09 | Digital Audio Workstation (DAW) | 0.1200 | SAFE | TN |
| 10 | Virtual Machine Guest Active | 0.2200 | SAFE | TN |
| 11 | Web Browser with 30 Open Tabs | 0.2200 | SAFE | TN |
| 12 | Docker Container Spin-up | 0.2400 | SAFE | TN |
| 13 | Antivirus Background Definitions Update | 0.1900 | SAFE | TN |
| 14 | CAD 3D Modeling Session | 0.1400 | SAFE | TN |
| 15 | Audio Podcast Rendering | 0.1100 | SAFE | TN |
| 16 | Data Science Jupyter Lab Session | 0.2500 | SAFE | TN |
| 17 | Network SMB File Transfer | 0.2100 | SAFE | TN |
| 18 | Graphic Design Vector Export | 0.0700 | SAFE | TN |
| 19 | Gaming Client with Anti-Cheat Service | 0.2600 | SAFE | TN |
| 20 | Code Editor & Git Rebase Session | 0.1000 | SAFE | TN |

**Observation:** Even during resource-heavy tasks (compilation, Docker spin-ups, gaming anti-cheat hooks), probability remained $\le 0.29$, comfortably below the $0.50$ warning threshold.

### 4.2 Synthetic Ransomware Behavioral Profiles (Ground Truth: THREAT)
Profiles modeled after published threat intelligence archetypes:

| Scenario Index | Threat Archetype Simulated | Probability ($p$) | Classification | Status |
|:---:|:---|:---:|:---:|:---:|
| 21 | Simulated LockBit 3.0 Profile | 0.8400 | WARNING / THREAT | TP |
| 22 | Simulated WannaCry Propagation | 0.8700 | WARNING / THREAT | TP |
| 23 | Simulated Conti Bulk Encryption | 0.8600 | WARNING / THREAT | TP |
| 24 | Simulated BlackCat (ALPHV) Execution | 0.8500 | WARNING / THREAT | TP |
| 25 | Simulated Ryuk AD Strike | 0.8400 | WARNING / THREAT | TP |
| 26 | Simulated REvil/Sodinokibi High-Thread | 0.8300 | WARNING / THREAT | TP |
| 27 | Simulated DarkSide Infrastructure Lock | 0.8800 | WARNING / THREAT | TP |
| 28 | Simulated Hive Rapid Symmetric Encryptor | 0.8700 | WARNING / THREAT | TP |
| 29 | Simulated Babuk Multi-threaded Burst | 0.8500 | WARNING / THREAT | TP |
| 30 | Simulated Maze Dual-Extortion Setup | 0.8100 | WARNING / THREAT | TP |
| 31 | Simulated Phobos Ransomware Traversal | 0.8600 | WARNING / THREAT | TP |
| 32 | Simulated Dharma Endpoint Disruption | 0.8500 | WARNING / THREAT | TP |
| 33 | Simulated MedusaLocker Service Disabler | 0.8900 | WARNING / THREAT | TP |
| 34 | Simulated NetWalker Fast Memory Injector | 0.8600 | WARNING / THREAT | TP |
| 35 | Simulated Avaddon Script-Driven Dropper | 0.8600 | WARNING / THREAT | TP |
| 36 | Simulated BianLian Go-compiled Burst | 0.8300 | WARNING / THREAT | TP |
| 37 | Simulated Play Ransomware Volume Stripper | 0.8700 | WARNING / THREAT | TP |
| 38 | Simulated Royal Ransomware High-IOPS | 0.8400 | WARNING / THREAT | TP |
| 39 | Simulated Akira File Tampering Pattern | 0.8300 | WARNING / THREAT | TP |
| 40 | Simulated Clop Shadow Copy Annihilator | 0.8100 | WARNING / THREAT | TP |

**Observation:** All ransomware profiles triggered probabilities between $0.81$ and $0.89$, driven predominantly by the three Shannon entropy indicators (which account for 41.31% of total Gini model weight), shadow-copy deletion attempts, and elevated crypto DLL counts.

---

## 5. Provenance Review of Stored Training Metrics

The project repository includes a legacy `models/metrics.json` file reporting internal cross-validation benchmark results:
- Random Forest Accuracy: `0.9567` | F1-Score: `0.9671`
- SVM Accuracy: `0.9567` | F1-Score: `0.9671`
- Logistic Regression Accuracy: `0.9567` | F1-Score: `0.9671`

### Academic Audit Findings:
1. **Identical Metric Anomaly:** Three distinct algorithms reporting identical discrete metrics to four decimal places indicates they were evaluated on an identical discrete test partition.
2. **Missing Training Artifacts:** Because the raw original CSV dataset, seed parameters, and evaluation scripts were not preserved in the repository, the historical 95.67% accuracy figure cannot be independently reproduced from source.
3. **Reproducibility Guarantee:** In contrast, the 40-case functional evaluation harness (`tests/run_evaluation_benchmark.py`) is **100% reproducible** and executes directly against the deployed `saved_model.pkl` and `scaler.pkl`.
