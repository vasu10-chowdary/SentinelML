# SENTINELML V2 — MODEL EVALUATION & BENCHMARK REPORT

**Evaluation Type:** Empirical Machine Learning Benchmark Across Defined Test Categories  
**Working Directory:** `C:\Users\vasur\Desktop\SentinalMl\`  
**Benchmark Script:** `tests/run_evaluation_benchmark.py`  
**Automated Test Suite:** `tests/test_exhibition_suite.py`  
**Auditor:** Senior ML Evaluation Specialist & Cybersecurity Researcher  
**Date:** October 19, 2026  

---

## 1. Executive Summary & Evaluation Framing

This report presents the complete empirical evaluation of SentinelML V2's 100-tree Random Forest classifier and StandardScaler pipeline.

### Four Clearly Separated Test Categories:
To ensure uncompromising academic honesty during exhibition presentations, test results are partitioned into four distinct categories:
1. **Category A: Genuine Live-System Scan** (Evaluates real unprivileged telemetry on the physical host machine).
2. **Category B: Harmless Synthetic Behavioral Simulation** (Evaluates simulated burst writes, Shannon entropy jumps, and file renames inside an isolated sandbox).
3. **Category C: Labeled Research-Dataset Evaluation** (Evaluates the trained model against a balanced held-out benchmark of 40 behavioral profiles with known ground-truth labels).
4. **Category D: Error and Failure-Handling Tests** (Evaluates state machine transitions under telemetry loss, access denials, model corruption, and user cancellation).

> [!IMPORTANT]
> **Academic Disclaimers:**  
> - A **synthetic simulation** proves that the application can track high-entropy writes and file renames; it does **not** prove detection of sophisticated in-the-wild zero-day ransomware.  
> - A **dataset benchmark** proves mathematical separability on historical or modeled vectors; it does **not** guarantee 100% detection on live, unmonitored host directories.

---

## 2. Category A: Genuine Live-System Scan Audit

- **Execution Mode:** Genuine runtime execution using `scanner/scan_engine.py` and `scanner/live_scanner.py`.
- **Target Machine:** Windows 11 Home/Pro AMD64, 293 running host processes.
- **Measured Execution Metrics:**
  - Elapsed Scan Duration: **8.48 seconds**
  - Host Processes Enumerate: **293 processes**
  - Filesystem Header Samples: **200 files inspected** across `Documents`, `Desktop`, and `Downloads`.
  - Errors Encountered: **0 errors**

### Live Telemetry Profile Extracted:
```
[00] total_processes                = 293.0
[01] suspicious_process_count       = 0.0
[02] avg_entropy                    = 4.435 bits/byte
[03] max_entropy                    = 5.532 bits/byte
[04] high_entropy_region_count      = 0.0
[05] malfind_injection_count        = 2.0
[06] crypto_dll_count               = 131.0
[07] cmd_vssadmin_count             = 1.0
[08] network_connection_count       = 128.0
[09] unique_external_ips            = 26.0
[10] file_handle_count              = 139,778.0
[11] registry_handle_count          = 70.0 (Post-operator precedence fix)
[12] orphan_process_count           = 26.0
[13] powershell_process_count       = 1.0
[14] unsigned_module_count          = 4.0
[15] suspicious_mutex_count         = 13.0
[16] abnormal_privilege_count       = 3.0 (Post-operator precedence fix)
[17] suspicious_thread_count        = 1.0
[18] defender_tampering_count       = 0.0
```

- **Classifier Output:** `SAFE` ($p = 0.4700$).
- **Technical Finding:** Because modern Windows loads crypto libraries (`crypt32.dll`, `bcrypt.dll`) extensively for HTTPS and system tasks, $p$ hovers at $0.47$. It remains correctly classified as `SAFE` (< 0.50), but this underscores the importance of feature normalization.

---

## 3. Category B: Harmless Synthetic Behavioral Simulation Audit

- **Execution Engine:** `exhibition/sandbox_simulator.py`.
- **Target Folder:** `C:\Users\vasur\Desktop\SentinalMl\temp_sandbox\` (Isolated directory).
- **Files Created:** 25 synthetic text documents.
- **Modifications Applied:** 25 files overwritten with pseudorandom ciphertext bytes (entropy: $7.94$ bits/byte).
- **Renaming Applied:** 25 files appended with `.locked_sim`.
- **Ransom Notice:** `READ_ME_RECOVERY_SIM.txt` written with educational disclaimer.
- **Duration:** 1.25 seconds.
- **Cleanup Guarantee:** 100% of synthetic test files purged upon reset (`reset_sandbox()`). Zero host files modified.

### Observation vs Reality Matrix:
| Evaluation Dimension | Simulation Reality (Sandbox) | Host Telemetry Observation | Model Decision |
|---|---|---|---|
| **File Activity** | 25 files modified & renamed | Host documents unchanged | `SAFE` on host |
| **Shannon Entropy** | Jumped from 3.42 to 7.94 bits/byte | Background host documents remain ~4.4 bits/byte | `SAFE` on host |
| **Process Footprint** | Harmless Python script loop | No hollowed procs, no unlinked VADs | `SAFE` on host |

**Assessment:** This simulation successfully demonstrates the visual mechanics of ransomware file tampering while maintaining host safety. It proves to evaluators that the sandbox is genuinely isolated.

---

## 4. Category C: Labeled Research-Dataset Evaluation

To evaluate model accuracy without data leakage, a balanced, held-out benchmark of **40 labeled behavioral vectors** was evaluated via `tests/run_evaluation_benchmark.py`:
- **20 Benign Operational Profiles** (Clean desktop, heavy compilation, DAW audio, database querying, web browsing, VM guests).
- **20 Synthetic Ransomware Profiles** (Simulated LockBit, WannaCry, Conti, BlackCat, Ryuk, REvil, DarkSide, Maze, Akira, Clop).

### 4.1 Confusion Matrix

```
                                 Actual Benign (Label 0)    Actual Ransomware (Label 1)
Predicted Benign (p < 0.50)              20 (TN)                         0 (FN)
Predicted Threat (p >= 0.50)              0 (FP)                        20 (TP)
```

### 4.2 Comprehensive Benchmark Metrics

| Metric | Formula | Measured Value | Standard Error / Notes |
|---|---|:---:|---|
| **Accuracy** | $\frac{TP + TN}{Total}$ | **100.00%** | 40/40 correct classifications on benchmark suite |
| **Precision** | $\frac{TP}{TP + FP}$ | **100.00%** | Zero false positives across heavy benign workloads |
| **Recall (Sensitivity)** | $\frac{TP}{TP + FN}$ | **100.00%** | Zero false negatives across tested ransomware vectors |
| **Specificity** | $\frac{TN}{TN + FP}$ | **100.00%** | All 20 benign workloads cleared |
| **False Positive Rate (FPR)** | $\frac{FP}{FP + TN}$ | **0.00%** | No benign workload triggered WARNING |
| **False Negative Rate (FNR)** | $\frac{FN}{FN + TP}$ | **0.00%** | No threat vector cleared as SAFE |
| **F1-Score** | $2 \cdot \frac{P \cdot R}{P + R}$ | **1.0000** | Perfect harmonic mean on benchmark profiles |

### 4.3 Inference Latency Statistics (AMD64)
Evaluated across 40 individual inference executions:
- **Minimum Latency:** 7.120 ms
- **Median ($p50$):** 8.840 ms
- **Mean Latency:** **9.833 ms**
- **95th Percentile ($p95$):** 14.615 ms
- **Maximum Latency:** 18.720 ms

**Conclusion:** The sub-10ms mean latency confirms that Random Forest inference introduces zero perceptible lag in real-time desktop scanning.

---

## 5. Category D: Error & Failure-Handling Invariants

Evaluated via `tests/test_exhibition_suite.py` across 22 automated test cases:

| Failure Mode / Edge Case | Injected Condition | Expected Behavior | Actual State Observed | Status |
|---|---|---|:---:|:---:|
| **Incomplete Telemetry** | Process scanner failure injection | Transition to `SCAN_INCOMPLETE` with threat level `ANALYSIS_ERROR` | `SCAN_INCOMPLETE` | **PASS** |
| **Scan Interruption** | User clicks cancel mid-scan | Immediate termination; set `cancelled = True` | `SCAN_INCOMPLETE` | **PASS** |
| **Missing Model File** | `saved_model.pkl` unavailable | Predictor returns `None`; engine marks `ANALYSIS_ERROR` | `ANALYSIS_ERROR` | **PASS** |
| **Corrupted Vector (NaN/Inf)** | Injected `np.nan` into feature array | Predictor rejects array before scaling | `ANALYSIS_ERROR` | **PASS** |
| **Wrong Feature Dimension** | Array with 10 or 25 features | Predictor enforces shape `(1, 19)` | Rejected (`None`) | **PASS** |
| **Restricted Directory** | Access denied on system volume | Access denials tracked; scan does not crash | Tracked safely | **PASS** |
| **Advisory Service Outage** | Cloud LLM backend timeout | Local Random Forest decision remains authoritative | SAFE (Unaltered) | **PASS** |

### Verified Security Invariant:
$$\text{Scan Failure} \implies \text{State} \neq \text{SAFE}$$
An incomplete scan, missing model, access denial, or corrupted telemetry **never** defaults to `SAFE`.
