# SENTINELML V2 — COMPREHENSIVE DETECTOR AUDIT

**Project:** SentinelML V2 — Behavioral Machine-Learning Ransomware Detection System  
**Working Directory:** `C:\Users\vasur\Desktop\SentinalMl\`  
**Target Environment:** Windows 11 AMD64 (Host) | Cross-Platform Telemetry Engine  
**Auditor:** Senior Cybersecurity Engineer, ML Evaluation Specialist & Technical Auditor  
**Date of Audit:** October 19, 2026  

---

## 1. Executive Summary

This audit delivers an evidence-based technical evaluation of SentinelML V2's ransomware detection engine. Rather than relying on assumptions or marketing claims, this audit analyzes the actual model artifacts (`saved_model.pkl`, `scaler.pkl`, `metrics.json`), the live telemetry extraction routines in `live_scanner.py`, the filesystem scanner in `filesystem_scanner.py`, the state machine in `scan_engine.py`, and the decoupled advisory copilot in `sentinel_ai.py`.

### Primary Audit Verdicts
1. **Genuine Live Telemetry Verified:** Live scans genuinely execute unprivileged system API calls (`psutil.process_iter`, socket queries, directory walks for Shannon entropy) and do **not** substitute hardcoded mock values during real scans.
2. **Deterministic ML Authority:** The local 100-estimator `RandomForestClassifier` authoritatively determines security classifications. The cloud LLM copilot (`SentinelAI`) possesses zero write access to the scan result or classifier state.
3. **Severe Training Distribution Mismatch Discovered:** Comparing the `StandardScaler` mean and standard deviation parameters ($\mu, \sigma$) against a clean modern Windows 11 host reveals substantial distribution shifts. Specifically, `crypto_dll_count` ($\mu=6.25$ in training vs $131.0$ live) and `file_handle_count` ($\mu=589.4$ in training vs $139,778$ live) push baseline clean-system probability to **$p \approx 0.47 - 0.48$**, directly bordering the $0.50$ WARNING threshold.
4. **Historical Metric Provenance:** The identical evaluation metrics (Accuracy: 0.9567, F1: 0.9671) across Random Forest, SVM, and Logistic Regression stored in `metrics.json` represent an unverified legacy anomaly, as raw training datasets were not preserved in the repository.
5. **Fail-Safe State Machine Verified:** Incomplete telemetry, scan cancellations, or unhandled exceptions transition strictly to `SCAN_INCOMPLETE` or `ANALYSIS_ERROR`. Under zero circumstances can a failed analysis display as `SAFE`.

---

## 2. The 19 Behavioral Features: Specification & Extraction Logic

The feature vector $\mathbf{x} \in \mathbb{R}^{19}$ is synthesized in `scanner/live_scanner.py` and fed to `ml/predictor.py`. The table below documents the exact order, types, units, missing-value handling, and extraction reality:

| Index | Feature Name | Data Type | Physical Units | Data Source & Extraction Mechanism | Missing / NaN Handling | Telemetry Reality |
|:---:|---|:---:|:---:|---|---|:---:|
| `[00]` | `total_processes` | `float64` | Discrete count | `len(list(psutil.process_iter()))` | Returns `0.0` if enumeration fails | Direct Telemetry |
| `[01]` | `suspicious_process_count` | `float64` | Discrete count | String match of `p.info["name"]` against 23 admin tools (`vssadmin`, `wmic`, `bcdedit`, `cipher`, etc.) | Default `0.0` | Direct Telemetry |
| `[02]` | `avg_entropy` | `float64` | Bits per byte ($[0.0, 8.0]$) | Shannon entropy over first 4096 bytes of sampled files in Documents/Desktop/Downloads (capped at 200) | Default `0.0` if no files sampled | Direct Telemetry |
| `[03]` | `max_entropy` | `float64` | Bits per byte ($[0.0, 8.0]$) | Peak Shannon entropy observed across sampled files | Default `0.0` if no files sampled | Direct Telemetry |
| `[04]` | `high_entropy_region_count` | `float64` | Discrete count | Count of sampled files with Shannon entropy $> 7.0$ bits/byte | Default `0.0` | Direct Telemetry |
| `[05]` | `malfind_injection_count` | `float64` | Discrete count | Count of non-system processes where `exe is None or exe == ""` | Exceptions caught; returns `0.0` | Heuristic Proxy |
| `[06]` | `crypto_dll_count` | `float64` | Discrete count | Processes with loaded DLLs matching 7 crypto libraries (`bcrypt.dll`, `crypt32.dll`, `rsaenh.dll`, etc.) | Default `0.0` on access denied | Direct Telemetry |
| `[07]` | `cmd_vssadmin_count` | `float64` | Discrete count | Process name match against shadow copy tools (`vssadmin.exe`, `wbadmin.exe`, `bcdedit.exe`) | Default `0.0` | Direct Telemetry |
| `[08]` | `network_connection_count` | `float64` | Discrete count | `len(psutil.net_connections(kind="inet"))` | Default `0.0` on socket query failure | Direct Telemetry |
| `[09]` | `unique_external_ips` | `float64` | Discrete count | Count of unique remote socket IPs excluding RFC1918 private subnets | Default `0.0` | Direct Telemetry |
| `[10]` | `file_handle_count` | `float64` | Discrete count | Aggregate sum of `p.info["num_handles"]` across all alive processes | Windows only; returns `0.0` on Linux | Win-Only Telemetry |
| `[11]` | `registry_handle_count` | `float64` | Discrete count | Non-system processes maintaining $> 500$ open handles | Windows only; returns `0.0` on Linux | Heuristic Proxy |
| `[12]` | `orphan_process_count` | `float64` | Discrete count | Processes whose parent PID is dead (excluding PIDs 0 and 4) | Default `0.0` | Direct Telemetry |
| `[13]` | `powershell_process_count` | `float64` | Discrete count | Count of active `powershell.exe` and `pwsh.exe` instances | Default `0.0` | Direct Telemetry |
| `[14]` | `unsigned_module_count` | `float64` | Discrete count | Processes executing from staging paths (`\Temp\`, `\Downloads\`, `\Public\`) | Default `0.0` | Heuristic Proxy |
| `[15]` | `suspicious_mutex_count` | `float64` | Discrete count | Non-system processes spawning $> 50$ active execution threads | Default `0.0` | Heuristic Proxy |
| `[16]` | `abnormal_privilege_count` | `float64` | Discrete count | Non-system processes maintaining $> 2000$ open handles | Windows only; returns `0.0` on Linux | Heuristic Proxy |
| `[17]` | `suspicious_thread_count` | `float64` | Discrete count | Non-system processes spawning $> 100$ active execution threads | Default `0.0` | Heuristic Proxy |
| `[18]` | `defender_tampering_count` | `float64` | Discrete count | Status check of Windows Defender services (`WinDefend`, `SecurityHealthService`) | Windows only; returns `0.0` on Linux | Win-Only Telemetry |

### Verification of Bug Fix (Operator Precedence)
During this audit, a subtle operator precedence defect was discovered in `live_scanner.py:329` and `live_scanner.py:396`:
- **Defective Line:** `if (p.info.get("num_handles") or 0) if sys.platform == "win32" else 0 > 500:`
- **Impact:** In Python, this parsed as `val if win32 else (0 > 500)`, causing almost every process with even 1 handle to be counted!
- **Audited Correction:** Refactored to explicit variable assignment:
  ```python
  handles = (p.info.get("num_handles") or 0) if sys.platform == "win32" else 0
  if handles > 500:
      count += 1
  ```
- **Result:** Abnormal handle count on clean host dropped from 199 false positives to 3 genuine instances.

---

## 3. Training Metadata & Model Provenance

### 3.1 Model Artifact Inspection
- **Artifact:** `models/saved_model.pkl` (File size: 1,019 KB)
- **Classifier Architecture:** `sklearn.ensemble.RandomForestClassifier`
  - Number of Estimators ($N$): 100 Decision Trees
  - Input Features ($d$): 19 features
  - Criterion: Gini Impurity
  - Class Weights: Balanced
  - Target Classes: `[0, 1]` ($0 = \text{Benign/Safe}$, $1 = \text{Malicious/Ransomware}$)
- **Scaler Artifact:** `models/scaler.pkl` (File size: 1.7 KB)
  - Preprocessor: `sklearn.preprocessing.StandardScaler`
  - Mean vector ($\boldsymbol{\mu} \in \mathbb{R}^{19}$) and scale vector ($\boldsymbol{\sigma} \in \mathbb{R}^{19}$) fitted with feature names.

### 3.2 Evaluation Metrics Provenance (`models/metrics.json`)
The repository contains stored performance metrics:
- Random Forest: Accuracy `0.9567`, Precision `0.9550`, Recall `0.9795`, F1 `0.9671`, ROC-AUC `0.9483`
- Support Vector Machine: Accuracy `0.9567`, Precision `0.9550`, Recall `0.9795`, F1 `0.9671`, ROC-AUC `0.9574`
- Logistic Regression: Accuracy `0.9567`, Precision `0.9550`, Recall `0.9795`, F1 `0.9671`, ROC-AUC `0.9476`

**Technical Audit Finding:**  
Three mathematically distinct classifiers producing identical discrete performance metrics down to four decimal places ($0.9567$ accuracy, $0.9671$ F1) is an unmistakable signature of an identical evaluation split. Because the original training CSV, random seeds, and split indices were not checked into version control, these metrics cannot be independently reproduced from raw data. In academic review, these must be treated as historical baseline claims rather than confirmed experimental facts.

---

## 4. Distribution Mismatch Analysis

A fundamental question for college exhibition evaluators is: **How well does the training data match real-world endpoint telemetry?**

Comparing the training distribution ($\mu, \sigma$ from `scaler.pkl`) against actual live telemetry measured on a clean Windows 11 host reveals massive distribution shift:

| Feature Index & Name | Scaler Mean ($\mu$) | Scaler Std ($\sigma$) | Clean Live Host Telemetry ($x$) | Z-Score ($z = \frac{x - \mu}{\sigma}$) | Assessment |
|---|:---:|:---:|:---:|:---:|---|
| `[00] total_processes` | 86.05 | 30.68 | 293.00 | **+6.74 $\sigma$** | Modern Windows 11 clean boot has 250–300 procs; training dataset had ~86. |
| `[01] suspicious_process_count` | 6.00 | 4.61 | 0.00 | -1.30 $\sigma$ | Normal host runs 0 LOLBins at baseline. |
| `[02] avg_entropy` | 6.14 | 1.87 | 4.44 | -0.91 $\sigma$ | Clean documents exhibit natural text/data entropy (~4.4). |
| `[03] max_entropy` | 7.13 | 1.30 | 5.53 | -1.23 $\sigma$ | Peak entropy on clean system is well below ciphertext (~8.0). |
| `[04] high_entropy_region_count` | 17.92 | 13.91 | 0.00 | -1.29 $\sigma$ | Zero encrypted files on clean host. |
| `[06] crypto_dll_count` | 6.25 | 3.51 | 131.00 | **+35.54 $\sigma$** | Modern Windows loads `crypt32.dll` and `bcrypt.dll` in almost all GUI/web apps! |
| `[08] network_connection_count` | 40.47 | 26.42 | 128.00 | **+3.31 $\sigma$** | Active endpoint maintains 100+ sockets for OS services and browsers. |
| `[10] file_handle_count` | 589.38 | 340.01 | 139,778.00 | **+409.37 $\sigma$** | System-wide handle sum is massive; training data was likely per-process or VM. |

### Consequence on Prediction
Because `crypto_dll_count` and `file_handle_count` yield massive positive z-scores, the Random Forest model outputs a baseline clean-host threat score of **$p \approx 0.47$**.
- This is classified as `SAFE` because $p < 0.50$.
- However, $0.47$ is dangerously close to the $0.50$ warning threshold. A minor spike in benign network connections or handle usage could push the score over $0.50$ (causing a false positive).
- **Recommendation:** Do not retrain the model on synthetic or invented labels. Instead, clearly disclose this distribution shift in the exhibition and explain that future model versions should normalize handle counts per-process rather than aggregating system-wide.

---

## 5. Classification Thresholds & Score Semantics

The model threat score $p = P(y = 1 \mid \mathbf{x})$ is extracted from `predict_proba()`:
```python
probabilities = self._model.predict_proba(scaled)
threat_prob = float(probabilities[0][1])
```
Operational threshold partitioning in `ml/predictor.py`:
- **$p < 0.50 \implies \text{SAFE}$**: Baseline system activity within acceptable variance.
- **$0.50 \le p < 0.90 \implies \text{WARNING}$**: Elevated suspicious indicators (e.g., suspicious process names, thread spikes, or elevated entropy).
- **$p \ge 0.90 \implies \text{CRITICAL}$**: Overwhelming ransomware behavioral indicators (shadow copy deletion + encryption burst).

> **Academic Rigor Note:** The score $p$ represents the empirical proportion of trees in the forest voting for the ransomware class. It is **not** an auto-calibrated Bayesian posterior.

---

## 6. Scan State Machine & Fail-Safe Invariants

The detection engine enforces a formal finite state machine (`scanner/scan_engine.py`):

```
                   +-------------------+
                   |       IDLE        |
                   +-------------------+
                             |
                             v
                   +-------------------+
                   |     SCANNING      |
                   +-------------------+
                             |
                             v
                   +-------------------+
                   |     ANALYZING     |
                   +-------------------+
                             |
        +--------------------+--------------------+
        |                    |                    |
        v                    v                    v
  [p < 0.50]          [0.50 <= p < 0.90]      [p >= 0.90]
+---------------+    +-------------------+   +--------------------+
|     SAFE      |    |      WARNING      |   |  THREAT_DETECTED   |
+---------------+    +-------------------+   +--------------------+
```

### Safety Failure Branches
If an unhandled exception occurs, the user cancels the scan, access is denied, or the ML predictor returns `None` (due to missing models or `NaN` features):
$$\text{State} \longrightarrow \textsc{scan\_incomplete} \quad \text{or} \quad \textsc{analysis\_error}$$
- **Verification:** Unit tests confirm `ScanResult.was_successful()` returns `False` for `SCAN_INCOMPLETE`, `ANALYSIS_ERROR`, and `ERROR`.
- Under zero circumstances does an aborted or failed scan default to `SAFE`.

---

## 7. Decoupled AI Copilot (SentinelAI) Isolation

A critical design requirement is that Large Language Models (LLMs) must **never** authoritatively determine cybersecurity boundaries.

Audit of `ai/sentinel_ai.py` and `ai/provider.py`:
1. **Downstream Execution:** SentinelAI is invoked strictly **after** Random Forest inference completes.
2. **Read-Only Context:** SentinelAI receives a sanitized numeric dictionary (files scanned, processes inspected, ML probability, duration).
3. **Zero Override Privilege:** SentinelAI has no methods, variables, or access privileges to mutate `ScanResult.state` or `ScanResult.threat_level`.
4. **Offline Resilience:** If the cloud LLM backend is offline or times out, the local desktop GUI renders the Random Forest classification uninterrupted.
