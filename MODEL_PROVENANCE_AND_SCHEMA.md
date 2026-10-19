# SENTINELML V2 — MODEL PROVENANCE AND SCHEMA REPORT

**Report Date:** October 19, 2026  
**Repository:** `C:\Users\vasur\Desktop\SentinalMl\`  
**Target Branch:** `exhibition-mode`  
**Investigation Team:** Senior Machine Learning Engineer & Cybersecurity Detection Research Assistant  

---

## 1. Executive Summary & Forensic Recovery Discovery

A comprehensive forensic audit of the host workstation, parent directories, and related project archives has successfully **recovered the exact, uncorrupted original training pipeline, dataset generator, and source configuration** that produced SentinelML's serialized machine learning artifacts.

### 1.1 Recovered Artifact Provenance Summary

The active model files in `SentinalMl/models/` are byte-for-byte identical to the output of the training pipeline located in the sibling repository `C:\Users\vasur\Desktop\Major Project\`:

| Artifact | SentinelML Path | Original Source Path | SHA-256 Checksum | Match Status |
|---|---|---|---|:---:|
| **Random Forest Model** | `models/saved_model.pkl` | `Major Project/model/saved_model.pkl` | `936d9e3ff0b97d762751bdcba34ad3d247a4280e38f84e32dc4f31bfa1174e33` | **100% IDENTICAL** |
| **StandardScaler** | `models/scaler.pkl` | `Major Project/model/scaler.pkl` | `d993e26a313f743bbfc351912f2ac4a3be2642f4722c8c5451baf9eda26281cb` | **100% IDENTICAL** |
| **Training Metrics** | `models/metrics.json` | `Major Project/model/metrics.json` | `8a24b01aa0d5b38ea099f391afb486fa9310fe0ff39ae645c132172170227c88` | **100% IDENTICAL** |
| **Training Script** | *Missing in SentinalMl* | `Major Project/model/train.py` | `d3dfa539bc7c40d9904d9c7da192b10e5c14fbc9671607590aaae2b95fa7848f` | **RECOVERED** |
| **Dataset Generator** | *Missing in SentinalMl* | `Major Project/dataset/generate_dataset.py` | `6ae7e6a75908cfabff09eecae894ec031da2945d8b74f387db2e96431f13f19e` | **RECOVERED** |
| **Source Dataset** | *Missing in SentinalMl* | `Major Project/dataset/sample_data.csv` | `05e557b44840bf24cf12257f867499692461ec4620a2ecaa0c5ef946ae8b548f` | **RECOVERED** |
| **Feature Builder** | *Missing in SentinalMl* | `Major Project/feature_extraction/feature_builder.py` | `05ea3bc8623d38734e5a953e5bc6e9cf04b7b2cefa33cb7cfc23c2a11b66804a` | **RECOVERED** |

---

## 2. Origin and Purpose of the Original Architecture

The forensic analysis reveals that the 19 features were originally designed for **offline memory dump analysis via Volatility 3**, rather than real-time Windows user-space host monitoring.

### 2.1 The Volatility 3 Feature Pipeline
In `Major Project/feature_extraction/volatility_runner.py` and `feature_builder.py`, the system was designed to parse raw physical RAM images (`.raw` / `.mem`) using 6 Volatility 3 plugins:
1. `windows.pslist.PsList`: Extracted `total_processes`, `suspicious_process_count`, `powershell_process_count`, `orphan_process_count`.
2. `windows.malfind.Malfind`: Extracted `malfind_injection_count` by scanning process Virtual Address Descriptors (VADs) for `PAGE_EXECUTE_READWRITE` permissions containing unbacked executable code.
3. `windows.dlllist.DllList`: Extracted `crypto_dll_count` (`bcrypt.dll`, `crypt32.dll`) and `unsigned_module_count`.
4. `windows.cmdline.CmdLine`: Extracted `cmd_vssadmin_count` and `defender_tampering_count`.
5. `windows.handles.Handles`: Extracted `file_handle_count`, `registry_handle_count`, and `suspicious_mutex_count`.
6. `windows.netscan.NetScan`: Extracted `network_connection_count` and `unique_external_ips`.

### 2.2 The Synthetic Training Dataset (`sample_data.csv`)
In `Major Project/dataset/generate_dataset.py`, the dataset was synthetically synthesized to emulate these Volatility outputs:
- **Total Samples:** 1,500 rows.
- **Benign Samples:** 500 rows drawn from parameterized Gaussian distributions (`BENIGN_DISTRIBUTIONS`).
- **Ransomware Samples:** 1,000 rows across 10 recognized ransomware families (100 samples each):
  - *WannaCry, Petya, LockBit, REvil, Ryuk, Conti, DarkSide, BlackCat, Hive, BlackMatter*.
- **Noise Injection:** 5% label noise (75 randomized label swaps) to simulate real-world mislabeling.
- **Evasion Simulation:** 5% adversarial evasion (suppressing suspicious processes and lowering entropy).

### 2.3 The Training Script (`train.py`)
In `Major Project/model/train.py`:
- **Data Splitting:** `train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)` (1,200 training / 300 test).
- **Scaler Fitting:** `StandardScaler()` fit strictly on `X_train`.
- **Model Training:** `RandomForestClassifier(random_state=42, class_weight="balanced")` tuned via `GridSearchCV` over 5-fold Stratified K-Fold cross-validation (`scoring="f1"`).
- **Optimal Threshold Extraction:** Using `precision_recall_curve`, an optimal threshold was calculated to enforce a target precision of 1.0 (Zero False Positives):
  $$\text{optimal\_threshold} = 0.90$$

---

## 3. The 19-Position Feature Schema Analysis

The table below contrasts the expected Volatility feature definition from `Major Project/config.py` against the runtime user-space extraction in `SentinalMl/scanner/live_scanner.py`:

| Idx | Feature Name | Expected Definition (Volatility 3 / Training) | Training Mean ($\mu$) | Live Extraction Method (`live_scanner.py`) | Divergence Severity & Technical Impact |
|:---:|---|---|:---:|---|---|
| **0** | `total_processes` | Active processes in memory dump via `pslist` | 86.05 | `len(procs)` via `psutil.process_iter()` | **Low**: Shift from ~86 in VM sandbox to ~280 on modern Windows 11 host. |
| **1** | `suspicious_process_count` | Processes matching 16 CLI utilities (`vssadmin`, `cipher`, etc.) | 6.00 | Case-insensitive name match on active procs | **Medium**: Benign on idle host; only catches active process execution. |
| **2** | `avg_entropy` | Mean Shannon entropy across memory segments or files | 6.14 | Shannon entropy of 4KB chunks in scanned directories | **Aligned**: Accurately computes Shannon entropy on targeted files. |
| **3** | `max_entropy` | Peak Shannon entropy across memory segments or files | 7.13 | Maximum Shannon entropy observed across sampled files | **Aligned**: Accurately measures peak entropy in target files. |
| **4** | `high_entropy_region_count` | Count of high-entropy memory regions / files ($> 7.0$) | 17.92 | Count of inspected files with entropy $> 7.0$ | **Aligned**: Correctly counts high-entropy files in target directory. |
| **5** | `malfind_injection_count` | VAD descriptors with `PAGE_EXECUTE_READWRITE` code | 6.79 | `_count_hollow_procs`: counts procs where `exe is None` | **CRITICAL MISMATCH**: Checks access-denied system services instead of memory injection. |
| **6** | `crypto_dll_count` | Count of loaded crypto DLLs across all processes | 6.25 | `_count_crypto_dll_procs`: counts procs with `bcrypt.dll` | **Extreme Drift**: Modern Windows host has ~130 procs loading bcrypt ($+35.5\sigma$). |
| **7** | `cmd_vssadmin_count` | Process CLI commands matching shadow copy deletion | 2.85 | `_count_vssadmin_procs`: matches `vssadmin.exe`, `wbadmin` | **Medium**: Detects running processes, misses transient one-shot commands. |
| **8** | `network_connection_count` | Total active network sockets via `netscan` | 40.47 | `_scan_network()[0]`: active TCP/UDP connections via `psutil` | **Aligned**: Measures live network sockets. |
| **9** | `unique_external_ips` | Non-private destination IP addresses via `netscan` | 12.66 | `_scan_network()[1]`: non-RFC1918 remote IP count | **Aligned**: Measures unique external destination IPs. |
| **10** | `file_handle_count` | Open file object handles via `windows.handles` | 589.38 | `_total_file_handles`: sum of `num_handles` across procs | **CRITICAL SCALE SHIFT**: Training mean is 589; Windows 11 host has $> 130,000$ handles ($+400\sigma$). |
| **11** | `registry_handle_count` | Open `\REGISTRY\` key handles via `windows.handles` | 139.33 | `_registry_handle_heuristic`: procs with $> 500$ handles | **CRITICAL MISMATCH**: Counts generic large-handle processes instead of registry keys. |
| **12** | `orphan_process_count` | Processes whose PPID is missing from `pslist` | 4.76 | `_count_orphan_procs`: procs whose parent PID is dead | **Low**: Legitimate proxy for orphan process enumeration. |
| **13** | `powershell_process_count` | Instances of `powershell.exe` and `pwsh.exe` | 2.20 | Case-insensitive name match on `powershell.exe` | **Aligned**: Directly counts running PowerShell processes. |
| **14** | `unsigned_module_count` | Loaded modules lacking Authenticode signatures | 5.08 | `_count_suspicious_path_procs`: checks `/temp/`, `/downloads/` | **CRITICAL MISMATCH**: Path heuristic does not inspect Authenticode signatures. |
| **15** | `suspicious_mutex_count` | Known ransomware mutant names in Object Manager | 1.12 | `_count_high_thread_procs(procs, 50)` | **CRITICAL MISMATCH**: Process thread count $> 50$ has no relation to named mutexes. |
| **16** | `abnormal_privilege_count` | Process tokens with `SeDebugPrivilege` enabled | 2.50 | `_count_abnormal_handle_procs(procs)`: procs with $> 2000$ handles | **CRITICAL MISMATCH**: Handle count $> 2000$ has no relation to security token privileges. |
| **17** | `suspicious_thread_count` | Threads starting in unbacked memory regions | 16.97 | `_count_high_thread_procs(procs, 100)` | **CRITICAL MISMATCH**: Heaviest feature in model (16.49%) measures concurrency, not injection. |
| **18** | `defender_tampering_count` | CLI commands disabling Defender or stopping service | 1.98 | `_check_defender_tampering`: queries Windows SCM services | **Aligned**: Directly inspects `WinDefend` service operational status. |

---

## 4. Root Cause Analysis: The Porting Transition Gap

The discrepancy between the model and the live scanner occurred during the port from the original research prototype to the standalone desktop application:
1. **Initial Design:** The research prototype analyzed static, post-mortem memory dumps using Python and Volatility 3 (`Major Project`).
2. **Desktop Adaptation:** To build an interactive GUI app (`SentinalMl`), offline Volatility dump parsing was replaced with real-time `psutil` sampling so scans could execute in seconds without needing 16 GB RAM dumps or administrative kernel privileges.
3. **The Heuristic Shortcuts:** Because unprivileged Ring-3 user-space code cannot inspect kernel VAD descriptors, token privileges, or the Object Manager directory without specialized drivers, heuristic approximations were substituted into the 19 slots to keep the array shape compatible with `saved_model.pkl` and `scaler.pkl`.
4. **The Consequence:** The Random Forest model evaluates features that possess the same names but fundamentally different semantic meanings and empirical distributions than the training dataset.

---

## 5. Formal Conclusion

The training provenance is now **100% recovered and documented**. However, because the original training dataset was synthetically generated from Gaussian distributions simulating offline Volatility memory forensics, and because the live scanner uses user-space heuristic approximations, the current model **CANNOT BE VALIDATED AGAINST REAL-WORLD RANSOMWARE OR LIVE HOST TELEMETRY**.

The model is maintained strictly as an **exhibition demonstration baseline**, and must be explicitly documented as such.
