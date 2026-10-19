# SENTINELML V2 — FEATURE SCHEMA AND PROVENANCE AUDIT

**Audit Date:** October 19, 2026  
**Target Repository:** `C:\Users\vasur\Desktop\SentinalMl\`  
**Target Branch:** `exhibition-mode`  
**Inspected Artifacts:**
- `ml/predictor.py`
- `scanner/live_scanner.py`
- `models/saved_model.pkl` (SHA-256: `936d9e3ff0b97d762751bdcba34ad3d247a4280e38f84e32dc4f31bfa1174e33`)
- `models/scaler.pkl` (SHA-256: `d993e26a313f743bbfc351912f2ac4a3be2642f4722c8c5451baf9eda26281cb`)
- `models/metrics.json` (SHA-256: `8a24b01aa0d5b38ea099f391afb486fa9310fe0ff39ae645c132172170227c88`)

---

## 1. Executive Summary & Core Verdict

A rigorous code-level and artifact-level investigation was conducted to determine the relationship between the serialized Random Forest classifier (`saved_model.pkl`), the feature scaler (`scaler.pkl`), the runtime telemetry collector (`live_scanner.py`), and the synthetic evaluation harness.

### Key Audit Findings:
1. **Severe Semantic Divergence in Core Features:** The serialized model and scaler expect 19 specific features derived from memory forensics and dynamic sandbox execution logs. However, in `scanner/live_scanner.py`, user-space heuristics based on `psutil` were substituted into slots requiring kernel-level or memory-inspection data.
2. **Top Features Impacted:** The five most critical mismatched features (`suspicious_thread_count`, `high_entropy_region_count`, `avg_entropy`, `malfind_injection_count`, `unsigned_module_count`) account for **68.17% of the model's total decision weight**. Specifically:
   - Index 5 (`malfind_injection_count`, 10.38% importance) is extracted by checking if `p.exe is None` (`_count_hollow_procs`).
   - Index 14 (`unsigned_module_count`, 5.97% importance) is extracted by checking if an executable path contains `/temp/` or `/downloads/`.
   - Index 15 (`suspicious_mutex_count`, 0.55% importance) is extracted by counting processes with more than 50 threads.
   - Index 16 (`abnormal_privilege_count`, 1.54% importance) is extracted by counting processes with more than 2,000 handles.
   - Index 17 (`suspicious_thread_count`, 16.49% importance — highest in the model) is extracted by counting processes with more than 100 threads.
3. **Training Provenance Gap:** Neither the original training dataset (CSV, parquet, or database dump) nor the training script (`train.py`) exists in the repository. The feature expectations can only be inferred from `scaler.feature_names_in_` and `model.feature_importances_`.
4. **Classification Status:** Because the live telemetry measurements do **not** genuinely correspond to the features on which the Random Forest model was trained, the model must be classified as **UNVALIDATED FOR LIVE HOST TELEMETRY**. The reported 100% benchmark score applies strictly to hand-authored synthetic feature profiles, not to live ransomware detection.

---

## 2. Complete 19-Position Feature Comparison Matrix

The table below contrasts the expected training schema stored in `scaler.pkl` against the actual extraction implementation in `scanner/live_scanner.py`:

| Idx | Scaler Feature Name (`scaler.feature_names_in_`) | Scaler Mean ($\mu$) | Scaler Var ($\sigma^2$) | Scaler Std ($\sigma$) | RF Importance | Live Extraction Method (`live_scanner.py`) | Semantic Alignment & Integrity Status |
|:---:|---|:---:|:---:|:---:|:---:|---|---|
| **0** | `total_processes` | 86.05 | 941.44 | 30.68 | 0.0190 | `float(len(procs))` | **ALIGNED (DISTRIBUTION SHIFT)**: Direct process count via `psutil`. Modern Windows 11 host has 250–350 procs ($+5.5\sigma$ shift). |
| **1** | `suspicious_process_count` | 6.00 | 21.24 | 4.61 | 0.0504 | `_count_suspicious_procs(procs)` | **HEURISTIC PROXY**: Checks running process names against hardcoded list (`vssadmin`, `cipher`, `wmic`). |
| **2** | `avg_entropy` | 6.14 | 3.51 | 1.87 | 0.1523 | `_scan_file_entropy()[0]` | **ALIGNED**: Shannon entropy calculated on 4KB file chunks. |
| **3** | `max_entropy` | 7.13 | 1.70 | 1.30 | 0.0977 | `_scan_file_entropy()[1]` | **ALIGNED**: Peak Shannon entropy observed across sampled files. |
| **4** | `high_entropy_region_count` | 17.92 | 193.46 | 13.91 | 0.1630 | `_scan_file_entropy()[2]` | **SEMANTIC SHIFT**: In memory forensics, counts high-entropy memory segments; live scanner counts whole files with entropy $> 7.0$. |
| **5** | `malfind_injection_count` | 6.79 | 33.66 | 5.80 | **0.1038** | `_count_hollow_procs(procs)` | **CRITICAL MISMATCH**: Volatility `malfind` plugin output (VAD `PAGE_EXECUTE_READWRITE` shellcode) replaced by empty `p.exe` check. |
| **6** | `crypto_dll_count` | 6.25 | 12.35 | 3.51 | 0.0190 | `_count_crypto_dll_procs(procs)` | **ALIGNED (EXTREME DISTRIBUTION SHIFT)**: Counts processes with `bcrypt.dll`/`crypt32.dll`. Live host has ~130 processes ($+35.5\sigma$). |
| **7** | `cmd_vssadmin_count` | 2.85 | 6.30 | 2.51 | 0.0431 | `_count_vssadmin_procs(procs)` | **HEURISTIC PROXY**: Counts active processes matching `vssadmin.exe`, `wbadmin.exe`, `bcdedit.exe`. |
| **8** | `network_connection_count` | 40.47 | 697.86 | 26.42 | 0.0156 | `_scan_network()[0]` | **ALIGNED**: Total active TCP/UDP sockets via `psutil.net_connections`. |
| **9** | `unique_external_ips` | 12.66 | 149.14 | 12.21 | 0.0131 | `_scan_network()[1]` | **ALIGNED**: Count of non-RFC1918 remote IP addresses. |
| **10** | `file_handle_count` | 589.38 | 115,607.9 | 340.01 | 0.0267 | `_total_file_handles(procs)` | **SCALE MISMATCH**: Training mean is 589 handles (single-sandbox profile); live Windows 11 host sum is $> 130,000$ handles ($+400\sigma$). |
| **11** | `registry_handle_count` | 139.33 | 5,629.8 | 75.03 | 0.0271 | `_registry_handle_heuristic(procs)` | **CRITICAL MISMATCH**: Open `\REGISTRY\` key handles replaced by count of non-system processes with $> 500$ handles. |
| **12** | `orphan_process_count` | 4.76 | 16.30 | 4.04 | 0.0096 | `_count_orphan_procs(procs)` | **HEURISTIC PROXY**: Processes whose parent PID is no longer alive in `psutil`. |
| **13** | `powershell_process_count` | 2.20 | 4.51 | 2.12 | 0.0073 | `_count_powershell_procs(procs)` | **ALIGNED**: Counts running instances of `powershell.exe` and `pwsh.exe`. |
| **14** | `unsigned_module_count` | 5.08 | 17.32 | 4.16 | **0.0597** | `_count_suspicious_path_procs(procs)` | **CRITICAL MISMATCH**: Authenticode digital signature validation replaced by process execution path heuristic (`/temp/`, `/downloads/`). |
| **15** | `suspicious_mutex_count` | 1.12 | 1.74 | 1.32 | **0.0055** | `_count_high_thread_procs(procs, 50)` | **CRITICAL MISMATCH**: Named mutant objects (`CreateMutexA`) replaced by checking if a process has $> 50$ threads. |
| **16** | `abnormal_privilege_count` | 2.50 | 6.03 | 2.45 | **0.0154** | `_count_abnormal_handle_procs(procs)` | **CRITICAL MISMATCH**: Process token privileges (`SeDebugPrivilege`, etc.) replaced by checking if process has $> 2,000$ handles. |
| **17** | `suspicious_thread_count` | 16.97 | 185.24 | 13.61 | **0.1649** | `_count_high_thread_procs(procs, 100)` | **CRITICAL MISMATCH**: Unbacked memory thread start addresses replaced by checking if process has $> 100$ threads. |
| **18** | `defender_tampering_count` | 1.98 | 5.92 | 2.43 | 0.0068 | `_check_defender_tampering()` | **ALIGNED**: Queries Windows service table for stopped `WinDefend`, `WdNisSvc`, `Sense`. |

---

## 3. Deep Investigation of the Five Suspected Mismatches

### 1. Index 5: `malfind_injection_count` versus `_count_hollow_procs(procs)`
- **Nominal Feature Concept:** In memory forensics (specifically Volatility's `windows.malfind` plugin), this feature quantifies the number of virtual address descriptors (VADs) configured with `PAGE_EXECUTE_READWRITE` permissions containing unbacked executable machine code or injected PE headers.
- **Actual Extraction Code:**
  ```python
  def _count_hollow_procs(self, procs: list) -> float:
      count = 0
      for p in procs:
          try:
              exe = p.info.get("exe")
              if exe is None or exe == "":
                  name = (p.info.get("name") or "").lower()
                  if name not in {"system","idle","registry","smss.exe","memory compression"}:
                      count += 1
          ...
      return float(count)
  ```
- **Auditor Finding:** An empty or `None` string for `p.info["exe"]` in `psutil` does not indicate process hollowing or memory injection. On modern Windows workstations, protected system processes (e.g. `audiodg.exe`, anti-malware services, Secure System) deny `PROCESS_QUERY_LIMITED_INFORMATION` access to unprivileged callers, returning `exe=None`. The code counts access-denied system services as "memory injections."
- **Model Impact:** `malfind_injection_count` accounts for **10.38%** of the Random Forest's feature importance and serves as the root split in 12 of the 100 decision trees. Substituting access-denied processes directly corrupts inference.

### 2. Index 14: `unsigned_module_count` versus `_count_suspicious_path_procs(procs)`
- **Nominal Feature Concept:** Number of loaded DLLs or executable binaries lacking a valid digital signature, verified via Win32 `WinVerifyTrust` / CryptoAPI.
- **Actual Extraction Code:**
  ```python
  def _count_suspicious_path_procs(self, procs: list) -> float:
      frags = ["\\temp\\","\\tmp\\","\\appdata\\local\\temp\\",
               "\\downloads\\","\\users\\public\\","\\programdata\\",
               "/tmp/", "/var/tmp/", "/dev/shm/", "/downloads/"]
      count = 0
      for p in procs:
          exe = (p.info.get("exe") or "").lower()
          if exe and any(f in exe for f in frags):
              count += 1
      return float(count)
  ```
- **Auditor Finding:** Digital signature validation requires file PE header inspection and catalog database verification. `_count_suspicious_path_procs` ignores digital signatures entirely and only checks file directory paths. Legitimate signed executables (such as Teams, Discord, or Chrome auto-updaters running from `AppData\Local`) are falsely counted.
- **Model Impact:** Holds **5.97%** feature importance and participates in 324 tree splits.

### 3. Index 15: `suspicious_mutex_count` versus `_count_high_thread_procs(procs, 50)`
- **Nominal Feature Concept:** Ransomware families frequently create distinctive named mutexes (e.g., LockBit's `{Global\e0e8...}` or WannaCry's `Global\MsWinZonesCacheCounterMutexA`) to prevent multiple instances from encrypting simultaneously.
- **Actual Extraction Code:**
  ```python
  features.append(self._count_high_thread_procs(procs, 50))  # [15]
  ```
- **Auditor Finding:** Mutex handles reside in the Windows Object Manager directory (`\BaseNamedObjects`). They have zero relationship to thread counts. Checking whether a process has $> 50$ threads is a thread concurrency metric, not a mutex metric.
- **Model Impact:** Holds **0.55%** importance across 143 tree splits.

### 4. Index 16: `abnormal_privilege_count` versus `_count_abnormal_handle_procs(procs)`
- **Nominal Feature Concept:** In Windows security architecture, token privileges dictate kernel access rights (e.g., `SeDebugPrivilege`, `SeTakeOwnershipPrivilege`, `SeTcbPrivilege`). Ransomware enables these privileges to terminate antivirus processes or access system volume shadow copies.
- **Actual Extraction Code:**
  ```python
  def _count_abnormal_handle_procs(self, procs: list) -> float:
      system_procs = {"system","lsass.exe","svchost.exe"}
      count = 0
      for p in procs:
          name = (p.info.get("name") or "").lower()
          if name in system_procs:
              continue
          handles = (p.info.get("num_handles") or 0) if sys.platform == "win32" else 0
          if handles > 2000:
              count += 1
      return float(count)
  ```
- **Auditor Finding:** Process token privileges are queried via `OpenProcessToken` and `GetTokenInformation(TokenPrivileges)`. The code completely ignores token privileges and instead counts processes with $> 2,000$ open handles (such as web browsers or IDEs).
- **Model Impact:** Holds **1.54%** importance across 258 tree splits.

### 5. Index 17: `suspicious_thread_count` versus `_count_high_thread_procs(procs, 100)`
- **Nominal Feature Concept:** In memory forensics, suspicious threads are those whose start address points to unbacked executable memory (dynamically allocated with `VirtualAlloc`), representing injected shellcode or hollowed threads.
- **Actual Extraction Code:**
  ```python
  features.append(self._count_high_thread_procs(procs, 100))  # [17]
  ```
- **Auditor Finding:** This feature has the **single highest feature importance in the entire model (16.49%)**, serving as the root split in 18 decision trees. The code measures this by counting whether any process has $> 100$ threads. On a modern multithreaded system, applications like Visual Studio Code, Chrome, or database servers routinely spawn 120–180 threads legitimately.
- **Model Impact:** A clean host with legitimate multithreaded applications receives artificial threat signals on the model's most heavily weighted feature.

---

## 4. Recoverability of Training Schema & Dataset Provenance

A recursive scan was performed across the entire repository and historical commit history on `exhibition-mode`:
1. **Training Scripts:** Searched for `train.py`, `train_model.py`, `model_train.py`, `fit_classifier.py`. **None found.**
2. **Raw Datasets:** Searched for `.csv`, `.parquet`, `.arrow`, `.h5`, `.npy` files. Only scikit-learn standard datasets (`iris.csv`, `wine_data.csv`, `breast_cancer.csv`) embedded inside virtual environments were present.
3. **Training Metadata:** `models/metrics.json` records historical test accuracies (Random Forest: 0.9567, SVM: 0.9567, Logistic Regression: 0.9567, optimal threshold: 0.9). However, no dataset schema documentation, data provenance log, or feature dictionary was saved.

### Conclusion on Recoverability
The original training schema cannot be recovered from the repository contents. While `models/scaler.pkl` preserves the empirical column names, means, and variances, the ground-truth definitions and collection techniques of the training data remain unverified.

**Auditor Requirement:** The application must document this limitation explicitly. Neither the application nor academic publications may claim that feature compatibility has been established between live host measurements and the trained model.
