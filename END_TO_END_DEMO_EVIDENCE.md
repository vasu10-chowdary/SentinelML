# SentinelML V2 — End-to-End Safe Demo Evidence Log

## Execution Context

**Test Script**: `scratch/test_safe_demo_e2e.py`  
**Execution Timestamp**: `2026-10-19T17:34:40+05:30`  
**Host Environment**: Windows 11 Workstation  
**Target Sandbox**: `C:\Users\vasur\Desktop\SentinalMl\temp_demo_e2e_sandbox`  
**Result**: **100% VERIFIED ACROSS ALL 9 PHASES**

---

## 1. Phase-by-Phase Evidence Record

### Phase 1: Pre-Demo Health Check
- **Healthy**: `True`
- **Checks Passed**:
  1. Sandbox Path: `temp_demo_e2e_sandbox` verified safe, isolated, and writable.
  2. Model Pipeline: `RandomForestClassifier` (100 trees, 19 features) and `StandardScaler` loaded cleanly.
  3. Host Sensors: `psutil` operational (329 active processes visible).
  4. Concurrency Lock: Unlocked and ready.

### Phase 2: Controlled Behavioral Simulation
- **Duration**: 1.061 seconds.
- **Files Created**: 20 synthetic documents (`.txt`, `.dat`, `.docx_sim`, `.csv_sim`, `.log`).
- **Encryption Burst**: 20 files overwritten with 2,048 bytes of pseudorandom ciphertext (`os.urandom(2048)`).
- **Entropy Shift**: Average Shannon entropy jumped from **`5.017 bits/byte`** (plaintext) to **`7.911 bits/byte`** (ciphertext).
- **Simulated Renaming**: 20 files renamed to `*.locked_sim`.
- **Ransom Notice**: 1 instructional note dropped (`READ_ME_RECOVERY_SIM.txt`).

### Phase 3: Filesystem Observation
- **Files Inspected**: 21 files.
- **Suspicious Files Flagged**: 21 files matching ransomware heuristics (`.locked_sim` extension + ransom note keywords).
- **Access Denied**: 0.
- **Filesystem Errors**: 0.

### Phase 4: Telemetry Extraction
- **Extracted Average Shannon Entropy**: `7.749 bits/byte`.
- **Processes Enumerated**: 326 host processes.
- **Suspicious Process Cmdlines**: 0.
- **Network Connections**: 214 active endpoints.
- **Telemetry Source**: Live Windows User-Space (`psutil` + filesystem chunk sampler).

### Phase 5: Feature Vector Validation
- **Legacy 19-Position Vector**:
  - Shape: `(1, 19)`.
  - Finite Check: `np.isfinite().all() == True` (0 NaN, 0 Inf).
  - Validation: **PASSED**.
- **Schema V2 16-Position Vector**:
  - Shape: `(1, 16)`.
  - `file_mod_rate`: 18.85 files/sec.
  - `file_rename_rate`: 18.85 files/sec.
  - `avg_shannon_entropy`: 7.911 bits/byte.
  - `ransom_extension_match_count`: 20.
  - Validation: **PASSED** (0 schema errors).

### Phase 6: Machine Learning Model Inference
- **Model Architecture**: `RandomForestClassifier` (100 Estimators, Gini Impurity).
- **Scaler**: `StandardScaler` (19 features).
- **Inference Latency**: 11.4 ms.
- **Voting Distribution**:
  - **57 Trees** voted for ransomware threat.
  - **43 Trees** voted for benign baseline.
- **Raw Threat Probability**: **`0.5700`**.

### Phase 7: Threat Classification & Decision Invariant
- **Decision Thresholds**:
  - `0.00 <= p < 0.50` -> `SAFE`
  - `0.50 <= p < 0.90` -> `WARNING`
  - `p >= 0.90` -> `CRITICAL`
- **Model Decision**: **`WARNING`** (p = 0.57).
- **Detection Achieved**: **`True`**.
- **Operational Boundary Disclosure**:
  - The elevated entropy profile crossed the `0.50` WARNING threshold.
  - It did **not** reach `0.90` (CRITICAL) because correlated process anomalies (`vssadmin delete shadows`, thread injection) were not present.
  - This protects against false alarms on benign high-entropy operations (compression, video rendering).

### Phase 8: Sandbox Containment & Cleanup
- **Containment Check**: All 21 files were inspected. **100%** resolved strictly within `temp_demo_e2e_sandbox`. Zero files were created or modified in user documents, Desktop, Downloads, or OS roots.
- **Automated Cleanup**: `reset_sandbox()` removed all 21 items.
- **Post-Cleanup Verification**: Sandbox contains exactly **0** files.

### Phase 9: Invariant Resilience & Concurrency Protection
- **Repeated Demo Run**: Second run executed immediately after cleanup, achieving `WARNING` (`p = 0.54`) and verifying clean state restoration.
- **Concurrency Lock Test**: When `_demo_lock` is acquired, a concurrent call to `run_safe_demo()` raises:
  `RuntimeError: Concurrency Lock: A demonstration or scan is already in progress.`
- **Clean Lock Release**: Lock is released in `finally` block; subsequent runs proceed normally.
- **Path Traversal Rejection**: Attempting to resolve `temp_demo_e2e_sandbox/../outside.txt` raises:
  `SecurityError: SECURITY VIOLATION: Path resolves outside sandbox!`
