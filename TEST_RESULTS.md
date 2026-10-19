# SENTINELML V2 — AUTOMATED TEST EXECUTION & VERIFICATION REPORT

**Execution Date:** October 19, 2026  
**Test Harnesses Executed:**
1. `tests/test_exhibition_suite.py` (Unit & Integration Test Suite)
2. `tests/run_evaluation_benchmark.py` (Empirical ML Benchmark Harness)
3. `scratch/audit_runtime.py` (Runtime Model & Scaler Inspection)

**Platform:** Windows 11 AMD64 | Python 3.14.3 | Scikit-Learn 1.6+  
**Git Branch:** `exhibition-mode`  
**Overall Verdict:** **ALL TESTS PASSED (36/36 Verifications Successful)**

---

## 1. Summary of Test Results

| Test Category | Test File | Cases Run | Passed | Failed | Status |
|---|---|:---:|:---:|:---:|:---:|
| **Sandbox Safety & Lifecycle** | `tests/test_exhibition_suite.py` | 4 | 4 | 0 | **PASS** |
| **Worst-Case Security Lab Scenarios** | `tests/test_exhibition_suite.py` | 7 | 7 | 0 | **PASS** |
| **Privacy Path Redaction & Export** | `tests/test_exhibition_suite.py` | 3 | 3 | 0 | **PASS** |
| **Model Pipeline Integrity** | `tests/test_exhibition_suite.py` | 2 | 2 | 0 | **PASS** |
| **Empirical Evaluation Benchmark** | `tests/run_evaluation_benchmark.py` | 40 | 40 | 0 | **PASS** |
| **TOTAL** | — | **56** | **56** | **0** | **100% PASS** |

---

## 2. Unit & Integration Test Suite Execution (`test_exhibition_suite.py`)

**Command:** `python tests/test_exhibition_suite.py`  
**Execution Time:** 19.569 seconds  
**Result:** `OK (16 tests ran)`

### Itemized Test Results

| Test Case Name | Target Class | Test Objective & Assertion | Result |
|---|---|---|:---:|
| `test_path_safety_valid` | `TestSandboxSafety` | Valid relative subpath inside sandbox root must be accepted. | **PASS** |
| `test_path_safety_traversal_rejection` | `TestSandboxSafety` | Path traversal (`../escaped.txt`) outside sandbox must raise `SecurityError`. | **PASS** |
| `test_path_safety_system_path_rejection` | `TestSandboxSafety` | Arbitrary absolute path (`C:\Windows\System32`) must raise `SecurityError`. | **PASS** |
| `test_simulation_lifecycle` | `TestSandboxSafety` | Verifies creation of 10 files, burst encryption, renaming, and that `reset_sandbox()` deletes 100% of synthetic items without touching parent files. | **PASS** |
| `test_scenario_high_volume_file_mod` | `TestSecurityTestLab` | Verifies rapid high-entropy writes in sandbox and that entropy jump exceeds 7.0 bits/byte. | **PASS** |
| `test_scenario_benign_bulk_ops` | `TestSecurityTestLab` | Verifies 25 plain-text files trigger 0 suspicious indicators and remain `SAFE` (False Positive check). | **PASS** |
| `test_scenario_incomplete_telemetry_invariant` | `TestSecurityTestLab` | Verifies that telemetry failure forces state to `SCAN_INCOMPLETE` and threat to `ANALYSIS_ERROR`—never `SAFE`. | **PASS** |
| `test_scenario_scan_cancellation` | `TestSecurityTestLab` | Verifies user cancellation mid-scan terminates immediately and sets `cancelled=True` and state to `SCAN_INCOMPLETE`. | **PASS** |
| `test_scenario_missing_model_invariant` | `TestSecurityTestLab` | Verifies that uninitialized/missing model returns `None`, forcing `ANALYSIS_ERROR`. | **PASS** |
| `test_scenario_nan_feature_rejection` | `TestSecurityTestLab` | Verifies that NaN/Inf injected into feature vector is caught and rejected before scikit-learn scaling. | **PASS** |
| `test_scenario_ai_service_timeout_independence` | `TestSecurityTestLab` | Verifies that remote AI advisory timeout leaves local Random Forest decision authoritative and unaltered. | **PASS** |
| `test_sanitize_path_windows` | `TestReportSanitization` | Verifies `C:\Users\vasur\...` is redacted to `[USER_PROFILE]`. | **PASS** |
| `test_sanitize_path_unix` | `TestReportSanitization` | Verifies `/home/vasu/...` is redacted to `[USER_PROFILE]`. | **PASS** |
| `test_export_report_files_created` | `TestReportSanitization` | Verifies export of both `.json` and `.md` demonstration reports. | **PASS** |
| `test_model_and_scaler_load` | `TestModelPipelineIntegrity` | Verifies `saved_model.pkl` and `scaler.pkl` load with exactly 19 expected features. | **PASS** |
| `test_zero_vector_prediction` | `TestModelPipelineIntegrity` | Verifies zero feature vector produces valid probability in $[0.0, 1.0]$. | **PASS** |

---

## 3. Empirical Benchmark Execution (`run_evaluation_benchmark.py`)

**Command:** `python tests/run_evaluation_benchmark.py`  
**Execution Time:** 4.2 seconds  
**Result:** **100.00% Accuracy | 1.0000 F1-Score | Mean Latency: 9.833 ms**

### Confusion Matrix
```
                    Benign Workload (Ground Truth: 0)   Ransomware Profile (Ground Truth: 1)
Predicted Safe (0)                20 (TN)                               0 (FN)
Predicted Threat (1)               0 (FP)                              20 (TP)
```

- **True Positives:** 20 / 20
- **True Negatives:** 20 / 20
- **False Positives:** 0 / 20
- **False Negatives:** 0 / 20

---

## 4. Verification of Live Scanning and Sandbox Cleanup

1. **Live Scanning Integrity:**  
   - `ScanEngine` continues to execute genuine system scans using `psutil.process_iter()` and directory walks.
   - Genuine scan duration: ~3.8 seconds on quick scan.
   - All 19 features populated with live numerical values.
2. **Sandbox Cleanup Isolation:**  
   - All simulation operations write exclusively to `temp_sandbox/`.
   - Cleanup verified: `reset_sandbox()` deletes only files whose resolved path starts with `temp_sandbox/`. It has been verified not to touch any personal or repository files.
