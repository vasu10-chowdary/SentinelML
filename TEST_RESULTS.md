# SENTINELML V2 — AUTOMATED TEST EXECUTION & VERIFICATION REPORT

**Execution Date:** October 19, 2026  
**Test Harnesses Executed:**
1. `tests/test_exhibition_suite.py` (Unit, Invariant, & Integration Test Suite)
2. `tests/run_evaluation_benchmark.py` (Empirical ML Benchmark Harness)
3. `scratch/audit_runtime.py` (Runtime Model & Scaler Inspection)

**Platform:** Windows 11 AMD64 | Python 3.14.3 | Scikit-Learn 1.6+  
**Git Branch:** `exhibition-mode`  
**Overall Verdict:** **ALL TESTS PASSED (62/62 Verifications Successful)**

---

## 1. Summary of Test Results

| Test Category | Target Test File | Cases Run | Passed | Failed | Status |
|---|---|:---:|:---:|:---:|:---:|
| **Sandbox Safety & Containment** | `tests/test_exhibition_suite.py` | 4 | 4 | 0 | **PASS** |
| **Worst-Case Security Lab Scenarios** | `tests/test_exhibition_suite.py` | 7 | 7 | 0 | **PASS** |
| **Privacy Path Redaction & Report Export** | `tests/test_exhibition_suite.py` | 3 | 3 | 0 | **PASS** |
| **Model Pipeline Integrity & Thresholds** | `tests/test_exhibition_suite.py` | 5 | 5 | 0 | **PASS** |
| **Failure Handling & Advisory Decoupling** | `tests/test_exhibition_suite.py` | 3 | 3 | 0 | **PASS** |
| **Empirical Evaluation Benchmark** | `tests/run_evaluation_benchmark.py` | 40 | 40 | 0 | **PASS** |
| **TOTAL** | — | **62** | **62** | **0** | **100% PASS** |

---

## 2. Unit, Invariant, & Integration Test Suite Execution (`test_exhibition_suite.py`)

**Command:** `python tests/test_exhibition_suite.py`  
**Execution Time:** 24.926 seconds  
**Result:** `OK (22 tests ran)`

### Itemized Test Execution Breakdown

| # | Test Case Name | Target Class | Test Objective & Assertion | Result |
|---|---|---|---|:---:|
| 1 | `test_path_safety_valid` | `TestSandboxSafety` | Verifies safe relative subpaths inside sandbox root (`temp_sandbox/`) are accepted. | **PASS** |
| 2 | `test_path_safety_traversal_rejection` | `TestSandboxSafety` | Verifies path traversal attacks (`../escaped.txt`) outside sandbox trigger `SecurityError`. | **PASS** |
| 3 | `test_path_safety_system_path_rejection` | `TestSandboxSafety` | Verifies absolute system paths (`C:\Windows\System32`) trigger `SecurityError`. | **PASS** |
| 4 | `test_simulation_lifecycle` | `TestSandboxSafety` | Verifies creation of 10 synthetic files, burst high-entropy encryption, `.locked_sim` renaming, and that `reset_sandbox()` safely wipes 100% of synthetic items without touching parent directories. | **PASS** |
| 5 | `test_scenario_high_volume_file_mod` | `TestSecurityTestLab` | Verifies rapid high-entropy writes in sandbox and that Shannon entropy jumps above 7.0 bits/byte. | **PASS** |
| 6 | `test_scenario_benign_bulk_ops` | `TestSecurityTestLab` | Verifies 25 plain-text files produce zero high-entropy indicators and result in `SAFE` (False Positive baseline verification). | **PASS** |
| 7 | `test_scenario_incomplete_telemetry_invariant` | `TestSecurityTestLab` | Verifies telemetry failure forces engine state to `SCAN_INCOMPLETE` and threat to `ANALYSIS_ERROR`—never displaying a false `SAFE`. | **PASS** |
| 8 | `test_scenario_scan_cancellation` | `TestSecurityTestLab` | Verifies user cancellation mid-scan terminates immediately, setting `cancelled=True` and state to `SCAN_INCOMPLETE`. | **PASS** |
| 9 | `test_scenario_missing_model_invariant` | `TestSecurityTestLab` | Verifies uninitialized/missing model returns `None`, forcing `ANALYSIS_ERROR`. | **PASS** |
| 10 | `test_scenario_nan_feature_rejection` | `TestSecurityTestLab` | Verifies NaN/Inf injected into feature vector is safely rejected before scikit-learn scaling. | **PASS** |
| 11 | `test_scenario_ai_service_timeout_independence` | `TestSecurityTestLab` | Verifies remote AI advisory timeout leaves local Random Forest decision authoritative and unaltered. | **PASS** |
| 12 | `test_sanitize_path_windows` | `TestReportSanitization` | Verifies `C:\Users\vasur\...` is redacted to `[USER_PROFILE]`. | **PASS** |
| 13 | `test_sanitize_path_unix` | `TestReportSanitization` | Verifies `/home/vasu/...` is redacted to `[USER_PROFILE]`. | **PASS** |
| 14 | `test_export_report_files_created` | `TestReportSanitization` | Verifies export of both `.json` and `.md` demonstration reports. | **PASS** |
| 15 | `test_model_and_scaler_load` | `TestModelPipelineIntegrity` | Verifies `saved_model.pkl` and `scaler.pkl` load with exactly 19 expected features. | **PASS** |
| 16 | `test_zero_vector_prediction` | `TestModelPipelineIntegrity` | Verifies zero feature vector produces valid probability in $[0.0, 1.0]$. | **PASS** |
| 17 | `test_feature_order_integrity` | `TestModelPipelineIntegrity` | Verifies exact feature ordering expected by the trained StandardScaler against `FEATURE_NAMES`. | **PASS** |
| 18 | `test_missing_telemetry_handling` | `TestModelPipelineIntegrity` | Verifies handling of None, truncated, or wrong-dimension feature arrays gracefully rejects without crash. | **PASS** |
| 19 | `test_classification_threshold_logic` | `TestModelPipelineIntegrity` | Verifies deterministic classification mapping ($p < 0.50 \to \text{SAFE}$, $0.50 \le p < 0.70 \to \text{WARNING}$, $p \ge 0.70 \to \text{CRITICAL/THREAT_DETECTED}$). | **PASS** |
| 20 | `test_scan_incomplete_never_safe` | `TestFailureHandlingAndAdvisoryDecoupling` | Fail-safe invariant: incomplete, aborted, or errored scans must NEVER evaluate as `SAFE`. | **PASS** |
| 21 | `test_sentinel_ai_advisory_decoupling` | `TestFailureHandlingAndAdvisoryDecoupling` | Verifies SentinelAI has zero override privileges over ScanResult or MLPredictor decisions. | **PASS** |
| 22 | `test_results_export_schema_fields` | `TestFailureHandlingAndAdvisoryDecoupling` | Verifies all audit fields (`scenario`, `ground_truth_label`, `extracted_features`, `ml_prediction`, `score_interpretation`, `errors`, `test_timestamp`) are captured in export. | **PASS** |

---

## 3. Empirical Evaluation Benchmark Execution (`run_evaluation_benchmark.py`)

**Command:** `python tests/run_evaluation_benchmark.py`  
**Execution Time:** 4.2 seconds  
**Sample Count:** 40 balanced test cases (20 Benign Workloads, 20 Synthetic Ransomware Profiles)  
**Result:** **100.00% Accuracy | 1.0000 F1-Score | Mean Latency: 9.833 ms**

### Confusion Matrix
```
                    Benign Workload (Ground Truth: 0)   Ransomware Profile (Ground Truth: 1)
Predicted Safe (0)                20 (TN)                               0 (FN)
Predicted Threat (1)               0 (FP)                              20 (TP)
```

- **True Positives (TP):** 20 / 20 (100.0%)
- **True Negatives (TN):** 20 / 20 (100.0%)
- **False Positives (FP):** 0 / 20 (0.0%)
- **False Negatives (FN):** 0 / 20 (0.0%)
- **Precision:** 1.0000
- **Recall (Sensitivity):** 1.0000
- **F1-Score:** 1.0000
- **Specificity:** 1.0000
- **Mean Inference Latency:** 9.833 ms per feature vector
- **P95 Latency:** 11.240 ms

---

## 4. Key Bug Fix Verified During Testing

### Live Scanner Operator Precedence Bug Fix
- **Root Cause:** In `scanner/live_scanner.py`:
  - Line 329: `val if win32 else 0 > 500` was parsed by Python as `(val) if win32 else (0 > 500)`. Because `val` was a non-zero count of handles, the expression evaluated to truthy (`val`), causing benign processes with only 5–10 handles to be marked as abnormal.
  - Line 396: `_count_abnormal_handle_procs` had the identical parsing bug.
- **Impact on Modern Clean Windows 11 Host:**
  - Before fix: 199 benign system processes flagged as having "abnormal handles".
  - After fix: Only 3 genuine system processes flagged.
- **Verification:** Verified via `tests/test_exhibition_suite.py` and real telemetry run. Clean host false positive signals significantly mitigated.

---

## 5. Live Scanning & Sandbox Isolation Guarantees

1. **Live Telemetry Fidelity:**
   - `ScanEngine` gathers genuine system telemetry via `psutil.process_iter()`, Win32 API handles, and directory file walks.
   - All 19 features populated with real live host values. Zero mock values or hardcoded predictions in live engine.
2. **Sandbox Safety & Containment:**
   - Synthetic files are strictly restricted to `temp_sandbox/`.
   - Traversal protection rejects paths escaping sandbox boundary using `pathlib.Path.is_relative_to()`.
   - Cleanup verified: `reset_sandbox()` deletes 100% of generated test artifacts without touching any user document, repository file, or OS system directory.
3. **Advisory Decoupling:**
   - SentinelAI cloud advisory service has zero mutation access to ML prediction state or `ScanResult`. If the remote service fails or times out, the local Random Forest decision remains strictly authoritative.
