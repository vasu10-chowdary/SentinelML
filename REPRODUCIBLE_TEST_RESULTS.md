# SENTINELML V2 — REPRODUCIBLE TEST RESULTS & VERIFICATION REPORT

**Execution Date:** October 19, 2026  
**Target Repository:** `C:\Users\vasur\Desktop\SentinalMl\`  
**Target Branch:** `exhibition-mode`  
**Execution Environment:** Windows 11 AMD64 | Python 3.14.3 | Scikit-Learn 1.6+ | Psutil 5.9+  
**Overall Verdict:** **ALL TESTS PASSED (66/66 Executions Successful)**

---

## 1. Executive Summary of Test Suites

| Test Suite File | Harness Focus | Test Cases | Passed | Failed | Status |
|---|---|:---:|:---:|:---:|:---:|
| `tests/test_exhibition_suite.py` | Unit, Invariant, 6-Stage Detection & Sandbox Safety | 26 | 26 | 0 | **100% PASS** |
| `tests/run_evaluation_benchmark.py` | 40-Case Polar Synthetic Evaluation Harness | 40 | 40 | 0 | **100% PASS** |
| **TOTAL** | — | **66** | **66** | **0** | **100% PASS** |

---

## 2. Unit, Invariant & 6-Stage Detection Test Suite (`test_exhibition_suite.py`)

**Command:**
```bash
python tests/test_exhibition_suite.py
```
**Execution Time:** 20.971 seconds  
**Recorded Output:** `Ran 26 tests in 20.971s | OK`

### Itemized Test Execution Results

| # | Test Method Name | Target Test Class | Objective & Assertion | Output Status |
|:---:|---|---|---|:---:|
| 1 | `test_path_safety_valid` | `TestSandboxSafety` | Valid relative subpath in disposable sandbox is accepted. | **PASS** |
| 2 | `test_path_safety_traversal_rejection` | `TestSandboxSafety` | Path traversal (`../escaped.txt`) outside sandbox triggers `SecurityError`. | **PASS** |
| 3 | `test_path_safety_system_path_rejection` | `TestSandboxSafety` | Absolute system root path (`C:\Windows\System32`) triggers `SecurityError`. | **PASS** |
| 4 | `test_simulation_lifecycle` | `TestSandboxSafety` | Verifies creation of 10 synthetic files, modification, renaming, and that `reset_sandbox()` deletes 100% of synthetic items without touching parent directories. | **PASS** |
| 5 | `test_scenario_high_volume_file_mod` | `TestSecurityTestLab` | Verifies the **6-Stage Detection Framework** on high-volume synthetic encryption: simulator activity, sandbox observation, telemetry collection, ML inference, and honest detection reporting. | **PASS** |
| 6 | `test_scenario_rapid_renaming` | `TestSecurityTestLab` | Verifies the **6-Stage Detection Framework** on rapid file renaming: heuristic extension detection, ML telemetry gap verification, and honest detection reporting. | **PASS** |
| 7 | `test_scenario_benign_bulk_ops` | `TestSecurityTestLab` | Verifies that 25 standard plaintext business documents produce zero suspicious indicators and evaluate as `SAFE` (False Positive check). | **PASS** |
| 8 | `test_scenario_incomplete_telemetry_invariant` | `TestSecurityTestLab` | Verifies that when process telemetry fails, scan state transitions to `SCAN_INCOMPLETE` with `ANALYSIS_ERROR`—never displaying `SAFE`. | **PASS** |
| 9 | `test_scenario_scan_cancellation` | `TestSecurityTestLab` | Verifies that user cancellation mid-scan terminates immediately, setting `cancelled=True` and `state=SCAN_INCOMPLETE`. | **PASS** |
| 10 | `test_scenario_missing_model_invariant` | `TestSecurityTestLab` | Verifies that an uninitialized or missing model pipeline returns `None`, forcing `ANALYSIS_ERROR`. | **PASS** |
| 11 | `test_scenario_nan_feature_rejection` | `TestSecurityTestLab` | Verifies that `NaN` or `Inf` injected into the 19-feature vector is safely rejected before reaching `StandardScaler`. | **PASS** |
| 12 | `test_scenario_ai_service_timeout_independence` | `TestSecurityTestLab` | Verifies that remote AI advisory service timeouts leave local Random Forest decisions authoritative and unaltered. | **PASS** |
| 13 | `test_sanitize_path_windows` | `TestReportSanitization` | Verifies Windows user profile paths (`C:\Users\vasur\...`) are redacted to `[USER_PROFILE]`. | **PASS** |
| 14 | `test_sanitize_path_unix` | `TestReportSanitization` | Verifies Unix user profile paths (`/home/vasu/...`) are redacted to `[USER_PROFILE]`. | **PASS** |
| 15 | `test_export_report_files_created` | `TestReportSanitization` | Verifies export of both `.json` and `.md` demonstration reports. | **PASS** |
| 16 | `test_model_and_scaler_load` | `TestModelPipelineIntegrity` | Verifies `saved_model.pkl` and `scaler.pkl` load with exactly 19 expected features. | **PASS** |
| 17 | `test_zero_vector_prediction` | `TestModelPipelineIntegrity` | Verifies zero feature vector produces valid probability in $[0.0, 1.0]$. | **PASS** |
| 18 | `test_feature_order_integrity` | `TestModelPipelineIntegrity` | Verifies exact feature ordering expected by the trained StandardScaler against `FEATURE_NAMES`. | **PASS** |
| 19 | `test_missing_telemetry_handling` | `TestModelPipelineIntegrity` | Verifies handling of None, truncated, or wrong-dimension feature arrays gracefully rejects without crashing. | **PASS** |
| 20 | `test_classification_threshold_logic` | `TestModelPipelineIntegrity` | Verifies discrete mapping: $p < 0.50 \to \text{SAFE}$, $0.50 \le p < 0.90 \to \text{WARNING}$, $p \ge 0.90 \to \text{CRITICAL}$. | **PASS** |
| 21 | `test_heuristic_proxy_divergence_documentation` | `TestModelPipelineIntegrity` | Audits the 5 critical heuristic proxies (Indices 5, 14, 15, 16, 17) substituted into memory forensics slots. | **PASS** |
| 22 | `test_custom_path_entropy_observation` | `TestModelPipelineIntegrity` | Verifies that passing `target_directories` to `LiveScanner` causes it to sample the targeted path directly. | **PASS** |
| 23 | `test_scan_engine_threshold_mapping` | `TestModelPipelineIntegrity` | Verifies `ScanEngine` reconciles $p \ge 0.50$ to `ScanState.THREAT_DETECTED` and $p < 0.50$ to `ScanState.SAFE`. | **PASS** |
| 24 | `test_scan_incomplete_never_safe` | `TestFailureHandlingAndAdvisoryDecoupling` | Fail-safe invariant: incomplete, aborted, or errored scans must NEVER evaluate as `SAFE`. | **PASS** |
| 25 | `test_sentinel_ai_advisory_decoupling` | `TestFailureHandlingAndAdvisoryDecoupling` | Verifies SentinelAI has zero override privileges over ScanResult or MLPredictor decisions. | **PASS** |
| 26 | `test_results_export_schema_fields` | `TestFailureHandlingAndAdvisoryDecoupling` | Verifies all exhibition audit fields (`scenario`, `ground_truth_label`, `extracted_features`, `ml_prediction`, `score_interpretation`, `errors`, `test_timestamp`) are captured in export. | **PASS** |

---

## 3. 6-Stage Detection Verification Output

The outputs from the newly implemented 6-stage detection validation in `exhibition/security_test_lab.py`:

### High-Volume Synthetic File Modification (`HIGH_VOLUME_FILE_MOD`)
```json
{
  "scenario_id": "HIGH_VOLUME_FILE_MOD",
  "stage_1_simulator_activity": true,
  "stage_2_filesystem_observed_sandbox": true,
  "stage_3_live_telemetry_collected_features": true,
  "stage_4_ml_processed_features": true,
  "stage_5_classifier_output": "WARNING",
  "malicious_probability": 0.5600,
  "stage_6_detection_achieved": true,
  "scan_state": "THREAT_DETECTED",
  "evidence": [
    "Stage 1 [Simulator]: Generated 20 high-entropy files (entropy: 5.01 -> 7.91)",
    "Stage 2 [Filesystem Scanner]: Inspected 21 files in sandbox",
    "Stage 3 [Live Telemetry]: Extracted avg_entropy=7.74 from sandbox target",
    "Stage 4 [ML Inference]: Processed 19-feature vector (ml_executed=True)",
    "Stage 5 [Classifier Output]: Threat level 'WARNING' (probability=0.5600)",
    "Stage 6 [Detection Result]: Detection Achieved = True"
  ],
  "limitation_notes": "OPERATIONAL LIMITATION CONFIRMED: High-entropy file modifications in the sandbox were observed by telemetry (avg_entropy=7.74), elevating probability to 0.56 (WARNING). The Random Forest model requires correlated process anomalies to cross into CRITICAL (>= 0.90)."
}
```

### Rapid File Renaming Scenario (`RAPID_RENAMING`)
```json
{
  "scenario_id": "RAPID_RENAMING",
  "stage_1_simulator_activity": true,
  "stage_2_filesystem_observed_sandbox": true,
  "stage_3_live_telemetry_collected_features": false,
  "stage_4_ml_processed_features": true,
  "stage_5_classifier_output": "WARNING",
  "malicious_probability": 0.5600,
  "stage_6_detection_achieved": true,
  "scan_state": "THREAT_DETECTED",
  "evidence": [
    "Stage 1 [Simulator]: Renamed 15 files with .locked_sim extension and dropped READ_ME note",
    "Stage 2 [Filesystem Scanner]: Flagged 16 suspicious items",
    "Stage 3 [Live Telemetry]: Feature vector does NOT contain file extension counts (feature absent from 19-vector)",
    "Stage 4 [ML Inference]: Evaluated 19 features without file extension inputs",
    "Stage 5 [Classifier Output]: Threat level 'WARNING' (probability=0.5600)",
    "Stage 6 [Detection Result]: Detection Achieved = True"
  ],
  "limitation_notes": "PIPELINE GAP CONFIRMED: Heuristic filesystem scanner flagged 16 suspicious files matching .locked_sim and ransom note keywords, but the 19-feature ML model does not ingest file extension telemetry."
}
```

---

## 4. Empirical Evaluation Benchmark Execution (`run_evaluation_benchmark.py`)

**Command:**
```bash
python tests/run_evaluation_benchmark.py
```
**Execution Time:** 3.8 seconds  
**Sample Count:** 40 balanced test cases (20 Benign Workloads, 20 Synthetic Ransomware Profiles)  
**Output File:** `tests/benchmark_results.json`

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
- **Mean Inference Latency:** 8.872 ms per sample
- **p95 Latency:** 12.639 ms

### Benchmark Integrity Clarification
As documented in `BENCHMARK_VALIDITY_AUDIT.md`, this benchmark evaluates hand-authored polar vectors where benign cases evaluate to $p \in [0.07, 0.29]$ and synthetic ransomware cases evaluate to $p \in [0.81, 0.89]$. This proves the mathematical consistency of the Random Forest pipeline across clean clusters, but does not constitute empirical validation against in-the-wild zero-day malware.
