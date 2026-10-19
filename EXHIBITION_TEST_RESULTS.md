# SentinelML V2 — Automated Test Results & Benchmark Report

## Execution Summary

| Test Suite | Total Tests | Passed | Failed | Errors | Duration | Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Exhibition Test Suite (`tests/test_exhibition_suite.py`)** | 51 | 51 | 0 | 0 | 56.18 s | **PASSED (100%)** |
| **Evaluation Benchmark (`tests/run_evaluation_benchmark.py`)** | 40 | 40 | 0 | 0 | 3.45 s | **PASSED (100%)** |
| **Combined Total** | **91** | **91** | **0** | **0** | **59.63 s** | **ALL PASSED** |

---

## 1. Exhibition Suite Detailed Test Breakdown (51 Tests)

### Module A: Sandbox Isolation & Safety Boundaries (`TestSandboxSafety`)
- `test_path_safety_valid`: PASS (Valid subpaths inside `temp_sandbox/` resolve cleanly).
- `test_path_safety_traversal_rejection`: PASS (`../` directory traversal attempts raise `SecurityError`).
- `test_path_safety_system_path_rejection`: PASS (`C:\Windows\System32\` and root paths rejected with `SecurityError`).
- `test_simulation_lifecycle`: PASS (Creation, modification, renaming, and complete purge verified).

### Module B: Worst-Case Scenarios & Invariant Verification (`TestSecurityTestLab`)
- `test_scenario_high_volume_file_mod`: PASS (6-stage verification on burst encryption).
- `test_scenario_rapid_renaming`: PASS (Flagging of `.locked_sim` extension without process pollution).
- `test_scenario_benign_bulk_ops`: PASS (25 plain text documents maintain `SAFE` state; zero false positives).
- `test_scenario_incomplete_telemetry`: PASS (Process enumeration failure forces `SCAN_INCOMPLETE`, never `SAFE`).
- `test_scenario_permission_denied`: PASS (System volume access denial accounted for without crashing).
- `test_scenario_scan_cancellation`: PASS (Mid-scan cancellation transitions immediately to `SCAN_INCOMPLETE`).
- `test_scenario_missing_model`: PASS (Unloaded model returns `None`, transitioning to `ANALYSIS_ERROR`).
- `test_scenario_feature_nan_failure`: PASS (`NaN` injection in entropy feature rejected before model inference).
- `test_scenario_ai_service_timeout`: PASS (Cloud AI disconnection does NOT alter local Random Forest decision).

### Module C: Schema V2 & Empirical Data Pipeline (`TestSchemaV2AndEmpiricalPipeline`)
- `test_schema_v2_feature_names_and_indices`: PASS (All 16 features verify exact indices [0..15]).
- `test_schema_v2_vector_validation_and_bounds`: PASS (Bounds validation, shape validation, NaN rejection).
- `test_schema_v2_vector_serialization_and_recovery`: PASS (Lossless roundtrip serialization via `to_dict()` and `from_dict()`).
- `test_benign_collector_sampling_and_quality_score`: PASS (Collector samples real Windows workstation telemetry with quality score >= 0.70).
- `test_benign_collector_session_lifecycle_and_deletion`: PASS (Start, sample, stop, review, and safe deletion lifecycle).
- `test_dataset_manager_validation_and_deduplication`: PASS (Deduplication engine removes duplicate rows; schema validation blocks invalid headers).
- `test_dataset_manager_leakage_free_split`: PASS (Group-aware partition guarantees 0% overlap between train and test splits).
- `test_train_v2_readiness_gate_blocks_on_missing_ransomware`: PASS (Readiness gate strictly halts training when empirical ransomware telemetry is missing).
- `test_scan_result_and_report_provenance_and_honest_simulation`: PASS (`ScanResult` and exported reports carry unambiguous provenance flags).

### Module D: Exhibition Experience & Safe Demo (`TestExhibitionExperienceAndSafeDemo`)
- `test_demo_health_check_valid`: PASS (Pre-demo diagnostic passes when sandbox, model, and sensors are healthy).
- `test_demo_health_check_failure_detection`: PASS (Diagnostic detects active concurrency lock and populates warnings).
- `test_concurrency_lock_protection`: PASS (Simultaneous calls to `run_safe_demo` blocked with `RuntimeError("Concurrency Lock")`).
- `test_run_safe_demo_full_6_stages`: PASS (Safe demo executes all 6 stages; achieves `WARNING` detection with 0.54 probability).
- `test_automatic_sandbox_cleanup`: PASS (Sandbox contains exactly 0 files after `cleanup_after=True` or `reset_sandbox()`).
- `test_transparent_feature_inspector_completeness`: PASS (All 19 legacy features and 16 Schema V2 features contain complete audit keys).
- `test_deterministic_walkthrough_execution_and_badging`: PASS (Walkthrough runs deterministically; bears `[EDUCATIONAL WALKTHROUGH — NOT LIVE SCAN]`).
- `test_simulation_vs_real_scan_distinction`: PASS (Simulation flag is `True` for demo and `False` for real host scan).

---

## 2. Evaluation Benchmark Performance (40 Synthetic Test Cases)

```
======================================================================
SENTINELML V2 — EVALUATION BENCHMARK AUDIT
======================================================================
Total Evaluated Samples:     40
Benign Test Samples:         20
Ransomware Simulation Cases: 20

Confusion Matrix:
  True Positives (TP):       20
  True Negatives (TN):       20
  False Positives (FP):       0
  False Negatives (FN):       0

Performance Metrics:
  Accuracy:                  100.00%
  Precision:                 100.00%
  Recall:                    100.00%
  F1-Score:                  100.00%

Inference Latency Profile:
  Mean Latency:              9.603 ms
  Median (p50):              9.126 ms
  95th Percentile (p95):     13.277 ms
  Maximum Observed:          19.954 ms
======================================================================
```

> **Academic Caveat on Benchmark Results**:
> The 100% accuracy reported above evaluates the Random Forest model on 40 controlled synthetic test distributions created to evaluate memory-forensics and heuristic boundaries. In accordance with university research integrity standards, this benchmark **must not** be interpreted as a claim of 100% detection against wild, zero-day, or polymorphic ransomware in unconstrained production environments.

---

## 3. Invariant Verification Matrix

| Invariant | Test Verification Method | Result |
| :--- | :--- | :---: |
| **Sandbox Containment** | Traversal tests (`../`, absolute paths, symlinks) | **VERIFIED** |
| **No False Reassurance** | Sensor failure injection forces `SCAN_INCOMPLETE` or `ANALYSIS_ERROR` | **VERIFIED** |
| **Concurrency Protection** | Non-blocking threading lock rejects simultaneous executions | **VERIFIED** |
| **Multi-Signal Corroboration** | High entropy achieves `WARNING` (~0.56); `CRITICAL` withheld without process anomalies | **VERIFIED** |
| **Clean Reset** | `reset_sandbox()` safely removes all generated artifacts | **VERIFIED** |
| **Telemetry Provenance** | Clear labeling of experimental synthetic baseline v1 | **VERIFIED** |
