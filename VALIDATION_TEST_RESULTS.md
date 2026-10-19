# SENTINELML V2 — VALIDATION TEST RESULTS REPORT

**Test Execution Date:** October 19, 2026  
**Target Repository:** `C:\Users\vasur\Desktop\SentinalMl\`  
**Target Branch:** `exhibition-mode`  
**Execution Environment:** Windows 11 Enterprise AMD64 | Python 3.14.3 | Scikit-Learn 1.6+ | Psutil 5.9+  
**Overall Verdict:** **100% OF TESTS PASSED (74/74 Test Executions Successful)**  

---

## 1. Executive Summary of Test Suites

| Test Suite File | Harness Focus | Test Cases | Passed | Failed | Errors | Status |
|---|---|:---:|:---:|:---:|:---:|:---:|
| `tests/test_exhibition_suite.py` | Unit, Invariant, 6-Stage Detection & Live Inference Validation | 34 | 34 | 0 | 0 | **100% PASS** |
| `tests/run_evaluation_benchmark.py` | 40-Case Polar Synthetic Evaluation Harness | 40 | 40 | 0 | 0 | **100% PASS** |
| **TOTAL** | — | **74** | **74** | **0** | **0** | **100% PASS** |

---

## 2. Itemized Execution Results: `tests/test_exhibition_suite.py`

**Execution Command:**
```bash
python -m unittest tests/test_exhibition_suite.py
```
**Recorded Output:** `Ran 34 tests in 38.490s | OK`

### 2.1 Sandbox Boundaries & Path Traversal Safety (`TestSandboxSafety`)
| # | Test Name | Target Assertion | Result |
|:---:|---|---|:---:|
| 1 | `test_path_safety_valid` | Valid relative subpath in disposable sandbox is accepted. | **PASS** |
| 2 | `test_path_safety_traversal_rejection` | Path traversal (`../escaped.txt`) outside sandbox triggers `SecurityError`. | **PASS** |
| 3 | `test_path_safety_system_path_rejection` | Absolute system root path (`C:\Windows\System32`) triggers `SecurityError`. | **PASS** |
| 4 | `test_simulation_lifecycle` | Creation, modification, renaming, and safe cleanup of 10 synthetic files verified. | **PASS** |

### 2.2 Security Test Lab & 6-Stage Detection Framework (`TestSecurityTestLab`)
| # | Test Name | Target Assertion | Result |
|:---:|---|---|:---:|
| 5 | `test_scenario_high_volume_file_mod` | Verifies full 6-stage detection pipeline on 20 encrypted files in sandbox ($p = 0.56$). | **PASS** |
| 6 | `test_scenario_rapid_renaming` | Verifies 6-stage detection pipeline on 15 renamed files and records extension telemetry gap. | **PASS** |
| 7 | `test_scenario_benign_bulk_ops` | 25 normal plain text business documents produce 0 alerts and evaluate as `SAFE`. | **PASS** |
| 8 | `test_scenario_incomplete_telemetry_invariant` | Process telemetry failure forces `SCAN_INCOMPLETE` with `ANALYSIS_ERROR`. | **PASS** |
| 9 | `test_scenario_scan_cancellation` | Mid-scan user cancellation terminates cleanly with `cancelled=True`. | **PASS** |
| 10 | `test_scenario_missing_model_invariant` | Unloadable model returns `None`, forcing `ANALYSIS_ERROR`. | **PASS** |
| 11 | `test_scenario_nan_feature_rejection` | `NaN` or `Inf` in feature vector is rejected before reaching `StandardScaler`. | **PASS** |
| 12 | `test_scenario_ai_service_timeout_independence` | AI copilot network timeouts leave local Random Forest decision authoritative. | **PASS** |

### 2.3 Report Sanitization & Redaction (`TestReportSanitization`)
| # | Test Name | Target Assertion | Result |
|:---:|---|---|:---:|
| 13 | `test_sanitize_path_windows` | Windows profile path (`C:\Users\vasur\...`) is redacted to `[USER_PROFILE]`. | **PASS** |
| 14 | `test_sanitize_path_unix` | Unix profile path (`/home/vasu/...`) is redacted to `[USER_PROFILE]`. | **PASS** |
| 15 | `test_export_report_files_created` | Verifies export of both `.json` and `.md` demonstration reports. | **PASS** |

### 2.4 Model Pipeline Integrity & Heuristic Proxy Audits (`TestModelPipelineIntegrity`)
| # | Test Name | Target Assertion | Result |
|:---:|---|---|:---:|
| 16 | `test_model_and_scaler_load` | `saved_model.pkl` and `scaler.pkl` load with exactly 19 features. | **PASS** |
| 17 | `test_zero_vector_prediction` | Zero vector produces valid probability $p \in [0.0, 1.0]$. | **PASS** |
| 18 | `test_feature_order_integrity` | Order expected by `StandardScaler` matches `FEATURE_NAMES`. | **PASS** |
| 19 | `test_missing_telemetry_handling` | None, truncated, or wrong-dimension arrays reject safely without crashing. | **PASS** |
| 20 | `test_classification_threshold_logic` | Discrete mappings ($0.0 \to \text{SAFE}$, $0.50 \to \text{WARNING}$, $0.90 \to \text{CRITICAL}$) verified. | **PASS** |
| 21 | `test_heuristic_proxy_divergence_documentation` | Audits the 5 heuristic proxy methods substituted into memory forensics slots. | **PASS** |
| 22 | `test_custom_path_entropy_observation` | Passing `target_directories` to `LiveScanner` causes direct target sampling ($H > 7.5$). | **PASS** |
| 23 | `test_scan_engine_threshold_mapping` | Engine reconciles $p \ge 0.50 \implies \text{THREAT\_DETECTED}$ and $p < 0.50 \implies \text{SAFE}$. | **PASS** |

### 2.5 State Invariants & Advisory Decoupling (`TestFailureHandlingAndAdvisoryDecoupling`)
| # | Test Name | Target Assertion | Result |
|:---:|---|---|:---:|
| 24 | `test_scan_incomplete_never_safe` | Incomplete or failed scans return `was_successful() == False`. | **PASS** |
| 25 | `test_sentinel_ai_advisory_decoupling` | SentinelAI has zero override privileges over ScanResult or MLPredictor. | **PASS** |
| 26 | `test_results_export_schema_fields` | Export captures all audit fields (`scenario`, `ground_truth_label`, `probability`, etc.). | **PASS** |

### 2.6 Live Inference Invariants & Schema Parity (`TestLiveInferenceValidation`)
| # | Test Name | Target Assertion | Result |
|:---:|---|---|:---:|
| 27 | `test_live_feature_vector_schema_and_types` | Live host extraction produces valid 1x19 finite float array (`np.isfinite.all()`). | **PASS** |
| 28 | `test_feature_order_pipeline_parity` | Exact positional match across `FEATURE_NAMES`, `scaler`, and recovered training config. | **PASS** |
| 29 | `test_missing_telemetry_never_converted_to_benign` | Failed process scan returns `False`, setting `threat_level="ANALYSIS_ERROR"`. | **PASS** |
| 30 | `test_invalid_model_output_causes_explicit_analysis_error` | Out-of-bounds probability, bad labels, or `None` predictions force `ANALYSIS_ERROR`. | **PASS** |
| 31 | `test_incomplete_scan_cannot_be_classified_as_safe` | `ScanResult` in incomplete states cannot have `state == ScanState.SAFE`. | **PASS** |
| 32 | `test_sentinel_ai_cannot_override_classifier` | Verifies absence of `override_decision`, `set_threat_level`, and `force_safe` methods. | **PASS** |
| 33 | `test_synthetic_scenario_honest_detection_criteria` | `detection_achieved` is strictly `True` only if $p \ge 0.50$; $p < 0.50$ evaluates `False`. | **PASS** |
| 34 | `test_six_stage_verification_independent_recording` | Verifies all 6 stages exist and record independently on `ScenarioOutcome`. | **PASS** |

---

## 3. Controlled Evaluation Benchmark Results (`run_evaluation_benchmark.py`)

**Execution Command:**
```bash
python tests/run_evaluation_benchmark.py
```
**Recorded Output:** `Processed 40 samples in 3.84s (Mean latency: 8.87 ms/sample)`

### Confusion Matrix (Functional Integration Test)
```
                    Predicted Safe (0)    Predicted Threat (1)
Actual Benign (0)           20                     0
Actual Threat (1)            0                    20
```

- **Accuracy:** $1.0000$ ($100.0\%$)
- **Precision:** $1.0000$ ($100.0\%$)
- **Recall (Sensitivity):** $1.0000$ ($100.0\%$)
- **F1-Score:** $1.0000$ ($100.0\%$)
- **Inference Latency:** Mean $8.872$ ms | $p95$ $12.639$ ms

### Academic Integrity Clarification
As established in `BENCHMARK_VALIDITY_AUDIT.md` and `INDEPENDENT_EVALUATION_REPORT.md`, these 40 balanced test cases evaluate hand-authored polar vectors. While they confirm that the Random Forest model and StandardScaler pipeline execute mathematically across clear clusters, they **do not validate in-the-wild zero-day ransomware detection**.

---

## 4. Test Harness Traceability Matrix

| Requirement | Governing Rule / Phase | Test Name in `test_exhibition_suite.py` | Status |
|---|---|---|:---:|
| Schema verification | Phase 5, Item 1 | `test_live_feature_vector_schema_and_types` | **VERIFIED** |
| Feature order parity | Phase 5, Item 2 | `test_feature_order_pipeline_parity` | **VERIFIED** |
| Missing telemetry handling | Phase 5, Item 3 | `test_missing_telemetry_never_converted_to_benign` | **VERIFIED** |
| Invalid prediction error | Phase 5, Item 4 | `test_invalid_model_output_causes_explicit_analysis_error` | **VERIFIED** |
| Incomplete scan safety | Phase 5, Item 5 | `test_incomplete_scan_cannot_be_classified_as_safe` | **VERIFIED** |
| Advisory decoupling | Phase 5, Item 6 | `test_sentinel_ai_cannot_override_classifier` | **VERIFIED** |
| Honest detection criteria | Phase 5, Item 7 | `test_synthetic_scenario_honest_detection_criteria` | **VERIFIED** |
| Independent 6-stage recording | Phase 5, Item 8 | `test_six_stage_verification_independent_recording` | **VERIFIED** |
| Disposable sandbox safety | Rule 1 & Rule 3 | `test_path_safety_traversal_rejection` | **VERIFIED** |
| Zero live malware executed | Rule 3 | All tests utilize synthetic profiles / simulations | **VERIFIED** |
