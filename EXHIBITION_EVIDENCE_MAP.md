# SentinelML V2 — 6-Stage Detection Evidence Map

## Executive Summary

This document establishes the end-to-end evidence trace for SentinelML V2's behavioral ransomware detection engine. It maps the observable data sources, preprocessing transformations, decision boundaries, and scientific disclosures across all six pipeline stages.

---

## 1. Six-Stage Evidence Trace Matrix

```mermaid
flowchart LR
    S1["Stage 1: Harmless Sandbox Activity"] --> S2["Stage 2: Filesystem Observation"]
    S2 --> S3["Stage 3: Telemetry Collection"]
    S3 --> S4["Stage 4: Feature Vector Validation"]
    S4 --> S5["Stage 5: Model Inference"]
    S5 --> S6["Stage 6: Threat Classification & Boundaries"]
```

| Stage | Name | Input Artifacts | Observable Measurements | Processing Components | Output State | Operational Limitation |
| :---: | :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | **Harmless Sandbox Activity** | Target Path: `temp_sandbox/`<br>Operation Count: 20 files | • Files Created: 20<br>• Files Modified: 20<br>• Files Renamed: 20 (`.locked_sim`)<br>• Initial Entropy: ~4.12<br>• Modified Entropy: ~7.89 | `SandboxSimulator`<br>`validate_path_safety()` | `STAGE_1_PASSED`<br>(Simulation Complete) | Operations strictly isolated to `temp_sandbox/`. No files created in user documents or OS system roots. |
| **2** | **Filesystem Observation** | Monitored Directory Tree | • Files Inspected: >= 20<br>• Suspicious Files Flagged: 20<br>• Ransom Note Matched: 1 (`READ_ME_RECOVERY_SIM.txt`) | `FilesystemScanner`<br>`DirectoryWalker` | `STAGE_2_PASSED`<br>(Observed) | User-space scanner polls target path without a Windows kernel filesystem minifilter driver (`fltmgr.sys`). |
| **3** | **Telemetry Collection** | Inspected File Bytes & OS Process Table | • Extracted Shannon Entropy: ~7.89 bits/byte<br>• Total Processes: 150 - 300<br>• Suspicious Cmdlines: 0<br>• Network Endpoints: 20 - 80 | `ShannonEntropyCalculator`<br>`psutil.process_iter()` | `STAGE_3_PASSED`<br>(Telemetry Gathered) | Process telemetry reflects host baseline because no live unmanaged malicious binary was executed. |
| **4** | **Feature Vector Validation** | Raw Sensor Telemetry | • Legacy 19-position array: `shape=(1, 19)`<br>• Schema V2 16-position array: `shape=(1, 16)`<br>• Finite Check: `np.isfinite().all() == True`<br>• Out-of-bounds Check: Passed | `validate_schema_v2_vector()`<br>`StandardScaler.transform()` | `STAGE_4_PASSED`<br>(Vector Validated) | Legacy 19 schema lacks file extension counts; Schema V2 incorporates them (`ransom_extension_match_count`). |
| **5** | **Model Inference** | Normalized Feature Vector (`Z-scores`) | • Voting Trees (Ransomware): 56 / 100<br>• Voting Trees (Benign): 44 / 100<br>• Raw Probability: ~0.5600<br>• Inference Latency: 5 - 15 ms | `RandomForestClassifier`<br>(100 Estimators, Gini Impurity) | `STAGE_5_PASSED`<br>(Probability Generated) | Model inference reflects synthetic-data baseline decision boundaries trained on memory forensics proxies. |
| **6** | **Threat Classification & Boundaries** | Model Probability: 0.5600 | • Threshold Warning: 0.50<br>• Threshold Critical: 0.90<br>• Classification: `WARNING`<br>• Detection Achieved: `True` | `MLPredictor.predict()`<br>`ScanEngine.state` | `STAGE_6_PASSED`<br>(Decision Rendered) | WARNING achieved via entropy elevation. CRITICAL withheld due to absence of correlated process anomalies. |

---

## 2. Decision Threshold Semantics & Invariants

SentinelML enforces strict state invariants to prevent both false alarms and false reassurances:

```
[ Probability Scale (0.00 to 1.00) ]
0.00 ─────── 0.49 ────────────────── 0.50 ──────────────────────── 0.89 ─────────────── 0.90 ────── 1.00
     SAFE                                      WARNING                                     CRITICAL
 (Baseline Normal)                     (Elevated Single-Signal)                     (Multi-Signal Corroborated)
```

1. **The Multi-Signal Corroboration Rule**:
   - High-entropy modifications alone push the tree vote distribution into the `0.50 - 0.89` band (`WARNING`).
   - Crossing the `0.90` threshold (`CRITICAL`) requires correlated process-level malicious activity (e.g., `vssadmin.exe delete shadows`, privilege tampering, or injection hooks).
   - This prevents false-positive shutdowns during benign high-entropy workloads (video encoding, archiving, encrypted database updates).

2. **The Non-Defaulting SAFE Rule**:
   - If telemetry collection encounters missing data, process access denial, or numerical exceptions (`NaN`), the scan **NEVER** defaults to `SAFE`.
   - The state machine transitions to `SCAN_INCOMPLETE` or `ANALYSIS_ERROR`.

3. **Ring-3 Advisory Isolation**:
   - The optional `SentinelAI` advisory service operates strictly downstream of the Random Forest.
   - Cloud LLM latency, disconnections, or timeout errors have **zero impact** on the deterministic local ML classification.

---

## 3. Generated Evidence Artifacts

When a demonstration or test run completes, evidence is serialized into two structured artifacts within the `reports/` directory:

1. **Human-Readable Markdown Report (`reports/exhibition_demo_<TIMESTAMP>.md`)**:
   - Formatted for academic auditors, presenting executive summary, stage-by-stage metrics, feature inventory, and technical caveats.
   - All user names, profile directories, and system paths are sanitized using `sanitize_path()`.

2. **Machine-Readable JSON Bundle (`reports/exhibition_demo_<TIMESTAMP>.json`)**:
   - Full structured telemetry vector (19 legacy features + 16 Schema V2 features).
   - Timestamped timeline of all file write/rename events with individual Shannon entropy measurements.
   - Explicit provenance metadata:
     ```json
     {
       "model_source": "EXPERIMENTAL_SYNTHETIC_BASELINE_V1",
       "is_simulation": true,
       "observable_schema": "SCHEMA_V2_COMPATIBLE",
       "detection_achieved": true,
       "threat_level": "WARNING",
       "probability": 0.56
     }
     ```
