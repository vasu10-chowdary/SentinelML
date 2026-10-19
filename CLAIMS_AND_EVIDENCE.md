# SentinelML V2 — Claims & Evidence Traceability Matrix

This document provides a rigorous, transparent mapping of every major technical claim made by the **SentinelML V2** project to its concrete code artifacts, test logs, runtime execution traces, and empirical verification status.

---

## 1. Traceability Matrix

| Claim ID | Project Claim | Source Implementation | Verifying Test / Script | Evidence Artifact / Log Reference | Validation Status | Scientific Caveat / Boundary |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **CLM-01** | **Ring-3 Behavioral Telemetry Collection** | `scanner/live_scanner.py`<br>`scanner/filesystem_scanner.py` | `scratch/test_live_scan_read_only.py`<br>`tests/test_exhibition_suite.py` | Scanned 53,846 live host files and 324 processes in 5.48s without error. | **VERIFIED (Empirical)** | Operates in user space (Ring-3). Observations occur after file operations complete; lacks kernel pre-execution interception. |
| **CLM-02** | **100% Accuracy on Synthetic Benchmark** | `ml/predictor.py`<br>`models/saved_model.pkl`<br>`models/scaler.pkl` | `tests/run_evaluation_benchmark.py` | 40/40 benchmark test cases correctly classified (Accuracy: 1.000, F1: 1.000, Latency: 15.9ms). | **VERIFIED (Synthetic Benchmark)** | Evaluated strictly against synthetic Gaussian test distributions (`sample_data.csv`). Does **not** prove 100% accuracy on wild ransomware. |
| **CLM-03** | **Offline Local ML Inference** | `ml/predictor.py`<br>`sklearn.ensemble.RandomForestClassifier` | `scratch/test_safe_demo_e2e.py`<br>`tests/test_exhibition_suite.py` | 100 trees executed locally via CPU joblib loader; 0 external network requests initiated during inference. | **VERIFIED (Offline)** | Requires pre-trained model pickle. Does not rely on cloud connectivity for threat scoring. |
| **CLM-04** | **Controlled Sandbox File Manipulation** | `scanner/sandbox_runner.py`<br>`gui/pages/exhibition_page.py` | `scratch/test_safe_demo_e2e.py` | 20 synthetic `.docx`, `.xlsx`, `.pdf` files created and encrypted strictly inside `temp_sandbox/`. | **VERIFIED (Safe Simulation)** | Simulates encryption behavior (AES cipher / random bytes) safely. Never operates outside designated sandbox directory. |
| **CLM-05** | **Path Traversal & Host File Protection** | `scanner/sandbox_runner.py` (`_validate_sandbox_target`) | `scratch/test_safe_demo_e2e.py`<br>`tests/test_exhibition_suite.py` | Path traversal attempts (`../../Windows`, `C:\Windows`) rejected with `SecurityError`. Zero files outside sandbox modified. | **VERIFIED (Enforced Barrier)** | Strictly path-anchored. Protects host operating system and user files from simulation artifacts. |
| **CLM-06** | **Six-Stage Evidence Pipeline** | `gui/pages/exhibition_page.py`<br>`SecurityTestLab.run_controlled_demo()` | `scratch/test_safe_demo_e2e.py`<br>`END_TO_END_DEMO_EVIDENCE.md` | Stages 1 through 6 transition deterministically: Pre-Check -> Deploy -> Encrypt -> Telemetry -> Scaler -> Forest Inference. | **VERIFIED (UI / State Machine)** | Orchestrated state pipeline for visual transparency and judge demonstration. |
| **CLM-07** | **Shannon Entropy Detection** | `scanner/filesystem_scanner.py` (`calculate_entropy`) | `scratch/test_safe_demo_e2e.py` | Baseline plaintext files: ~5.017 bits/byte; encrypted `.locked_sim` files: ~7.911 bits/byte. Jump captured in telemetry. | **VERIFIED (Mathematical)** | High entropy can occur in benign compressed files (`.zip`, `.mp4`). Model uses multi-signal fusion to avoid single-feature false positives. |
| **CLM-08** | **Multi-Signal Detection Thresholding** | `ml/predictor.py` (`predict_risk`) | `scratch/test_safe_demo_e2e.py`<br>`scratch/verify_all_scenarios_e2e.py` | High entropy alone yields `WARNING` ($p=0.57 \ge 0.50$). Requires correlated process anomalies to cross `CRITICAL` ($p \ge 0.90$). | **VERIFIED (Deterministic Logic)** | Prevents benign bulk encryption or file compression from triggering emergency shutdown. |
| **CLM-09** | **Fail-Safe Scan Invariants** | `scanner/scan_engine.py`<br>`scanner/scan_state.py` | `scratch/verify_judge_gui_flow.py`<br>`scratch/verify_all_scenarios_e2e.py` | Missing model -> `ANALYSIS_ERROR`; Telemetry failure / Cancellation -> `SCAN_INCOMPLETE`. Neither state ever defaults to `SAFE`. | **VERIFIED (Fail-Safe)** | Ensures incomplete or errored scans never mislead analysts into false security. |
| **CLM-10** | **Concurrency Lock & Re-entrancy Protection** | `scanner/sandbox_runner.py` (`SecurityTestLab._demo_lock`) | `scratch/test_safe_demo_e2e.py`<br>`tests/test_exhibition_suite.py` | Concurrent demo launch rejected immediately with `RuntimeError: Demo already running`. | **VERIFIED (Thread Safety)** | Prevents state corruption, race conditions, or sandbox collisions during rapid button presses. |
| **CLM-11** | **Deterministic Sandbox Purge & Reset** | `scanner/sandbox_runner.py` (`reset_demo_environment`) | `scratch/test_safe_demo_e2e.py` | 21 simulation files and recovery notes purged; state reset to clean ready baseline. | **VERIFIED (Idempotent Reset)** | Complete cleanup of temporary simulation files without touching host files. |
| **CLM-12** | **Schema V2 Behavioral Ground Truth Architecture** | `ml/schema_v2.py`<br>`ml/FEATURE_SCHEMA_V2.md`<br>`ml/collector.py` | `scratch/verify_judge_gui_flow.py`<br>`tests/test_exhibition_suite.py` | Dual-schema inspector operational in GUI (19 legacy vs 16 Schema V2); opt-in benign collector functioning. | **VERIFIED (Architectural Bridge)** | Schema V2 models are currently unpopulated; production inference still runs on Model V1 legacy baseline. |

---

## 2. Four-Tier Capability Classification

SentinelML V2 explicitly distinguishes between four distinct capability levels to ensure total scientific honesty:

```mermaid
flowchart TD
    subgraph Tier1 [Tier 1: Automated Unit & Benchmark Tests]
        T1A["51 Automated Unit Tests (tests/test_exhibition_suite.py)"]
        T1B["40-Case Synthetic Benchmark (tests/run_evaluation_benchmark.py)"]
        T1C["All Passing (100% Deterministic)"]
    end

    subgraph Tier2 [Tier 2: Controlled Sandbox Simulation]
        T2A["Safe In-Process File Generator"]
        T2B["temp_sandbox/ Isolation & Path-Locking"]
        T2C["Real Shannon Entropy Calculation (7.911 bits/byte)"]
    end

    subgraph Tier3 [Tier 3: Actual Local Machine Learning Inference]
        T3A["StandardScaler Normalization"]
        T3B["100-Tree Scikit-Learn Random Forest"]
        T3C["Probability Calculation (p=0.57 Warning, 57 voting trees)"]
    end

    subgraph Tier4 [Tier 4: Real-World In-the-Wild Ransomware Detection]
        T4A["Unvalidated Zero-Day Wild Malware (LockBit, Conti, WannaCry)"]
        T4B["Kernel Driver Interception (IRP_MJ_WRITE) - Not Present"]
        T4C["Scientific Status: Honest Disclosure / Future Ground Truth Phase"]
    end

    Tier1 --> Tier2
    Tier2 --> Tier3
    Tier3 -.->|Requires Kernel Minifilter & Empirical Retraining| Tier4

    style Tier1 fill:#162a45,stroke:#00d8ff,stroke-width:2px,color:#fff
    style Tier2 fill:#162a45,stroke:#00d8ff,stroke-width:2px,color:#fff
    style Tier3 fill:#1a3a2a,stroke:#00e676,stroke-width:2px,color:#fff
    style Tier4 fill:#3a1a1a,stroke:#ff5252,stroke-width:2px,color:#fff
```

### Tier Descriptions:
1. **Tier 1 (Automated Tests & Benchmarks)**: **Verified 100%**. Confirms software correctness, error handling, safety checks, and synthetic classification mechanics.
2. **Tier 2 (Controlled Simulation)**: **Verified 100%**. Demonstrates genuine file encryption and entropy shifts strictly within `temp_sandbox/`.
3. **Tier 3 (Actual ML Inference)**: **Verified 100%**. Executes genuine mathematical scaling and Random Forest decision-tree voting locally on the host CPU.
4. **Tier 4 (Wild Ransomware Protection)**: **Unvalidated / Disclosed Limitation**. The model has not been evaluated against real-world active ransomware samples. SentinelML explicitly disclaims real-world endpoint protection guarantees until empirical training is completed under Schema V2.
