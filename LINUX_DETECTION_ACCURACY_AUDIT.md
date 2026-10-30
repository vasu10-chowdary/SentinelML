# SentinelML — Linux Detection Accuracy: Phase 1 Technical Audit

**Status:** Phase 1 audit complete. Read-only. No source, model, threshold, or build changes were made.

**Date:** 2026-10-30

**Audited tree:** `C:\Users\<user>\Desktop\SentinalMl` (git HEAD `a37046d`; the prior INCONCLUSIVE fix remains uncommitted)

**Target:** native Kali Linux, SentinelML Linux v3.0.0 AppImage

---

## 0. Verdict

1. **The current Linux result is not a scientific ransomware assessment.** The production model is a Windows/Volatility-oriented, synthetically trained 19-feature classifier. On Linux, 4 of its 19 inputs are hard-zeroed, several more are permanently zero, and several high-weight inputs measure something semantically different from what the model was trained on. The resulting probability (0.37 on the observed host) is an out-of-distribution extrapolation, not evidence of safety or threat.
2. **`INCONCLUSIVE` is the correct current Linux state.** The prior fix that preserves `INCONCLUSIVE` instead of reporting a scan failure must remain unchanged.
3. **A separate Linux feature schema and model are justified.** Retraining the same 19 features on Linux would perpetuate invalid or unavailable indicators (`malfind`, registry handles, Defender tampering, mutexes, token privileges). The Windows model, scaler, 19-feature order, and thresholds must remain frozen.
4. **No Linux model can be trained yet.** No empirical Linux dataset exists in the project. The existing Schema V2 pipeline is Windows-specific, currently blocked (`DATASET_UNAVAILABLE`), and its collector has quality-accounting defects that would make Linux coverage look better than it is.
5. **The only defensible Linux training plan is empirical benign telemetry plus safe, controlled ransomware-like simulations.** Real ransomware execution is prohibited. Therefore a Linux model can be validated for the defined simulation distribution, not for in-the-wild ransomware. Accuracy claims must say exactly that.

**Requested review:** approve or revise the proposed Linux Behavioral Schema v1 (LBS-1) in [LINUX_FEATURE_SCHEMA_V1.md](LINUX_FEATURE_SCHEMA_V1.md). No training should begin before that review.

---

## 1. Scope and method

### 1.1 What was inspected

- Model artifacts and metrics:
  - `models/saved_model.pkl`
  - `models/scaler.pkl`
  - `models/metrics.json`
  - `models/v2/training_run_report.json`
- Runtime feature extraction:
  - `scanner/live_scanner.py`
  - `scanner/filesystem_scanner.py`
  - `scanner/scan_engine.py`
  - `ml/predictor.py`
  - `utils/platform_adapter.py`
  - `utils/platform_utils.py`
  - `utils/platform_capabilities.py`
- Schema V2 and data pipeline:
  - `ml/schema_v2.py`
  - `ml/collector_v2.py`
  - `ml/dataset_manager.py`
  - `ml/train_v2.py`
- Evaluation and provenance:
  - `tests/run_evaluation_benchmark.py`
  - `tests/test_platform_compatibility.py`
  - `tests/test_inconclusive_handling.py`
  - `TRAINING_DATA_READINESS.md`
  - `MODEL_PROVENANCE_AND_SCHEMA.md`
  - `FEATURE_SCHEMA_AUDIT.md`
  - `FEATURE_COMPATIBILITY_REPORT.md`
  - `LIVE_TELEMETRY_COMPATIBILITY.md`
  - `BENCHMARK_VALIDITY_AUDIT.md`
  - `INDEPENDENT_EVALUATION_REPORT.md`
  - `ml/FEATURE_SCHEMA_V2.md`
  - `ml/MODEL_V2_REBUILD_PLAN.md`
  - `ml/VALIDATION_LIMITATIONS.md`
  - `data/dataset_audit_log.jsonl`

### 1.2 How Linux telemetry feasibility was tested

A read-only probe was run as an unprivileged user (uid 1000) on **Ubuntu WSL2, kernel 6.18.54.1-microsoft-standard-WSL2, psutil 7.2.2**. This is a Linux kernel reference, **not native Kali**. The probe results describe kernel/procfs semantics; they must be re-verified on the Kali host before training.

The probe created no files, changed no configuration, and read no file contents beyond `/proc` metadata and 2 KB samples of `/proc` files. No monitored user files were modified.

### 1.3 Evidence classes used in this document

- **Verified in this audit:** hashes, code behavior, Linux probe results, current scanner output.
- **Verified by prior project audits:** original dataset generator, training script, model provenance.
- **User-supplied runtime observation:** the native Kali scan result (probability, 4 unavailable sensors, `INCONCLUSIVE`).
- **Inferred:** what the model is likely doing with out-of-distribution inputs. Inferences are labeled as such.

---

## 2. The production ML contract that Linux currently runs

### 2.1 Artifacts

| Artifact | SHA-256 (verified 2026-10-30) | Role |
|---|---|---|
| `models/saved_model.pkl` | `936d9e3ff0b97d762751bdcba34ad3d247a4280e38f84e32dc4f31bfa1174e33` | Random Forest classifier, 19 inputs |
| `models/scaler.pkl` | `d993e26a313f743bbfc351912f2ac4a3be2642f4722c8c5451baf9eda26281cb` | `StandardScaler`, 19 inputs |
| `models/metrics.json` | `8a24b01aa0d5b38ea099f391afb486fa9310fe0ff39ae645c132172170227c88` | Stored synthetic-test metrics and threshold |

The model is `RandomForestClassifier`, 100 trees, 19 input features. Stored metrics: accuracy 0.9567, precision 0.9550, recall 0.9795, F1 0.9671, ROC-AUC 0.9483, CV F1 0.9608. `optimal_threshold` is 0.90.

These metrics are **in-distribution synthetic-data metrics**. They are not Linux metrics and not real-world ransomware metrics.

### 2.2 Feature order

The 19-feature order is duplicated in at least three places:

- `scanner/live_scanner.py:38`
- `ml/predictor.py:62`
- `models/scaler.pkl` (`feature_names_in_`, recovered by the prior forensic audit)

Any Linux schema must not reuse this order.

### 2.3 Prediction path

`MLPredictor.predict()` performs these steps (`ml/predictor.py:158`):

1. Shape check against `(1, 19)`.
2. Finite-value check.
3. `self._scaler.transform(features)` (`ml/predictor.py:176`).
4. `self._model.predict_proba(scaled)` (`ml/predictor.py:180`).
5. Banding at 0.50 / 0.90 (`ml/predictor.py:195`).

There is **no platform guard**. `load_model()` (`ml/predictor.py:92`) loads the same `saved_model.pkl` and `scaler.pkl` on Windows, Linux, and macOS. The Linux application therefore sends Linux telemetry into a model that was never trained for it.

### 2.4 How the 19-vector is assembled on Linux

`LiveScanner.scan_system()` (`scanner/live_scanner.py:370`) appends features in fixed positions. On Linux, unavailable sensors return literal `0.0` values that are passed to the scaler as if they had been measured. There is no `NaN` or masked-value channel in the model input.

The engine records a nominal availability map (`scanner/scan_engine.py:697`):

```python
avail_map = self._process_scanner.get_feature_availability()
result.telemetry_availability = avail_map
missing = [f for f, s in avail_map.items()
           if s.startswith("UNAVAILABLE") or s.startswith("RESTRICTED")]
result.missing_features = missing
result.available_feature_count = len(avail_map) - len(missing)
result.telemetry_coverage_ratio = round(result.available_feature_count / 19, 3)
```

This ratio counts `SUBSTITUTED` and `HEURISTIC_PROXY` features as available. It is a **nominal** ratio, not a semantic coverage measure.

### 2.5 Where `INCONCLUSIVE` is applied

`scanner/scan_engine.py:516` converts a completed scan to `INCONCLUSIVE` only when the ML output is `SAFE`/`LOW`:

```python
elif result.ml_executed and result.threat_level in ["SAFE", "LOW"]:
    if scan_type in (ScanType.QUICK, ScanType.FULL) ... and len(result.missing_features) > 0 ...:
        result.state = ScanState.INCONCLUSIVE
```

Consequence: if the Windows model returns `WARNING` or `CRITICAL` on Linux, the scan can be reported as a live threat even though four inputs were never measured. The current gate protects against false `SAFE`, but not against false `WARNING`/`CRITICAL` from invalid inputs. This is a confidence-design defect to fix in Phase 5, not by lowering thresholds.

---

## 3. The 19-feature audit

### 3.1 What the model was trained on

The prior provenance audit recovered the original pipeline outside this repository:

- Features were designed for **offline Volatility 3 memory-dump analysis**, not live user-space monitoring.
- Training data `sample_data.csv` was generated by `generate_dataset.py` using parameterized Gaussian distributions.
- The production artifacts are byte-identical to that training output.

Therefore the model expects memory-forensics semantics such as VAD injections, unbacked threads, token privileges, Object Manager mutexes, and registry handles. The Linux runtime cannot supply those semantics.

### 3.2 Feature-by-feature matrix

Legend for **Linux reality**:

- **Measured** — a real Linux signal is collected.
- **Measured, different meaning** — a real signal, but not the signal the model was trained on.
- **Partial / restricted** — collected only for some processes or under permissions.
- **Always zero** — the Linux code path cannot produce a non-zero value.
- **Invalid proxy** — the code produces a number, but it is not a valid measurement of the named concept.

| # | Feature | Training intent (Volatility / Windows) | Linux extraction | Declared Linux status | Audit finding |
|:--:|---|---|---|---|---|
| 0 | `total_processes` | Process count in a memory dump | `len(procs)` via psutil (`live_scanner.py:407`) | GENUINE_MEASURED | Measured, but training mean is 86 and host scale differs; distribution shift |
| 1 | `suspicious_process_count` | Processes matching known admin/destruction tools | Linux adapter name set: `vssadmin.exe`, `shred`, `srm`, `wipe`, `dd`, `cryptsetup`, `pwsh`, `powershell` (`platform_adapter.py:342`) | GENUINE_MEASURED | Measured, but list includes legitimate `dd`/`cryptsetup`; process name only, no command line; partial |
| 2 | `avg_entropy` | Mean Shannon entropy of memory/file regions | 4 KB samples of up to 200 files (`live_scanner.py:498`) | GENUINE_MEASURED | Measured; file-based, not memory-based; skips compressed/media extensions; valid Linux signal |
| 3 | `max_entropy` | Peak entropy | Same sampling path | GENUINE_MEASURED | Measured; same caveat |
| 4 | `high_entropy_region_count` | High-entropy memory regions | Count of sampled files with H > 7.0 (`live_scanner.py:555`) | GENUINE_MEASURED | Measured, but counts files, not memory regions; semantic shift |
| 5 | `malfind_injection_count` | VAD `PAGE_EXECUTE_READWRITE` injection | `_count_hollow_procs()`: processes with `exe is None`/empty (`live_scanner.py:574`) | HEURISTIC_PROXY | **Invalid proxy on Linux.** Empty `exe` usually means `/proc/<pid>/exe` was denied or the task is a kernel thread, not injection. Filters remove bracketed kernel tasks and ppid 0/1/2/4, but a same-host service with a normal name and denied `exe` can still be counted. |
| 6 | `crypto_dll_count` | Count of loaded crypto DLLs | `p.memory_maps()` matched against `libcrypto.so`, `libssl.so`, `libgnutls.so`, etc. (`live_scanner.py:628`, `platform_adapter.py:347`) | SUBSTITUTED | **Partial / restricted.** `memory_maps()` is readable only for the current user's processes (probe: 3 of 76). Most system processes are invisible. Any own-user process loading OpenSSL is counted, including benign browsers and Python. |
| 7 | `cmd_vssadmin_count` | Shadow-copy deletion commands | `_count_vssadmin_procs()` checks only `cmd.exe`, `vssadmin.exe`, `bcdedit.exe`, `wbadmin.exe` (`live_scanner.py:643`, `:136`) | SUBSTITUTED | **Always zero on Linux.** The Linux adapter's tool names are not used here. The declared `SUBSTITUTED` status is factually wrong. |
| 8 | `network_connection_count` | Active sockets | `psutil.net_connections(kind="inet")` (`live_scanner.py:654`) | GENUINE_MEASURED | Measured system-wide (probe: 9 connections). May require privileges on hardened kernels. |
| 9 | `unique_external_ips` | Non-private remote endpoints | Remote IPs filtered by IPv4 private ranges + `::1` (`live_scanner.py:153`) | GENUINE_MEASURED | Measured, but IPv6 ULA (`fc00::/7`), link-local (`fe80::/10`), CGNAT (`100.64.0.0/10`), and other reserved ranges are not excluded; local IPv6 peers can be counted as external. |
| 10 | `file_handle_count` | Windows per-process handle sum | `_total_file_handles()` returns `0` on non-Windows (`live_scanner.py:670`) | UNAVAILABLE_PLATFORM | **Always zero.** Linux `num_fds` exists but is a different concept; not used. Zero is fed to the model. |
| 11 | `registry_handle_count` | Open registry key handles | `_registry_handle_heuristic()` returns `0` on non-Windows (`live_scanner.py:681`) | UNAVAILABLE_PLATFORM | **Always zero.** Linux has no registry. Zero is fed to the model. |
| 12 | `orphan_process_count` | Processes whose parent is gone | `_count_orphan_procs()` (`live_scanner.py:699`) | GENUINE_MEASURED | Measured, but Linux reparents orphans to init/systemd, so ppid is usually 1 and excluded by the `{0,1,2,4}` filter; signal is near-zero and semantically weak. |
| 13 | `powershell_process_count` | PowerShell instances | Name match on `powershell.exe`/`pwsh.exe` (`live_scanner.py:712`) | GENUINE_MEASURED | Measured but near-zero on most Linux hosts; not a Linux-native shell indicator. `pwsh` may be installed legitimately. |
| 14 | `unsigned_module_count` | Unsigned loaded modules | `_count_suspicious_path_procs()`: executable path contains `/tmp/`, `/var/tmp/`, `/dev/shm/`, `/downloads/` (`live_scanner.py:723`) | HEURISTIC_PROXY | **Invalid proxy for signatures.** It measures execution path, not Authenticode/Linux signatures. Cross-user `exe` is denied, so it under-counts. |
| 15 | `suspicious_mutex_count` | Named ransomware mutexes | `_count_high_thread_procs(procs, 50)` (`live_scanner.py:448`) | HEURISTIC_PROXY | **Invalid proxy.** Thread count has no relationship to named mutexes; Linux does not expose Windows mutant objects. |
| 16 | `abnormal_privilege_count` | Token privileges (`SeDebugPrivilege`, etc.) | `_count_abnormal_handle_procs()` returns `0` on non-Windows (`live_scanner.py:750`) | UNAVAILABLE_PLATFORM | **Always zero.** Linux capabilities exist and are readable in `/proc/<pid>/status`, but are not measured here. Zero is fed to the model. |
| 17 | `suspicious_thread_count` | Threads starting in unbacked memory | `_count_high_thread_procs(procs, 100)` (`live_scanner.py:450`) | HEURISTIC_PROXY | **Invalid proxy.** It counts processes with >100 threads. This is the model's highest-weight feature (16.49%); legitimate Linux services and browsers routinely exceed 100 threads. |
| 18 | `defender_tampering_count` | Windows Defender service stopped/disabled | `_check_defender_tampering()` delegates to the adapter; Linux returns `0.0` (`platform_adapter.py:439`) | UNAVAILABLE_PLATFORM | **Always zero.** Linux has no Defender. Zero is fed to the model as if "no tampering" was measured. |

### 3.3 Declared Linux availability versus actual behavior

The Linux map in `scanner/live_scanner.py:80` is inconsistent with the code paths:

| Feature | Map says | Code actually does | Consequence |
|---|---|---|---|
| `cmd_vssadmin_count` | SUBSTITUTED | Checks Windows executable names only | Always 0 |
| `crypto_dll_count` | SUBSTITUTED | `memory_maps()` for accessible processes only | Partial, biased to current user |
| `malfind_injection_count` | HEURISTIC_PROXY | Counts unreadable/empty `exe` | Invalid; may count access denial |
| `unsigned_module_count` | HEURISTIC_PROXY | Path fragment match | Not a signature check |
| `suspicious_mutex_count` | HEURISTIC_PROXY | Thread count > 50 | Unrelated concept |
| `abnormal_privilege_count` | UNAVAILABLE_PLATFORM | Returns 0 | Zero fed to model |
| `suspicious_thread_count` | HEURISTIC_PROXY | Thread count > 100 | Unrelated concept |
| `powershell_process_count` | GENUINE_MEASURED | `powershell.exe`/`pwsh.exe` name match | Near-zero on Linux |
| `orphan_process_count` | GENUINE_MEASURED | ppid-not-alive check | Near-zero because of reparenting |
| `network_connection_count` | GENUINE_MEASURED | System-wide `net_connections` | Genuine, permission-dependent |
| `unique_external_ips` | GENUINE_MEASURED | Partial private-range filter | Genuine but IPv6/reserved gaps |

### 3.4 Decision-weight impact

Using the forest's Gini importances recovered by the prior model audit:

| Group | Features | Weight | Meaning |
|---|---|---:|---|
| Unavailable / zero-filled | 10, 11, 16, 18 | **7.60%** | The model reads `0.0` as a measured benign value |
| Semantically invalid or misnamed | 5, 6, 7, 14, 15, 17 | **39.60%** | Measures access denial, path strings, thread counts, or always zero |
| Partial proxies / scale-shifted | 0, 1, 12, 13 | **8.63%** | Measured, but semantics or host scale differ |
| Measured with training-distribution shift | 2, 3, 4, 8, 9 | **44.17%** | Genuine live signals, but trained on memory-forensics distributions |
| **Total** | | **100.00%** | |

No single feature group is both (a) valid on Linux and (b) represented in the training distribution. Even the 44.17% "genuine" group shifts from memory-region entropy to file entropy and from Windows socket semantics to Linux sockets. The model is therefore not doing Linux behavioral inference; it is extrapolating outside its training manifold.

**Caveat:** Gini importance is a global model-level statistic. It is not a per-scan explanation and does not prove how any individual prediction was formed. It is used here only to show how much of the model's learned structure depends on inputs Linux cannot supply.

---

## 4. Live Linux behavior evidence

### 4.1 Unprivileged procfs and sensor probe

**Environment:** Ubuntu WSL2, kernel 6.18.54.1, uid 1000, psutil 7.2.2. **Not native Kali.**

| Telemetry source | Unprivileged result | Interpretation |
|---|---|---|
| `/proc/<pid>/status`, `stat`, `statm`, `cmdline`, `limits` | 76 / 76 readable | Process identity, state, parent, threads, command line, memory sizes are available |
| `/proc/<pid>/exe`, `cwd`, `root`, `environ`, `maps`, `smaps_rollup` | 3 / 76 readable | Only the current user's processes; cross-user is denied |
| `/proc/<pid>/fd` | 4 / 76 readable | Only the current user's processes |
| `/proc/<pid>/io` | 0 / 76 readable | Per-process I/O is not available unprivileged |
| `psutil.net_connections(kind="inet")` | 9 connections | System-wide socket table readable in this environment |
| `inotify_init1` + watch on a directory | Success | Filesystem event monitoring is available unprivileged |
| `/proc/sys/kernel/yama/ptrace_scope` | 1 | Restricted ptrace; cross-user process inspection is blocked |
| `/proc/sys/kernel/unprivileged_bpf_disabled` | 2 | Unprivileged eBPF is disabled |
| `auditctl` / `/etc/audit/auditd.conf` | Absent | No auditd telemetry available in the probe environment |
| AppArmor tooling | Present | LSM exists, but no tamper telemetry is collected today |
| Effective capabilities of the probe shell | Empty (`Current: =`) | No `CAP_SYS_ADMIN`, no `CAP_BPF`, no `CAP_SYS_PTRACE` |

**Implication:** Linux-native detection must be designed around world-readable `/proc` metadata, `inotify`, system-wide socket counters, and filesystem metadata. It cannot assume per-process `exe`, `maps`, `fd`, `io`, or cross-user attribution. Those are optional, permission-gated extensions.

### 4.2 Current 19-feature scanner on Linux

Running the current `LiveScanner` helpers against a 70-process snapshot on the probe host produced:

| Feature helper | Value |
|---|---:|
| `_count_hollow_procs` | 0 |
| `_count_suspicious_procs` | 0 |
| `_count_crypto_dll_procs` | 0 |
| `_count_vssadmin_procs` | 0 |
| `_count_powershell_procs` | 0 |
| `_count_suspicious_path_procs` | 0 |
| `_count_high_thread_procs(…, 50)` | 0 |
| `_count_high_thread_procs(…, 100)` | 0 |
| `_count_orphan_procs` | 2 |
| `_total_file_handles` | 0 |
| `_registry_handle_heuristic` | 0 |
| `_count_abnormal_handle_procs` | 0 |
| `_scan_network` | (9 connections, 1 external IP) |
| `_check_defender_tampering` | 0 |

On this host, nearly every process heuristic is zero. The vector is dominated by `total_processes`, the entropy features, and network counts. A probability produced from that vector is not a Linux behavioral verdict.

The zero values are not harmless. The scaler transforms them and the forest routes them through splits learned on Windows/synthetic data. A zero `defender_tampering_count`, for example, means "Defender was measured healthy" to the model, not "this platform has no Defender."

### 4.3 Native Kali observation

The user-supplied native Kali run is consistent with the audit:

- 19 features extracted
- 15 nominally available, 4 unavailable
- ML probability 0.37
- Raw model prediction `SAFE`
- Final state `INCONCLUSIVE`
- Missing features: `file_handle_count`, `registry_handle_count`, `abnormal_privilege_count`, `defender_tampering_count`

The prior independent Linux verification in this repository also produced probability 0.37, `INCONCLUSIVE`, coverage 0.789, and the same four missing features on WSL Ubuntu. That reproducibility confirms the pipeline behavior; it does not validate the probability.

### 4.4 What the 0.37 probability means

It means: "this 19-dimensional vector, mostly zeroed or out-of-distribution, landed at 0.37 under a forest trained on synthetic Windows memory-forensics data." It does **not** mean 37% ransomware risk, 63% safety, or a calibrated Linux posterior. It must not be presented as a Linux risk score.

---

## 5. Training-data provenance and validity

### 5.1 Production model provenance

The prior forensic audit recovered the original training pipeline:

- Dataset: `sample_data.csv`, 1,500 rows.
- Benign: 500 rows from Gaussian `BENIGN_DISTRIBUTIONS`.
- Ransomware: 1,000 rows, 100 each across WannaCry, Petya, LockBit, REvil, Ryuk, Conti, DarkSide, BlackCat, Hive, BlackMatter.
- Generation: `np.random.normal(...)`, rounded to non-negative integers, with artificial correlations and 5% label noise; 5% adversarial evasion simulation.
- Split: 1,200 train / 300 test, stratified.
- Scaler: `StandardScaler` fit on training data only.
- Model: Random Forest with `GridSearchCV`, 5-fold stratified CV.
- Threshold: `optimal_threshold = 0.90`, selected to target precision 1.0.

The stored 0.9567 accuracy is the synthetic test-set result. It says nothing about Linux or real ransomware.

### 5.2 The 40-profile benchmark

`tests/run_evaluation_benchmark.py` contains 20 hand-authored benign vectors and 20 hand-authored ransomware-like vectors. They are separated by extreme, textbook anomalies. The reported 100% result is a **bimodal synthetic artifact**, as the project's own `BENCHMARK_VALIDITY_AUDIT.md` states.

The test `tests/test_platform_compatibility.py:359` claims "Windows and Linux parity" by zeroing features 10, 11, 16, and 18 on those synthetic vectors and checking that the model still classifies them correctly. That test:

- Does not use Linux telemetry.
- Does not model Linux distributions, process visibility, or filesystem behavior.
- Only proves that the synthetic polar vectors survive zeroing four inputs.

It must not be cited as Linux validation. It should be relabeled or replaced in Phase 7.

### 5.3 Schema V2 status

`models/v2/training_run_report.json`:

- `status`: `TRAINING_BLOCKED`
- `reason`: `DATASET_UNAVAILABLE`
- empirical benign samples: 0
- empirical ransomware samples: 0

Schema V2 is a 16-feature Windows behavioral schema (`ml/schema_v2.py:22`). It is not a Linux schema. Its collector has additional quality-accounting issues that matter if anyone tries to reuse it on Linux:

- On non-Windows, the Defender sensor still increments `sensors_succeeded` while leaving `defender_tampered = 0.0` (`ml/collector_v2.py:225`).
- A failed network probe still increments `sensors_succeeded` (`ml/collector_v2.py:252`).
- When no filesystem target is supplied, nine filesystem sensors are counted as succeeded with baseline defaults (`ml/collector_v2.py:184`).
- `files_renamed_count` uses `st_ctime` as a rename proxy (`ml/collector_v2.py:159`); on Linux `ctime` changes on metadata updates, not only renames.
- The crypto-module sensor only looks for `bcrypt`/`ncrypt` (`ml/collector_v2.py:214`), so it is structurally zero on Linux while still counting as successful.

**Conclusion:** V2 is not a viable Linux foundation as-is. Its feature concepts are useful, but Linux needs its own collector and its own quality contract.

### 5.4 Dataset readiness

- No empirical Linux telemetry dataset exists in the project.
- The legacy synthetic dataset is disqualified by the project's own readiness report.
- Public Windows datasets (EMBER, SOREL-20M, EldeRan, CIC-MalAnal2020) do not match a runtime Linux behavioral schema.
- Real ransomware execution is prohibited by the project rules. That removes the only way to obtain genuine in-the-wild malicious telemetry.
- Therefore the Linux model can be trained on:
  - empirical benign telemetry from real Linux workloads;
  - empirical telemetry from safe, controlled ransomware-like simulations.
- Its evaluation is valid for **that defined distribution**, not for real-world ransomware. The model card and UI must say so.

---

## 6. Suitability of the Windows model for Linux inference

### 6.1 Findings

1. **No platform binding.** The same artifacts load on every OS (`ml/predictor.py:92`).
2. **No semantic feature validation.** The predictor checks shape and finiteness only; it does not know that four inputs are placeholders.
3. **Zero-fill is treated as measurement.** No `NaN`/mask reaches the model.
4. **Coverage is nominal, not semantic.** `SUBSTITUTED` and `HEURISTIC_PROXY` count as available.
5. **Uncertainty protection is one-sided.** Only `SAFE`/`LOW` outputs become `INCONCLUSIVE`; `WARNING`/`CRITICAL` can pass through with invalid inputs.
6. **The highest-weight features are the least valid on Linux.** `suspicious_thread_count` (16.49%) and `malfind_injection_count` (10.38%) measure thread count and access denial, respectively.
7. **Even "valid" features are distribution-shifted.** File entropy is not memory entropy; Linux process counts and socket counts differ from the synthetic training means.

### 6.2 Decision

**The Windows model is not suitable for Linux inference.** It must not be retrained, replaced, or threshold-adjusted as part of the Linux work. The correct architecture is:

- **Windows:** unchanged legacy model, 19 features, 0.50/0.90 thresholds, existing behavior.
- **Linux:** separate schema, collector, scaler, model, versioning, and coverage contract.
- **Shared:** `ScanResult`, dashboard, audit schema, state semantics, and the strict rule that insufficient evidence is never `SAFE`.

Retraining the same 19 features on Linux is rejected because features 5, 7, 10, 11, 15, 16, 17, and 18 have no valid Linux equivalent. A Linux model must be built on Linux-native signals.

---

## 7. Result-confidence audit

### 7.1 What is correct today

- `INCONCLUSIVE` is distinct from `SCAN_INCOMPLETE`, `ANALYSIS_ERROR`, `ERROR`, and `CANCELLED`.
- The prior fix routes completed `INCONCLUSIVE` results to the dashboard instead of the error path.
- The dashboard shows the exact notice, the actual probability, the raw model prediction, the unavailable sensor count, and the unavailable feature names.
- `INCONCLUSIVE` is not counted as a threat and does not raise a threat alert.
- `was_successful()` remains strict (`SAFE` and `THREAT_DETECTED` only).
- Thresholds remain 0.50 / 0.90.

These behaviors must be preserved.

### 7.2 What must change for a Linux model

The final assessment must separate four layers:

1. **Telemetry coverage:** which required sensor groups executed, for the full observation window, with sufficient sample counts.
2. **Model prediction:** the calibrated Linux probability and raw band.
3. **Model confidence:** calibration quality, distance from threshold, and known distribution limits.
4. **Final assessment:** `SAFE`, `WARNING`, `CRITICAL`, `INCONCLUSIVE`, `ANALYSIS_ERROR`.

Proposed rules:

- If any required Linux sensor group fails or coverage is below the approved threshold: **`INCONCLUSIVE`**, regardless of model output. Do not display a Linux risk score as authoritative.
- If the Linux model artifacts are missing, corrupt, wrong schema, wrong feature order, or wrong platform: **`ANALYSIS_ERROR`**.
- If the model runs and coverage is sufficient: map the calibrated probability to `SAFE`/`WARNING`/`CRITICAL` using approved thresholds.
- A probability near a threshold is shown as such; it is not promoted to a confident verdict.
- No threshold is lowered to reduce `INCONCLUSIVE`.
- No zero-fill is used for required Linux features.

### 7.3 Threshold policy

- Windows thresholds stay 0.50 / 0.90.
- Linux thresholds will be calibrated on the validation split only, with the test split held out.
- The calibration target should prioritize a low false-positive rate on hard benign workloads (archives, backups, builds, legitimate encryption), consistent with the project's existing V2 precision target.
- If the target cannot be met, report the achieved precision/recall and keep the conservative threshold. Do not move the threshold to manufacture a better-looking result.

---

## 8. Test coverage gaps

The existing suites are strong on state invariants but weak on Linux detection science.

| Area | Current coverage | Gap |
|---|---|---|
| Linux feature availability | `test_platform_compatibility.py:332` checks ≥4 missing features | Does not validate actual Linux values or semantic meaning |
| Windows/Linux parity | Synthetic vectors with four zeroed features (`:359`) | Not Linux telemetry; gives false confidence |
| INCONCLUSIVE routing | `test_inconclusive_handling.py` | Good; preserve |
| Model loading failure | Covered | Good; preserve |
| Cancellation / access denial | Covered | Good; preserve |
| Linux inotify collection | None | Must add |
| `/proc` permission handling | None | Must add |
| Cross-user process visibility | None | Must add |
| Coverage gating for WARNING/CRITICAL | None | Must add |
| Model/platform schema guard | None | Must add |
| Benign hard-case false positives | None | Must add |
| Dataset leakage / group split | None for Linux | Must add |
| Simulation-to-real gap | Documented only | Must keep explicit in model card |

---

## 9. Risks and constraints

### 9.1 Permission and visibility

- Cross-user `/proc/<pid>/exe`, `maps`, `fd`, `environ`, and `io` are denied unprivileged.
- `auditd`, eBPF, and fanotify require root or capabilities and cannot be assumed.
- AppArmor/SELinux may restrict access further.
- Hardened kernels may restrict `net_connections`.
- `hidepid` mount options can hide other users' `/proc` entries.

### 9.2 Collection risks

- `inotify` watch limits (`max_user_watches`) can be exhausted on large home directories.
- Recursive watches on entire home trees add overhead; noise directories must be pruned.
- File entropy sampling reads file bytes; only 4 KB per file is read and no content is stored, but this must remain explicit and opt-in for telemetry collection.
- Command lines can contain secrets; raw command lines must never be persisted in telemetry. Only local pattern matches and counts should be stored.
- Process polling can miss very short-lived processes; the observation window and poll interval must be documented.

### 9.3 Detection risks

- **False positives:** archives, backups, builds, package updates, photo/video import, legitimate bulk rename, legitimate encryption (`openssl`, `gpg`, `age`, `cryptsetup`, VeraCrypt).
- **False negatives:** intermittent encryption, fileless/LotL attacks, encrypted files with preserved headers, attacks that avoid monitored roots, kernel-level attacks, attacks that disable the scanner.
- **Simulation gap:** safe simulations cannot reproduce the full behavior, evasion, or speed of real ransomware. A model trained on them may learn simulator artifacts.
- **Host variability:** kernel version, filesystem, desktop environment, containerization, and workload mix change feature distributions.
- **Concept drift:** benign software behavior changes over time; periodic revalidation is required.

### 9.4 Non-claims

This audit and the proposed schema do **not** claim:

- that the current 0.37 Linux probability is a calibrated risk;
- that the Windows model detects Linux ransomware;
- that a simulation-trained model detects real ransomware;
- that Linux has a registry or Microsoft Defender equivalent;
- that unprivileged user-space telemetry can replace kernel-level EDR;
- that any accuracy number can be reported without a named dataset, split, and held-out test.

---

## 10. Phase 1 conclusion and requested review

### 10.1 Conclusion

The current Linux pipeline is honest about its uncertainty but not scientifically valid as a detector. The correct next step is a separate Linux-native behavioral schema, a separate collector, a separate model, and a separate coverage contract. The Windows model and 19-feature contract must remain untouched.

### 10.2 Requested decisions

Please review and approve or revise:

1. **Linux Behavioral Schema v1 (LBS-1)** as proposed in [LINUX_FEATURE_SCHEMA_V1.md](LINUX_FEATURE_SCHEMA_V1.md).
2. **Malicious-class definition:** empirical benign telemetry plus safe controlled ransomware-like simulations; no real ransomware; explicit non-real-world claim.
3. **Observation window:** proposed default 15 seconds (minimum 10, maximum 60), added to Linux scan duration.
4. **Artifact layout:** separate `models/linux_v1/` directory; Windows artifacts untouched.
5. **Threshold policy:** calibrate on validation only; keep conservative; never lower to reduce `INCONCLUSIVE`.
6. **Privileged extensions:** auditd/eBPF/fanotify remain out of scope for v1 and are documented as future permission-gated work.

No training, code changes, or rebuilds should occur until these decisions are recorded.

---

## Appendix A — Probe environment and results

**Host:** Ubuntu WSL2, kernel `6.18.54.1-microsoft-standard-WSL2`, x86_64, glibc 2.43.
**User:** uid 1000 (unprivileged).
**Python:** 3.14.x in `$HOME/sentinel_venv_v3`.
**psutil:** 7.2.2.

Key results:

- 76 PIDs visible.
- `status`, `stat`, `statm`, `cmdline`, `limits`: 76/76 readable.
- `exe`, `cwd`, `root`, `environ`, `maps`, `smaps_rollup`: 3/76 readable.
- `fd`: 4/76 readable.
- `io`: 0/76 readable.
- `psutil.net_connections(kind="inet")`: 9 connections.
- `inotify_init1` and `inotify_add_watch`: success.
- `yama/ptrace_scope`: 1.
- `unprivileged_bpf_disabled`: 2.
- `auditctl`: absent.
- `aa-status`: present.
- Effective capabilities: empty.

**Caveat:** WSL2 is not native Kali. Re-run the same probes on the Kali target before training. Results may differ for a full desktop session with more same-user processes; cross-user restrictions are expected to remain.

---

## Appendix B — Verified artifact hashes (2026-10-30)

| Artifact | SHA-256 |
|---|---|
| `models/saved_model.pkl` | `936d9e3ff0b97d762751bdcba34ad3d247a4280e38f84e32dc4f31bfa1174e33` |
| `models/scaler.pkl` | `d993e26a313f743bbfc351912f2ac4a3be2642f4722c8c5451baf9eda26281cb` |
| `models/metrics.json` | `8a24b01aa0d5b38ea099f391afb486fa9310fe0ff39ae645c132172170227c88` |
| `dist_linux_inconclusive_fix/SentinelML-x86_64.AppImage` | `34211937385a20468ea0e88506fc15912df73dd77e1def15668c62e68fc9a536` |
| `dist_linux/SentinelML-x86_64.AppImage` (prior) | `24b5a5cb3cfd3503d4609afc11f0107fba78b55b437fe5552937c3dbf98fd5e8` |
| `SentinelML-x86_64.AppImage` (October 10) | `51ab9c8731c3ec313998817da89b20233cd22fd5f6bd71d9e7be05696a9f7eed` |

The Windows installer was not re-hashed in this audit and was not modified.

---

## Appendix C — Files inspected

- `scanner/live_scanner.py`
- `scanner/filesystem_scanner.py`
- `scanner/scan_engine.py`
- `ml/predictor.py`
- `ml/schema_v2.py`
- `ml/collector_v2.py`
- `ml/dataset_manager.py`
- `ml/train_v2.py`
- `utils/platform_adapter.py`
- `utils/platform_utils.py`
- `utils/platform_capabilities.py`
- `tests/run_evaluation_benchmark.py`
- `tests/test_platform_compatibility.py`
- `tests/test_inconclusive_handling.py`
- `models/metrics.json`
- `models/v2/training_run_report.json`
- `data/dataset_audit_log.jsonl`
- `TRAINING_DATA_READINESS.md`
- `MODEL_PROVENANCE_AND_SCHEMA.md`
- `FEATURE_SCHEMA_AUDIT.md`
- `FEATURE_COMPATIBILITY_REPORT.md`
- `LIVE_TELEMETRY_COMPATIBILITY.md`
- `BENCHMARK_VALIDITY_AUDIT.md`
- `INDEPENDENT_EVALUATION_REPORT.md`
- `ml/FEATURE_SCHEMA_V2.md`
- `ml/MODEL_V2_REBUILD_PLAN.md`
- `ml/VALIDATION_LIMITATIONS.md`
- `dist_linux_inconclusive_fix/LINUX_INCONCLUSIVE_FIX_REPORT.md`
