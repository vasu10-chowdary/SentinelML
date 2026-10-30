# SentinelML — LBS-1 Implementation Plan

**Status:** PLAN — G1 APPROVED 2026-10-30; Stage A and Stage B implementation authorized.
**Revision:** 2 (2026-10-30) — resolves the G1 / native-Ubuntu approval-sequence conflict. No
feature, threshold, label, or gate G2–G5 change. Revision 1 backed up to
`backups/lbs1_plan_20261030_164244/`.
**Decision record:** `LINUX_LBS1_APPROVED_DECISIONS.md`
**Schema:** `LINUX_FEATURE_SCHEMA_V1.md` (approved, 20 features; definedness clarification
2026-10-30, §3.1)
**Repository HEAD:** `a37046d` · **Baseline:** 483 tests collected; Windows 475 passed / 8
environmental skips; Linux 483 passed.

This plan is ordered so that no model is trained and no Linux verdict reaches the UI until the
dataset and evaluation gates are separately approved. Every stage lists exact files, tests,
acceptance criteria, and rollback. Stages A–D are additive: they touch no existing production
file. Existing files change only in Stage E, after gate G3.

---

## 1. Gate sequence

```
G0  decision record + plan                          ← complete
G1  plan approved (2026-10-30)                      → Stage A + B implementation and
                                                       unit/fixture testing only
                                                       (Windows, WSL dev-only, native Kali)
C0  Stage C entry approval (separate; after A/B)    → provision native Ubuntu VM;
                                                       complete Stage A native-Ubuntu acceptance
                                                       and Stage B native-Ubuntu rerun;
                                                       then collect data
G2  dataset ready + approved                        → Stage D : training and held-out evaluation
G3  held-out evaluation approved                    → Stage E : Linux verdict integration
G4  integration + native regression approved        → Stage F : build/deliver AppImage
G5  independent CRITICAL validation approved        → enable CRITICAL (separate change)
```

Sequence rules:

1. **G1 authorizes Stage A and Stage B implementation and unit/fixture testing only.** It does
   not authorize VM provisioning, workload data collection, model training, verdict integration,
   AppImage building, or any modification of Windows files or artifacts.
2. **C0 is the separate Stage C entry approval.** It is not a member of the G-series, is not a
   substitute for G2, and may not be combined with G2 in a single approval. It authorizes: (a)
   provisioning the native Ubuntu LTS VM, (b) the native-Ubuntu rows of Stage A acceptance and
   the native-Ubuntu rerun of Stage B, and (c) data collection under the Stage C guard rails.
3. **Stage A is not fully accepted at G1.** At G1 it can reach at most
   `STAGE_A_PARTIAL_KALI_WSL` (§2.1). `STAGE_A_ACCEPTED` requires the native-Ubuntu evidence,
   which only exists after C0. Stage C data collection may not begin until `STAGE_A_ACCEPTED`.
4. Existing Kali and WSL environments may be used at G1 only within their documented
   limitations: Kali yields real native evidence for its rows; WSL yields `DEV_ONLY_WSL`
   development signal and is never counted as native validation.
5. Hard stops: a failed gate is reported, not bypassed. No threshold, family, or label changes
   are made in response to a failed gate.

### 1.1 Authorization boundaries at G1

| Action | At G1 |
|---|---|
| Create Stage A/B new files and run their unit/fixture tests | authorized |
| Unit/fixture tests on Windows host, WSL2 (dev-only), native Kali VM | authorized |
| Fixture-scoped observation over a disposable pytest temp directory | authorized (see §2.1) |
| Collect telemetry from real workloads, or retain any session corpus / manifest / JSONL | **not authorized** |
| Provision, download, or install the Ubuntu VM | **not authorized** (pending C0) |
| Run native-Ubuntu Stage A/B acceptance | **not authorized** (pending C0) |
| Execute `linux_train.py` / produce any model artifact | **not authorized** (pending G2) |
| Edit any existing production file (verdict integration) | **not authorized** (pending G3) |
| Build or deliver an AppImage | **not authorized** (pending G4) |
| Modify Windows model, scaler, metrics, thresholds, predictor or live scanner | **prohibited at every gate** |
| Commit, push, upload, or publish | **not without an explicit request** |

---

## 2. Stage A — Linux telemetry collector (original Phase 2)

**Objective:** produce a complete 20-feature `LinuxObservation` with honest sensor-health
accounting, using only unprivileged data. No model, no scan-engine integration.

### New files

| File | Responsibility |
|---|---|
| `scanner/linux_fs_types.py` | Parse `/proc/self/mountinfo`; classify ext4/xfs/btrfs/tmpfs/overlay as supported, `9p`/`drvfs`/`fuse`/`nfs`/`cifs`/`sshfs` as unsupported for LBS-1 |
| `scanner/linux_inotify.py` | ctypes libc inotify wrapper: recursive add, watch budget, raw event parsing, cookie pairing, `IN_Q_OVERFLOW` detection. No third-party dependency |
| `scanner/linux_entropy.py` | 4 KB Shannon entropy; event-touched sampling for features 6/7; fixed baseline cohort for feature 8 re-sampled **in full** at window end; status assignment for empty populations |
| `scanner/linux_processes.py` | Snapshot diff, create/exit/short-lived accounting, destructive-rule matcher, shell ancestry, temp-exec resolution, `/proc/<pid>/status` privilege parsing, network breadth |
| `scanner/linux_telemetry.py` | Orchestrator: 15 s window, feature assembly in schema order, sensor-group health, cancellation, `LinuxObservation` dataclass |
| `tools/lbs1/benchmark_collector.py` | Measures CPU, RSS, scan latency, overflow count; executed on native Kali at G1 and native Ubuntu at C0 |

`LinuxObservation` fields: `features: Optional[np.ndarray]` (non-None **only** when
`observation_state == MODEL_READY`), `feature_values: Dict[str, Optional[float]]` (never a
numeric sentinel; `None` for undefined), `feature_status: Dict[str, str]`, `observation_state`
(`MODEL_READY` / `INSUFFICIENT_ACTIVITY` / `DEGRADED`), `sensor_groups`, `reasons`,
`window_seconds`, `overflow`, `filesystem_types`, `events_processed`, `platform`,
`collector_version`.

### 2.1 Execution environments and acceptance ledger

Two distinct concepts, deliberately separated:

- **Implementation/testing at G1** — code is written and exercised. Evidence is real where the
  environment is native (Kali), development-only where it is WSL, and platform-independent where
  it is Windows.
- **Stage A acceptance** — a single status that requires *all* rows below, including the native
  Ubuntu rows that cannot exist until C0.

| Evidence | Windows host | WSL2 Ubuntu | Native Kali VM | Native Ubuntu VM |
|---|---|---|---|---|
| fs_types / inotify-parser / entropy / processes / sensor_health unit tests | required (Linux-only skip) | required, `DEV_ONLY_WSL` | required | **pending C0** |
| Applicability invariant (`MODEL_READY` ⇔ 20 finite values) | required | required, `DEV_ONLY_WSL` | required | **pending C0** |
| Real inotify counts on disposable ext4 temp tree | — | dev signal only | required | **pending C0** |
| 15 s observation over a disposable fixture directory | — | dev signal only | required | **pending C0** |
| Sensor-health transitions (OK / NOT_APPLICABLE / DEGRADED) on real sensors | — | dev signal only | required | **pending C0** |
| Overhead measurement (CPU / RSS / entropy I/O) | — | indicative only | required | **pending C0** |
| Windows import side-effect / collector-refusal tests | required | — | — | — |

**Fixture scope (applies at G1 and C0).** The real-inotify and 15 s observation runs operate only
on a disposable directory created by the test process (`tmp_path`), never on a user home
directory, never on a mounted real workload, and never on a real corpus. Nothing is persisted
outside the pytest temp directory: no `manifest.json`, no `observations.jsonl`, no session
identifier, no retained feature record. Fixture-scoped execution is testing, not data collection.
Any run that would persist a record or observe non-test files is Stage C and is not authorized at
G1.

**Status tokens:**

| Token | Meaning | Satisfies Stage A acceptance? |
|---|---|---|
| `STAGE_A_IN_PROGRESS` | Code exists; one or more G1 rows failing | No |
| `STAGE_A_PARTIAL_KALI_WSL` | All G1-available rows pass (Windows, WSL dev-only, native Kali); Ubuntu rows not executed | **No** — interim evidence only |
| `STAGE_A_ACCEPTED` | Every row above passes, including native Kali and native Ubuntu, independently | Yes |

`STAGE_A_PARTIAL_KALI_WSL` is the maximum state reachable at G1. It must never be reported,
summarized, or relied upon as "Stage A accepted", and it is not a valid precondition for Stage C
collection.

### New tests

| File | Covers |
|---|---|
| `tests/test_lbs1_fs_types.py` | mountinfo parsing, supported/unsupported classification, bind mounts |
| `tests/test_lbs1_inotify.py` | synthetic buffer parsing; write/rename/delete counts; cookie pairing; unpaired move → delete; duplicate `IN_MODIFY` dedupe; overflow invalidates window; watch-budget shortfall; real temp-dir events |
| `tests/test_lbs1_entropy.py` | known-content entropy (zeros vs random); 4 KB head-only sampling; zero-size exclusion; sample cap; **fixed-cohort ΔH** (unchanged cohort → `0.0`; all changed; in-place same-size change); cohort read-failure budget (≤10% excluded, >10% → `UNAVAILABLE_PERMISSION`); unreadable-file accounting; cohort absent → `NOT_APPLICABLE_NO_BASELINE_COHORT`; cohort deleted/moved out → `NOT_APPLICABLE_COHORT_UNAVAILABLE` |
| `tests/test_lbs1_processes.py` | injected snapshot fixtures for deterministic counts; real short-lived/long-lived child processes; shell ancestry; destructive-rule matching incl. `rm` flag logic; temp-exec paths; network classification via `ipaddress`; **created=0 → ratio `None` + `NOT_APPLICABLE_NO_PROCESS_ACTIVITY`; created>0, zero exits → `0.0`** |
| `tests/test_lbs1_sensor_health.py` | each group OK/DEGRADED/NOT_APPLICABLE transition; no-write and all-zero-file G2 N/A; zero-PID G5/G6 N/A (no zero-denominator rate); cohort permission denial beyond budget → G2 DEGRADED; unreadable dir; G7 network failure/restricted → DEGRADED; resolution-rate threshold; `features is None` unless `MODEL_READY` (all seven groups `OK` and all 20 features `DEFINED`); no-activity vs unavailable reason codes distinct |
| `tests/test_lbs1_applicability.py` | enumerated activity matrix; `MODEL_READY` ⇒ exactly 20 `float64` finite non-negative values in schema order; every `NOT_APPLICABLE_*`/`UNAVAILABLE_*` ⇒ `features is None`; no sentinel numbers; no numeric value written for undefined features; **zero-event count/rate features remain `DEFINED` at `0.0`; only features 6/7/8/13 can receive a `NOT_APPLICABLE_*` status** |
| `tests/test_lbs1_privacy.py` | no file content, raw cmdline, username, or absolute home path persisted; entropy reads transient |
| `tests/test_lbs1_windows_import.py` | importing every `scanner/linux_*` module on Windows is side-effect free; collector refuses to run |

### Acceptance criteria

1. **Interim acceptance at G1:** all new tests pass on the Windows host (Linux-only tests skip),
   on WSL2 (`DEV_ONLY_WSL`), and on the **native Kali VM**, including real inotify on a
   disposable ext4 temp tree and a 15 s fixture-scoped observation. The native **Ubuntu** rows
   are explicitly **blocked pending C0** and are not claimed.
2. **Full acceptance at C0:** the identical tests pass independently on the **native Ubuntu VM**.
   Only when both native rows pass does the stage report `STAGE_A_ACCEPTED`; until then the
   status is `STAGE_A_PARTIAL_KALI_WSL`. WSL results are never substituted for either native row.
3. Real inotify counts on the temp ext4 tree match expected ±0 for create/write/delete and ±0 for
   rename pairing; overflow path exercised by parser fixture (a real overflow is destructive to
   trigger and is not forced).
4. A 15 s observation on a native machine yields exactly 20 finite values **only** when
   `observation_state == MODEL_READY`; a no-activity window yields `INSUFFICIENT_ACTIVITY` with
   `features=None` and explicit `NOT_APPLICABLE_*` statuses; a sensor failure yields `DEGRADED`
   with `features=None`. No value is ever defaulted to 0 or any sentinel. Required on Kali at G1
   and Ubuntu at C0.
5. `tests/test_lbs1_applicability.py` proves the exhaustive invariant over an enumerated matrix:
   `MODEL_READY` ⇔ (vector shape `(20,)`, `float64`, all finite, all `>= 0`, schema order);
   every other state ⇔ `features is None`; undefined features have `None` values and a
   non-`DEFINED` status, never a number. Zero-event count/rate features are `DEFINED` at `0.0`;
   only features 6/7/8/13 can be `NOT_APPLICABLE_*`.
6. No-activity reason codes (`NOT_APPLICABLE_NO_FILE_ACTIVITY`,
   `NOT_APPLICABLE_NO_SAMPLEABLE_FILES`, `NOT_APPLICABLE_NO_BASELINE_COHORT`,
   `NOT_APPLICABLE_COHORT_UNAVAILABLE`, `NOT_APPLICABLE_NO_PROCESS_ACTIVITY`) are asserted
   distinct from `UNAVAILABLE_PERMISSION` / `UNAVAILABLE_SENSOR`.
7. Windows suite: 483 collected, 475 passed / 8 skipped, unchanged. New Linux tests skip.
8. Frozen-file hashes in the decision record §6 unchanged.
9. Overhead within budget on **native Kali at G1** and **native Ubuntu at C0**: CPU < 3% of one
   core, RSS < 100 MB, entropy I/O ≤ 4 MB/window. Both are required for full acceptance. Actuals
   reported; misses disclosed, not adjusted away.
10. **Fixture-only evidence:** at G1 no real workload is observed and no dataset, manifest,
    JSONL, session ID, or retained feature record is produced. Violating this converts the run
    into unauthorized Stage C collection and is a stop condition, not a test failure to work
    around.
11. `STAGE_A_ACCEPTED` is reported as a single explicit token, never inferred from "tests are
    green". No downstream stage may treat `STAGE_A_PARTIAL_KALI_WSL` as accepted.

### Rollback

Delete all new files (listed in `backups/lbs1_stageA_<ts>/NEW_FILES.txt`); no existing file was
touched. Re-run the Windows suite and hash check.

---

## 3. Stage B — schema, guarded predictor, dataset/training tooling (Phase 3)

**Objective:** freeze the schema contract, make artifact/schema failures fail closed, and build
the dataset/gate machinery. Still **no training**.

### New files

| File | Responsibility |
|---|---|
| `ml/linux_schema.py` | `LBS1_FEATURE_NAMES` (20, ordered), units, status enum, `validate_observation()` (**`MODEL_READY` ⇔ all seven sensor groups `OK` and all 20 features `DEFINED`**, plus the vector contract), dtype/finite/non-negative validation, `schema_hash()`, `LINUX_SCHEMA_ID="LBS-1"`, `PLATFORM_TAG="linux"`, `LBS1_CRITICAL_ENABLED=False` |
| `ml/linux_predictor.py` | Guarded artifact load: schema hash, platform tag, feature count/order, model/calibrator/scaler hashes, finite input, **observation_state == MODEL_READY and every feature DEFINED**. Typed errors: `ArtifactError`, `SchemaMismatchError`, `InputValidationError`, `NotApplicableError`. Maps `p` to verdict with critical cap |
| `ml/linux_dataset.py` | Session discovery, manifest validation (`source_type`, family, distro, seed, sensor status, observation state), dedupe, **MODEL_READY-only model inputs**, grouped 70/15/15 split, split lock, coverage statistics, dataset-card data |
| `ml/linux_train.py` | Requires `models/linux_v1/APPROVED_FOR_TRAINING`; trains candidates, calibrates on validation, freezes threshold, writes only `models/linux_v1/`; refuses non-model-ready rows |
| `ml/linux_evaluate.py` | One-shot test evaluation; confusion matrices; per-family; session- and window-level metrics; clustered bootstrap CIs; Brier/ECE; latency; **model-ready coverage and non-evaluable sessions** |
| `tools/lbs1/verify_artifacts.py` | Independent hash/manifest verification for CI and delivery |

`APPROVED_FOR_TRAINING` is a JSON marker containing approval ID, date, dataset SHA-256, and
artifact directory. Absence blocks training with a typed error.

### New tests

All Stage B tests operate on **synthetic fixtures only** at G1. No real dataset, session, or
collected window is read; `ml/linux_dataset.py` and `ml/linux_train.py` are exercised against
fabricated manifests and fabricated `LinuxObservation` objects.

| File | Covers |
|---|---|
| `tests/test_lbs1_schema_contract.py` | exact name order; hash stability; reject 19/21 features, reorder, non-finite, wrong dtype; `MODEL_READY` ⇔ contract; undefined status cannot be coerced to a number |
| `tests/test_lbs1_predictor_guards.py` | missing/corrupt artifact, wrong platform tag, schema mismatch, wrong count, NaN/Inf, tampered scaler hash → typed error → `ANALYSIS_ERROR`; `INSUFFICIENT_ACTIVITY`/`DEGRADED` → `NotApplicableError`/`INCONCLUSIVE`, predictor not called; **critical cap at p=0.99 → WARNING** |
| `tests/test_lbs1_dataset_split.py` | no session crosses splits; family stratification; dedupe; reject `HAND_AUTHORED_VECTOR`; require hard-benign count; split lock prevents re-split; **non-model-ready rows excluded from model inputs and counted as coverage** |
| `tests/test_lbs1_training_gate.py` | trainer refuses without marker; refuses below volume thresholds; refuses to write outside `models/linux_v1/` |
| `tests/test_lbs1_windows_isolation.py` | SHA-256 of all frozen files; `ml/predictor.py` never imports Linux modules; Windows benchmark output unchanged; Windows scan path untouched |

### Acceptance criteria

1. **At G1:** all guard tests pass on the Windows host, on WSL2 (`DEV_ONLY_WSL`), and on the
   **native Kali VM**. **At C0:** the same suite is re-run on the **native Ubuntu VM**. Full Stage
   B acceptance requires the Ubuntu rerun; at G1 the token is `STAGE_B_ACCEPTED_PENDING_UBUNTU`.
2. Frozen hashes unchanged; Windows suite unchanged.
3. Trainer performs **no training** during this stage; a dry-run reports
   `TRAINING_BLOCKED: NO_APPROVAL_MARKER`. A dataset with any non-model-ready row cannot enter
   fitting; the trainer reports the excluded count.
4. `schema.json` hash, feature order, units, and the status vocabulary match the approved
   schema exactly.
5. Predictor rejects any observation that is not `MODEL_READY`, even if a 20-float array happens
   to be supplied; no mechanism can bypass the definedness guard.
6. No model artifact, marker, dataset, manifest, or JSONL is produced or retained at G1. Test
   markers use a test-only path and are deleted before the stage is reported.
7. Stage B is not reported as accepted on Windows-plus-Kali evidence alone; the native Ubuntu
   rerun is a recorded C0 item.

### Rollback

Delete new `ml/linux_*` files and `tools/lbs1/verify_artifacts.py`; no existing file changed.
If a marker was created during tests, delete it (test-only path).

---

## 4. Stage C — data collection and dataset gate (Phase 4a)

**Objective:** collect empirical benign and safe simulated sessions on native Kali and Ubuntu,
build a leakage-free dataset, and stop at gate G2.

### Entry condition (C0) — mandatory, checked before any collection

Stage C does not begin on the strength of G1. It begins only after the separate C0 approval, and
in this order:

1. **Report** Stage A and Stage B results to the approver, including the explicit status token
   (`STAGE_A_PARTIAL_KALI_WSL`, `STAGE_B_ACCEPTED_PENDING_UBUNTU`) and the exact Ubuntu rows that
   were not executed.
2. **Obtain C0 approval.** No VM download, install, or snapshot occurs before this.
3. **Provision the native Ubuntu LTS VM** from an official ISO; snapshot it; record distro,
   kernel, and filesystem versions.
4. **Complete Stage A native-Ubuntu acceptance** (all §2.1 Ubuntu rows) and the **Stage B
   native-Ubuntu rerun**, on that VM. Stage A must reach `STAGE_A_ACCEPTED`.
5. **Snapshot the native Kali VM** and confirm the G1 native-Kali evidence is still reproducible
   at the recorded kernel/filesystem versions.
6. Only then create the Stage C tooling sandbox and begin collection.

If step 4 fails, the failure is reported and Stage C collection does not start. The response is a
corrected implementation, not a relaxed acceptance row, not a WSL substitute, and not a
reclassification of the row as optional.

### New files

| File | Responsibility |
|---|---|
| `tools/lbs1/simulation_guard.py` | Canonical path check: must be inside a `sandbox` root created by the tool; refuses `/`, home, `/etc`, `/usr`, `/var`, `/boot`, symlink escapes, `..`, and any target outside the sandbox; refuses real-malware indicators |
| `tools/lbs1/run_simulation.py` | Six+ safe families with intensity levels; operates only on generated dummy files; records per-window provenance |
| `tools/lbs1/collect_benign.py` | Session runner with workload tag; runs collector; writes manifest + JSONL; never stores content/cmdline |
| `tools/lbs1/build_dataset.py` | Validates manifests, dedupes, creates grouped splits, writes dataset card and SHA-256 |
| `tests/test_lbs1_simulation_guard.py` | 100% refusal matrix (absolute/relative/symlink/root/home/system paths); accepts only sandbox; refuses unknown family; no destructive command outside sandbox |
| `tests/test_lbs1_dataset_volume.py` | Volume/family/hard-benign gates; both-distro representation; no session overlap; MODEL_READY coverage fields present |
| `LINUX_LBS1_DATASET_CARD.md` | Generated after collection: counts, families, distros, window lengths, sensor health, `MODEL_READY` / `INSUFFICIENT_ACTIVITY` / `DEGRADED` coverage per family and per distro, exclusions, privacy statement, simulation-only limitation |

### Data layout (not committed)

```
data/linux_lbs1/
  benign/<session_id>/manifest.json + observations.jsonl
  simulated/<run_id>/manifest.json + observations.jsonl
  dataset/<dataset_hash>/train|val|test.jsonl + split_manifest.json
```

Add `data/linux_lbs1/` to `.gitignore` (this is the only existing file touched in Stage C;
backup first).

### Volume gates (must all hold before G2)

- ≥30 benign sessions, ≥10 families, ≥2,000 **`MODEL_READY`** windows.
- ≥8 hard-benign sessions **per distro** (GPG, OpenSSL, encrypted archive, backup, build,
  package management, media processing, media encode).
- ≥60 simulation runs, ≥6 families, ≥2,000 **`MODEL_READY`** windows, intensity ladder including
  intermittent.
- Both native Kali and native Ubuntu represented in train and test; WSL data excluded from
  train/test (may exist only as `dev_only/` and is never counted).
- Zero session overlap across splits; dedupe complete; test split locked.
- Privacy scan: no content, raw command lines, usernames, or absolute home paths.
- Sensor-health statistics per family; windows with degraded groups excluded from model training
  and counted separately.
- **Coverage accounting:** every collected window is labelled `MODEL_READY`,
  `INSUFFICIENT_ACTIVITY`, or `DEGRADED`. The dataset card reports counts and percentages for
  each state overall, per family, and per distro. Non-`MODEL_READY` windows are retained as
  coverage evidence but never enter model inputs. The window volume gates above count only
  `MODEL_READY` windows; a dataset cannot pass G2 by inflating its total with non-model-ready
  windows.

### Acceptance criteria

1. Simulation guard refusal matrix 100% pass on native Linux.
2. Volume gates pass; dataset card generated and reviewed, including `MODEL_READY` coverage per
   family and distro and the count of `INSUFFICIENT_ACTIVITY` / `DEGRADED` windows.
3. Split integrity and privacy checks pass; no non-`MODEL_READY` window appears in any split file
   used for fitting or evaluation.
4. No model artifact exists; no training executed.
5. Collection started only after C0 and only with `STAGE_A_ACCEPTED` recorded; the dataset card
   cites the acceptance token and the native Ubuntu VM/kernel versions used.
6. **Gate G2:** approver signs off on the dataset card. Training remains blocked until then.

### Rollback

Data is disposable and path-guarded. Delete `data/linux_lbs1/`; delete the five new tool/test
files; restore `.gitignore` from backup. No production file changed. VM snapshots are reverted,
not deleted, so the Ubuntu environment stays available for a corrected collection.

---

## 5. Stage D — training and held-out evaluation (Phase 4b)

**Objective:** train only after G2, calibrate on validation, open the test set once, and produce
an honest evaluation report. Stop at gate G3.

### New files / outputs

| Path | Content |
|---|---|
| `models/linux_v1/model.pkl` | Chosen classifier |
| `models/linux_v1/calibrator.pkl` | Probability calibration |
| `models/linux_v1/scaler.pkl` | Fit on Linux train only |
| `models/linux_v1/schema.json` | Names, units, window, list version, schema hash |
| `models/linux_v1/manifest.json` | Artifact hashes, dataset hash, env, training date, approval ID, `simulation_only=true` |
| `models/linux_v1/metrics.json` | Full metrics, per-family tables, CIs |
| `LINUX_LBS1_EVALUATION_REPORT.md` | Limitations first; confusion matrices; calibration; latency; failures; **model-ready coverage and non-evaluable sessions** |
| `tests/test_lbs1_training_determinism.py` | Same seed/data → same artifacts/metrics |
| `tests/test_lbs1_no_test_leakage.py` | Test split untouched during train/calibrate; threshold frozen before test; test opened once |
| `tests/test_lbs1_evaluation_coverage.py` | Metrics computed only over `MODEL_READY` rows; non-evaluable sessions counted and reported; >10% non-evaluable forces an inconclusive evaluation result |

### Procedure

1. Verify G2 marker and dataset SHA-256.
2. Train only on `MODEL_READY` train rows; rows in any other observation state are never used as
   model inputs. Report how many were excluded and why.
3. Train logistic-regression baseline, bounded random forest, and histogram gradient boosting on
   train; select by validation under the threshold policy.
4. Calibrate on validation; choose warning/critical thresholds on validation only; write
   `thresholds.json` and freeze.
5. Run `linux_evaluate.py` once on `MODEL_READY` test rows; record test-split hash and timestamp.
   Report the count and share of test sessions with **zero `MODEL_READY` windows**
   (non-evaluable, whether `INSUFFICIENT_ACTIVITY` or `DEGRADED`) separately from accuracy
   metrics.
6. Report window-level and session-level metrics, per-family results, hard-benign FPR, CIs,
   Brier/ECE, detection latency, overhead, and model-ready coverage.
7. Verify Windows hashes and suite.

### Acceptance criteria

1. Training deterministic under fixed seed; artifact hashes reproducible.
2. No test leakage; test opened exactly once (lock + timestamp evidence).
3. Report includes every required metric and every family, including failures, and states
   model-ready coverage and non-evaluable counts explicitly.
4. Threshold documented with the validation objective; no post-test tuning.
5. Windows suite and hashes unchanged.
6. **Evaluation coverage rule:** a session is non-evaluable when it has zero `MODEL_READY`
   windows. If more than 10% of test sessions in either class are non-evaluable, the evaluation is
   reported as inconclusive for the purpose of gate G3 — it may not be presented as a
   detection-accuracy result, and G3 cannot pass on it without a new dataset collection.
7. **Gate G3:** approver reviews the evaluation and authorizes (or rejects) verdict integration.
   Rejection means correction and re-freeze, not threshold edits.

### Rollback

Delete `models/linux_v1/` and the evaluation report; delete the evaluation test files; no existing
file changed. The dataset remains for a corrected run.

---

## 6. Stage E — Linux verdict integration (Phases 5–6), only after G3

**Objective:** route Linux scans through LBS-1 while leaving the Windows path byte-identical.

### Existing files modified (backup each before edit)

| File | Change | Anchors |
|---|---|---|
| `scanner/scan_engine.py` | Platform dispatch; `_scan_linux_telemetry()`, `_run_linux_ml_analysis()`; verdict mapping; additive `ScanResult` fields (`sensor_groups`, `feature_status`, `observation_state`, `quality_reasons`, `model_version`, `feature_schema`, `feature_count`); `ml_probability: Optional[float]` | scan orchestration at `:452–475`; failure rules at `:488`; INCONCLUSIVE at `:516–529`; existing `_scan_processes` `:658`, `_run_ml_analysis` `:716` left for Windows |
| `utils/scan_audit.py` | Add `sensor_groups`, `feature_status`, `observation_state`, `quality_reasons`, `model_version`, `feature_schema` to `_RECORD_KEYS` and record builder; allow `probability=None` | `_RECORD_KEYS` `:56`; append trim `:405` |
| `gui/pages/dashboard.py` | Linux status card: show group reasons, "no probability available" when None, WARNING-cap notice; keep Windows rendering unchanged | routing `:997–1013`; status card `:2187+` |
| `packaging/linux/SentinelML_Linux.spec` | Bundle `models/linux_v1` (datas already include `models`; verify) | datas `:26–34`; Analysis `:121` |
| `.gitignore` | Ensure `data/linux_lbs1/` ignored (Stage C) | — |

Not modified: `ml/predictor.py`, `scanner/live_scanner.py`, `models/saved_model.pkl`,
`models/scaler.pkl`, `models/metrics.json`, thresholds.

### Verdict mapping (exact)

```
linux scan:
  collector raises / artifact load fails / schema mismatch / non-finite:
      ANALYSIS_ERROR, ml_probability=None
  observation.observation_state == DEGRADED (any group DEGRADED/UNAVAILABLE, or any feature UNAVAILABLE_*):
      INCONCLUSIVE, ml_probability=None, model NOT called,
      reasons = group statuses + UNAVAILABLE_* feature statuses
  observation.observation_state == INSUFFICIENT_ACTIVITY (no degraded/unavailable sensor; some feature or group NOT_APPLICABLE_*):
      INCONCLUSIVE, ml_probability=None, model NOT called,
      reasons = NOT_APPLICABLE_* feature statuses   # genuine no-activity, never SAFE
  observation.observation_state == MODEL_READY:
      p = guarded_predict(features)                  # exactly 20 finite floats
      if p >= warning_threshold: WARNING   # critical cap while LBS1_CRITICAL_ENABLED=False
      else: SAFE
```

No-activation windows (`INSUFFICIENT_ACTIVITY`) and sensor failures (`DEGRADED`) both produce
`INCONCLUSIVE` with `ml_probability=None`, but they are recorded with different
`observation_state` values and different reason codes so that audit and UI can distinguish
"nothing happened" from "we could not see what happened."

`PROCESS`-only and unsupported-filesystem scans → `INCONCLUSIVE`. Cancellation → existing
`CANCELLED`/`SCAN_INCOMPLETE`, never SAFE.

### New tests

| File | Covers |
|---|---|
| `tests/test_lbs1_verdict_mapping.py` | full matrix: healthy+low → SAFE; healthy+warning → WARNING; healthy+p=0.99 → WARNING (capped) with notice; **no-activity (`INSUFFICIENT_ACTIVITY`) → INCONCLUSIVE with reasons and predictor not called**; degraded → INCONCLUSIVE and predictor not called; the two INCONCLUSIVE causes carry distinct `observation_state`; model failure/schema mismatch/NaN → ANALYSIS_ERROR; process-only → INCONCLUSIVE |
| `tests/test_lbs1_scan_dispatch.py` | Linux dispatch calls collector exactly once; Windows dispatch never imports/calls Linux modules; Windows call sequence unchanged |
| `tests/test_lbs1_audit_fields.py` | audit record includes `sensor_groups`, `feature_status`, `observation_state`, `quality_reasons`; INCONCLUSIVE (both no-activity and degraded) not FAILED; `probability=None`; old records still load |
| `tests/test_lbs1_dashboard_render.py` | render helpers: None probability hidden; no-activity reasons shown distinctly from degraded reasons; WARNING cap notice; Windows strings unchanged |
| `tests/test_lbs1_windows_parity.py` | Windows 19-feature vector order/values unchanged; 0.50/0.90 behavior unchanged; frozen hashes |

### Acceptance criteria

1. Entire verdict matrix passes on Linux, including both `INCONCLUSIVE` causes being reported as
   `INCONCLUSIVE` with `ml_probability=None`.
2. Windows suite passes unchanged; manual Windows QUICK scan produces identical classification
   behavior to baseline; frozen hashes unchanged.
3. No code path can call the LBS-1 model unless `observation_state == MODEL_READY` with exactly 20
   finite values (assert via mock); a 20-float array supplied with any non-`DEFINED` feature status
   is still rejected.
4. `INCONCLUSIVE` audit records are `INCONCLUSIVE`, not `FAILED`, with `probability=None` and the
   triggering `observation_state` / `feature_status` persisted.
5. Dashboard verified on native Kali and native Ubuntu with screenshots; no fabricated score
   displayed when unavailable; no-activity and degraded wording are distinguishable.
6. Full Windows + Linux suites pass; new tests included.

### Rollback

Restore the four modified files from `backups/lbs1_stageE_<ts>/`; revert `.gitignore` if needed.
New modules remain but are unreachable because the dispatch is restored. Verify frozen hashes and
run both suites.

---

## 7. Stage F — native regression and artifacts (Phases 7–8), after G4

**Objective:** prove the integrated build on native Kali and native Ubuntu independently, then
produce a Linux AppImage in a separate output directory.

### New files

| File | Content |
|---|---|
| `tests/test_lbs1_native_integration.py` | Requires `SENTINEL_NATIVE_ENV=kali|ubuntu`; refuses WSL by inspecting `/proc/version`; end-to-end scan, audit record, dashboard helper; permission-denied and cancellation cases |
| `LINUX_LBS1_REGRESSION_REPORT.md` | Per-distro results, suite counts, hashes, screenshots, performance |
| `dist_linux_lbs1/SentinelML-x86_64.AppImage` | New artifact; prior `dist_linux/` and `dist_linux_inconclusive_fix/` untouched |
| `LINUX_LBS1_SHA256SUMS.txt` | Artifact and bundled model hashes |

### Acceptance criteria

1. Windows: full suite pass; frozen hashes unchanged; real QUICK scan parity.
2. Native Ubuntu VM: full suite pass; healthy scan → SAFE or WARNING with probability; degraded
   scenario → INCONCLUSIVE with no probability; screenshots.
3. Native Kali VM: same, independently; WSL results not substituted.
4. Simulation sessions in the UI are labeled simulated and never presented as real detection.
5. AppImage builds in `dist_linux_lbs1/`, launches on both native distros, bundles
   `models/linux_v1` plus the unchanged Windows model/scaler, and passes hash verification.
6. No publication or upload.

### Rollback

Delete `dist_linux_lbs1/`; restore any packaging file from backup; no existing artifact touched.

---

## 8. Stage G — CRITICAL enablement (separate approval, not automatic)

**Objective:** evaluate the predefined criteria in the decision record §5 on **fresh, independent**
data collected after the Stage D artifact freeze.

### Procedure

1. Snapshot both VMs; record kernel, filesystem, and distro versions.
2. Freeze artifacts and evaluation code (hashes).
3. Collect new held-out sessions per C2/C4; never reuse Stage D test data.
4. Run the frozen evaluator; produce `LINUX_LBS1_CRITICAL_VALIDATION_REPORT.md`.
5. Compare against C1–C11; publish pass/fail per criterion, including failures.
6. Only if all pass and the approver signs off: set `LBS1_CRITICAL_ENABLED=True` in
   `ml/linux_schema.py`, add a test asserting CRITICAL is reachable only with all groups healthy,
   rebuild, and re-run both suites.

### Failure handling

Any failed criterion → `CRITICAL` stays disabled, the failure is documented, and a new freeze
with new data is required. No test-set threshold tuning, no hard-benign removal, no relabeling.

---

## 9. Test matrix

Column meaning: **G1** columns are the only ones executed under G1 approval. The native Ubuntu
column is executed at **C0** and again where Stage E/F requires it.

| Area | Windows host (G1) | WSL2 (G1, dev only) | Native Kali VM (G1) | Native Ubuntu VM (C0) |
|---|---|---|---|---|
| Existing suite (483) | Required | Required | Required | Required at C0 |
| LBS-1 unit tests | skipped | required (dev) | required | required at C0 |
| LBS-1 applicability invariant (20 values ⇔ `MODEL_READY`) | required | required | required | required at C0 |
| Dataset/evaluation `MODEL_READY`-only enforcement | — | required (dev, fixtures) | required (fixtures) | required at C0 |
| Collector real inotify | — | dev signal | required | required at C0 |
| Predictor guards | required | required | required | required at C0 |
| Verdict/audit/UI | required (Windows parity) | optional | required | required at C0 |
| Native integration | — | **prohibited** | required at Stage F | required at C0 / Stage F |
| Performance budget | — | indicative | required | required at C0 |
| AppImage launch | — | — | required at Stage F | required at Stage F |

Counts are reported exactly; a skip is never reported as a pass. WSL results are always labeled
`DEV_ONLY_WSL`. A native-Ubuntu cell that has not been executed is reported as `PENDING_C0`,
never as "required later" in a way that implies completion.

---

## 10. Rollback strategy (global)

1. **Before any edit** to an existing file, copy it to
   `backups/lbs1_stage<X>_<YYYYMMDD_HHMMSS>/<relative_path>` and write `MANIFEST.sha256`.
2. Record every new file in `NEW_FILES.txt` in the same backup directory.
3. Never touch `models/saved_model.pkl`, `models/scaler.pkl`, `models/metrics.json`,
   `ml/predictor.py`, `scanner/live_scanner.py`, or existing installers/AppImages.
4. Rollback = copy backed-up files back, delete only files listed in `NEW_FILES.txt`, then:
   - verify frozen hashes against decision record §6;
   - run the full Windows suite and the current Linux suite;
   - confirm no new artifact directory was created outside the stage's designated path.
5. No `git reset`, `git checkout`, `git clean`, stash drop, force push, or history rewrite at any
   point. No commit or push without an explicit request.
6. Build outputs always go to a new directory; prior `dist_linux/` and
   `dist_linux_inconclusive_fix/` are never overwritten.
7. VM provisioning is undone by reverting to the snapshot taken before provisioning; the VM image
   itself is never deleted as part of a Stage A/B/C rollback.

---

## 11. Risk register

| Risk | Impact | Mitigation | Stop condition |
|---|---|---|---|
| inotify watch limits / overflow on real workloads | Undercounts events → false SAFE | Watch budget + explicit overflow → INCONCLUSIVE | Any overflow counted as healthy |
| WSL/DrvFs inotify semantics differ | Invalid "native" claims | FS-type detection; WSL labeled dev-only | WSL data used in train/test |
| `hidepid` / restricted `/proc` | Missing process evidence | Resolution-rate gate → INCONCLUSIVE | Zero-fill or imputation |
| No-activity windows dominate real Linux use | High INCONCLUSIVE rate limits usefulness | Report `MODEL_READY` coverage honestly; tune only the workload mix, never the schema | Any undefined feature serialized as a number, or no-activity mapped to SAFE |
| Simulation/real-world gap | Overstated capability | Simulation-only labeling in manifest, report, UI | Any "real ransomware accuracy" claim |
| Correlated windows inflate metrics | Misleading precision/recall | Session-level primary metrics; grouped splits; clustered CIs | Window-only reporting |
| Hard-benign encryption indistinguishable at 15 s | High FPR blocks CRITICAL | Hard-benign class; report confusion honestly | Removing hard-benign to pass |
| **G1 mistaken for full Stage A acceptance** | Ubuntu evidence absent but treated as validated; invalid native claim; collection starts without acceptance | Acceptance ledger (§2.1) and explicit tokens; `STAGE_A_PARTIAL_KALI_WSL` cannot satisfy any precondition; C0 gate before collection | Any status, report, or summary calling Stage A accepted before native Ubuntu passes, or any collection started before `STAGE_A_ACCEPTED` |
| Ubuntu native VM unavailable | Gate C3/G4 and C0 blocked | Provision under C0 approval; no substitution | WSL treated as Ubuntu native |
| Shared `ScanResult.ml_probability` type change | Windows/UI regression | Additive Optional handling; Windows sets floats; parity tests | Any Windows classification change |
| Audit `_RECORD_KEYS` trims new fields | Lost evidence | Extend keys + backward-compat test | New fields silently dropped |
| PyInstaller misses Linux artifacts/modules | Packaged app fails | `verify_artifacts.py` inside AppImage smoke test | Silent fallback to Windows model |
| User config toggles security boundary | Unsafe disable/enable | CRITICAL is a code constant | Any config/env toggle for verdicts |

---

## 12. What is requested now

**Gate G1 is approved (2026-10-30).** It authorizes Stage A and Stage B implementation and
unit/fixture testing only:

- implementation of the unprivileged collector, schema module, guarded predictor,
  dataset/training tooling, and their unit/fixture tests;
- test execution on the Windows host, WSL2 (labeled `DEV_ONLY_WSL`), and the existing native Kali
  VM, including real inotify on disposable pytest temp directories;
- **no** telemetry collection from real workloads, and no retained dataset, manifest, JSONL,
  session, or feature record;
- **no** provisioning, downloading, or installing of the Ubuntu VM;
- **no** native-Ubuntu acceptance run (that is a C0 item);
- **no** training, no model artifact, no verdict integration, no AppImage build;
- **no** modification of any existing production file, Windows artifact, or frozen hash;
- **no** commit, push, upload, or publication.

G1 is **not** Stage A acceptance. The maximum status reachable under G1 is
`STAGE_A_PARTIAL_KALI_WSL` (plus `STAGE_B_ACCEPTED_PENDING_UBUNTU`). `STAGE_A_ACCEPTED` requires
the native-Ubuntu evidence obtained under the separate **C0 / Stage C entry approval**, which
also authorizes Ubuntu VM provisioning and subsequent data collection. Everything after C0 —
Stage D training, Stage E integration, Stage F build, Stage G CRITICAL — remains behind G2–G5.
