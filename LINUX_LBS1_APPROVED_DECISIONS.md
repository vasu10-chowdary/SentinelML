# SentinelML — LBS-1 Decision Record

**Decision ID:** LBS1-APPROVAL-2026-10-30
**Status:** APPROVED — implementation not started
**Schema:** Linux Behavioral Schema v1 (LBS-1), 20 features
**Companion documents:** `LINUX_DETECTION_ACCURACY_AUDIT.md`, `LINUX_FEATURE_SCHEMA_V1.md`,
`LINUX_LBS1_IMPLEMENTATION_PLAN.md`
**Repository HEAD at approval:** `a37046d`

This record is the authoritative statement of what has been approved, what remains
unauthorized, and the conditions under which Linux verdicts and the `CRITICAL` level may be
enabled. It supersedes the open-decisions table in `LINUX_FEATURE_SCHEMA_V1.md` §12.

---

## 1. Approved decisions

| ID | Decision | Resolution | Binding consequence |
|---|---|---|---|
| D1 | LBS-1 feature set | **APPROVED** — all 20 features, in the specified order | Feature names, order, units, and dtypes are a hashed artifact contract. Any change requires LBS-2 and a new artifact directory. |
| D2 | Training data | **APPROVED** — empirical benign workloads + safe, controlled, path-guarded ransomware-*like* simulations only | No real malware. No hand-authored Gaussian vectors. Every record carries `source_type`; `HAND_AUTHORED_VECTOR` is rejected by the dataset gate. |
| D3 | Observation window | **APPROVED** — 15 s default (10–60 s configurable), frozen per model version | Window length is stored in `schema.json` and the scan result. A change requires a new schema version. |
| D4 | Entropy policy | **APPROVED** — no extension filtering | Compressed media/archives are included in entropy statistics. False-positive pressure is handled by the hard-benign class, not by hiding it. |
| D5 | Thresholds | **APPROVED** — calibrate on validation only; never inherit 0.50/0.90 | Test split is opened once after the threshold is frozen. No tuning on test. No threshold change to reduce INCONCLUSIVE. |
| D6 | Privileged sensors | **APPROVED** — auditd, eBPF, fanotify excluded from v1 | v1 is unprivileged only. Privileged work is a separately approved future version. |
| D7 | Diagnostic probability on incomplete telemetry | **APPROVED** — not allowed | When any required sensor group is degraded, the model is not invoked and no probability is reported. |
| D8 | Artifact location | **APPROVED** — `models/linux_v1/` | Windows artifacts are never overwritten, read as fallback, or reinterpreted. |
| D9 | Linux classification levels | **APPROVED** — `SAFE`, `WARNING`, `INCONCLUSIVE` initially; `CRITICAL` disabled | Probabilities in the critical band are capped at `WARNING` with an explicit "CRITICAL disabled pending independent validation" notice. Enabling `CRITICAL` requires §5 and a separate approval. |

**Clarification 2026-10-30 (reviewer-requested, subject to G1 review).** The schema now defines an
explicit **definedness layer** for proportions/means over empty populations. Undefined features
are never encoded as `0`, `-1`, a mean, or a previous value. Feature 8's denominator changed to the
full re-sampled baseline cohort; features 6/7 remain event-touched; feature 13 remains a ratio.
No feature was added, removed, or reordered. Details: `LINUX_FEATURE_SCHEMA_V1.md` §3.1 and §14.

### Derived decisions (required by the contract, flagged for visibility)

| ID | Decision | Rationale |
|---|---|---|
| D10 | Linux `PROCESS`-only scans return `INCONCLUSIVE` | A process-only scan cannot supply filesystem/entropy features. Running the model on a partial vector is forbidden by D7. |
| D11 | Targets on `9p`, `drvfs`, `fuse`, `nfs`, `cifs`, `sshfs` are not LBS-1-valid | Inotify semantics are unreliable or absent. Such runs are `INCONCLUSIVE` with the filesystem type named. |
| D12 | `LBS1_CRITICAL_ENABLED` is a code constant, not user configuration | A security boundary must not be toggleable from a config file. It changes only through a reviewed code change and the §5 gate. |
| D13 | No imputation of any kind | Missing values are never replaced by 0, the mean, or a previous window. |
| D14 | No-activity representation | Each feature is `DEFINED` or carries an explicit `NOT_APPLICABLE_*` / `UNAVAILABLE_*` status. Undefined values are absent from the vector, never sentinel numbers. Only the four population-based features (6, 7, 8, 13) can be not-applicable; the sixteen count/rate features remain `DEFINED` at a measured `0` when no matching event occurred |
| D15 | `entropy_increase_ratio` denominator | The fixed baseline cohort re-sampled in full at window end. Denominator = surviving readable cohort files; ≤10% permission loss is excluded and recorded, >10% → `UNAVAILABLE_PERMISSION` / G2 `DEGRADED`. `0.0` is a genuine “0 of N increased” measurement; not-applicable only if the cohort is absent or entirely deleted/moved out. |
| D16 | `avg_shannon_entropy` / `high_entropy_file_ratio` | Event-touched files only. No file activity → `NOT_APPLICABLE_NO_FILE_ACTIVITY`; events but only zero-length files → `NOT_APPLICABLE_NO_SAMPLEABLE_FILES`; either gives `INCONCLUSIVE`. |
| D17 | `short_lived_process_ratio` with zero creation | `NOT_APPLICABLE_NO_PROCESS_ACTIVITY` → `INCONCLUSIVE`; never `0.0`, never redefined as a count. |
| D18 | “Healthy” for inference | `MODEL_READY` = all seven sensor groups `OK` **and** all 20 features `DEFINED`. Only then is a 20-value vector produced. |

---

## 2. Mandatory safety and preservation invariants

These map directly to the approver's ten requirements and are test-enforced, not just documented.

| ID | Invariant | Enforcement |
|---|---|---|
| M1 | Windows 19-feature extractor, model, scaler, metrics, and thresholds untouched | SHA-256 checks in `tests/test_lbs1_windows_isolation.py` + diff review; hashes in §6 |
| M2 | Windows prediction behavior unchanged | Existing Windows suite + golden benchmark + manual scan parity; all Linux code is additive and platform-dispatched |
| M3 | Missing/inaccessible/degraded telemetry **and no-activity** windows never become zero-filled evidence or `SAFE` | Collector returns `features=None` unless the observation is `MODEL_READY`; undefined features carry statuses, never numbers; model call is guarded; tests assert the predictor is never called for `DEGRADED` or `INSUFFICIENT_ACTIVITY` |
| M4 | Model load, schema, and artifact failures produce `ANALYSIS_ERROR` | Typed exceptions mapped to `ScanState.ANALYSIS_ERROR`, `threat_level="ANALYSIS_ERROR"`, probability `None` |
| M5 | Native Kali and native Ubuntu tested independently; WSL is not native validation | `tests/test_lbs1_native_integration.py` refuses to run on WSL (`/proc/version` contains `microsoft`) unless an explicit dev-only flag is set; gate reports are per-distro |
| M6 | Hard-benign workloads included | Dataset gate requires ≥8 hard-benign sessions per distro in the test set: GPG, OpenSSL, encrypted archives, backups, builds, package management, media processing |
| M7 | No real ransomware; nothing outside disposable path-guarded sandboxes | `tools/lbs1/simulation_guard.py` refuses non-sandbox paths, symlink escapes, `/`, home, and system roots; tests prove 100% refusal |
| M8 | Simulation results never reported as real-world ransomware accuracy | Dataset card, model manifest, evaluation report, and UI model-details all carry the simulation-only limitation |
| M9 | Every existing user modification preserved; no destructive Git | Backups before edits; no reset/checkout/clean/stash-drop/force-push; no commit or push without explicit request |
| M10 | No training or Linux verdict integration before dataset, evaluation, and approval gates | `models/linux_v1/APPROVED_FOR_TRAINING` marker required by the trainer; verdict integration blocked until G3 approval |

---

## 3. Linux verdict contract (v1)

| Final state | Condition | Probability reported | Model invoked |
|---|---|---|---|
| `SAFE` | Observation `MODEL_READY` (all seven sensor groups `OK` **and** all 20 features `DEFINED`), supported filesystem, no event overflow, artifact verified, calibrated `p < warning_threshold` | Yes | Yes |
| `WARNING` | Observation `MODEL_READY`, artifact verified, `p ≥ warning_threshold` (including `p ≥ critical_threshold`, capped) | Yes | Yes |
| `INCONCLUSIVE` | Observation `DEGRADED` (group/sensor/permission failure), or `INSUFFICIENT_ACTIVITY` (any `NOT_APPLICABLE_*` feature: no file activity, no sampleable files, no baseline cohort, cohort deleted/moved out, no process creation); process-only scan; unsupported target filesystem | **No** (`None`) | **No** |
| `ANALYSIS_ERROR` | Artifact missing/corrupt, schema/platform mismatch, non-finite or wrong-shaped features, extraction crash, model exception | **No** | Attempted, failed |
| `CANCELLED` / `SCAN_INCOMPLETE` | User cancellation or incomplete scan | **No** | Depending on phase |

Observation states:

| State | Condition | Vector |
|---|---|---|
| `MODEL_READY` | All seven sensor groups `OK` and all 20 features `DEFINED` | Exactly 20 `float64`, finite, non-negative |
| `INSUFFICIENT_ACTIVITY` | No group `DEGRADED`/`UNAVAILABLE`, but ≥1 feature `NOT_APPLICABLE_*` (equivalently a group `NOT_APPLICABLE` because there was no population) | `None` |
| `DEGRADED` | Any feature `UNAVAILABLE_*`, or any group `DEGRADED`/`UNAVAILABLE` | `None` |

A `NOT_APPLICABLE` group means "the sensor worked but had nothing to measure" (e.g. zero new
PIDs for G5/G6). It is not a `DEGRADED` sensor; it contributes to `INSUFFICIENT_ACTIVITY` when no
sensor is degraded, and it never yields `SAFE`.

**Feature-status vocabulary (exact, shared with schema §3.1):** `DEFINED`,
`NOT_APPLICABLE_NO_FILE_ACTIVITY`, `NOT_APPLICABLE_NO_SAMPLEABLE_FILES`,
`NOT_APPLICABLE_NO_BASELINE_COHORT`, `NOT_APPLICABLE_COHORT_UNAVAILABLE`,
`NOT_APPLICABLE_NO_PROCESS_ACTIVITY`, `UNAVAILABLE_PERMISSION`, `UNAVAILABLE_SENSOR`. No other
feature status is valid.

Additional rules:

- `SAFE` means "no validated evidence of ransomware-like behavior within the observed scope,"
  not "the host is clean." The dashboard wording must say this.
- A degraded group never downgrades to `SAFE` and never upgrades to `WARNING`/`CRITICAL`.
- No-activity never downgrades to `SAFE` either. It is `INCONCLUSIVE` with a reason code
  (`NOT_APPLICABLE_NO_FILE_ACTIVITY`, `NOT_APPLICABLE_NO_SAMPLEABLE_FILES`,
  `NOT_APPLICABLE_NO_BASELINE_COHORT`, `NOT_APPLICABLE_COHORT_UNAVAILABLE`, or
  `NOT_APPLICABLE_NO_PROCESS_ACTIVITY`) that is distinct from permission/sensor failures.
- When a healthy scan scores in the critical band, the UI shows
  `WARNING — score above CRITICAL band; CRITICAL disabled pending independent validation`.
  The raw score is shown because it is a genuinely computed value; the classification is capped.
- Audit classification for `INCONCLUSIVE` remains `INCONCLUSIVE`, never `FAILED`
  (`utils/scan_audit.py:VALID_CLASSIFICATIONS`), with `probability=None` and reasons recorded.

---

## 4. Sensor groups (health gate)

`SAFE`/`WARNING` require **all seven** groups healthy:

1. **G1 Filesystem events** — supported local FS, ≥1 watch, no watch shortfall, no `IN_Q_OVERFLOW`.
2. **G2 Entropy sampling** — **OK** if file events occurred and ≥20 files were sampled with ≤10% read failures (or the event count was <20 and all touched non-zero files were sampled), and baseline-cohort re-sampling stayed within its 10% failure budget. **NOT_APPLICABLE** when there were zero file events, every touched file was zero-length, or no baseline cohort existed (→ `INSUFFICIENT_ACTIVITY`). **DEGRADED** when non-zero files existed but reads were denied beyond the budget, cohort re-sampling was denied beyond its budget, or the shortfall is unexplained by zero-length files or a low event count.
3. **G3 Filename signatures** — list version loaded and applied to every event.
4. **G4 Process dynamics** — ≥3 snapshots and consistent create/exit accounting; zero created processes is **not** a G4 failure (it makes feature 13 `NOT_APPLICABLE_NO_PROCESS_ACTIVITY`).
5. **G5 Command semantics** — ≥90% of new PIDs resolved via `cmdline`/`exe` or documented fallback; `NOT_APPLICABLE` when zero PIDs were created.
6. **G6 Privilege observation** — `/proc/<pid>/status` readable for ≥90% of new PIDs; `NOT_APPLICABLE` when zero PIDs were created.
7. **G7 Network** — `net_connections` succeeded and was not restricted.

A group is `OK`, `DEGRADED`, `UNAVAILABLE`, or `NOT_APPLICABLE`. Any non-`OK` value on a required
group blocks the model call. `NOT_APPLICABLE` due to no activity and `DEGRADED`/`UNAVAILABLE` due
to sensor failure are different states with different reason codes. All reasons are user-visible
and audit-persisted.

---

## 5. Predefined criteria for enabling `CRITICAL`

`CRITICAL` remains disabled until **all** criteria below are met and the approver signs off.
These criteria are fixed now, before any test data exists, so they cannot be retrofitted to a
result.

| ID | Criterion | Threshold |
|---|---|---|
| C1 | **Artifact freeze** | Model, calibrator, scaler, schema, and evaluation code hashes recorded before validation; no change during validation |
| C2 | **Independent data** | Held-out sessions collected after the freeze, on machines not used for training, by scripts hashed at freeze time; never used for training, calibration, or model selection; test split opened once |
| C3 | **Native environments** | Full VM or bare metal on current Kali and Ubuntu LTS, distro kernels; WSL and containers are excluded; kernel/FS versions recorded |
| C4 | **Independence per distro** | ≥20 benign sessions (≥8 families, ≥8 hard-benign) and ≥20 simulation runs (≥5 families) on **each** distro; ≥90% of sessions yield at least one `MODEL_READY` window |
| C5 | **Hard-benign false positives** | **Zero** hard-benign session false positives on each distro; window-level benign FPR ≤ 0.5% with Wilson 95% upper bound ≤ 2% |
| C6 | **Detection** | Session-level recall ≥ 0.80 overall and ≥ 0.60 for the intermittent/low-rate family, computed over evaluable sessions only; per-family results published, not just the aggregate |
| C7 | **Calibration** | Brier score ≤ 0.10 and expected calibration error ≤ 0.05 on held-out data |
| C8 | **Reproducibility** | Two independent evaluation runs, same frozen artifacts, metrics within ±0.02 |
| C9 | **Windows regression** | Full Windows suite passes and all frozen artifact hashes in §6 are unchanged |
| C10 | **Review** | Evaluation report includes confusion matrices, per-family tables, CIs, model-ready coverage, non-evaluable sessions, limitations, and explicit simulation-only claim; approver signs off |
| C11 | **Evaluability** | ≤10% of sessions per class are non-evaluable (zero `MODEL_READY` windows); non-evaluable sessions are neither detections nor false positives; otherwise validation is declared inconclusive |

Failure of any criterion keeps `CRITICAL` disabled. The response is a root-cause fix and a new
freeze with new held-out data — never threshold tuning on the existing test set, never dropping
hard-benign families, and never relabeling data.

---

## 6. Frozen Windows contract (must remain byte-identical)

| Artifact / file | SHA-256 |
|---|---|
| `models/saved_model.pkl` | `936d9e3ff0b97d762751bdcba34ad3d247a4280e38f84e32dc4f31bfa1174e33` |
| `models/scaler.pkl` | `d993e26a313f743bbfc351912f2ac4a3be2642f4722c8c5451baf9eda26281cb` |
| `models/metrics.json` | `8a24b01aa0d5b38ea099f391afb486fa9310fe0ff39ae645c132172170227c88` |
| `ml/predictor.py` | `4b4f9c90eff4a4144115b4cb5848a4d9f957032fb81f4af435e18fbfd6beb491` |
| `scanner/live_scanner.py` | `fe34386fa3612c9cd203e2bc1cbdd4607644a216ce8b2255d122db2997e5ede1` |

Baseline behavior to preserve: 19 features in the existing order, thresholds 0.50/0.90,
`optimal_threshold` 0.9, stored metrics accuracy 0.9567 (synthetic in-distribution only).
`scanner/scan_engine.py`, `utils/scan_audit.py`, and `gui/pages/dashboard.py` may change only
additively and only at Stage E, behind the platform dispatch, with backups and diff review.

---

## 7. Native validation environments

| Environment | Status | Use |
|---|---|---|
| Windows 10/11 host (this machine) | Available | Windows regression suite, Windows scan parity |
| VirtualBox VM `kali-linux-2026.1-virtualbox-amd64` | Available, not running | Native Kali validation and data collection |
| Native Ubuntu LTS VM | **Must be provisioned** (no Ubuntu VM exists; only WSL) | Native Ubuntu validation and data collection |
| WSL2 Ubuntu | Available | Development and unit tests only — **never counted as native validation** |
| Containers | Not used | Shared kernel; excluded by C3 |

Native validation requires VM snapshots for clean, reproducible sessions. Provisioning the
Ubuntu VM (ISO download + install) is a separate action requiring approval at Stage C.

---

## 8. Approval gates

| Gate | Requires | Authorizes |
|---|---|---|
| **G0** | This decision record + implementation plan | Read-only inspection and planning only |
| **G1** | Plan review (this document set) | Stages A–B: collector, schema module, guarded predictor, dataset/training tooling, and their unit tests; no training, no data collection beyond fixtures, no verdict integration |
| **G2** | Dataset card showing required volume, `MODEL_READY` coverage, families, hard-benign coverage, privacy checks, and split integrity | Stage D: training and held-out evaluation (Stage C collection is separately authorized after Stage A/B results) |
| **G3** | Held-out evaluation report with metrics, CIs, per-family results, and limitations | Stage E: Linux verdict integration at SAFE/WARNING/INCONCLUSIVE |
| **G4** | Integration + full Windows and native Linux regression | Stage F: AppImage build and delivery artifacts |
| **G5** | §5 criteria on fresh independent data | Enabling `CRITICAL` (separate code change and approval) |

Each gate is a hard stop. A failed gate does not get "worked around"; it gets reported and the
preceding stage is corrected.

---

## 9. Current authorization

**Authorized now:** read-only inspection; recording of these decisions; production of the
implementation plan.

**Not authorized yet:** writing collector/schema/model code; collecting telemetry; provisioning
VMs or downloading ISOs; training; integrating Linux verdicts; modifying any existing source file;
building or publishing artifacts; committing or pushing.

The next action after this record is review and approval of
`LINUX_LBS1_IMPLEMENTATION_PLAN.md` (gate G1).
