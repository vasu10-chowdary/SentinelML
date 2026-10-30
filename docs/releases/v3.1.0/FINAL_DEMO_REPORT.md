# SentinelML — Final Kali Linux Demonstration Report

Date: 2026-10-30 · Guest: Kali GNU/Linux Rolling 2026.1, kernel 6.18.12+kali-amd64
(VM `kali-linux-2026.1-virtualbox-amd64`, headless Xvfb :99 1600x1000x24)
Scope: audit only. No source changes, no model training/replacement, no real ransomware,
no Ubuntu/C0/Stage C.

---

## 1. Launch command and environment activation

```
Xvfb :99 -screen 0 1600x1000x24 &
cd /home/kali/SentinelML
DISPLAY=:99 /home/kali/lbs1_audit/venv/bin/python app.py > /tmp/app_audit.log 2>&1 &
```

- Isolated venv: `/home/kali/lbs1_audit/venv` (Python 3.13.12; no global installs).
- Startup log (`app_startup.log`): platform adapter `linux`, cinematic animation
  started at 11:27:22 and finished at 11:27:27, dashboard constructed, ML pipeline
  loaded ("critical=0.90, warning=0.50"). **0 ERROR / 0 Traceback.**
- `app_runtime.log` (whole session, including the GUI scan) also has **0 ERROR /
  0 Traceback**.

## 2. Features verified (screenshots in this directory)

| Check | Evidence | Result |
|---|---|---|
| Startup animation | `startup_animation_1.png`, `app_startup.log` | Cinematic initialization frame; no traceback |
| Dashboard loads | `dashboard.png` | READY TO SCAN, tiles, monitoring card, SOC feed |
| Host monitoring status | `dashboard.png` | **Host: Monitored**, DATA QUALITY **LIVE**, update 29 s ago / next in 31 s |
| Guard status | `dashboard.png` | **Guard: Active** (green), Guard Uptime 3 m (20 m after scan) |
| SOC dashboard | `dashboard.png` | Live telemetry chips + Live SOC Feed with explicit `[SIMULATION]` label |
| Live Host Scan page | `live_host_scan_page.png` | IDLE, 3D core, pipeline stages, Start Live Scan |
| No startup crash | `app_startup.log`, `app_runtime.log` | No ERROR/Traceback lines |

## 3. Filesystem scan (CUSTOM, disposable fixture)

Fixture `/home/kali/lbs1_demo_fixture` (self-created, harmless: `notes.txt`,
`data.bin`, `hello.sh`). Source of truth: `final_scans_output.txt`.

- Files inspected: **3** · Directories: **1** · Files skipped: **0** · FS errors: **0** ·
  Access denied: **0**
- Processes analyzed: **65** · process errors: **0**
- ML executed: **true** · prediction: **SAFE** · probability: **0.32**
- State: **safe** · threat level: **SAFE** · model: `EXPERIMENTAL_SYNTHETIC_BASELINE_V1`
- Phase timings: filesystem 0.014 s, process 2.505 s, ML 34.339 s (sklearn warm-up),
  total 36.88 s · scan id `SCN-1E6FA449DE6A` · origin `DEMO_FIXTURE`

GUI filesystem coverage additionally demonstrated by the QUICK scan in §2
(`gui_scan_inconclusive.png`): 5 files, 65 processes, 31%, verdict **INCONCLUSIVE**.

## 4. Process-only scan

Source: `final_scans_output.txt` (second block).

- No path required: `files_inspected=0`, `directories=0`, `filesystem_s=0.0`, and the
  scan completed normally — the prior "No valid scan paths" defect is fixed.
- Processes enumerated: **65** · process errors: **0**
- ML executed only after a valid vector: **true** · prediction **SAFE** ·
  probability **0.29** · state **safe** · `scan_type=process`
- Total 1.24 s (process 1.063 s, ML 0.125 s) · scan id `SCN-341E4204A293`
- Regression proof: `tests/test_scan_engine_process_only.py` (6 tests) passes on Kali,
  including "process scan runs without paths", "ignores supplied paths",
  "custom scan still requires paths", and failure → ANALYSIS_ERROR (never SAFE).

## 5. Error-handling verification (mocks only; model files untouched)

Script `error_handling.py`; raw output `error_handling_results.txt`.

| Scenario | Result | SAFE? | Probability fabricated? |
|---|---|---|---|
| A. Process extraction failure (`scan_system→None`) | `scan_incomplete`, `ANALYSIS_ERROR`, `ml_executed=false` | No | No (0.0, empty prediction) |
| B. ML model load failure (`load_model→False`) | `scan_incomplete`, `ANALYSIS_ERROR` | No | No |
| C. Invalid vector (19×NaN, real predictor) | `scan_incomplete`, `ANALYSIS_ERROR` ("Feature vector contains NaN or infinite values") | No | No |
| D. Missing sensors (QUICK on Linux, 5 unavailable) | `inconclusive`, `INCONCLUSIVE`, reason names the 5 sensors, 14/19 available | No | Model ran (0.12) but verdict is INCONCLUSIVE, not SAFE |
| E. ML exception (RuntimeError in predict) | `scan_incomplete`, `ANALYSIS_ERROR`, traceback logged, no result invented | No | No |

Additional real (unmocked) evidence from the GUI QUICK scan: 4 of 19 sensors
unavailable → **INCONCLUSIVE — LIMITED COVERAGE**, "this host cannot be certified as
SAFE", ML output shown as "SAFE (model output only)". Sensor availability is probed at
runtime, so the unavailable count was 5 in scenario D and 4 in the GUI run; both runs
produced honest non-SAFE verdicts.

## 6. SOC and monitoring data quality (full detail in `SOC_DATA_QUALITY.md`)

- **Real:** process enumeration, system CPU/memory, file-metadata scope (monitored dirs,
  metadata only, depth 1, max 2 000 files/cycle), network connections, OS event channel,
  security services; registry correctly `n/a` on Linux. Guard status from the live
  `SentinelGuard` instance. Data quality **LIVE**.
- **Simulated:** the Live SOC Feed entry is `[SIMULATION] Suspicious Activity Detected`
  with `[SANDBOX SIMULATION]` badge, source "Sandbox Simulation". Demo mode is OFF
  (`DEMO_CONFIG["enabled"]=False`, verified in the guest). No simulation is presented as
  a real ransomware detection.
- **Findings (disclosed, not patched):**
  1. RECENT SOC EVENTS renders persisted alerts with **HH:MM only**; during the audit it
     showed 2026-10-24 "Host Scan: WARNING" records, which can look current.
  2. **THREATS (24H) = 84** is reproducible as **75 `[SIMULATION]` alerts + 9 legacy scan
     alerts**, of which **18 are future-dated** because the alert store carries naive
     host timestamps read by a guest clock in a different timezone; the formula
     (`livemon/telemetry.py:597`) has no upper time bound and does not exclude simulation.
     It is not 84 host threats.
  3. Scan tiles (Scans Today 1, Threats Found 0, Blocked 0) are session counters and are
     consistent with the single GUI scan performed.
  4. `soc/` is empty; SOC data is generated in-process by `livemon/`.

## 7. Regression testing (Kali)

Command:

```
/home/kali/lbs1_audit/venv/bin/python -m pytest -p no:cacheprovider -q \
    tests/test_lbs1_*.py tests/test_scan_audit.py tests/test_scan_engine_process_only.py
```

- **Combined: 308 passed, 7 skipped, 0 failed, 99.21 s** (`full_test_log.txt`).
- 13 LBS-1 files: 293 passed + 4 skipped (inotify non-Linux contract ×1,
  windows_import refusal ×2, windows_isolation refusal ×1).
- `test_scan_engine_process_only.py`: **6 passed**.
- `test_scan_audit.py` headless: 9 passed, 3 skipped (Tk unavailable). Re-run with
  `DISPLAY=:99`: **12 passed, 0 skipped** (`gui_audit_tests.log`), i.e. no coverage gap.
- Training-gate file took 67.9 s on this VM (prior 20 s); counts unchanged.

## 8. Files modified and backup hashes

No file was modified during this audit. The only production delta remains the previously
authorized process-only gate (one condition + one comment):

- `scanner/scan_engine.py`: backup `2d767daefa1e410cf86f0937d12733fc20d57267ffcf42873448f313c34ee4bd`
  → current `9af97eb497a1ad75666b1a5c9ec5e6b69a4e3cf40b2a47f34475839024321afe`
  (host backup `scratch/kali_fix_backup_20261030/scan_engine.py`, guest copy
  `/home/kali/SentinelML_backup_20261030/scan_engine.py`)
- `tests/test_scan_engine_process_only.py`: new, `6790bd81563713f26ae51c8bb1b2ae21fd2915e1935ccfc48e623d70c4c2030b`

Frozen artifacts re-verified today — all match the recorded values:
`models/saved_model.pkl 936d9e3f…`, `models/scaler.pkl d993e26a…`,
`models/metrics.json 8a24b01a…`, `ml/predictor.py 4b4f9c90…`,
`scanner/live_scanner.py fe34386f…`, `scanner/linux_processes.py 5d8f1fbf…`,
`scanner/linux_telemetry.py 4c26e7ea…`, `tests/test_lbs1_processes.py 45ddedaf…`,
`LINUX_LBS1_IMPLEMENTATION_PLAN.md 38a40ed2…`.

## 9. Remaining limitations

1. GUI was exercised on a headless Xvfb display, not a physical Kali desktop; rendering
   and input were verified through screenshots and xdotool. No compositor effects tested.
2. No detection accuracy is claimed. The model is `EXPERIMENTAL_SYNTHETIC_BASELINE_V1`;
   the SAFE results (0.29–0.32) are model outputs on a clean host, not proof of
   real-world ransomware detection.
3. On Linux, GUI QUICK/FULL scans are INCONCLUSIVE by design while Windows-only sensors
   are missing (4–5 of 19). Process-only and CUSTOM scans can reach SAFE when all inputs
   succeed.
4. SOC widget shows date-less historical alerts, and the THREATS (24H) tile mixes
   simulation/legacy/clock-skewed records (see §6). Both need a demo caveat or a later
   fix; they do not affect scan verdicts.
5. The alert store is shared between host and guest runs with naive timestamps, causing
   clock-skew artifacts.
6. Validation is a single audit session on one VM; no native Ubuntu validation (C0) was
   performed or authorized.

## 10. Evidence location

`docs/releases/v3.1.0/` in this repository
(README.md, environment.txt, screenshots, scan outputs, error-handling output,
SOC_DATA_QUALITY.md, full_test_log.txt, gui_audit_tests.log, app logs, SHA256SUMS.txt).
Prior evidence directories untouched.

## 11. Verdict

**DEMO READY WITH LIMITATIONS.**

The existing Kali build launches cleanly, monitors the host with real telemetry, runs
filesystem, process-only and GUI scans with correct honest outcomes (SAFE only when all
inputs succeed; INCONCLUSIVE on missing Linux sensors; ANALYSIS_ERROR on any failure),
and passes 308 tests with 0 failures. The limitations above must be stated during a demo:
headless display, experimental synthetic baseline (no real-world accuracy claim), the
INCONCLUSIVE behavior on Linux QUICK/FULL scans, and the two SOC-display caveats.
