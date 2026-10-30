# SentinelML Release Notes

---

## v3.1.0 — Kali Linux Compatibility

**Release date:** 2026-10-30
**Base:** `a37046d` (existing `v3.0.0` tag, branch `exhibition-mode`)
**Type:** Source release (no new binary assets)

### Highlights

v3.1.0 makes the existing Linux implementation demonstrably runnable and testable on
Kali Linux without changing the detection model, the 19-feature contract or any frozen
Windows artifact. It also fixes the process-only scan path and completes the honest
`INCONCLUSIVE` contract across the UI.

### What's new

1. **Kali Linux verification.**
   The application was launched and exercised on Kali GNU/Linux Rolling 2026.1
   (kernel 6.18.12+kali-amd64, Python 3.13.12, Tk 8.6) under a headless Xvfb 1600×1000
   display. Startup animation, dashboard, host monitoring, Guard, SOC feed, Live Host Scan
   page, filesystem scan, process-only scan and a GUI scan all completed with **0 ERROR /
   0 Traceback** in the application logs. Screenshots and raw logs are published in
   [docs/releases/v3.1.0/](docs/releases/v3.1.0/README.md).

2. **Process-only scan fix.**
   `scanner/scan_engine.py` no longer aborts a `ScanType.PROCESS` scan with
   `No valid scan paths`. The filesystem-path requirement now applies to path-based scan
   types only, and the model runs only after a valid feature vector exists.
   Verified: 65 processes, 0 process errors, `SAFE`, p = 0.29, 1.24 s total.
   Regression file `tests/test_scan_engine_process_only.py` (6 tests) covers the missing
   path, ignored supplied paths, CUSTOM still requiring paths, missing custom path,
   process failure → `ANALYSIS_ERROR`, and ML failure → `ANALYSIS_ERROR`.

3. **INCONCLUSIVE state completed across the UI.**
   When Linux cannot supply Windows-only sensors, the dashboard routes an
   `INCONCLUSIVE` result through the completion path, marks tiles as limited coverage,
   suppresses alert generation, describes the ML number as "model output only", and the 3D
   core renders an amber `INCONCLUSIVE // LIMITED TELEMETRY` state. `LIMITED_COVERAGE` is
   mapped consistently. Scenario-lab cancellation now accepts the same completed states.

4. **LBS-1 Linux behavioral pipeline (experimental).**
   New modules: `scanner/linux_processes.py`, `linux_telemetry.py`, `linux_entropy.py`,
   `linux_fs_types.py`, `linux_inotify.py`; `ml/linux_schema.py`, `linux_dataset.py`,
   `linux_train.py`, `linux_evaluate.py`, `linux_predictor.py`; verification tooling in
   `tools/lbs1/`. The pipeline is gated and documented; **no validated Linux detector is
   claimed**.

5. **Linux packaging and documentation.**
   `packaging/linux/SentinelML_Linux.spec` and `packaging/linux/build_appimage.sh`, plus
   installation, platform, build, schema and accuracy-audit documents.

6. **Sanitized evidence package.**
   Reports, screenshots, scan outputs, error-handling results and logs under
   `docs/releases/v3.1.0/`, with SHA-256 checksums.

### Fixes

| Fix | File |
|---|---|
| Process-only scans no longer require filesystem paths | `scanner/scan_engine.py` |
| POSIX root `/` treated as unsafe target but not as a path prefix (temp dirs stay usable) | `exhibition/integrity_watchtower.py` |
| Scenario-lab cancellation race accepts SAFE/INCONCLUSIVE/LIMITED_COVERAGE and clears inconclusive flags | `exhibition/scenario_lab.py` |
| INCONCLUSIVE results reach the completion UI; no alerts for inconclusive scans; detailed coverage text | `gui/pages/dashboard.py` |
| INCONCLUSIVE / LIMITED_COVERAGE mapped to the amber core state | `gui/dashboard_3d.py` |
| Unified dashboard regression coverage for the new states | `tests/test_unified_dashboard.py` |
| Application version reported as v3.1.0 | `constants.py`, `gui/pages/settings.py` |

### Verification

Release suite: 359 tests across 17 files.

| Environment | Result |
|---|---|
| Kali 2026.1 (guest VM) | **355 passed, 4 skipped, 0 failed** in 306.34 s |
| Windows 11 (host) | **357 passed, 2 skipped, 0 failed** in 188.97 s |
| Windows 11 (earlier run) | 356 passed, 3 skipped, 0 failed in 167.12 s (one Tk-dependent test skipped: no display) |
| Windows 11 (alternate run) | 355 passed, 3 skipped, **1 failed** — Tk teardown flake (`invalid command name "tcl_findLibrary"`) in `test_dashboard_3d_core_live_state_transitions`; passes in isolation |

Additional verification:

- Five mocked failure scenarios (process extraction, model load, NaN vector, missing
  sensors, ML exception) all ended non-`SAFE` with no fabricated probability.
- Filesystem CUSTOM scan on a harmless fixture: 3 files, 0 errors, `SAFE`, p = 0.32;
  34.3 s of the 36.9 s total was one-time sklearn warm-up.
- GUI QUICK scan on Kali: 4/19 sensors unavailable → `INCONCLUSIVE — LIMITED COVERAGE`.
- Frozen artifacts re-verified (SHA-256): `models/saved_model.pkl` `936d9e3f…`,
  `models/scaler.pkl` `d993e26a…`, `models/metrics.json` `8a24b01a…`,
  `ml/predictor.py` `4b4f9c90…`, `scanner/live_scanner.py` `fe34386f…`,
  `scanner/linux_processes.py` `5d8f1fbf…`, `scanner/linux_telemetry.py` `4c26e7ea…`,
  `tests/test_lbs1_processes.py` `45ddedaf…`,
  `LINUX_LBS1_IMPLEMENTATION_PLAN.md` `38a40ed2…`.

### ML baseline disclosure

The bundled model is a 100-tree Random Forest over 19 synthetic, Windows/Volatility-oriented
behavioral features. Stored metrics (`accuracy` 0.9567, `precision` 0.9550, `recall` 0.9795,
`F1` 0.9671, `ROC-AUC` 0.9483) are **in-distribution synthetic test results**. The legacy
40/40 benchmark is a bimodal synthetic artifact. Linux vectors are partly zeroed or
substituted, so Linux probabilities are out-of-distribution extrapolations. **No real-world
ransomware detection accuracy is claimed for any platform.** No real ransomware or
malicious sample was used in producing this release.

### Known limitations

- Kali GUI was verified on a headless Xvfb display via screenshots and xdotool, not on a
  physical desktop with a compositor.
- Linux `QUICK`/`FULL` scans are `INCONCLUSIVE` by design while 4–5 Windows-only sensors
  are missing; `PROCESS` and `CUSTOM` scans can complete when all inputs succeed.
- `THREATS (24H)` mixes `[SIMULATION]` alerts, legacy scan alerts and clock-skewed
  records; `RECENT SOC EVENTS` shows time-of-day without a date. Simulation entries are
  labelled; none is presented as a real detection.
- No native Ubuntu validation (C0) was performed. macOS remains code-ready, unverified.
- No Linux or Windows binary is attached to v3.1.0. The existing v3.0.0 Windows executable
  predates the process-only fix.

### Compatibility and upgrade notes

- The existing `v3.0.0` tag and GitHub release are **untouched**; this release builds on the
  same commit.
- No alert-store schema change and no migration is required.
- `requirements.txt` and `requirements-linux.txt` are unchanged.
- `APP_VERSION` is now `3.1.0`; the version is visible in the sidebar and Settings > About.

---

## v2.0.0-GA — Cross-Platform Hardening & Telemetry Integrity

**Release**: Version 2.0.0-GA
**Codename**: Cross-Platform Hardening & Telemetry Integrity
**Release Date**: October 25, 2026

### Highlights

SentinelML V2 brings robust multi-platform execution to behavioral ransomware defense. This release expands support beyond Windows to Linux environments while enforcing strict verification standards: **unsupported or missing operating system telemetry is never masked as a false "SAFE" verdict.**

## What's New in V2.0

### 1. Cross-Platform Platform Adapter Layer
- Introduced `utils/platform_adapter.py` abstracting OS-specific primitives:
  - Single-instance locking: Win32 named Mutex on Windows, POSIX `fcntl.flock` on Linux and macOS.
  - Window icon management: Supports native `.ico` on Windows and `.png` via Tkinter `iconphoto()` on Linux/macOS.
  - Autostart registry/service persistence: Windows Registry Run keys, Linux XDG `.desktop` entries, macOS LaunchAgents.
  - Path resolution: Fully normalized using `pathlib.Path` with platform-appropriate application data directories (`%APPDATA%`, `~/.local/share/sentinelml`, `~/Library/Application Support/SentinelML`).

### 2. Telemetry Fidelity & The `INCONCLUSIVE` Scan State
- Explicit tracking of behavioral feature availability per operating system.
- On Linux and macOS, where system-wide file handles, registry hooks, and Windows Defender tampering are architecturally unavailable, the scan engine deterministically transitions to `ScanState.INCONCLUSIVE` instead of declaring a clean system.
- Full UI integration of the `INCONCLUSIVE` state across the **Dashboard**, **Scan Visualizer**, **Threat Log**, and **Report Exporters**.

### 3. Linux Kernel Thread & Process Filtering
- Eliminated false positives on Linux by filtering internal kernel threads (`PID <= 2`, `PPID in {0, 1, 2, 4}`, and bracketed daemons like `[kworker/*]`).
- Adapted cryptographic module detection to inspect `.so` shared libraries (`libcrypto.so`, `libssl.so`, `libgcrypt.so`).

### 4. Preserved Artifacts & Models
- Retained the existing 100-estimator scikit-learn Random Forest model (`models/saved_model.pkl`) and `StandardScaler` (`models/scaler.pkl`).
- Maintained exact 19-feature ordering and decision thresholds ($p < 0.50$ Low, $0.50 \le p < 0.90$ Warning, $p \ge 0.90$ Critical).
- Preserved `tests/benchmark_results.json` without modification.
- Retained all 3D animations, the interactive shield canvas, and the SentinelAI advisory panel.

## Benchmark & Detection Performance Disclosures

### Synthetic Benchmark Performance
- Evaluated on 40 controlled test profiles (20 Benign system templates, 20 Synthetic Ransomware family profiles):
  - **Windows Telemetry**: 40/40 (100% Accuracy)
  - **Linux Telemetry (4 unavailable features zeroed)**: 40/40 (100% Accuracy)

### Real-World Evasion Limitations
- **Synthetic vs. Wild Malware**: The 100% benchmark score demonstrates functional consistency against known behavioral templates. In the wild, sophisticated ransomware employing in-memory evasion, kernel exploits, or low-entropy chunked encryption may evade user-space heuristics.
- **User-Space Scope**: SentinelML operates at Ring-3 user space. It does not replace kernel-level endpoint detection and response (EDR) or hardware-enforced protection.

## Known Platform Limitations

1. **Linux**:
   - Clean scans will report `INCONCLUSIVE — LIMITED COVERAGE` rather than `SAFE` because system-wide file handles and registry telemetry cannot be collected without Windows kernel APIs.
   - Requires `libfuse2` when executing the AppImage on newer Ubuntu distributions.
2. **macOS**:
   - Build scripts and platform adapters are code-ready, but binary runtime on physical Apple hardware remains unverified. Notarization is required for distribution outside of developer mode.
3. **Windows**:
   - Sequential batch execution of multiple Tkinter test windows under Python 3.14 can cause Tkinter interpreter teardown races. All tests pass with 100% reliability when run individually.
