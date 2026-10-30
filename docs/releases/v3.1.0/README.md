# v3.1.0 — Kali Linux verification evidence

**Date:** 2026-10-30
**Scope:** Read-only verification of the Kali-compatible implementation, the process-only
scan fix, the `INCONCLUSIVE` contract and the frozen Windows artifacts. No real ransomware
or malicious samples were used; the only scan fixture was a self-created directory
containing `notes.txt`, `data.bin` and `hello.sh`.
**Environment:** Kali GNU/Linux Rolling 2026.1 (kernel 6.18.12+kali-amd64, Python 3.13.12,
Tk 8.6) in a headless VirtualBox VM with Xvfb 1600×1000; Windows 11 host for the
cross-platform suite.

This directory is a sanitized subset of the audit evidence. Absolute user paths were
genericized; the original evidence remains outside the repository.

---

## Key results

| Check | Result |
|---|---|
| Application launch (Kali) | Startup animation, dashboard, Guard and SOC start; 0 ERROR / 0 Traceback |
| Host monitoring / Guard / SOC feed | Live, real telemetry; simulation entries explicitly labelled `[SIMULATION]` |
| Live Host Scan page | Loads and runs a process-only scan |
| Filesystem CUSTOM scan | 3 files, 0 errors, `SAFE`, p = 0.32 (34.3 s sklearn warm-up of 36.9 s total) |
| Process-only scan | 65 processes, 0 errors, `SAFE`, p = 0.29, 1.24 s — path requirement fixed |
| GUI QUICK scan (Kali) | 4/19 sensors unavailable → `INCONCLUSIVE — LIMITED COVERAGE` |
| Error handling (5 mocked scenarios) | All non-`SAFE`; no fabricated probability |
| Release suite, Kali | 355 passed, 4 skipped, 0 failed in 306.34 s |
| Release suite, Windows | 357 passed, 2 skipped, 0 failed in 188.97 s (an earlier run: 356/3/0; an alternate run had one Tk teardown flake; see below) |
| Frozen Windows artifacts | 9/9 SHA-256 hashes unchanged |

---

## Contents

### Reports

- [FINAL_DEMO_REPORT.md](FINAL_DEMO_REPORT.md) — full audit: launch, features, scans,
  error handling, SOC data quality, tests, limitations, verdict.
- [SOC_DATA_QUALITY.md](SOC_DATA_QUALITY.md) — what is real telemetry and what is simulated;
  the `THREATS (24H)` conflation and clock-skew findings.
- [environment.txt](environment.txt) — host and guest versions, launch command, test
  invocation, frozen-artifact statement.
- [frozen_artifacts.sha256](frozen_artifacts.sha256) — recorded SHA-256 values for the nine
  frozen artifacts; verify from the repository root:
  `sha256sum -c docs/releases/v3.1.0/frozen_artifacts.sha256`.

### Screenshots (Kali, headless Xvfb)

All badge-bearing pages were re-captured on 2026-10-30 from the running v3.1.0 source tree;
the sidebar version badge reads `v3.1.0`. The startup frame is unchanged because the splash
screen does not render a version badge.

| File | Shows |
|---|---|
| [screenshots/startup_animation_1.png](screenshots/startup_animation_1.png) | Cinematic startup frame |
| [screenshots/dashboard.png](screenshots/dashboard.png) | Dashboard: Host Monitored, Guard Active, SOC feed with `[SIMULATION]` label |
| [screenshots/live_host_scan_page.png](screenshots/live_host_scan_page.png) | Live Host Scan page, idle 3D core |
| [screenshots/gui_scan_inconclusive.png](screenshots/gui_scan_inconclusive.png) | GUI QUICK scan result: `INCONCLUSIVE — LIMITED COVERAGE`, 4/19 sensors missing |
| [screenshots/dashboard_after_gui_scan.png](screenshots/dashboard_after_gui_scan.png) | Dashboard after the GUI scan |
| [screenshots/scan_audit_history.png](screenshots/scan_audit_history.png) | Persisted scan audit history |

### Logs

- `logs/final_scans_output.txt` — filesystem CUSTOM and process-only scan JSON.
- `logs/error_handling_results.txt` — five mocked failure scenarios.
- `logs/full_test_log.txt` — per-file Kali run (308 passed, 7 skipped in 99.21 s) for the
  LBS-1, scan-audit and process-only files.
- `logs/gui_audit_tests.log` — `test_scan_audit.py` re-run with a display: 12 passed.
- `logs/kali_release_suite.log` — 17-file release suite on Kali: 355 passed, 4 skipped.
- `logs/windows_release_suite_clean.log` — 17-file release suite on Windows: 357 passed,
  2 skipped.
- `logs/windows_release_suite_alternate_run.log` — alternate Windows run with the Tk
  teardown flake (`invalid command name "tcl_findLibrary"`); the failing test passes in
  isolation.
- `logs/app_startup.log` — startup sequence with 0 errors.

### Scripts

- `scripts/final_scans.py` — runs the two scans documented above.
- `scripts/error_handling.py` — mock-based failure scenarios; model files are not modified.

Both scripts had their absolute paths genericized (repo root resolved from `__file__`,
fixture created under the current user's home) before publication; the logic is unchanged.

---

## Reproduction

```bash
# Release suite (17 files, 359 tests)
python -m pytest -p no:cacheprovider -q \
  tests/test_lbs1_*.py tests/test_scan_audit.py tests/test_scan_engine_process_only.py \
  tests/test_inconclusive_handling.py tests/test_unified_dashboard.py

# Headless GUI launch
Xvfb :99 -screen 0 1600x1000x24 &
DISPLAY=:99 python3 app.py
```

## Caveats

- The GUI was exercised on a headless Xvfb display, not a physical Kali desktop.
- No detection accuracy is claimed. The model is `EXPERIMENTAL_SYNTHETIC_BASELINE_V1`;
  `SAFE` results on a clean host are model outputs, not proof of real-world detection.
- `QUICK`/`FULL` scans on Linux are `INCONCLUSIVE` by design while Windows-only sensors are
  missing.
- The SOC widgets have the two display caveats documented in
  [SOC_DATA_QUALITY.md](SOC_DATA_QUALITY.md); they do not affect scan verdicts.
- The alert store uses naive timestamps and can show clock-skew artifacts when shared
  between hosts in different time zones.

## Checksums

See [SHA256SUMS.txt](SHA256SUMS.txt). Verify with `sha256sum -c SHA256SUMS.txt` from this
directory.
