# SOC / Monitoring Data-Quality Report — Kali Final Demo Audit

Date: 2026-10-30 (guest clock EDT). Evidence: `dashboard.png`, `final_scans_output.txt`,
`app_startup.log`, guest `alerts/alerts.json`, and source at the cited lines.

## 1. What is genuinely live host telemetry

The MONITORING card is fed by `SOCMonitor` (`livemon/monitor.py`) with a 60 s refresh,
collecting from `livemon/telemetry.py` (`_collect_guard` ~line 560, network ~line 539,
events ~line 620). Verified in `dashboard.png`:

- Status line: "Auto-refresh every 60 s · latest scan: NOT_SCANNED"; LAST SUCCESSFUL
  UPDATE 29 s ago; NEXT REFRESH in 31 s; DATA QUALITY **LIVE**; MONITORING badge green.
- Telemetry chips shown available: Process enumeration, System CPU & memory,
  File metadata scope, Network connections, OS event channel, security services.
  `Registry telemetry (n/a)` is correctly shown as not applicable on Linux.
- File scope line matches code/config: monitored directories only, metadata only
  (size + mtime), depth 1, max 2,000 files per cycle.
- Header: **Host: Monitored** and **Guard: Active** (green), Guard Uptime 3 m.
  Guard state comes from the running `SentinelGuard` instance
  (`guard/sentinel_guard.py`, `is_running()`), not from a static label.

These values are computed from the live guest (psutil probes, file metadata,
connection table, capability probes); none of it is fabricated.

## 2. Real scan results (not SOC telemetry)

`final_scans_output.txt` records two scans executed on the guest via `ScanEngine`:

| Field | CUSTOM (fixture) | PROCESS-only |
|---|---|---|
| files_inspected | 3 | 0 |
| directories_inspected | 1 | 0 |
| files_skipped / filesystem_errors | 0 / 0 | 0 / 0 |
| processes_analyzed | 65 | 65 |
| ml_executed / ml_prediction / ml_probability | true / SAFE / 0.32 | true / SAFE / 0.29 |
| state / threat_level | safe / SAFE | safe / SAFE |
| model_source | EXPERIMENTAL_SYNTHETIC_BASELINE_V1 | same |
| scan_origin | DEMO_FIXTURE | DEMO_FIXTURE |

`scan_origin=DEMO_FIXTURE` marks these as harmless fixture scans run for this audit;
they are real engine executions with the real frozen model, not simulation events.

## 3. Simulated entries and how they are labeled

- The Live SOC Feed row visible in `dashboard.png` is
  `[SIMULATION] Suspicious Activity Detected` with the badge `[SANDBOX SIMULATION]`,
  description "Sandbox simulation triggered WARNING classification ... Result: WARNING
  [SIMULATION]". Code: `gui/pages/dashboard.py:2597-2604` prefixes `[SIMULATION]` and
  sets `source="Sandbox Simulation"`, `category="simulation"`. It originates from a
  controlled sandbox simulation alert persisted earlier; it is not a host detection.
- Demo mode is **OFF**: `demo_data.py:205-207` sets `DEMO_CONFIG["enabled"] = False`,
  and the guest interpreter confirmed `demo_mode_enabled=False`. The hardcoded demo
  dataset (`demo_data.py:13-101`, timestamps 2026-08-25) was not in use.
- No simulation entry is labeled as a real ransomware detection: every simulated record
  carries `[SIMULATION]` in the title and/or the SANDBOX badge, and source
  "Sandbox Simulation".

## 4. Data-quality findings (disclosed, not patched)

1. **RECENT SOC EVENTS shows stale, date-less history.** The three rows
   ("15:24 / 12:10 / 12:07 Host Scan: WARNING") are persisted records from
   `alerts/alerts.json`, dated **2026-10-24** (severity HIGH, source Fast Live Scan).
   The widget renders only HH:MM, so old alerts can look current
   (`gui/pages/dashboard.py:3515-3521`). The title format "Host Scan: ..." does not
   exist in the current source; these are legacy records retained in the store.

2. **"THREATS (24H) 84 crit/high" is not 84 real host threats.** Reproduced exactly with
   the telemetry formula (`livemon/telemetry.py:583-606`): 66 = alerts within the last
   24 h, plus 18 future-dated records = 84. Composition: **75 `[SIMULATION]`
   alerts + 9 `Fast Live Scan` alerts**, zero real ransomware detections. Two causes:
   (a) the window check `now - ts <= 86400` has no upper bound, so timestamps ahead of
   the current clock count; (b) the store is shared across host runs with naive
   timestamps — the host writes IST and the guest reads EDT, which produced the
   18 future-dated entries. The counter also does not exclude category=simulation.

3. **Scan tiles are session-scoped.** "Scans Today 0 / Threats Found 0 / Blocked/Guard 0"
   reflect this GUI session, in which scanning was driven through `ScanEngine` scripts
   rather than the GUI, so they are consistent rather than contradictory.

4. **`soc/` directory is empty.** SOC data is produced in-process by `livemon/`; there
   is no separate SOC service or external feed, and nothing here claims to be one.

## 5. Verdict for the demo

No simulated event is presented as a real ransomware detection; the feed is explicitly
labeled. Two dashboard elements need a spoken caveat or a later fix (not changed during
this audit, per the "no unnecessary source changes" rule): the date-less RECENT SOC
EVENTS list (stale 2026-10-24 alerts) and the THREATS (24H) tile, which includes
simulation and clock-skewed records. Neither affects scan verdict logic.
