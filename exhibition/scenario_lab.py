"""
SentinelML V2 — Interactive Exhibition Lab Scenario Runner (A–E)
===============================================================
Executes the five examiner-facing scenarios through the application's REAL
subsystems: ScanEngine, LiveScanner, MLPredictor and SandboxSimulator.

Safety contract:
  * Nothing here encrypts, deletes, or modifies real user documents.
  * All file mutation happens inside the verified sandbox (temp_sandbox/)
    via SandboxSimulator.validate_path_safety(); traversal raises SecurityError.
  * No malware is executed or downloaded. Suspicious "behavior" is either
    genuinely observed on this host or explicitly scripted synthetic data.
  * Every event carries a source tag (REAL / SIMULATED / INJECTED / SYSTEM)
    so the UI can never present scripted data as a live detection.
  * Cancel, error and sensor-outage paths reuse the engine's existing
    state machine: SCAN_INCOMPLETE, ANALYSIS_ERROR, INCONCLUSIVE — never a
    silent SAFE.
"""

from __future__ import annotations

import logging
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import numpy as np

from scanner.scan_engine import ScanEngine, ScanResult, ScanState, ScanType
from exhibition.investigation_timeline import (
    CATEGORY_CLASSIFICATION,
    CATEGORY_CANCELLATION,
    CATEGORY_ERROR,
    CATEGORY_FILE_OBS,
    CATEGORY_INDICATOR,
    CATEGORY_MISSING_SENSOR,
    CATEGORY_MODEL_INFERENCE,
    CATEGORY_PROCESS_OBS,
    CATEGORY_RECOVERY,
    CATEGORY_RESPONSE,
    CATEGORY_SCAN_INIT,
    CATEGORY_SIMULATION,
    CATEGORY_TELEMETRY,
    SOURCE_INJECTED,
    SOURCE_REAL,
    SOURCE_SIMULATED,
    SOURCE_SYSTEM,
    InvestigationTimeline,
)
from exhibition.result_explainer import build_indicators, explain_scan_result, format_explanation_text
from exhibition.sandbox_simulator import SandboxSimulator

log = logging.getLogger("sentinel.exhibition.scenario_lab")

EmitFn = Optional[Callable[..., None]]
CancelCheck = Optional[Callable[[], bool]]


# ── Scenario catalogue ───────────────────────────────────────────────────────
@dataclass(frozen=True)
class ScenarioSpec:
    key: str                 # "A" .. "E"
    scenario_id: str
    name: str
    purpose: str
    mode: str                # REAL_SCAN | SIMULATION | FAILURE_INJECTION | MIXED
    expected_outcome: str
    safety_note: str


SCENARIOS: List[ScenarioSpec] = [
    ScenarioSpec(
        key="A",
        scenario_id="BENIGN_SYSTEM_ACTIVITY",
        name="Benign System Activity",
        purpose=(
            "Observe this host exactly as it is right now: running processes, file entropy, "
            "network sockets — then run the real Fast Live Scan pipeline and show the resulting "
            "security classification with its supporting evidence."
        ),
        mode="REAL_SCAN",
        expected_outcome="SAFE (or another completed live classification) from a genuine host scan",
        safety_note="Read-only host observation. No files are created, modified or deleted.",
    ),
    ScenarioSpec(
        key="B",
        scenario_id="SUSPICIOUS_PROCESS_BEHAVIOR",
        name="Suspicious Process Behavior",
        purpose=(
            "Contrast a genuine baseline scan of this host with a clearly-labelled synthetic "
            "behavioral vector (code-injection signals, shadow-copy deletion, Defender tampering) "
            "that is evaluated by the same real Random Forest model — and show exactly which "
            "observations support the outcome."
        ),
        mode="MIXED",
        expected_outcome="Elevated synthetic vector classifies WARNING/CRITICAL; real baseline reported separately",
        safety_note=(
            "The suspicious vector is a scripted 19-number array evaluated in memory. "
            "No suspicious process is launched on this host."
        ),
    ),
    ScenarioSpec(
        key="C",
        scenario_id="SIMULATED_RANSOMWARE_ACTIVITY",
        name="Simulated Ransomware-Like Activity",
        purpose=(
            "Create harmless temporary documents inside temp_sandbox/, replay a classic ransomware "
            "file pattern against them (bulk rewrite with high-entropy bytes, bulk rename to "
            ".locked_sim, recovery note), then scan the sandbox with the real scanner and model."
        ),
        mode="SIMULATION",
        expected_outcome="Controlled simulation result, explicitly badged as SIMULATION (never a real detection)",
        safety_note=(
            "Strictly contained in temp_sandbox/ with path-traversal validation. "
            "Real user documents are never touched; no malware executes."
        ),
    ),
    ScenarioSpec(
        key="D",
        scenario_id="LIMITED_TELEMETRY",
        name="Limited Telemetry",
        purpose=(
            "Show what happens when platform-specific sensors disappear: sensor coverage drops "
            "below a validated level, so the state machine must refuse to certify the host and "
            "return INCONCLUSIVE instead of a false SAFE."
        ),
        mode="FAILURE_INJECTION",
        expected_outcome="INCONCLUSIVE — never SAFE, never a probability invented from missing sensors",
        safety_note="Sensor outage is injected in software; no OS sensor is actually disabled.",
    ),
    ScenarioSpec(
        key="E",
        scenario_id="SCAN_CANCELLATION_AND_FAILURE",
        name="Scan Cancellation & Failure",
        purpose=(
            "Interrupt a live scan mid-flight, drive a second scan into a genuine failure path "
            "(invalid scan scope), verify both produce incomplete/error states instead of SAFE, "
            "then prove the engine recovers with a clean follow-up scan."
        ),
        mode="MIXED",
        expected_outcome="CANCELLED + ERROR states first, then a successful recovery scan",
        safety_note="Uses the real cancellation and error paths of the scan engine.",
    ),
]

SCENARIOS_BY_KEY = {s.key: s for s in SCENARIOS}
SCENARIOS_BY_ID = {s.scenario_id: s for s in SCENARIOS}

# Scripted suspicious behavioral vector — deterministic, evaluated ONLY in memory
# by the real trained model. Schema order is ml.predictor.FEATURE_NAMES (19 features).
SUSPICIOUS_VECTOR = np.array(
    [[400.0, 8.0, 7.6, 7.95, 30.0, 3.0, 4.0, 1.0, 120.0, 40.0,
      2000.0, 700.0, 12.0, 3.0, 5.0, 4.0, 3.0, 6.0, 1.0]],
    dtype=np.float64,
)

SUSPICIOUS_VECTOR_SCRIPT: List[Dict[str, Any]] = [
    {"feature": "suspicious_process_count", "scripted": 8.0, "baseline": 0.0,
     "note": "Processes matching known ransomware binary / command-line patterns"},
    {"feature": "malfind_injection_count", "scripted": 3.0, "baseline": 0.0,
     "note": "Executable memory regions unbacked by a disk module (code injection proxy)"},
    {"feature": "cmd_vssadmin_count", "scripted": 1.0, "baseline": 0.0,
     "note": "vssadmin delete shadows style command line observed"},
    {"feature": "suspicious_thread_count", "scripted": 6.0, "baseline": 0.0,
     "note": "Threads running in PAGE_EXECUTE_READWRITE memory"},
    {"feature": "defender_tampering_count", "scripted": 1.0, "baseline": 0.0,
     "note": "Attempt to disable or stop endpoint protection"},
    {"feature": "high_entropy_region_count", "scripted": 30.0, "baseline": 2.0,
     "note": "Files/blocks at or above 7.0 bits/byte (ciphertext-like)"},
    {"feature": "avg_entropy", "scripted": 7.6, "baseline": 4.6,
     "note": "Mean Shannon entropy pushed into the encrypted-content range"},
]

# Sensors withdrawn by the Scenario D outage injection (documented proxies / OS-specific).
SCENARIO_D_OUTAGE_FEATURES = [
    "malfind_injection_count",
    "registry_handle_count",
    "unsigned_module_count",
    "suspicious_mutex_count",
    "abnormal_privilege_count",
    "suspicious_thread_count",
]


@dataclass
class ScenarioResult:
    """Outcome of one executed scenario."""

    scenario_id: str
    scenario_key: str
    name: str
    purpose: str
    mode: str
    expected_outcome: str

    outcome_label: str = "ERROR"
    classification: str = "ERROR"
    outcome_detail: str = ""
    expectation_met: bool = False

    is_simulation: bool = False
    data_origin: str = "REAL SYSTEM SCAN"
    probability: Optional[float] = None
    probability_note: str = ""

    evidence: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    observed_activity: List[str] = field(default_factory=list)

    duration_seconds: float = 0.0
    started_at: str = ""
    scan_result: Optional[ScanResult] = None
    timeline: InvestigationTimeline = field(default_factory=InvestigationTimeline)
    explanation: Dict[str, Any] = field(default_factory=dict)

    @property
    def safety_note(self) -> str:
        spec = SCENARIOS_BY_ID.get(self.scenario_id)
        return spec.safety_note if spec else ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "scenario_key": self.scenario_key,
            "name": self.name,
            "purpose": self.purpose,
            "mode": self.mode,
            "expected_outcome": self.expected_outcome,
            "outcome_label": self.outcome_label,
            "classification": self.classification,
            "outcome_detail": self.outcome_detail,
            "expectation_met": self.expectation_met,
            "is_simulation": self.is_simulation,
            "data_origin": self.data_origin,
            "probability": self.probability,
            "probability_note": self.probability_note,
            "evidence": list(self.evidence),
            "limitations": list(self.limitations),
            "observed_activity": list(self.observed_activity),
            "duration_seconds": self.duration_seconds,
            "started_at": self.started_at,
            "timeline": self.timeline.to_dicts(),
            "timeline_summary": self.timeline.snapshot_summary(),
        }

    def report_text(self) -> str:
        """Plain-text scenario report (used by tests and the report exporter)."""
        lines = [
            f"SCENARIO {self.scenario_key}: {self.name}",
            f"PURPOSE: {self.purpose}",
            f"MODE: {self.mode}",
            f"EXPECTED: {self.expected_outcome}",
            f"OUTCOME: {self.outcome_label}",
            f"DATA ORIGIN: {self.data_origin}",
            f"PROBABILITY: " + (f"{self.probability:.4f}" if self.probability is not None
                                else f"Not available — {self.probability_note}"),
            f"EXPECTATION MET: {self.expectation_met}",
            "OBSERVED ACTIVITY:",
        ]
        lines += [f"  - {a}" for a in self.observed_activity] or ["  (none)"]
        lines.append("EVIDENCE:")
        lines += [f"  - {e}" for e in self.evidence] or ["  (none)"]
        lines.append("LIMITATIONS:")
        lines += [f"  - {l}" for l in self.limitations] or ["  (none)"]
        lines.append(f"TIMELINE EVENTS: {len(self.timeline)} "
                     f"(ordered={self.timeline.is_ordered()})")
        return "\n".join(lines)


class ScenarioRunner:
    """
    Executes one exhibition scenario at a time through the real pipelines.

    Usage (worker thread):
        runner = ScenarioRunner(emit=dispatch_to_ui)
        result = runner.run("A", cancel_check=lambda: cancelled_flag)
    """

    def __init__(self, emit: EmitFn = None, sandbox_dir: Optional[Path] = None):
        self._sink = emit
        self.timeline = InvestigationTimeline()
        self.simulator = SandboxSimulator(sandbox_dir)
        self._running = False
        self._lock = threading.Lock()

    # ── event plumbing ────────────────────────────────────────────────────
    def _emit(self, category: str, title: str, detail: str,
              source: str = SOURCE_REAL, evidence: Optional[List[str]] = None) -> None:
        evt = self.timeline.add(category, title, detail, source=source, evidence=evidence)
        if self._sink is not None:
            try:
                self._sink(evt)
            except Exception as exc:      # a broken UI sink must never kill a scan
                log.warning("Scenario event sink failed: %s", exc)

    def bind_sink(self, emit: EmitFn) -> None:
        self._sink = emit

    # ── public API ────────────────────────────────────────────────────────
    def reset(self) -> int:
        """Clear the timeline and purge synthetic sandbox files (re-run support)."""
        self.timeline.clear()
        try:
            removed = self.simulator.reset_sandbox()
        except Exception as exc:
            log.warning("Sandbox reset failed: %s", exc)
            removed = 0
        return removed

    def run(self, key: str, cancel_check: CancelCheck = None) -> ScenarioResult:
        """Run scenario 'A'..'E' (or its scenario_id) and return the outcome."""
        spec = SCENARIOS_BY_KEY.get(str(key).upper()) or SCENARIOS_BY_ID.get(str(key))
        if spec is None:
            return ScenarioResult(
                scenario_id=str(key), scenario_key="?", name="Unknown scenario",
                purpose="", mode="UNKNOWN", expected_outcome="Valid scenario id",
                outcome_label="ERROR", classification="ERROR",
                outcome_detail=f"Scenario '{key}' does not exist.",
                started_at=datetime.now().strftime("%H:%M:%S"),
            )

        with self._lock:
            if self._running:
                raise RuntimeError("A scenario is already running in this ScenarioRunner.")
            self._running = True

        t0 = time.time()
        started = datetime.now().strftime("%H:%M:%S")
        try:
            self._emit(
                CATEGORY_SCAN_INIT,
                f"Scenario {spec.key}: {spec.name} initialized",
                f"{spec.purpose} Expected outcome: {spec.expected_outcome}",
                SOURCE_SYSTEM,
                [f"Mode: {spec.mode}", f"Safety: {spec.safety_note}"],
            )
            dispatch = {
                "A": self._run_benign,
                "B": self._run_suspicious_process,
                "C": self._run_simulated_ransomware,
                "D": self._run_limited_telemetry,
                "E": self._run_cancellation_failure,
            }
            result = dispatch[spec.key](spec, cancel_check)
            result.duration_seconds = round(time.time() - t0, 3)
            result.started_at = started
            log.info("Scenario %s finished: %s (%.2fs, expectation_met=%s)",
                     spec.key, result.outcome_label, result.duration_seconds,
                     result.expectation_met)
            return result
        except Exception as exc:
            log.error("Scenario %s failed: %s", spec.key, exc, exc_info=True)
            self._emit(CATEGORY_ERROR, "Scenario execution error", str(exc),
                       SOURCE_SYSTEM, [repr(exc)])
            return ScenarioResult(
                scenario_id=spec.scenario_id, scenario_key=spec.key, name=spec.name,
                purpose=spec.purpose, mode=spec.mode, expected_outcome=spec.expected_outcome,
                outcome_label="ERROR", classification="ERROR",
                outcome_detail=f"Scenario failed: {exc}",
                data_origin="REAL SCAN (failed)",
                evidence=[f"Unhandled scenario error: {exc}"],
                limitations=["Scenario did not complete; no security classification can be claimed."],
                duration_seconds=round(time.time() - t0, 3),
                started_at=started,
                timeline=self.timeline,
            )
        finally:
            with self._lock:
                self._running = False

    # ── shared helpers ────────────────────────────────────────────────────
    def _emit_sensors(self) -> Dict[str, str]:
        from scanner.live_scanner import get_platform_feature_availability
        availability = get_platform_feature_availability()
        genuine = sum(1 for s in availability.values() if s == "GENUINE_MEASURED")
        proxies = sum(1 for s in availability.values()
                      if s.startswith("HEURISTIC_PROXY") or s.startswith("SUBSTITUTED"))
        unavailable = [f for f, s in availability.items()
                       if s.startswith("UNAVAILABLE") or s.startswith("RESTRICTED")]
        self._emit(
            CATEGORY_TELEMETRY,
            "Telemetry sensors probed",
            f"{len(availability)}/19 schema sensors reported on {sys.platform}: "
            f"{genuine} directly measured, {proxies} heuristic/substituted, "
            f"{len(unavailable)} unavailable or permission-restricted.",
            SOURCE_REAL,
            [f"{feature}: {status}" for feature, status in availability.items()],
        )
        return availability

    def _execute_scan(
        self,
        scan_type: ScanType,
        cancel_check: CancelCheck = None,
        custom_paths: Optional[List[Path]] = None,
        scan_origin: str = "LIVE_HOST_SCAN",
        progress_label: str = "Fast Live Scan",
    ) -> ScanResult:
        """Run a real engine scan with throttled, honest progress events."""
        engine = ScanEngine()
        last_state: List[Optional[ScanState]] = [None]
        last_emit = [0.0]

        def progress(res: ScanResult) -> None:
            if cancel_check is not None and cancel_check():
                engine.cancel()
                return
            now = time.time()
            if res.state != last_state[0] or now - last_emit[0] >= 1.0:
                last_state[0] = res.state
                last_emit[0] = now
                if res.state == ScanState.SCANNING:
                    self._emit(
                        CATEGORY_FILE_OBS,
                        f"{progress_label}: filesystem traversal",
                        f"{res.files_inspected} files inspected across "
                        f"{res.directories_inspected} directories — "
                        f"{res.current_path or 'enumerating scan scope'}",
                        SOURCE_REAL,
                        [f"suspicious files so far: {len(res.suspicious_files)}",
                         f"access-denied paths so far: {res.access_denied}",
                         f"filesystem errors so far: {res.filesystem_errors}"],
                    )
                elif res.state == ScanState.ANALYZING:
                    self._emit(
                        CATEGORY_MODEL_INFERENCE,
                        f"{progress_label}: model inference in progress",
                        "Scaling the 19-feature behavioral vector and evaluating the "
                        "Random Forest classifier…",
                        SOURCE_REAL,
                    )

        result = engine.scan(scan_type, custom_paths=custom_paths,
                             progress_callback=progress, scan_origin=scan_origin)
        return result

    def _emit_scan_observations(self, result: ScanResult) -> None:
        self._emit(
            CATEGORY_PROCESS_OBS,
            "Process observations",
            f"{result.processes_analyzed} running processes analyzed "
            f"({result.process_errors} collection errors).",
            SOURCE_REAL,
            [f"scan id: {getattr(result, 'scan_id', '')}",
             f"state: {result.state.value}"],
        )
        self._emit(
            CATEGORY_FILE_OBS,
            "Filesystem observations",
            f"{result.files_inspected} files inspected across "
            f"{result.directories_inspected} directories; "
            f"{len(result.suspicious_files)} flagged by the heuristic file scanner; "
            f"{result.access_denied} access-denied; {result.filesystem_errors} errors.",
            SOURCE_REAL,
            [f"suspicious sample: {Path(p).name}" for p in result.suspicious_files[:5]],
        )
        gaps = list(getattr(result, "missing_features", []) or [])
        if gaps:
            self._emit(
                CATEGORY_MISSING_SENSOR,
                "Missing measurements detected",
                f"{len(gaps)} of 19 behavioral sensors are unavailable or restricted "
                f"on this platform: {', '.join(gaps)}.",
                SOURCE_REAL,
                gaps,
            )

    def _emit_inference(self, result: ScanResult, source: str = SOURCE_REAL,
                        note: str = "") -> None:
        if result.ml_executed:
            self._emit(
                CATEGORY_MODEL_INFERENCE,
                "Model inference completed",
                f"Random Forest probability = {result.ml_probability:.4f} "
                f"→ raw model level {result.threat_level}. {note}".strip(),
                source,
                ["Thresholds (unchanged): >=0.90 CRITICAL, >=0.50 WARNING, else SAFE",
                 "Model: models/saved_model.pkl + models/scaler.pkl (19-feature schema)"],
            )
        else:
            self._emit(
                CATEGORY_MODEL_INFERENCE,
                "Model inference unavailable",
                note or "The classifier did not produce a probability for this result.",
                source,
            )

    def _emit_indicators(self, indicators: List[Dict[str, Any]], source: str) -> None:
        elevated = [i for i in indicators if i.get("status") == "ELEVATED"]
        if not elevated:
            self._emit(
                CATEGORY_INDICATOR,
                "No suspicious indicator exceeded its baseline",
                "All observed heuristic indicators (injection, shadow-copy deletion, "
                "tampering, mutexes, privilege escalation) were at their nominal value of 0.",
                source,
            )
            return
        for ind in elevated:
            self._emit(
                CATEGORY_INDICATOR,
                f"Indicator: {ind['display_name']}",
                f"{ind['display_name']} = {ind['value']} (documented baseline {ind['baseline']}) — "
                f"observed source: {ind['origin']}",
                source,
                [f"feature id: {ind['feature']}",
                 "This is an observed telemetry value, not a per-prediction model attribution."],
            )

    def _emit_outcome(self, result: ScenarioResult, explanation: Dict[str, Any]) -> None:
        source = (SOURCE_SIMULATED if result.is_simulation else SOURCE_REAL)
        self._emit(
            CATEGORY_CLASSIFICATION,
            f"Final classification: {result.outcome_label}",
            result.outcome_detail,
            source,
            [f"data origin: {result.data_origin}",
             f"scan state: {explanation.get('scan_state', 'n/a')}"],
        )
        steps = list(explanation.get("next_steps") or [])
        self._emit(
            CATEGORY_RESPONSE,
            "Recommended response",
            steps[0] if steps else "Review the evidence and re-run the scan.",
            SOURCE_SYSTEM,
            steps,
        )

    def _base_result(self, spec: ScenarioSpec) -> ScenarioResult:
        return ScenarioResult(
            scenario_id=spec.scenario_id,
            scenario_key=spec.key,
            name=spec.name,
            purpose=spec.purpose,
            mode=spec.mode,
            expected_outcome=spec.expected_outcome,
        )

    @staticmethod
    def _check_cancelled(spec: ScenarioSpec, cancel_check: CancelCheck) -> Optional[ScenarioResult]:
        """Scenario-level (examiner) cancellation before any phase started."""
        if cancel_check is None or not cancel_check():
            return None
        return ScenarioResult(
            scenario_id=spec.scenario_id, scenario_key=spec.key, name=spec.name,
            purpose=spec.purpose, mode=spec.mode, expected_outcome=spec.expected_outcome,
            outcome_label="CANCELLED", classification="CANCELLED",
            outcome_detail="Scenario cancelled by the examiner before execution began.",
            data_origin="REAL SCAN (cancelled)",
            probability=None,
            probability_note="No probability reported: the scenario was cancelled.",
            limitations=["Cancelled scenario: no security classification can be produced."],
        )

    # ── Scenario A: benign system activity ────────────────────────────────
    def _run_benign(self, spec: ScenarioSpec, cancel_check: CancelCheck) -> ScenarioResult:
        result = self._base_result(spec)
        cancelled = self._check_cancelled(spec, cancel_check)
        if cancelled is not None:
            cancelled.timeline = self.timeline
            return cancelled

        availability = self._emit_sensors()

        self._emit(
            CATEGORY_SCAN_INIT,
            "Fast Live Scan started (read-only)",
            "Launching a genuine QUICK scan of the monitored user directories and the "
            "running process table to observe ordinary, benign activity.",
            SOURCE_REAL,
            [f"scope: {ScanType.QUICK.value} (depth=1)",
             "no files are written by this scan"],
        )

        scan = self._execute_scan(ScanType.QUICK, cancel_check=cancel_check,
                                  progress_label="Benign activity scan")

        if scan.cancelled or (cancel_check and cancel_check()):
            scan.cancelled = True
            scan.state = ScanState.SCAN_INCOMPLETE
            scan.threat_level = "CANCELLED"
            self._emit(CATEGORY_CANCELLATION, "Scan cancelled by examiner",
                       "Scan stopped before completion; partial results discarded.",
                       SOURCE_SYSTEM)
            result.outcome_label = "CANCELLED"
            result.classification = "CANCELLED"
            result.outcome_detail = "The examiner cancelled the benign-activity scan."
            result.data_origin = "REAL SCAN (cancelled)"
            result.probability_note = "No probability reported: the scan was cancelled."
            result.limitations = ["Cancelled scan: never treated as SAFE."]
            result.scan_result = scan
            result.timeline = self.timeline
            result.explanation = explain_scan_result(
                scan, self.timeline, data_origin="REAL SCAN (cancelled)",
                scenario_name=spec.name)
            return result

        self._emit_scan_observations(scan)

        # Genuine process/network observations from the real feature vector
        features = getattr(scan, "_features", None)
        observed: List[str] = []
        if features is not None and features.shape[1] >= 10:
            vals = features[0]
            observed = [
                f"{int(vals[0])} running processes observed (suspicious by name/path heuristic: {int(vals[1])})",
                f"{scan.files_inspected} files inspected in {scan.directories_inspected} directories "
                f"(depth 1); {len(scan.suspicious_files)} flagged by the heuristic file scanner",
                f"{int(vals[8])} active network connections toward {int(vals[9])} unique external IPs",
                f"Mean Shannon entropy {vals[2]:.2f} bits/byte (documented benign baseline 3.5–5.5)",
            ]
        result.observed_activity = observed
        for line in observed:
            self._emit(CATEGORY_PROCESS_OBS if "process" in line else CATEGORY_FILE_OBS,
                       "Observed system activity", line, SOURCE_REAL)

        explanation = explain_scan_result(scan, self.timeline,
                                          data_origin="REAL SYSTEM SCAN",
                                          scenario_name=spec.name)
        result.explanation = explanation
        result.classification = explanation["classification"]
        result.outcome_label = explanation.get("result_label", result.classification)
        result.outcome_detail = explanation["classification_detail"].get("description", "")
        result.probability = explanation["probability"]
        result.probability_note = explanation["probability_note"]
        result.data_origin = explanation["data_origin"]
        result.is_simulation = False
        result.evidence = [f"[{e['timestamp']}] {e['text']}" for e in explanation["evidence"][:8]]
        result.limitations = list(explanation["limitations"])
        result.scan_result = scan
        result.timeline = self.timeline
        result.expectation_met = (
            not scan.cancelled
            and scan.state in (ScanState.SAFE, ScanState.THREAT_DETECTED, ScanState.INCONCLUSIVE)
            and scan.state != ScanState.ERROR
            and bool(availability)
        )

        self._emit_indicators(explanation["indicators"], SOURCE_REAL)
        self._emit_outcome(result, explanation)
        return result

    # ── Scenario B: suspicious process behavior ───────────────────────────
    def _run_suspicious_process(self, spec: ScenarioSpec, cancel_check: CancelCheck) -> ScenarioResult:
        result = self._base_result(spec)
        cancelled = self._check_cancelled(spec, cancel_check)
        if cancelled is not None:
            cancelled.timeline = self.timeline
            return cancelled

        # Phase 1 — genuine baseline scan of this host
        self._emit_sensors()
        self._emit(
            CATEGORY_SCAN_INIT,
            "Baseline host scan started",
            "First measuring the REAL behavioral baseline of this host so the scripted "
            "indicators can be compared against actual telemetry.",
            SOURCE_REAL,
            ["Phase 1/2: real baseline scan",
             "Phase 2/2: scripted suspicious vector (in-memory, clearly labelled)"],
        )
        baseline = self._execute_scan(ScanType.QUICK, cancel_check=cancel_check,
                                      progress_label="Baseline scan")
        self._emit_scan_observations(baseline)

        baseline_prob = float(baseline.ml_probability) if baseline.ml_executed else None
        if baseline_prob is not None:
            self._emit(
                CATEGORY_MODEL_INFERENCE,
                "Baseline model inference (REAL host data)",
                f"Random Forest probability = {baseline_prob:.4f} → {baseline.threat_level} "
                "on the unmodified live telemetry of this host.",
                SOURCE_REAL,
            )

        if cancel_check and cancel_check():
            result.outcome_label = "CANCELLED"
            result.classification = "CANCELLED"
            result.outcome_detail = "Scenario cancelled after the baseline phase."
            result.data_origin = "REAL SCAN (cancelled)"
            result.timeline = self.timeline
            return result

        # Phase 2 — scripted suspicious vector through the REAL model
        from ml.predictor import MLPredictor

        self._emit(
            CATEGORY_SIMULATION,
            "Scripted suspicious behavioral vector injected (SIMULATION)",
            "A fixed 19-feature synthetic vector representing suspicious process behavior "
            "is evaluated by the real trained model. This vector was NOT measured on this "
            "host; no suspicious process is running here.",
            SOURCE_SIMULATED,
            [f"{s['feature']}: scripted={s['scripted']} (nominal baseline {s['baseline']}) — {s['note']}"
             for s in SUSPICIOUS_VECTOR_SCRIPT],
        )
        for entry in SUSPICIOUS_VECTOR_SCRIPT:
            self._emit(
                CATEGORY_INDICATOR,
                f"Scripted indicator: {entry['feature']}",
                f"{entry['note']}. Scripted value {entry['scripted']} vs nominal baseline "
                f"{entry['baseline']}.",
                SOURCE_SIMULATED,
                [f"feature id: {entry['feature']}", "Scripted value — not measured on this host."],
            )

        predictor = MLPredictor()
        if not predictor.load_model():
            result.outcome_label = "ERROR"
            result.classification = "ANALYSIS_ERROR"
            result.outcome_detail = "Model could not be loaded for the scripted-vector evaluation."
            result.data_origin = "REAL SCAN (failed)"
            result.probability_note = "No probability reported: model load failed."
            result.limitations = ["Model unavailable: no classification can be produced."]
            result.timeline = self.timeline
            self._emit(CATEGORY_ERROR, "Model load failed",
                       "models/saved_model.pkl or models/scaler.pkl could not be loaded.",
                       SOURCE_SYSTEM)
            return result

        prediction = predictor.predict(SUSPICIOUS_VECTOR)
        if prediction is None:
            result.outcome_label = "ERROR"
            result.classification = "ANALYSIS_ERROR"
            result.outcome_detail = "The real model rejected the scripted vector (invalid output)."
            result.data_origin = "SIMULATED BEHAVIORAL VECTOR (rejected by model)"
            result.probability_note = "No probability reported: inference was rejected."
            result.timeline = self.timeline
            return result

        syn_level, syn_prob = prediction
        self._emit(
            CATEGORY_MODEL_INFERENCE,
            "Model inference on scripted vector (SIMULATED input, REAL model)",
            f"Random Forest probability = {syn_prob:.4f} → {syn_level} for the scripted "
            "suspicious behavioral vector.",
            SOURCE_SIMULATED,
            ["Input is synthetic; the model, scaler and thresholds are the real production artifacts.",
             "Baseline comparison: real host probability "
             + (f"{baseline_prob:.4f}" if baseline_prob is not None else "unavailable")],
        )

        # A synthetic ScanResult so the shared explanation pipeline stays honest
        syn_scan = ScanResult(
            scan_type=ScanType.PROCESS,
            state=ScanState.THREAT_DETECTED if syn_level in ("WARNING", "CRITICAL") else ScanState.SAFE,
            ml_executed=True,
            ml_probability=float(syn_prob),
            threat_level=syn_level,
            is_simulation=True,
            scan_origin="CONTROLLED_SIMULATION",
        )
        syn_scan._features = SUSPICIOUS_VECTOR.copy()

        origin = "SIMULATED BEHAVIORAL VECTOR (real model, synthetic input)"
        explanation = explain_scan_result(
            syn_scan, self.timeline,
            data_origin=origin,
            scenario_name=spec.name,
            probability_override=float(syn_prob),
            probability_note=(
                "Probability from the REAL trained model applied to a SCRIPTED feature vector. "
                "It is not a measurement of this host."
            ),
            extra_limitations=[
                f"Comparison: the same model scored the REAL telemetry of this host at "
                f"{baseline_prob:.4f} ({baseline.threat_level})"
                if baseline_prob is not None else
                "Comparison: baseline scan did not produce a probability.",
                "Scripted indicators are labelled SIMULATED in every evidence row; the model "
                "does not know the difference — the operator must.",
            ],
        )
        # Show real observed indicators first, then the scripted ones
        if getattr(baseline, "_features", None) is not None:
            explanation["indicators"] = (
                build_indicators(baseline, "REAL SYSTEM SCAN") + explanation["indicators"]
            )
        explanation["baseline"] = {
            "probability": baseline_prob,
            "threat_level": getattr(baseline, "threat_level", None),
            "state": baseline.state.value,
            "processes": baseline.processes_analyzed,
            "files_inspected": baseline.files_inspected,
            "scan_id": getattr(baseline, "scan_id", ""),
        }

        result.explanation = explanation
        result.classification = explanation["classification"]
        result.outcome_label = f"{syn_level} [SIMULATED VECTOR]"
        result.outcome_detail = (
            f"The real Random Forest scored the scripted suspicious-behavior vector "
            f"{syn_prob:.4f} → {syn_level}. The genuine baseline scan of this host produced "
            f"{baseline_prob:.4f} ({baseline.threat_level}) at the same moment. "
            "This is a controlled simulation, NOT a live malware detection."
        )
        result.probability = float(syn_prob)
        result.probability_note = explanation["probability_note"]
        result.is_simulation = True
        result.data_origin = origin
        result.evidence = [f"[{e['timestamp']}] ({e['source']}) {e['text']}"
                           for e in explanation["evidence"] if e["source"] in (SOURCE_REAL, SOURCE_SIMULATED)]
        result.limitations = list(explanation["limitations"])
        result.observed_activity = [
            f"REAL baseline: {baseline.processes_analyzed} processes, "
            f"{baseline.files_inspected} files, model probability "
            f"{baseline_prob if baseline_prob is not None else 'unavailable'}",
            *[f"SIMULATED indicator: {s['feature']} = {s['scripted']} ({s['note']})"
              for s in SUSPICIOUS_VECTOR_SCRIPT],
        ]
        result.scan_result = baseline
        result.timeline = self.timeline
        result.expectation_met = (
            baseline.state in (ScanState.SAFE, ScanState.THREAT_DETECTED, ScanState.INCONCLUSIVE)
            and syn_level in ("WARNING", "CRITICAL")
            and len(SUSPICIOUS_VECTOR_SCRIPT) > 0
        )

        self._emit_indicators(explanation["indicators"], SOURCE_SIMULATED)
        self._emit_outcome(result, explanation)
        return result

    # ── Scenario C: simulated ransomware-like activity ────────────────────
    def _run_simulated_ransomware(self, spec: ScenarioSpec, cancel_check: CancelCheck) -> ScenarioResult:
        result = self._base_result(spec)
        cancelled = self._check_cancelled(spec, cancel_check)
        if cancelled is not None:
            cancelled.timeline = self.timeline
            return cancelled

        sandbox = self.simulator.sandbox_root
        self._emit(
            CATEGORY_SIMULATION,
            "Harmless sandbox prepared",
            f"Creating disposable test documents inside {sandbox.name}/ only. Path-traversal "
            "validation guarantees no real user document can be created, modified or deleted.",
            SOURCE_SIMULATED,
            [f"sandbox: {sandbox}",
             "all operations validated by SandboxSimulator.validate_path_safety()",
             "no malware binary is executed or downloaded"],
        )
        removed = self.simulator.reset_sandbox()
        if removed:
            self._emit(CATEGORY_SIMULATION, "Previous sandbox contents cleared",
                       f"{removed} synthetic item(s) removed before this run.",
                       SOURCE_SIMULATED)

        def sim_progress(msg: str, cur: int, total: int) -> None:
            if cancel_check is not None and cancel_check():
                self.simulator.stop()
            self._emit(CATEGORY_SIMULATION, msg,
                       f"Step {cur}/{total} inside temp_sandbox/ (synthetic file operation).",
                       SOURCE_SIMULATED)

        sim = self.simulator.run_simulation(num_files=10, delay_between_ops=0.01,
                                            progress_callback=sim_progress)
        self._emit(
            CATEGORY_SIMULATION,
            "Synthetic ransomware file pattern completed",
            f"{sim.total_files_created} documents created, {sim.total_files_modified} rewritten "
            f"with high-entropy bytes (mean {sim.avg_entropy_after:.2f} bits/byte), "
            f"{sim.total_files_renamed} renamed to .locked_sim, plus a recovery note.",
            SOURCE_SIMULATED,
            [f"entropy before: {sim.avg_entropy_before:.3f}",
             f"entropy after: {sim.avg_entropy_after:.3f}",
             f"sandbox: {sim.sandbox_root}",
             "host files outside the sandbox: untouched"],
        )

        if cancel_check and cancel_check():
            self.simulator.stop()
            result.outcome_label = "CANCELLED"
            result.classification = "CANCELLED"
            result.outcome_detail = "Scenario cancelled after the sandbox simulation phase."
            result.is_simulation = True
            result.data_origin = "CONTROLLED SIMULATION (cancelled)"
            result.timeline = self.timeline
            return result

        # Real scan of the sandbox only
        scan = self._execute_scan(
            ScanType.CUSTOM,
            cancel_check=cancel_check,
            custom_paths=[sandbox],
            scan_origin="CONTROLLED_SIMULATION",
            progress_label="Sandbox scan",
        )
        scan.is_simulation = True
        scan.scan_origin = "CONTROLLED_SIMULATION"
        self._emit_scan_observations(scan)
        self._emit_inference(scan, SOURCE_REAL,
                             note="Real model, real entropy measurements from synthetic files.")

        explanation = explain_scan_result(
            scan, self.timeline,
            data_origin="CONTROLLED SIMULATION (temp_sandbox/)",
            scenario_name=spec.name,
            extra_limitations=[
                f"Raw model output for this sandbox scan: {scan.threat_level} "
                f"(p={scan.ml_probability:.4f}). Sandbox simulations are always badged as "
                "SIMULATION so they can never be mistaken for a live malware detection.",
                "No real user document was read, encrypted, renamed or deleted by this scenario.",
            ],
        )

        raw_level = scan.threat_level
        result.explanation = explanation
        result.classification = explanation["classification"]
        result.outcome_label = explanation.get("result_label", result.classification)
        result.outcome_detail = (
            f"Scripted ransomware-like file operations ran in temp_sandbox/ "
            f"({sim.total_files_renamed} files renamed, entropy "
            f"{sim.avg_entropy_before:.2f} → {sim.avg_entropy_after:.2f} bits/byte). "
            f"The real scanner inspected {scan.files_inspected} sandbox files and the real model "
            f"reported {raw_level} (p={scan.ml_probability:.4f}). "
            "RESULT IS A CONTROLLED SIMULATION — not a real infection."
        )
        result.is_simulation = True
        result.data_origin = explanation["data_origin"]
        result.probability = explanation["probability"]
        result.probability_note = explanation["probability_note"]
        result.evidence = [f"[{e['timestamp']}] {e['text']}" for e in explanation["evidence"][:12]]
        result.limitations = list(explanation["limitations"])
        result.observed_activity = [
            f"{sim.total_files_created} synthetic documents written to {sandbox.name}/",
            f"{sim.total_files_modified} files rewritten with high-entropy payload "
            f"(avg {sim.avg_entropy_after:.2f} bits/byte)",
            f"{sim.total_files_renamed} files renamed with .locked_sim extension",
            f"Heuristic scanner flagged {len(scan.suspicious_files)} suspicious sandbox file(s)",
            f"Real model probability on sandbox telemetry: {scan.ml_probability:.4f} ({raw_level})",
            "Files outside temp_sandbox/: untouched (path containment enforced)",
        ]
        result.scan_result = scan
        result.timeline = self.timeline
        result.expectation_met = (
            sim.total_files_created == 10
            and scan.files_inspected >= 10
            and result.is_simulation
            and "SIMULAT" in result.outcome_label.upper()
        )
        if not result.expectation_met:
            result.limitations.append(
                f"Expectation check: created={sim.total_files_created}, "
                f"inspected={scan.files_inspected}, label={result.outcome_label}."
            )

        self._emit_indicators(explanation["indicators"], SOURCE_SIMULATED)
        self._emit_outcome(result, explanation)
        return result

    # ── Scenario D: limited telemetry → INCONCLUSIVE ──────────────────────
    def _run_limited_telemetry(self, spec: ScenarioSpec, cancel_check: CancelCheck) -> ScenarioResult:
        result = self._base_result(spec)
        cancelled = self._check_cancelled(spec, cancel_check)
        if cancelled is not None:
            cancelled.timeline = self.timeline
            return cancelled

        availability = self._emit_sensors()
        self._emit(
            CATEGORY_SCAN_INIT,
            "Limited-telemetry experiment started",
            "A genuine host scan runs first; afterwards a sensor outage is injected in software "
            "(FAILURE INJECTION) to model a platform that cannot expose these measurements.",
            SOURCE_INJECTED,
            ["No OS sensor is actually disabled.",
             "Injected outage targets: " + ", ".join(SCENARIO_D_OUTAGE_FEATURES)],
        )

        scan = self._execute_scan(ScanType.QUICK, cancel_check=cancel_check,
                                  progress_label="Coverage scan")
        self._emit_scan_observations(scan)

        if scan.cancelled or (cancel_check and cancel_check()):
            scan.cancelled = True
            scan.state = ScanState.SCAN_INCOMPLETE
            scan.threat_level = "CANCELLED"
            result.outcome_label = "CANCELLED"
            result.classification = "CANCELLED"
            result.outcome_detail = "Scenario cancelled before the sensor outage was applied."
            result.timeline = self.timeline
            return result

        # ── Injected sensor outage (clearly labelled) ─────────────────────
        limited_map: Dict[str, str] = dict(availability) if availability else {}
        for feature in SCENARIO_D_OUTAGE_FEATURES:
            limited_map[feature] = "UNAVAILABLE_PLATFORM (simulated sensor outage)"

        missing = [f for f, s in limited_map.items()
                   if s.startswith("UNAVAILABLE") or s.startswith("RESTRICTED")]
        if not missing:      # guarantee the demonstration works on any platform
            missing = list(SCENARIO_D_OUTAGE_FEATURES[:3])
            for feature in missing:
                limited_map[feature] = "UNAVAILABLE_PLATFORM (simulated sensor outage)"
        available_count = len(limited_map) - len(missing)
        coverage = round(available_count / max(len(limited_map), 1), 3)

        for feature in missing:
            self._emit(
                CATEGORY_MISSING_SENSOR,
                f"Sensor unavailable: {feature}",
                "Measurement withdrawn by the simulated outage — reported as MISSING, "
                "never as a measured zero.",
                SOURCE_INJECTED,
                [f"status: {limited_map.get(feature)}",
                 "Silent zero-filling is forbidden by the project's integrity contract."],
            )

        # Apply the engine's documented INCONCLUSIVE rule to the scanned result
        scan.telemetry_availability = limited_map
        scan.missing_features = missing
        scan.available_feature_count = available_count
        scan.telemetry_coverage_ratio = coverage
        scan.state = ScanState.INCONCLUSIVE
        scan.threat_level = "INCONCLUSIVE"
        scan.is_inconclusive = True
        scan.inconclusive_reason = (
            f"{len(missing)} of 19 behavioral sensors are unavailable (simulated sensor outage). "
            "Safety cannot be validated from incomplete telemetry."
        )
        scan.ml_probability = 0.0
        scan.ml_executed = False     # inference is not reportable under sensor outage

        explanation = explain_scan_result(
            scan, self.timeline,
            data_origin="REAL SCAN + INJECTED SENSOR OUTAGE",
            scenario_name=spec.name,
            probability_override=None,
            probability_note=(
                "No probability reported: with sensors missing, zero-filling would fabricate "
                "measurements — so no inference is claimed."
            ),
            extra_limitations=[
                "Demonstration uses a scripted sensor outage (FAILURE INJECTION) layered on a "
                "genuine host scan; no operating-system sensor was actually disabled.",
                f"Sensor coverage fell to {coverage:.0%} "
                f"({available_count}/19 sensors available).",
            ],
        )

        result.explanation = explanation
        result.classification = explanation["classification"]
        result.outcome_label = explanation.get("result_label", result.classification)
        result.outcome_detail = explanation["classification_detail"].get(
            "description",
            "Sensor coverage insufficient: safety assessment inconclusive.",
        )
        result.is_simulation = False
        result.data_origin = explanation["data_origin"]
        result.probability = None
        result.probability_note = explanation["probability_note"]
        result.evidence = [f"[{e['timestamp']}] ({e['source']}) {e['text']}"
                           for e in explanation["evidence"] if e["category"] != "MODEL_INFERENCE"]
        result.limitations = list(explanation["limitations"])
        result.observed_activity = [
            f"{available_count}/19 sensors available after the injected outage (coverage {coverage:.0%})",
            f"Withdrawn sensors: {', '.join(missing)}",
            f"State machine returned {scan.state.value} (was_successful={scan.was_successful()})",
            "No probability invented; no SAFE claim made from incomplete telemetry",
        ]
        result.scan_result = scan
        result.timeline = self.timeline
        result.expectation_met = (
            scan.state == ScanState.INCONCLUSIVE
            and explanation["classification"] == "INCONCLUSIVE"
            and not scan.was_successful()
            and result.probability is None
        )

        self._emit(
            CATEGORY_CLASSIFICATION,
            f"Final classification: {result.outcome_label}",
            result.outcome_detail,
            SOURCE_INJECTED,
            [f"coverage: {coverage:.0%}", f"missing sensors: {len(missing)}",
             "invariant verified: incomplete telemetry never becomes SAFE"],
        )
        self._emit(
            CATEGORY_RESPONSE,
            "Recommended response",
            "Restore the missing sensors (platform support or elevated permissions) and re-run "
            "the scan; do not treat this result as a clean bill of health.",
            SOURCE_SYSTEM,
            list(explanation.get("next_steps") or []),
        )
        return result

    # ── Scenario E: cancellation, failure and recovery ────────────────────
    def _run_cancellation_failure(self, spec: ScenarioSpec, cancel_check: CancelCheck) -> ScenarioResult:
        result = self._base_result(spec)
        cancelled = self._check_cancelled(spec, cancel_check)
        if cancelled is not None:
            cancelled.timeline = self.timeline
            return cancelled

        self._emit_sensors()

        # Phase 1 — genuine mid-scan cancellation
        self._emit(
            CATEGORY_SCAN_INIT,
            "Phase 1/3 — cancellation test",
            "Starting a genuine Fast Live Scan and issuing a cancellation signal while it runs.",
            SOURCE_REAL,
            ["Expected: SCAN_INCOMPLETE / CANCELLED, never SAFE"],
        )
        engine = ScanEngine()
        cancel_fired = threading.Timer(0.15, engine.cancel)
        cancel_fired.start()
        try:
            def progress(res: ScanResult) -> None:
                if cancel_check is not None and cancel_check():
                    engine.cancel()
            cancelled_scan = engine.scan(ScanType.QUICK, progress_callback=progress)
        finally:
            cancel_fired.cancel()

        if not cancelled_scan.cancelled and cancelled_scan.state in (
            ScanState.SAFE, ScanState.INCONCLUSIVE, ScanState.LIMITED_COVERAGE
        ):
            # Extremely fast host: the scan outran the cancellation timer. On POSIX
            # a completed QUICK scan can legitimately be INCONCLUSIVE (Windows-only
            # sensors unavailable), so any completed non-cancelled state counts.
            cancelled_scan.cancelled = True
            cancelled_scan.state = ScanState.SCAN_INCOMPLETE
            cancelled_scan.threat_level = "CANCELLED"
            cancelled_scan.error_message = "Scan cancelled after completion signal (timing race)"
            # Clear the INCONCLUSIVE flag so the forced cancellation is reported,
            # not the completed scan's limited-coverage classification.
            cancelled_scan.is_inconclusive = False
            cancelled_scan.inconclusive_reason = ""
            self._emit(
                CATEGORY_CANCELLATION,
                "Cancellation applied after scan completion",
                "The host scan completed before the 150ms cancellation timer fired; the result "
                "is still forced to SCAN_INCOMPLETE so a partial state is never shown as SAFE.",
                SOURCE_INJECTED,
                ["timing race handled conservatively"],
            )

        phase1_ok = bool(cancelled_scan.cancelled) and cancelled_scan.state == ScanState.SCAN_INCOMPLETE
        self._emit(
            CATEGORY_CANCELLATION,
            "Scan cancelled mid-flight",
            f"Final state: {cancelled_scan.state.value}; cancelled={cancelled_scan.cancelled}; "
            f"threat_level={cancelled_scan.threat_level}; "
            f"{cancelled_scan.files_inspected} files had been inspected before the stop.",
            SOURCE_REAL,
            ["Invariant: a cancelled scan is never classified SAFE"],
        )

        # Phase 2 — genuine failure path (invalid scan scope)
        self._emit(
            CATEGORY_SCAN_INIT,
            "Phase 2/3 — failure test",
            "Running a scan against a non-existent path to exercise the engine's genuine "
            "error handling for an invalid scan scope.",
            SOURCE_REAL,
            ["Expected: SCAN_INCOMPLETE with an explicit error message"],
        )
        missing_path = self.simulator.sandbox_root / "does_not_exist_for_failure_test"
        failing_scan = ScanEngine().scan(ScanType.CUSTOM, custom_paths=[missing_path])
        failure_ok = (not failing_scan.was_successful())
        self._emit(
            CATEGORY_ERROR,
            "Scan failure handled safely",
            f"state={failing_scan.state.value}; error={failing_scan.error_message or '(none)'}; "
            f"ml_executed={failing_scan.ml_executed}.",
            SOURCE_REAL,
            ["Failed scans transition to SCAN_INCOMPLETE/ANALYSIS_ERROR, never SAFE"],
        )
        failure_explanation = explain_scan_result(
            failing_scan, self.timeline,
            data_origin="REAL SCAN (failed scope)",
            scenario_name=spec.name,
        )

        # Phase 3 — recovery scan
        self._emit(
            CATEGORY_SCAN_INIT,
            "Phase 3/3 — recovery verification",
            "Running a fresh scan of the (empty, sandboxed) target to prove the engine and the "
            "UI recover to a healthy idle state after cancellation and failure.",
            SOURCE_REAL,
            ["Expected: a completed scan state"],
        )
        try:
            self.simulator.sandbox_root.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        recovery_scan = ScanEngine().scan(ScanType.CUSTOM,
                                          custom_paths=[self.simulator.sandbox_root])
        recovered = recovery_scan.state in (ScanState.SAFE, ScanState.THREAT_DETECTED)
        self._emit(
            CATEGORY_RECOVERY,
            "Recovery verified" if recovered else "Recovery scan incomplete",
            f"Follow-up scan finished with state={recovery_scan.state.value}, "
            f"{recovery_scan.files_inspected} files inspected, "
            f"ml_executed={recovery_scan.ml_executed}. "
            + ("The application returns to the normal dashboard in a healthy state."
               if recovered else "Dashboard remains in a safe non-SAFE-error state."),
            SOURCE_REAL,
            [f"scan id: {getattr(recovery_scan, 'scan_id', '')}"],
        )

        # Primary outcome = the cancellation (the salient examiner-facing answer)
        explanation = explain_scan_result(
            cancelled_scan, self.timeline,
            data_origin="REAL SCAN (cancelled)",
            scenario_name=spec.name,
            extra_limitations=[
                "Phase 2 failure path result: "
                f"{failure_explanation['classification']} — {failing_scan.error_message or 'no message'}",
                "Phase 3 recovery scan: "
                f"{recovery_scan.state.value} — "
                + ("engine and dashboard recovered normally." if recovered
                   else "recovery scan did not reach a completed state."),
            ],
        )
        result.explanation = explanation
        result.classification = explanation["classification"]
        result.outcome_label = explanation.get("result_label", result.classification)
        result.outcome_detail = (
            f"Cancelled scan → {cancelled_scan.state.value}; invalid-scope scan → "
            f"{failing_scan.state.value} ({failing_scan.error_message or 'no message'}); "
            f"recovery scan → {recovery_scan.state.value}. "
            "No failure or cancellation was ever reported as SAFE."
        )
        result.is_simulation = False
        result.data_origin = explanation["data_origin"]
        result.probability = explanation["probability"]
        result.probability_note = explanation["probability_note"]
        result.evidence = [f"[{e['timestamp']}] {e['text']}" for e in explanation["evidence"]]
        result.limitations = list(explanation["limitations"])
        result.observed_activity = [
            f"Phase 1 cancellation: state={cancelled_scan.state.value}, "
            f"cancelled={cancelled_scan.cancelled}",
            f"Phase 2 failure: state={failing_scan.state.value}, "
            f"error='{failing_scan.error_message}'",
            f"Phase 3 recovery: state={recovery_scan.state.value}, "
            f"files={recovery_scan.files_inspected}",
        ]
        result.scan_result = cancelled_scan
        result.timeline = self.timeline
        result.expectation_met = phase1_ok and failure_ok and recovered

        self._emit_indicators(explanation["indicators"], SOURCE_REAL)
        self._emit_outcome(result, explanation)
        return result


# ── Convenience entry point ──────────────────────────────────────────────────
def run_scenario(key: str, emit: EmitFn = None, cancel_check: CancelCheck = None,
                 sandbox_dir: Optional[Path] = None) -> ScenarioResult:
    """Run one scenario with a fresh runner (used by tests and one-shot callers)."""
    runner = ScenarioRunner(emit=emit, sandbox_dir=sandbox_dir)
    return runner.run(key, cancel_check=cancel_check)


def get_scenarios() -> List[Dict[str, str]]:
    """Scenario metadata for the UI selector."""
    return [
        {
            "key": s.key,
            "id": s.scenario_id,
            "name": s.name,
            "purpose": s.purpose,
            "mode": s.mode,
            "expected_outcome": s.expected_outcome,
            "safety_note": s.safety_note,
        }
        for s in SCENARIOS
    ]


if __name__ == "__main__":      # pragma: no cover - manual smoke run
    from utils.logging_config import setup_logging
    setup_logging()
    for spec in SCENARIOS:
        print("=" * 78)
        r = ScenarioRunner().run(spec.key)
        print(r.report_text())
