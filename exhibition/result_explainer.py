"""
SentinelML V2 — Detection Result Explanation (Investigation Panel)
===================================================================
Builds a factual, human-readable explanation of a completed scan or scenario
outcome for the Investigation panel (Exhibition Lab and Dashboard).

Honesty contract:
  * probability is reported ONLY when the model genuinely executed
    (ScanResult.ml_executed). Otherwise it is None and the panel says so.
  * Indicators are OBSERVED TELEMETRY values compared against the documented
    baseline ranges. They are NOT claimed to be per-prediction model
    attributions (no SHAP/permutation explanation runs in this project).
  * Missing/RESTRICTED sensors are listed explicitly; they are never silently
    treated as measured zeros.
  * Cancelled, failed, or incomplete scans are never presented as SAFE.
  * data_origin states plainly whether the outcome came from a real scan or a
    controlled simulation.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from scanner.scan_engine import ScanResult, ScanState

# Display metadata for the 19-feature schema (order matches ml.predictor.FEATURE_NAMES)
_FEATURE_DISPLAY = {
    "total_processes": ("Total Processes", "150 - 300", False),
    "suspicious_process_count": ("Suspicious Processes", "0", True),
    "avg_entropy": ("Average File Entropy", "3.5 - 5.5 bits/byte", False),
    "max_entropy": ("Maximum File Entropy", "4.5 - 7.2 bits/byte", False),
    "high_entropy_region_count": ("High-Entropy Regions (>=7.0)", "0 - 5", True),
    "malfind_injection_count": ("Code Injection Signals", "0", True),
    "crypto_dll_count": ("Crypto Library Usage", "0 - 3", False),
    "cmd_vssadmin_count": ("Shadow Copy Deletion Commands", "0", True),
    "network_connection_count": ("Network Connections", "20 - 80", False),
    "unique_external_ips": ("Unique External IPs", "2 - 15", False),
    "file_handle_count": ("Open File Handles", "500 - 2500", False),
    "registry_handle_count": ("Open Registry Handles", "100 - 800", False),
    "orphan_process_count": ("Orphan Processes", "0 - 5", False),
    "powershell_process_count": ("PowerShell Instances", "0 - 1", False),
    "unsigned_module_count": ("Unsigned Modules", "0 - 2", True),
    "suspicious_mutex_count": ("Suspicious Mutexes", "0", True),
    "abnormal_privilege_count": ("Abnormal Privileges", "0", True),
    "suspicious_thread_count": ("Suspicious Threads", "0", True),
    "defender_tampering_count": ("Defender Tampering Attempts", "0", True),
}

# Feature subset that is always shown as context even when nominal
_CONTEXT_FEATURES = ("total_processes", "avg_entropy", "max_entropy", "network_connection_count")

_THRESHOLD_NOTE = (
    "Decision thresholds (unchanged): probability >= 0.90 => CRITICAL, "
    ">= 0.50 => WARNING, otherwise SAFE. Thresholds come from models/metrics.json."
)

_NEXT_STEPS = {
    "SAFE": [
        "Continue routine monitoring with the background Guard.",
        "Re-run a Fast Live Scan after any new software installation or USB insertion.",
        "Keep SentinelML's threat log for audit history.",
    ],
    "WARNING": [
        "Open the Threat Log and review the flagged processes and files.",
        "Isolate the affected user session from shared drives and network shares.",
        "Export the incident report before any remediation so evidence is preserved.",
        "Run a Full System Scan for deeper filesystem coverage.",
    ],
    "CRITICAL": [
        "Disconnect the host from networks immediately to limit lateral movement.",
        "Preserve evidence: export the incident report before rebooting.",
        "Restore affected files from offline/known-good backups.",
        "Rebuild the host from a trusted image if encryption activity is confirmed.",
    ],
    "INCONCLUSIVE": [
        "Restore the missing telemetry sensors (platform support or permissions) and re-run the scan.",
        "Do not treat this result as a clean bill of health — no safety classification was produced.",
        "Run the scan from an elevated shell if sensors are permission-restricted.",
        "Record the platform limitation in the incident report.",
    ],
    "CANCELLED": [
        "Re-run the scan to completion — partial results were discarded.",
        "Avoid cancelling mid-scan during forensic triage; coverage is unknown for the aborted scope.",
    ],
    "ERROR": [
        "Check logs/app.log and logs for the underlying failure.",
        "Verify models/saved_model.pkl and models/scaler.pkl are present and readable.",
        "Restart the application and re-run the scan; report persistent failures.",
    ],
}


def _level_for_result(result: ScanResult) -> str:
    """Authoritative classification level for the panel header."""
    try:
        return str(result.get_unified_classification().get("level", "ERROR"))
    except Exception:
        return "ERROR"


def _extract_feature_values(result: ScanResult) -> Optional[Dict[str, float]]:
    features = getattr(result, "_features", None)
    try:
        if features is None:
            return None
        row = features[0]
        from ml.predictor import FEATURE_NAMES
        if len(row) != len(FEATURE_NAMES):
            return None
        return {name: float(row[i]) for i, name in enumerate(FEATURE_NAMES)}
    except Exception:
        return None


def build_indicators(result: ScanResult, data_origin_label: str) -> List[Dict[str, Any]]:
    """
    Observed telemetry indicators (factual values vs documented baselines).
    'elevated' rows are heuristic observations, not model attributions.
    """
    values = _extract_feature_values(result)
    if not values:
        return []

    rows: List[Dict[str, Any]] = []
    for name, value in values.items():
        display, baseline, is_security_signal = _FEATURE_DISPLAY.get(name, (name, "n/a", False))
        elevated = bool(is_security_signal and value > 0)
        context = name in _CONTEXT_FEATURES
        if not elevated and not context:
            continue
        rows.append(
            {
                "feature": name,
                "display_name": display,
                "value": round(float(value), 3),
                "baseline": baseline,
                "status": "ELEVATED" if elevated else "NOMINAL",
                "origin": data_origin_label,
            }
        )
    return rows


def build_telemetry_gaps(result: ScanResult) -> Dict[str, Any]:
    """Unavailable / restricted telemetry, honestly reported."""
    availability = dict(getattr(result, "telemetry_availability", {}) or {})
    missing = list(getattr(result, "missing_features", []) or [])
    unavailable: List[Dict[str, str]] = []
    proxies: List[Dict[str, str]] = []
    for feature, status in availability.items():
        s = str(status)
        if s.startswith("UNAVAILABLE") or s.startswith("RESTRICTED"):
            unavailable.append({"feature": feature, "status": s})
        elif s.startswith("HEURISTIC_PROXY") or s.startswith("SUBSTITUTED"):
            proxies.append({"feature": feature, "status": s})
    for feature in missing:
        if not any(u["feature"] == feature for u in unavailable):
            status = str(availability.get(feature, "UNAVAILABLE_PLATFORM"))
            unavailable.append({"feature": feature, "status": status})

    coverage = getattr(result, "telemetry_coverage_ratio", None)
    return {
        "unavailable": unavailable,
        "substituted_or_proxy": proxies,
        "missing_feature_names": missing,
        "coverage_ratio": coverage,
        "available_feature_count": getattr(result, "available_feature_count", None),
        "declared_reason": getattr(result, "inconclusive_reason", "") or "",
    }


def build_evidence(result: ScanResult, timeline=None) -> List[Dict[str, str]]:
    """Timestamped evidence rows from the timeline, else from scan statistics."""
    evidence: List[Dict[str, str]] = []
    if timeline is not None and len(timeline) > 0:
        for evt in timeline.events:
            evidence.append(
                {
                    "timestamp": evt.timestamp,
                    "category": evt.category,
                    "text": f"{evt.title} — {evt.detail}",
                    "source": evt.source,
                }
            )
        return evidence

    # Fallback: derive evidence strictly from the scan result itself.
    stamp = datetime.now().strftime("%H:%M:%S")
    evidence.append({"timestamp": stamp, "category": "SCAN_INIT",
                     "text": f"Scan {getattr(result, 'scan_id', '') or '(no id)'} "
                             f"({result.scan_type.value}) completed in "
                             f"{getattr(result, 'elapsed_seconds', 0.0):.2f}s",
                     "source": "REAL"})
    evidence.append({"timestamp": stamp, "category": "FILE_OBSERVATION",
                     "text": f"{result.files_inspected} files / {result.directories_inspected} directories "
                             f"inspected; {len(result.suspicious_files)} flagged suspicious",
                     "source": "REAL"})
    evidence.append({"timestamp": stamp, "category": "PROCESS_OBSERVATION",
                     "text": f"{result.processes_analyzed} processes analyzed; "
                             f"{result.process_errors} process errors",
                     "source": "REAL"})
    if result.ml_executed:
        evidence.append({"timestamp": stamp, "category": "MODEL_INFERENCE",
                         "text": f"Random Forest probability {result.ml_probability:.4f} "
                                 f"({result.threat_level})",
                         "source": "REAL"})
    if result.error_message:
        evidence.append({"timestamp": stamp, "category": "ERROR",
                         "text": result.error_message, "source": "SYSTEM"})
    return evidence


def explain_scan_result(
    result: ScanResult,
    timeline=None,
    *,
    data_origin: Optional[str] = None,
    result_label: Optional[str] = None,
    probability_override: Optional[float] = "__compute__",
    probability_note: str = "",
    extra_limitations: Optional[List[str]] = None,
    scenario_name: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build the investigation-panel payload for a ScanResult.

    Returns a dict with:
        classification, probability (None when genuinely unavailable),
        indicators, telemetry_gaps, evidence, next_steps, data_origin,
        is_simulation, limitations, generated_at
    """
    classification = result.get_unified_classification()
    level = str(classification.get("level", "ERROR"))
    is_sim = bool(classification.get("is_simulation", False))

    if data_origin is None:
        if is_sim or getattr(result, "scan_origin", "") == "CONTROLLED_SIMULATION":
            data_origin = "CONTROLLED SIMULATION (sandbox)"
        elif classification.get("level") in ("CANCELLED", "ANALYSIS_ERROR"):
            data_origin = "REAL SCAN (incomplete)"
        else:
            data_origin = "REAL SYSTEM SCAN"

    # --- probability: only when the model genuinely ran -------------------
    if probability_override == "__compute__":
        if result.ml_executed and level in ("SAFE", "WARNING", "CRITICAL"):
            probability: Optional[float] = float(result.ml_probability)
            probability_note = _THRESHOLD_NOTE
        else:
            probability = None
            if level == "INCONCLUSIVE":
                probability_note = (
                    "No probability reported: sensor coverage was insufficient to validate an "
                    "inference, and zero-filling missing sensors would fabricate measurements."
                )
            elif level == "CANCELLED":
                probability_note = "No probability reported: the scan was cancelled before inference completed."
            elif level in ("ERROR", "ANALYSIS_ERROR"):
                probability_note = "No probability reported: model inference did not complete successfully."
            else:
                probability_note = "No probability available for this result."
    else:
        probability = probability_override  # may be None or a float

    indicators = build_indicators(result, data_origin if not is_sim else "SIMULATED (sandbox)")
    telemetry_gaps = build_telemetry_gaps(result)
    evidence = build_evidence(result, timeline)
    next_steps = list(_NEXT_STEPS.get(level, _NEXT_STEPS["ERROR"]))

    limitations: List[str] = []
    try:
        limitations.extend(list(classification.get("disclosures", []) or []))
    except Exception:
        pass
    if classification.get("is_borderline"):
        limitations.append(str(classification.get("borderline_note", "")).strip())
    if telemetry_gaps["unavailable"]:
        limitations.append(
            f"{len(telemetry_gaps['unavailable'])} telemetry sensor(s) unavailable or permission-"
            "restricted; unavailable sensors are reported as missing, never as measured zeros."
        )
    limitations.append(
        "SentinelML performs user-space (Ring-3) behavioral monitoring only; it does not provide "
        "kernel-level protection, blocking, or quarantine."
    )
    if extra_limitations:
        limitations.extend([l for l in extra_limitations if l])

    return {
        "classification": level,
        "classification_detail": classification,
        "result_label": result_label or classification.get("status_title", level),
        "probability": probability,
        "probability_note": probability_note,
        "indicators": indicators,
        "telemetry_gaps": telemetry_gaps,
        "evidence": evidence,
        "next_steps": next_steps,
        "data_origin": data_origin,
        "is_simulation": is_sim,
        "limitations": [l for l in limitations if l],
        "scenario_name": scenario_name,
        "scan_id": getattr(result, "scan_id", "") or "",
        "scan_state": result.state.value if isinstance(result.state, ScanState) else str(result.state),
        "duration_seconds": getattr(result, "elapsed_seconds", 0.0),
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "advisory_note": (
            "SentinelAI output is advisory only and can never override this classification."
        ),
    }


def format_explanation_text(explanation: Dict[str, Any]) -> str:
    """Plain-text rendering of the explanation (used in reports and tests)."""
    lines: List[str] = []
    lines.append(f"CLASSIFICATION: {explanation.get('result_label')}")
    origin = explanation.get("data_origin", "")
    lines.append(f"DATA ORIGIN: {origin}")
    prob = explanation.get("probability")
    if prob is None:
        lines.append(f"MODEL PROBABILITY: Not available — {explanation.get('probability_note', '')}")
    else:
        lines.append(f"MODEL PROBABILITY: {prob:.4f} ({explanation.get('probability_note', '')})")

    lines.append("OBSERVED INDICATORS:")
    indicators = explanation.get("indicators") or []
    if not indicators:
        lines.append("  (no telemetry feature vector available for this result)")
    for ind in indicators:
        lines.append(
            f"  [{ind['status']}] {ind['display_name']}: {ind['value']} "
            f"(baseline {ind['baseline']}, source: {ind['origin']})"
        )

    gaps = explanation.get("telemetry_gaps") or {}
    unavailable = gaps.get("unavailable") or []
    lines.append("UNAVAILABLE TELEMETRY:")
    if unavailable:
        for gap in unavailable:
            lines.append(f"  - {gap['feature']}: {gap['status']}")
    else:
        lines.append("  (all 19 schema sensors were reported available for this run)")

    lines.append("EVIDENCE:")
    for ev in (explanation.get("evidence") or []):
        lines.append(f"  [{ev['timestamp']}] ({ev['source']}/{ev['category']}) {ev['text']}")

    lines.append("RECOMMENDED NEXT STEPS:")
    for step in explanation.get("next_steps") or []:
        lines.append(f"  - {step}")

    lines.append("LIMITATIONS:")
    for lim in explanation.get("limitations") or []:
        lines.append(f"  - {lim}")

    lines.append(f"NOTE: {explanation.get('advisory_note', '')}")
    lines.append(f"GENERATED: {explanation.get('generated_at', '')}")
    return "\n".join(lines)
