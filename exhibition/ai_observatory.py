"""
SentinelML V2 — Explainable AI Observatory (pure logic, no Tkinter)
==================================================================
Builds the data the AI Observatory page renders:
  * the 19 model input features with their values and an honest status
    (MEASURED / UNAVAILABLE / SIMULATED);
  * the model's actual prediction probability and classification, with the
    hard invariant that a missing/error/incomplete scan is NEVER converted
    into SAFE;
  * global model-level feature importance (Gini) — only when it can be
    derived from the trained forest — clearly labelled as a model aggregate,
    NOT a per-prediction explanation.

The model, scaler, feature order and thresholds are never modified here.
"""

from __future__ import annotations

import math
from typing import Any, List, Optional, Tuple

from ml.predictor import FEATURE_NAMES, MLPredictor

STATUS_MEASURED = "MEASURED"
STATUS_UNAVAILABLE = "UNAVAILABLE"
STATUS_SIMULATED = "SIMULATED"
STATUS_INJECTED = "INJECTED"
STATUS_ERROR = "ERROR"

# Plain-English meaning for each of the 19 model inputs (display only — the
# model itself only sees the numeric order in FEATURE_NAMES).
FEATURE_DESCRIPTIONS = {
    "total_processes": "Processes running when the scan ran.",
    "suspicious_process_count": "Processes matching suspicious-name / parent heuristics.",
    "avg_entropy": "Average file entropy — high values can indicate packed or encrypted data.",
    "max_entropy": "Highest single-file entropy — near 8.0 suggests random/encrypted content.",
    "high_entropy_region_count": "Regions or files above the high-entropy threshold.",
    "malfind_injection_count": "Memory regions flagged by the malfind-style heuristic.",
    "crypto_dll_count": "Loaded modules exposing cryptographic APIs (often legitimate).",
    "cmd_vssadmin_count": "Command lines matching shadow-copy or backup deletion patterns.",
    "network_connection_count": "Active network connections at scan time.",
    "unique_external_ips": "Distinct non-local IP addresses among those connections.",
    "file_handle_count": "Open file handles across inspected processes.",
    "registry_handle_count": "Open registry handles across inspected processes.",
    "orphan_process_count": "Processes whose parent process no longer exists.",
    "powershell_process_count": "Running PowerShell processes.",
    "unsigned_module_count": "Loaded modules without a valid digital signature.",
    "suspicious_mutex_count": "Mutex names matching suspicious patterns (heuristic).",
    "abnormal_privilege_count": "Processes holding unusual privilege sets.",
    "suspicious_thread_count": "Threads observed in suspicious states (heuristic).",
    "defender_tampering_count": "Observations consistent with security-tool tampering (heuristic).",
}


def plain_english(feature_name: str) -> str:
    """Return the display description for a model input, or a neutral fallback."""
    return FEATURE_DESCRIPTIONS.get(feature_name, "No description available for this input.")

# Status prefixes from scanner.live_scanner.get_platform_feature_availability()
_UNAVAILABLE_PREFIXES = ("UNAVAILABLE", "RESTRICTED")
_PROXY_PREFIXES = ("HEURISTIC_PROXY", "SUBSTITUTED")


def classify_feature_status(feature: str, availability: Optional[dict],
                            value: Any = None, source: str = "real") -> str:
    """Return the honest status for one feature.

    ``source="real"`` -> MEASURED unless the platform reports the sensor as
    unavailable/restricted (then UNAVAILABLE, regardless of a zero value).
    ``source="simulated"`` -> SIMULATED (a scripted input, not a measurement).
    """
    src = str(source).lower()
    if src == "simulated":
        return STATUS_SIMULATED
    if src == "injected":
        return STATUS_INJECTED
    if src == "error":
        # A failed scan has no readings at all — never show a zero as measured.
        return STATUS_ERROR
    if src in ("unavailable", "missing"):
        return STATUS_UNAVAILABLE
    status = ""
    if availability:
        status = str(availability.get(feature, ""))
    if status.startswith(_UNAVAILABLE_PREFIXES):
        return STATUS_UNAVAILABLE
    # proxy/substituted sensors are still measurements (documented as proxies)
    return STATUS_MEASURED


def _finite_float(value: Any) -> Optional[float]:
    if value is None:
        return None
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    if math.isnan(f) or math.isinf(f):
        return None
    return f


def feature_rows(vector: Any, availability: Optional[dict],
                  feature_names: Optional[List[str]] = None,
                  source: str = "real") -> List[dict]:
    """Return one row per feature: {name, index, value, status, raw}.

    ``vector`` may be a (1, 19) ndarray, a length-19 sequence, or None.
    Unavailable features show value None (the UI renders them as '—', not 0).
    """
    names = feature_names or FEATURE_NAMES
    rows: List[dict] = []
    # Normalise vector to a flat list of 19
    flat: List[Optional[float]] = [None] * len(names)
    if vector is not None:
        try:
            import numpy as np  # local import keeps the module import-light
            arr = np.asarray(vector, dtype=float)
            if arr.ndim == 2 and arr.shape[0] == 1:
                arr = arr[0]
            if arr.ndim == 1 and arr.shape[0] == len(names):
                for i in range(len(names)):
                    v = arr[i]
                    flat[i] = _finite_float(v)
        except Exception:
            # Fallback: plain sequence
            try:
                seq = list(vector)
                for i in range(min(len(seq), len(names))):
                    flat[i] = _finite_float(seq[i])
            except Exception:
                pass
    for i, name in enumerate(names):
        status = classify_feature_status(name, availability, flat[i], source)
        rows.append({
            "index": i,
            "name": name,
            "value": flat[i] if status not in (STATUS_UNAVAILABLE, STATUS_ERROR) else None,
            "status": status,
            "raw": flat[i],
            "description": plain_english(name),
        })
    return rows


def coverage_summary(rows: List[dict]) -> dict:
    """Summarise how many of the model inputs carry real readings.

    Returns counts plus a coverage ratio in [0, 1]. Simulated / error inputs
    never count as measured coverage.
    """
    counts = {STATUS_MEASURED: 0, STATUS_UNAVAILABLE: 0,
              STATUS_SIMULATED: 0, STATUS_INJECTED: 0, STATUS_ERROR: 0}
    missing: List[str] = []
    for row in rows or []:
        status = row.get("status", STATUS_UNAVAILABLE)
        counts[status] = counts.get(status, 0) + 1
        if status != STATUS_MEASURED:
            missing.append(str(row.get("name", "")))
    total = len(rows or [])
    measured = counts.get(STATUS_MEASURED, 0)
    return {
        "total": total,
        "measured": measured,
        "unavailable": counts.get(STATUS_UNAVAILABLE, 0),
        "simulated": counts.get(STATUS_SIMULATED, 0),
        "injected": counts.get(STATUS_INJECTED, 0),
        "error": counts.get(STATUS_ERROR, 0),
        "coverage_ratio": (measured / total) if total else 0.0,
        "not_measured": missing,
    }


def model_availability(predictor: MLPredictor) -> dict:
    """Read-only snapshot of model / scaler availability and thresholds."""
    info: dict = {}
    try:
        info = predictor.get_model_info() or {}
    except Exception:
        info = {}
    return {
        "model_loaded": bool(info.get("loaded", False)),
        "model_type": str(info.get("type", "Unknown")),
        "scaler_loaded": bool(info.get("scaler_loaded", False)),
        "feature_count": len(FEATURE_NAMES),
        "expected_features": int(info.get("expected_features", 0) or 0),
        "threshold_warning": float(info.get("threshold_warning", 0.5)),
        "threshold_critical": float(info.get("threshold_critical", 0.9)),
    }


def _is_finite01(prob: Any) -> bool:
    f = _finite_float(prob)
    return f is not None and 0.0 <= f <= 1.0


def classification_from_scan(scan_result: Any) -> Tuple[str, Optional[float], str]:
    """Honest (label, probability, note) for a real ScanResult.

    Uses the engine's authoritative ``get_unified_classification`` so that
    cancelled / error / incomplete / inconclusive scans are NEVER SAFE.
    Probability is only reported when the model genuinely executed.
    """
    label = "NOT AVAILABLE"
    prob: Optional[float] = None
    note = ""
    try:
        if scan_result is None:
            return "NOT AVAILABLE", None, "No scan result available."
        if getattr(scan_result, "cancelled", False):
            return "CANCELLED", None, "Scan cancelled — no safety claim."
        state = getattr(scan_result, "state", None)
        state_name = getattr(state, "value", str(state)).upper() if state is not None else ""
        if state_name in ("ERROR", "ANALYSIS_ERROR"):
            return "ERROR", None, "Scan error — never SAFE."
        if state_name in ("SCAN_INCOMPLETE", "INCOMPLETE"):
            return state_name if state_name else "INCOMPLETE", None, "Scan incomplete — never SAFE."
        if state_name in ("INCONCLUSIVE", "LIMITED_COVERAGE") or \
                bool(getattr(scan_result, "is_inconclusive", False)):
            return "INCONCLUSIVE", None, "Insufficient telemetry — inconclusive, not SAFE."
        # Ask the engine's authoritative classification when available
        unified = None
        if hasattr(scan_result, "get_unified_classification"):
            try:
                unified = scan_result.get_unified_classification()
            except Exception:
                unified = None
        if unified and "level" in unified:
            label = str(unified["level"])
        else:
            label = str(getattr(scan_result, "threat_level", "NOT AVAILABLE") or "NOT AVAILABLE")
        if getattr(scan_result, "ml_executed", False):
            p = getattr(scan_result, "ml_probability", None)
            if _is_finite01(p):
                prob = float(p)
            else:
                note = "Model executed but probability out of contract — not reported."
        else:
            prob = None
            note = "Model did not execute on this scan — no probability reported."
        return label, prob, note
    except Exception as exc:  # never let the observatory fabricate a SAFE
        return "ERROR", None, f"Classification unavailable: {exc}"


def classification_from_prediction(threat_level: Optional[str],
                                    prob: Optional[float],
                                    ml_executed: bool) -> Tuple[str, Optional[float], str]:
    """Honest (label, probability, note) for a directly-evaluated vector.

    Used for simulated/loaded vectors. The caller is responsible for badging
    the result as SIMULATED. Never reports SAFE when the model did not run.
    """
    if not ml_executed:
        return "NOT AVAILABLE", None, "Model did not execute — no probability, not SAFE."
    label = str(threat_level or "NOT AVAILABLE")
    if label.upper() == "NONE":
        label = "NOT AVAILABLE"
    p = float(prob) if _is_finite01(prob) else None
    note = "" if p is not None else "Probability unavailable (out of contract)."
    return label, p, note


def global_feature_importance(predictor: MLPredictor) -> Optional[List[Tuple[str, float]]]:
    """Return [(feature_name, importance)] sorted desc, or None if not derivable.

    This is the trained forest's Gini feature_importances_ — a model-level
    aggregate. It is NOT a per-prediction explanation and must be labelled as
    such by the UI. Read-only: never retrains or modifies the model.
    """
    try:
        importances = predictor.get_feature_importances()
    except Exception:
        return None
    if importances is None:
        return None
    try:
        pairs = [(FEATURE_NAMES[i], float(importances[i]))
                 for i in range(min(len(importances), len(FEATURE_NAMES)))]
    except Exception:
        return None
    pairs.sort(key=lambda x: x[1], reverse=True)
    return pairs


def importance_disclaimer() -> str:
    return ("Global model importance (Gini, model-level aggregate). It describes which "
            "features the trained forest used across all training samples. It is NOT a "
            "per-prediction explanation of any individual scan, and does not prove that a "
            "feature caused a given outcome.")
