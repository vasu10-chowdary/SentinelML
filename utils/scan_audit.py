"""
SentinelML V2 — Persistent scan audit history.
===============================================
Stores the latest 10 *completed* scan audit records in a versioned JSON file
under the application's user-data directory.

Safety invariants:
  * Only scans that actually started are recorded.
  * Failed, cancelled and incomplete scans keep their true status
    (``FAILED`` / ``INCONCLUSIVE``); they are never rewritten as ``SAFE``.
  * Values that the scan did not produce are stored as ``None`` and rendered
    as ``N/A`` — never as zero.
  * Live SOC refreshes never create audit records.
  * Writes are atomic (temp file + ``os.replace``); a corrupt file is
    quarantined and the store continues with an empty active list.
"""

from __future__ import annotations

import copy
import json
import logging
import os
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("sentinel.audit")

AUDIT_SCHEMA_VERSION = 1
MAX_AUDIT_RECORDS = 10
AUDIT_FILENAME = "scan_audit_history.json"

VALID_CLASSIFICATIONS = ("SAFE", "WARNING", "CRITICAL", "FAILED", "INCONCLUSIVE")

# Presentation-only mapping derived from the unified classification. It adds
# no new evidence; unknown states stay unknown.
SEVERITY_BY_CLASSIFICATION = {
    "CRITICAL": "CRITICAL",
    "WARNING": "MEDIUM",
    "SAFE": "NONE",
    "INCONCLUSIVE": "UNKNOWN",
    "FAILED": "N/A (failed)",
}

_SCAN_TYPE_LABELS = {
    "quick": "Manual quick scan",
    "full": "Manual full scan",
    "custom": "Manual custom scan",
    "process": "Manual process scan",
}

_RECORD_KEYS = (
    "audit_id",
    "scan_id",
    "started_at",
    "completed_at",
    "recorded_at_epoch",
    "duration_s",
    "scan_type",
    "classification",
    "severity",
    "probability",
    "files_examined",
    "processes_examined",
    "findings",
    "error",
    "provenance",
    "model_source",
    "app_version",
    "coverage_ratio",
    "missing_features",
    "source",
)


def _now_iso(ts: Optional[float] = None) -> str:
    try:
        return datetime.fromtimestamp(float(ts if ts is not None else time.time())).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    except Exception:
        return ""


def _as_int(value: Any) -> Optional[int]:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except Exception:
        return None


def _as_float(value: Any) -> Optional[float]:
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except Exception:
        return None


def default_audit_path() -> Path:
    from utils.paths import get_user_data_root

    return get_user_data_root() / AUDIT_FILENAME


def _state_name(result) -> str:
    state = getattr(result, "state", None)
    return getattr(state, "name", None) or getattr(state, "value", None) or str(state or "")


def classify_outcome(result, outcome: str) -> Tuple[str, str]:
    """Map a terminal scan callback to (classification, explanation).

    ``outcome`` is ``"completed"``, ``"cancelled"`` or ``"error"``. The
    classification is always one of ``VALID_CLASSIFICATIONS`` and never
    defaults to ``SAFE``.
    """
    if result is None:
        if outcome == "cancelled":
            return "INCONCLUSIVE", "Scan was cancelled before a result was produced."
        if outcome == "error":
            return "FAILED", "Scan failed before a result was produced."
        return "INCONCLUSIVE", "No scan result was produced."

    state = _state_name(result)
    try:
        unified = result.get_unified_classification() or {}
    except Exception:
        unified = {}
    level = str(unified.get("level") or "")

    cancelled = (
        bool(getattr(result, "cancelled", False))
        or state == "SCAN_INCOMPLETE"
        or level == "SCAN_INCOMPLETE"
    )
    if outcome == "cancelled" or cancelled:
        reason = (
            getattr(result, "error_message", "")
            or getattr(result, "inconclusive_reason", "")
            or "Scan was stopped before completion; partial results are not classified."
        )
        return "INCONCLUSIVE", reason

    is_sim = bool(
        getattr(result, "is_simulation", False)
        or getattr(result, "scan_origin", "") == "CONTROLLED_SIMULATION"
    )
    if is_sim:
        simulated_level = str(getattr(result, "threat_level", "") or "").upper()
        if simulated_level in ("CRITICAL", "THREAT_DETECTED"):
            return "CRITICAL", ""
        if simulated_level == "WARNING":
            return "WARNING", ""
        if simulated_level in ("SAFE", "LOW"):
            return "SAFE", ""
        if simulated_level in ("ERROR", "ANALYSIS_ERROR"):
            return "FAILED", "Simulated scan did not produce a classification."

    failed = outcome == "error" or state in ("ERROR", "ANALYSIS_ERROR") or level == "ANALYSIS_ERROR"
    if failed:
        reason = (
            getattr(result, "error_message", "")
            or unified.get("description", "")
            or "Scan analysis failed; no security classification can be determined."
        )
        return "FAILED", reason

    if level in ("SAFE", "WARNING", "CRITICAL"):
        return level, ""

    if level == "INCONCLUSIVE" or bool(getattr(result, "is_inconclusive", False)):
        reason = (
            getattr(result, "inconclusive_reason", "")
            or unified.get("description", "")
            or "Telemetry coverage was insufficient for a validated classification."
        )
        return "INCONCLUSIVE", reason

    # Unknown / unexpected state must not be reported as clean.
    return "INCONCLUSIVE", f"Unrecognised scan state '{state or 'unknown'}'; classification withheld."


def build_audit_record(
    scan_result=None,
    *,
    outcome: str = "completed",
    started_at: Optional[float] = None,
    completed_at: Optional[float] = None,
    scan_type: Optional[str] = None,
    error_message: Optional[str] = None,
    scan_origin: Optional[str] = None,
    model_source: Optional[str] = None,
    app_version: Optional[str] = None,
) -> Dict[str, Any]:
    """Build one serialisable audit record from a ``ScanResult``.

    Missing values are stored as ``None`` (rendered ``N/A``), never invented.
    """
    completed = float(completed_at) if completed_at is not None else time.time()
    started = float(started_at) if started_at is not None else None

    classification, reason = classify_outcome(scan_result, outcome)
    if error_message and classification in ("FAILED", "INCONCLUSIVE"):
        reason = str(error_message)

    type_value = ""
    if scan_result is not None:
        raw_type = getattr(scan_result, "scan_type", None)
        type_value = getattr(raw_type, "value", None) or str(raw_type or "")
    label = scan_type or _SCAN_TYPE_LABELS.get(type_value, "Manual scan")

    duration = _as_float(getattr(scan_result, "elapsed_seconds", None)) if scan_result else None
    if duration is None or duration <= 0:
        duration = (completed - started) if started is not None else None
        if duration is not None:
            duration = max(0.0, duration)

    probability = None
    if scan_result is not None:
        ml_executed = bool(getattr(scan_result, "ml_executed", False))
        classified = classification in ("SAFE", "WARNING", "CRITICAL")
        if ml_executed or classified:
            probability = _as_float(getattr(scan_result, "ml_probability", None))

    files_examined = _as_int(getattr(scan_result, "files_inspected", None)) if scan_result else None
    processes_examined = _as_int(getattr(scan_result, "processes_analyzed", None)) if scan_result else None

    findings: Optional[int] = None
    if scan_result is not None and classification in ("SAFE", "WARNING", "CRITICAL"):
        suspects = getattr(scan_result, "suspicious_files", None)
        if suspects is not None:
            try:
                findings = len(list(suspects))
            except Exception:
                findings = None

    coverage = None
    if scan_result is not None:
        coverage = _as_float(getattr(scan_result, "telemetry_coverage_ratio", None))

    missing: List[str] = []
    if scan_result is not None:
        missing = [str(x) for x in (getattr(scan_result, "missing_features", None) or [])]

    origin = scan_origin or (getattr(scan_result, "scan_origin", "") if scan_result else "") or "UNKNOWN"
    model_id = model_source or (getattr(scan_result, "model_source", "") if scan_result else "") or None

    record = {
        "audit_id": f"AUD-{uuid.uuid4().hex}",
        "scan_id": (getattr(scan_result, "scan_id", "") if scan_result else "") or None,
        "started_at": _now_iso(started) if started is not None else None,
        "completed_at": _now_iso(completed),
        # Sub-second ordering key: two scans can share the same displayed
        # second, and "newest first" must still be deterministic.
        "recorded_at_epoch": round(completed, 6),
        "duration_s": round(duration, 3) if duration is not None else None,
        "scan_type": label,
        "classification": classification,
        "severity": SEVERITY_BY_CLASSIFICATION.get(classification, "UNKNOWN"),
        "probability": round(probability, 4) if probability is not None else None,
        "files_examined": files_examined,
        "processes_examined": processes_examined,
        "findings": findings,
        "error": reason or None,
        "provenance": origin,
        "model_source": model_id,
        "app_version": app_version,
        "coverage_ratio": coverage,
        "missing_features": missing,
        "source": "SCAN_AUDIT",
    }
    return record


def _valid_record(record: Any) -> bool:
    if not isinstance(record, dict):
        return False
    if not isinstance(record.get("audit_id"), str) or not record["audit_id"]:
        return False
    if record.get("classification") not in VALID_CLASSIFICATIONS:
        return False
    if not isinstance(record.get("completed_at"), str) or not record["completed_at"]:
        return False
    return True


def _sort_key(record: Dict[str, Any]) -> Tuple[float, str]:
    epoch = _as_float(record.get("recorded_at_epoch"))
    return (epoch if epoch is not None else 0.0, str(record.get("completed_at") or ""))


class ScanAuditStore:
    """Thread-safe, atomic JSON store for the latest completed scan audits."""

    def __init__(
        self,
        path: Optional[Any] = None,
        *,
        max_records: int = MAX_AUDIT_RECORDS,
    ) -> None:
        self.path = Path(path) if path is not None else default_audit_path()
        self.max_records = max(1, int(max_records))
        self._lock = threading.RLock()
        self._records: List[Dict[str, Any]] = []
        self.last_error: str = ""
        self.load_error: str = ""
        self._load()

    # ── Loading ───────────────────────────────────────────────────────────
    def _load(self) -> None:
        self._records = []
        self.load_error = ""
        if not self.path.exists():
            return
        try:
            raw = self.path.read_text(encoding="utf-8")
            payload = json.loads(raw) if raw.strip() else {"records": []}
        except Exception as exc:
            self._quarantine(f"Unreadable audit file: {exc}")
            return

        if isinstance(payload, dict):
            records = payload.get("records", [])
        elif isinstance(payload, list):  # tolerate a bare list
            records = payload
        else:
            self._quarantine("Audit file has an unsupported structure")
            return

        if not isinstance(records, list):
            self._quarantine("Audit file 'records' is not a list")
            return

        valid = [dict(r) for r in records if _valid_record(r)]
        dropped = len(records) - len(valid)
        if dropped:
            self.load_error = f"{dropped} invalid audit record(s) were skipped on load."
            log.warning(self.load_error)
        valid.sort(key=_sort_key, reverse=True)
        self._records = valid[: self.max_records]

    def _quarantine(self, message: str) -> None:
        self.load_error = message
        log.error("Scan audit store: %s", message)
        try:
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            target = self.path.with_name(f"{self.path.name}.corrupt-{stamp}")
            os.replace(self.path, target)
            self.load_error += f" Existing file preserved as {target.name}."
            log.error("Quarantined corrupt audit file to %s", target)
        except Exception as exc:
            self.load_error += f" Could not quarantine the file: {exc}"
            log.error("Could not quarantine corrupt audit file: %s", exc)

    # ── Saving ────────────────────────────────────────────────────────────
    def _save(self) -> bool:
        payload = {
            "schema_version": AUDIT_SCHEMA_VERSION,
            "updated_at": _now_iso(),
            "records": copy.deepcopy(self._records),
        }
        tmp_path = self.path.with_name(f"{self.path.name}.tmp-{os.getpid()}")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(tmp_path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, ensure_ascii=False)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_path, self.path)
            self.last_error = ""
            return True
        except Exception as exc:
            self.last_error = f"Could not write audit history: {exc}"
            log.error(self.last_error)
            try:
                if tmp_path.exists():
                    tmp_path.unlink()
            except Exception:
                pass
            return False

    # ── Public API ────────────────────────────────────────────────────────
    def records(self) -> List[Dict[str, Any]]:
        """Return the active records, newest first (copies)."""
        with self._lock:
            return [dict(r) for r in self._records]

    def count(self) -> int:
        with self._lock:
            return len(self._records)

    def reload(self) -> List[Dict[str, Any]]:
        with self._lock:
            self._load()
            return [dict(r) for r in self._records]

    def append(self, record: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
        """Insert or update a record; trims the active list to ``max_records``.

        Returns ``(stored_record, created)``. Duplicate callbacks carrying the
        same ``audit_id`` or ``scan_id`` update the existing entry instead of
        creating a second one.
        """
        if not _valid_record(record):
            raise ValueError("Invalid scan audit record")

        entry = {key: record.get(key) for key in _RECORD_KEYS}
        entry["audit_id"] = record["audit_id"]
        entry["classification"] = record["classification"]
        entry["completed_at"] = record["completed_at"]

        with self._lock:
            index = self._find_existing(entry)
            if index is None:
                self._records.append(entry)
                created = True
            else:
                merged = dict(self._records[index])
                for key, value in entry.items():
                    if value is not None:
                        merged[key] = value
                merged["audit_id"] = self._records[index]["audit_id"]
                self._records[index] = merged
                entry = merged
                created = False

            self._records.sort(key=_sort_key, reverse=True)
            if len(self._records) > self.max_records:
                self._records = self._records[: self.max_records]
            self._save()
            return dict(entry), created

    def _find_existing(self, entry: Dict[str, Any]) -> Optional[int]:
        audit_id = entry.get("audit_id")
        scan_id = entry.get("scan_id")
        for index, existing in enumerate(self._records):
            if existing.get("audit_id") == audit_id:
                return index
            if scan_id and existing.get("scan_id") == scan_id:
                return index
        return None

    def clear_active(self) -> None:
        """Drop the active list only (the previous file is not deleted)."""
        with self._lock:
            self._records = []
            self._save()
