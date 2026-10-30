"""
SentinelML V2 — Evidence Correlation Engine
===========================================
Read-only correlation of evidence produced by SentinelML's existing tools:
scan results, file-integrity comparisons, investigation timelines, and alerts.

Design rules (deliberate, safety-relevant):
- Evidence keeps its provenance: MEASURED, SIMULATED, HEURISTIC, UNAVAILABLE,
  ERROR, or APPLICATION. Provenance is never upgraded by correlation.
- Correlation never infers causation. Co-occurrence in time is reported as
  co-occurrence, with an explicit caveat.
- A hash change is reported as a change, not as ransomware or tampering.
- Heuristic indicators are never described as confirmed malware.
- Missing timestamps, duplicates, incomplete scans, and empty inputs are
  handled explicitly instead of being guessed at.

This module has no GUI dependencies so it can be used by Story Mode, the
challenge, incident reports, and unit tests alike.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence

PROV_MEASURED = "MEASURED"
PROV_SIMULATED = "SIMULATED"
PROV_HEURISTIC = "HEURISTIC"
PROV_UNAVAILABLE = "UNAVAILABLE"
PROV_ERROR = "ERROR"
PROV_APPLICATION = "APPLICATION"

VALID_PROVENANCE = frozenset({
    PROV_MEASURED, PROV_SIMULATED, PROV_HEURISTIC,
    PROV_UNAVAILABLE, PROV_ERROR, PROV_APPLICATION,
})

PROVENANCE_LABELS = {
    PROV_MEASURED: "MEASURED",
    PROV_SIMULATED: "SIMULATED",
    PROV_HEURISTIC: "HEURISTIC INDICATOR",
    PROV_UNAVAILABLE: "UNAVAILABLE",
    PROV_ERROR: "ERROR",
    PROV_APPLICATION: "APPLICATION",
}

# Evidence that can support a claim in a finding.
_ELEVATED_LEVELS = {"WARNING", "CRITICAL", "THREAT_DETECTED", "HIGH"}


@dataclass
class EvidenceItem:
    """One provenance-tagged observation in an investigation."""

    category: str
    title: str
    detail: str = ""
    provenance: str = PROV_MEASURED
    source: str = ""
    timestamp: Optional[float] = None
    evidence: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    seq: int = 0

    def __post_init__(self) -> None:
        prov = str(self.provenance or "").upper()
        if prov not in VALID_PROVENANCE:
            self.limitations.append(
                f"Unrecognized provenance {self.provenance!r}; treated as UNAVAILABLE."
            )
            prov = PROV_UNAVAILABLE
        self.provenance = prov
        try:
            self.timestamp = float(self.timestamp) if self.timestamp is not None else None
        except (TypeError, ValueError):
            self.limitations.append("Unparseable timestamp; event has no time.")
            self.timestamp = None
        if self.timestamp is not None and self.timestamp < 0:
            self.limitations.append("Negative timestamp; event has no usable time.")
            self.timestamp = None

    @property
    def provenance_label(self) -> str:
        return PROVENANCE_LABELS.get(self.provenance, self.provenance)

    @property
    def dedupe_key(self) -> str:
        stamp = "" if self.timestamp is None else f"{self.timestamp:.3f}"
        return "|".join([
            self.category, self.title, self.detail, self.source, stamp,
        ])

    def to_dict(self) -> Dict[str, Any]:
        return {
            "seq": self.seq,
            "category": self.category,
            "title": self.title,
            "detail": self.detail,
            "provenance": self.provenance,
            "provenance_label": self.provenance_label,
            "source": self.source,
            "timestamp": self.timestamp,
            "timestamp_text": format_timestamp(self.timestamp),
            "evidence": list(self.evidence),
            "limitations": list(self.limitations),
        }


def format_timestamp(ts: Optional[float]) -> str:
    """Human-readable local timestamp, or an explicit missing-time marker."""
    if ts is None:
        return "TIME UNAVAILABLE"
    try:
        return datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return "TIME UNAVAILABLE"


def _parse_iso(value: Any) -> Optional[float]:
    if not value or not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value).timestamp()
    except (ValueError, OSError):
        return None


def _enum_value(value: Any) -> str:
    return str(getattr(value, "value", value) or "")


class EvidenceCorrelator:
    """Collects provenance-tagged evidence and produces a safe timeline."""

    def __init__(self) -> None:
        self._items: List[EvidenceItem] = []
        self._keys: set[str] = set()
        self._next_seq = 1
        self._classification: str = ""
        self._probability: Optional[float] = None
        self._scan_simulated = False
        self._scan_available = False

    # -- collection ------------------------------------------------------
    def add(self, item: EvidenceItem) -> Optional[EvidenceItem]:
        """Add an item unless an identical one is already present."""
        key = item.dedupe_key
        if key in self._keys:
            return None
        item.seq = self._next_seq
        self._next_seq += 1
        self._keys.add(key)
        self._items.append(item)
        return item

    def add_manual(
        self,
        category: str,
        title: str,
        detail: str = "",
        provenance: str = PROV_MEASURED,
        source: str = "",
        timestamp: Optional[float] = None,
        evidence: Optional[Iterable[str]] = None,
        limitations: Optional[Iterable[str]] = None,
    ) -> Optional[EvidenceItem]:
        return self.add(EvidenceItem(
            category=category, title=title, detail=detail,
            provenance=provenance, source=source, timestamp=timestamp,
            evidence=list(evidence or []), limitations=list(limitations or []),
        ))

    def add_scan_result(
        self,
        scan_result: Any,
        when: Optional[float] = None,
        source: str = "",
    ) -> List[EvidenceItem]:
        """Translate a ScanResult into evidence items without inventing values."""
        if scan_result is None:
            return []
        added: List[EvidenceItem] = []
        stamp = time.time() if when is None else float(when)
        origin = str(getattr(scan_result, "scan_origin", "") or "LIVE_HOST_SCAN")
        simulated = bool(getattr(scan_result, "is_simulation", False)) or (
            origin == "CONTROLLED_SIMULATION")
        prov = PROV_SIMULATED if simulated else PROV_MEASURED
        if not simulated:
            self._scan_available = True
            self._scan_simulated = False
        else:
            self._scan_simulated = True
        src = source or origin

        scan_id = str(getattr(scan_result, "scan_id", "") or "SCAN-UNIDENTIFIED")
        state = str(getattr(scan_result, "state", "") or "").upper()
        state = str(getattr(getattr(scan_result, "state", ""), "value", state) or state).upper()
        files = int(getattr(scan_result, "files_inspected", 0) or 0)
        directories = int(getattr(scan_result, "directories_inspected", 0) or 0)
        procs = int(getattr(scan_result, "processes_analyzed", 0) or 0)

        item = self.add(EvidenceItem(
            category="SCAN",
            title=f"Scan {scan_id} finished",
            detail=(f"State {state or 'UNKNOWN'} · {files:,} files · "
                    f"{directories:,} folders · {procs:,} processes"),
            provenance=prov,
            source=src,
            timestamp=stamp,
            evidence=[
                f"duration {float(getattr(scan_result, 'elapsed_seconds', 0.0) or 0.0):.2f}s",
                f"model source {getattr(scan_result, 'model_source', 'UNAVAILABLE')}",
            ],
            limitations=(["Scan was executed in a controlled simulation."] if simulated else []),
        ))
        if item:
            added.append(item)

        ml_executed = bool(getattr(scan_result, "ml_executed", False))
        level = str(getattr(scan_result, "threat_level", "") or "").upper()
        try:
            probability = float(getattr(scan_result, "ml_probability", 0.0) or 0.0)
        except (TypeError, ValueError):
            probability = 0.0

        if ml_executed:
            self._classification = level
            self._probability = probability
            item = self.add(EvidenceItem(
                category="MODEL_INFERENCE",
                title=f"Model prediction: {level or 'UNKNOWN'}",
                detail=f"Malicious probability {probability:.3f}",
                provenance=PROV_SIMULATED if simulated else PROV_MEASURED,
                source=f"{src} · ML pipeline",
                timestamp=stamp,
                evidence=[
                    f"thresholds: warning 0.50, critical 0.90",
                    f"scan {scan_id}",
                ],
                limitations=(["Prediction is scripted for the demonstration."]
                             if simulated else
                             ["A probability is a model estimate, not proof of malware."]),
            ))
            if item:
                added.append(item)
        else:
            error_state = state in {"ERROR", "ANALYSIS_ERROR"}
            item = self.add(EvidenceItem(
                category="MODEL_INFERENCE",
                title="No model prediction available",
                detail=(getattr(scan_result, "error_message", "")
                        or getattr(scan_result, "inconclusive_reason", "")
                        or "ML stage did not produce a verdict."),
                provenance=PROV_ERROR if error_state else PROV_UNAVAILABLE,
                source=f"{src} · ML pipeline",
                timestamp=stamp,
                limitations=["Without a prediction the scan cannot be reported as SAFE."],
            ))
            if item:
                added.append(item)

        suspicious = list(getattr(scan_result, "suspicious_files", []) or [])
        if suspicious:
            item = self.add(EvidenceItem(
                category="FILE_OBSERVATION",
                title=f"{len(suspicious)} file(s) flagged by filesystem heuristics",
                detail="Heuristic path/entropy flags raised by the scanner.",
                provenance=PROV_HEURISTIC,
                source=f"{src} · filesystem scanner",
                timestamp=stamp,
                evidence=[str(p) for p in suspicious[:5]],
                limitations=[
                    "Heuristic flags are indicators, not proof of encryption or malware.",
                ],
            ))
            if item:
                added.append(item)

        missing = list(getattr(scan_result, "missing_features", []) or [])
        if missing:
            item = self.add(EvidenceItem(
                category="TELEMETRY_GAP",
                title=f"{len(missing)} sensor(s) unavailable",
                detail="Feature coverage was incomplete for this scan.",
                provenance=PROV_UNAVAILABLE,
                source=f"{src} · telemetry",
                timestamp=stamp,
                evidence=[str(m) for m in missing[:8]],
                limitations=["Verdict reliability is reduced where sensors are unavailable."],
            ))
            if item:
                added.append(item)

        if state in {"SCAN_INCOMPLETE", "CANCELLED"} or bool(getattr(scan_result, "cancelled", False)):
            item = self.add(EvidenceItem(
                category="CANCELLATION",
                title="Scan did not complete",
                detail=(getattr(scan_result, "error_message", "")
                        or "The scan was cancelled or ended before all phases finished."),
                provenance=PROV_UNAVAILABLE,
                source=src,
                timestamp=stamp,
                limitations=["Partial results are not a clean bill of health."],
            ))
            if item:
                added.append(item)

        try:
            denied = int(getattr(scan_result, "access_denied", 0) or 0)
        except (TypeError, ValueError):
            denied = 0
        if denied:
            item = self.add(EvidenceItem(
                category="TELEMETRY_GAP",
                title=f"{denied} path(s) could not be read",
                detail="Permission errors limited filesystem coverage.",
                provenance=PROV_UNAVAILABLE,
                source=f"{src} · filesystem scanner",
                timestamp=stamp,
                limitations=["Unreadable locations were not examined."],
            ))
            if item:
                added.append(item)

        return added

    def add_integrity_diff(
        self,
        diff: Any,
        baseline_at: Optional[float] = None,
        compared_at: Optional[float] = None,
        source: str = "File Integrity Watchtower",
    ) -> List[EvidenceItem]:
        """Translate an IntegrityDiff into file-change evidence."""
        if diff is None:
            return []
        added: List[EvidenceItem] = []
        stamp = compared_at
        base_note = (f"baseline {format_timestamp(baseline_at)}"
                     if baseline_at is not None else "baseline time unavailable")

        def _add(status: str, changes: Sequence[Any], limitation: str) -> None:
            changes = list(changes or [])
            if not changes:
                return
            item = self.add(EvidenceItem(
                category="FILE_INTEGRITY",
                title=f"{len(changes)} file(s) {status} since baseline",
                detail=f"Comparison against {base_note}",
                provenance=PROV_MEASURED,
                source=source,
                timestamp=stamp,
                evidence=[str(getattr(c, "relpath", c)) for c in changes[:6]],
                limitations=[limitation],
            ))
            if item:
                added.append(item)

        _add("added", getattr(diff, "added", []),
             "New files may be legitimate; a new file is not proof of malicious activity.")
        _add("modified", getattr(diff, "modified", []),
             "A changed hash proves the content changed, not why or by what.")
        _add("deleted", getattr(diff, "deleted", []),
             "Deletion may be routine cleanup; absence is not evidence of encryption.")

        try:
            total = int(getattr(diff, "total", 0) or 0)
            skipped = list(getattr(diff, "skipped", []) or [])
        except (TypeError, ValueError):
            total, skipped = 0, []
        if total == 0:
            item = self.add(EvidenceItem(
                category="FILE_INTEGRITY",
                title="No readable files in integrity comparison",
                detail="The comparison produced no file records.",
                provenance=PROV_UNAVAILABLE,
                source=source,
                timestamp=stamp,
                limitations=["An empty comparison does not show that files are unchanged."],
            ))
            if item:
                added.append(item)
        if skipped:
            item = self.add(EvidenceItem(
                category="FILE_INTEGRITY",
                title=f"{len(skipped)} path(s) could not be hashed",
                detail="Unreadable, vanished, or out-of-scope entries were skipped.",
                provenance=PROV_UNAVAILABLE,
                source=source,
                timestamp=stamp,
                evidence=[str(p) for p in skipped[:6]],
                limitations=["Skipped paths were not compared."],
            ))
            if item:
                added.append(item)
        return added

    def add_timeline(self, timeline: Any) -> List[EvidenceItem]:
        """Import an InvestigationTimeline without upgrading provenance."""
        if timeline is None:
            return []
        added: List[EvidenceItem] = []
        mapping = {
            "REAL": PROV_MEASURED,
            "SIMULATED": PROV_SIMULATED,
            "INJECTED": PROV_SIMULATED,
            "SYSTEM": PROV_APPLICATION,
        }
        try:
            events = list(getattr(timeline, "events", []) or [])
        except Exception:
            return []
        for event in events:
            src = str(getattr(event, "source", "REAL"))
            prov = mapping.get(src, PROV_UNAVAILABLE)
            stamp_text = str(getattr(event, "timestamp", "") or "")
            item = self.add(EvidenceItem(
                category=str(getattr(event, "category", "EVENT")),
                title=str(getattr(event, "title", "Event")),
                detail=str(getattr(event, "detail", "") or ""),
                provenance=prov,
                source=f"timeline · {src}",
                timestamp=None,
                evidence=[str(e) for e in (getattr(event, "evidence", []) or [])],
                limitations=([f"Timeline timestamp was {stamp_text!r}; it has no full date."]
                             if stamp_text else ["Timeline event has no timestamp."]),
            ))
            if item:
                added.append(item)
        return added

    def add_alert(self, alert: Dict[str, Any]) -> Optional[EvidenceItem]:
        """Import an AlertManager record."""
        if not isinstance(alert, dict):
            return None
        metadata = alert.get("metadata") or {}
        simulated = bool(metadata.get("is_simulation")) if isinstance(metadata, dict) else False
        severity = str(alert.get("severity", "") or "").upper()
        prov = PROV_SIMULATED if simulated else (
            PROV_ERROR if severity == "ERROR" else PROV_MEASURED)
        return self.add(EvidenceItem(
            category="ALERT",
            title=str(alert.get("title", "Alert")),
            detail=str(alert.get("message", "") or ""),
            provenance=prov,
            source=str(alert.get("source", "") or "alert manager"),
            timestamp=_parse_iso(alert.get("timestamp")),
            evidence=[f"severity {severity}", f"category {alert.get('category', '')}"],
            limitations=(["Simulation alert; not a host observation."] if simulated else []),
        ))

    # -- queries ---------------------------------------------------------
    @property
    def items(self) -> List[EvidenceItem]:
        return list(self._items)

    def __len__(self) -> int:
        return len(self._items)

    def ordered_events(self) -> List[EvidenceItem]:
        """Timed evidence first (ascending), untimed evidence after, stable."""
        timed = [e for e in self._items if e.timestamp is not None]
        untimed = [e for e in self._items if e.timestamp is None]
        timed.sort(key=lambda e: (e.timestamp, e.seq))
        untimed.sort(key=lambda e: e.seq)
        return timed + untimed

    def by_provenance(self, provenance: str) -> List[EvidenceItem]:
        prov = str(provenance).upper()
        return [e for e in self.ordered_events() if e.provenance == prov]

    def summary(self) -> Dict[str, Any]:
        counts = {prov: 0 for prov in VALID_PROVENANCE}
        for e in self._items:
            counts[e.provenance] = counts.get(e.provenance, 0) + 1
        stamps = [e.timestamp for e in self._items if e.timestamp is not None]
        span = (max(stamps) - min(stamps)) if len(stamps) >= 2 else 0.0
        return {
            "total": len(self._items),
            "counts": counts,
            "measured": counts[PROV_MEASURED],
            "simulated": counts[PROV_SIMULATED],
            "heuristic": counts[PROV_HEURISTIC],
            "unavailable": counts[PROV_UNAVAILABLE],
            "errors": counts[PROV_ERROR],
            "application": counts[PROV_APPLICATION],
            "missing_timestamps": sum(1 for e in self._items if e.timestamp is None),
            "has_measured": counts[PROV_MEASURED] > 0,
            "has_simulated": counts[PROV_SIMULATED] > 0,
            "incomplete": (counts[PROV_UNAVAILABLE] + counts[PROV_ERROR]) > 0,
            "span_seconds": round(span, 3),
        }

    def findings(self) -> List[Dict[str, Any]]:
        """Evidence-based correlation statements; never causal claims."""
        findings: List[Dict[str, Any]] = []
        summary = self.summary()
        elevated = (self._classification in _ELEVATED_LEVELS)
        prob_text = ("UNAVAILABLE" if self._probability is None
                     else f"{self._probability:.3f}")
        heuristic = [e for e in self._items if e.provenance == PROV_HEURISTIC]
        integrity = [e for e in self._items if e.category == "FILE_INTEGRITY"
                     and e.provenance == PROV_MEASURED]
        model = [e for e in self._items if e.category == "MODEL_INFERENCE"
                 and e.provenance in (PROV_MEASURED, PROV_SIMULATED)]

        if not self._items:
            findings.append({
                "kind": "NO_EVIDENCE",
                "statement": "No evidence is available; no conclusions can be drawn.",
                "provenance": PROV_UNAVAILABLE,
                "supporting": [],
                "caveat": "Run a scan or select evidence before investigating.",
            })
            return findings

        if elevated and (heuristic or integrity):
            supporting = [e.seq for e in (model + heuristic + integrity)]
            findings.append({
                "kind": "CO_OCCURRENCE",
                "statement": (
                    f"An elevated model probability ({prob_text}) co-occurred with "
                    f"{len(heuristic)} heuristic indicator group(s) and "
                    f"{len(integrity)} file-integrity observation group(s). "
                    "This is co-occurrence, not causation."
                ),
                "provenance": (PROV_SIMULATED if self._scan_simulated else PROV_MEASURED),
                "supporting": supporting,
                "caveat": ("Temporal proximity and a changed hash do not establish "
                           "that any specific file caused the prediction."),
            })
        elif elevated:
            supporting = [e.seq for e in model]
            findings.append({
                "kind": "MODEL_ONLY",
                "statement": (
                    f"The model raised {self._classification} at p={prob_text}, "
                    "but no corroborating file or heuristic evidence was recorded."
                ),
                "provenance": (PROV_SIMULATED if self._scan_simulated else PROV_MEASURED),
                "supporting": supporting,
                "caveat": "A prediction without corroboration is not confirmed malware.",
            })

        if integrity:
            findings.append({
                "kind": "FILE_CHANGE",
                "statement": (
                    f"{len(integrity)} integrity observation group(s) recorded file "
                    "additions, changes, or deletions."
                ),
                "provenance": PROV_MEASURED,
                "supporting": [e.seq for e in integrity],
                "caveat": ("A changed hash proves only that content changed; it does "
                           "not prove ransomware or tampering."),
            })

        if summary["incomplete"]:
            findings.append({
                "kind": "COVERAGE_GAP",
                "statement": (
                    f"{summary['unavailable'] + summary['errors']} observation(s) were "
                    "unavailable or failed; coverage is incomplete."
                ),
                "provenance": PROV_UNAVAILABLE,
                "supporting": [e.seq for e in self._items
                               if e.provenance in (PROV_UNAVAILABLE, PROV_ERROR)],
                "caveat": "Missing evidence cannot be interpreted as absence of threats.",
            })

        if self._items and not summary["has_measured"]:
            findings.append({
                "kind": "SIMULATION_ONLY",
                "statement": (
                    "All correlated evidence is simulated or application-generated; "
                    "it does not describe this host."
                ),
                "provenance": PROV_SIMULATED,
                "supporting": [e.seq for e in self._items],
                "caveat": "Use a live scan to collect measured evidence.",
            })

        if summary["missing_timestamps"]:
            findings.append({
                "kind": "MISSING_TIME",
                "statement": (
                    f"{summary['missing_timestamps']} event(s) have no timestamp and "
                    "are listed after timed events."
                ),
                "provenance": PROV_UNAVAILABLE,
                "supporting": [e.seq for e in self._items if e.timestamp is None],
                "caveat": "Ordering of untimed events is insertion order, not time order.",
            })

        return findings

    def display_rows(self, limit: int = 8) -> List[Dict[str, Any]]:
        """Compact rows for UI panels."""
        rows = []
        for e in self.ordered_events()[:limit]:
            rows.append({
                "seq": e.seq,
                "time": format_timestamp(e.timestamp),
                "title": e.title,
                "provenance": e.provenance,
                "provenance_label": e.provenance_label,
                "source": e.source,
                "detail": e.detail,
                "evidence": list(e.evidence),
                "limitations": list(e.limitations),
            })
        return rows

    def to_dicts(self) -> List[Dict[str, Any]]:
        return [e.to_dict() for e in self.ordered_events()]

    def clear(self) -> None:
        self._items.clear()
        self._keys.clear()
        self._next_seq = 1
        self._classification = ""
        self._probability = None
        self._scan_simulated = False
        self._scan_available = False


def demo_correlator(now: Optional[float] = None) -> EvidenceCorrelator:
    """Deterministic simulated evidence for Story Mode when no scan exists."""
    base = 1_700_000_000.0 if now is None else float(now)
    c = EvidenceCorrelator()
    c.add_manual(
        "SCAN", "Demo scan SCN-DEMO-042 finished",
        "State COMPLETE · 20 sandbox files · 110 simulated processes",
        provenance=PROV_SIMULATED, source="CONTROLLED_SIMULATION",
        timestamp=base,
        evidence=["duration 2.00s", "model source DEMO_MODE_SIMULATED_DATA"],
        limitations=["Demonstration data; no host files were read or changed."],
    )
    c.add_manual(
        "MODEL_INFERENCE", "Model prediction: WARNING",
        "Malicious probability 0.650 (simulated)",
        provenance=PROV_SIMULATED, source="CONTROLLED_SIMULATION · ML pipeline",
        timestamp=base + 2,
        evidence=["thresholds: warning 0.50, critical 0.90", "scan SCN-DEMO-042"],
        limitations=["Scripted demonstration value, not a measured prediction."],
    )
    c.add_manual(
        "FILE_OBSERVATION", "2 sandbox files flagged by heuristics",
        "Entropy and rename patterns observed inside the sandbox copy.",
        provenance=PROV_HEURISTIC, source="sandbox scanner",
        timestamp=base + 3,
        evidence=["temp_sandbox/doc_01.txt.locked_sim", "temp_sandbox/doc_02.txt.locked_sim"],
        limitations=["Heuristic flags are indicators, not proof of encryption."],
    )
    c.add_manual(
        "FILE_INTEGRITY", "1 sandbox file modified since baseline",
        "Comparison of the sandbox copy only.",
        provenance=PROV_SIMULATED, source="File Integrity Watchtower (demo)",
        timestamp=base + 4,
        evidence=["temp_sandbox/doc_01.txt"],
        limitations=["A changed hash proves only that content changed."],
    )
    c._classification = "WARNING"
    c._probability = 0.65
    c._scan_simulated = True
    return c
