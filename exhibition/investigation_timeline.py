"""
SentinelML V2 — Threat Investigation Timeline
=============================================
Chronological record of investigation events produced while a scan or an
exhibition scenario runs.

Design rules (mirrors the rest of the project):
  * Pure data structure — no Tkinter, safe to use from worker threads.
  * Every event declares where it came from:
        REAL      -> measured on this host during this run (scan/telemetry)
        SIMULATED -> scripted demonstration data (sandbox / injected vectors)
        INJECTED  -> deliberate failure injection (sensor outage, missing model)
        SYSTEM    -> application-level bookkeeping (init, recovery, response)
  * Events are strictly ordered by sequence number; selection is by sequence,
    so a stale UI callback can never reorder or fabricate events.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

# Canonical categories — Phase 3 investigation stages.
CATEGORY_SCAN_INIT = "SCAN_INIT"
CATEGORY_PROCESS_OBS = "PROCESS_OBSERVATION"
CATEGORY_FILE_OBS = "FILE_OBSERVATION"
CATEGORY_TELEMETRY = "TELEMETRY_SENSOR"
CATEGORY_MISSING_SENSOR = "MISSING_MEASUREMENT"
CATEGORY_MODEL_INFERENCE = "MODEL_INFERENCE"
CATEGORY_INDICATOR = "SUSPICIOUS_INDICATOR"
CATEGORY_CLASSIFICATION = "FINAL_CLASSIFICATION"
CATEGORY_RESPONSE = "RECOMMENDED_RESPONSE"
CATEGORY_SIMULATION = "SIMULATION_ACTIVITY"
CATEGORY_CANCELLATION = "CANCELLATION"
CATEGORY_ERROR = "ERROR"
CATEGORY_RECOVERY = "RECOVERY"

# Source labels
SOURCE_REAL = "REAL"
SOURCE_SIMULATED = "SIMULATED"
SOURCE_INJECTED = "INJECTED"
SOURCE_SYSTEM = "SYSTEM"

VALID_SOURCES = (SOURCE_REAL, SOURCE_SIMULATED, SOURCE_INJECTED, SOURCE_SYSTEM)

CATEGORY_ORDER: List[str] = [
    CATEGORY_SCAN_INIT,
    CATEGORY_PROCESS_OBS,
    CATEGORY_FILE_OBS,
    CATEGORY_TELEMETRY,
    CATEGORY_MISSING_SENSOR,
    CATEGORY_MODEL_INFERENCE,
    CATEGORY_INDICATOR,
    CATEGORY_SIMULATION,
    CATEGORY_CANCELLATION,
    CATEGORY_ERROR,
    CATEGORY_CLASSIFICATION,
    CATEGORY_RESPONSE,
    CATEGORY_RECOVERY,
]


@dataclass
class InvestigationEvent:
    """A single timestamped investigation event."""

    seq: int
    category: str
    title: str
    detail: str
    source: str = SOURCE_REAL
    timestamp: str = ""
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "seq": self.seq,
            "category": self.category,
            "title": self.title,
            "detail": self.detail,
            "source": self.source,
            "timestamp": self.timestamp,
            "evidence": list(self.evidence),
        }

    @property
    def source_label(self) -> str:
        """Human-readable provenance tag for the UI."""
        return {
            SOURCE_REAL: "MEASURED",
            SOURCE_SIMULATED: "SIMULATED",
            SOURCE_INJECTED: "FAILURE INJECTION",
            SOURCE_SYSTEM: "APPLICATION",
        }.get(self.source, self.source)


class InvestigationTimeline:
    """Thread-safe, strictly ordered investigation event log."""

    def __init__(self) -> None:
        self._events: List[InvestigationEvent] = []
        self._lock = threading.Lock()

    # -- mutation ---------------------------------------------------------
    def add(
        self,
        category: str,
        title: str,
        detail: str,
        source: str = SOURCE_REAL,
        evidence: Optional[List[str]] = None,
    ) -> InvestigationEvent:
        """Append an event and return it. Safe to call from worker threads."""
        if source not in VALID_SOURCES:
            source = SOURCE_SYSTEM
        with self._lock:
            seq = len(self._events) + 1
            evt = InvestigationEvent(
                seq=seq,
                category=category,
                title=title,
                detail=detail,
                source=source,
                timestamp=datetime.now().strftime("%H:%M:%S.%f")[:-3],
                evidence=list(evidence or []),
            )
            self._events.append(evt)
            return evt

    def clear(self) -> None:
        with self._lock:
            self._events.clear()

    # -- reads ------------------------------------------------------------
    @property
    def events(self) -> List[InvestigationEvent]:
        """All events in insertion (chronological) order."""
        with self._lock:
            return list(self._events)

    def __len__(self) -> int:
        with self._lock:
            return len(self._events)

    def get(self, seq: int) -> Optional[InvestigationEvent]:
        """Return the event with the given sequence number (1-based), or None."""
        with self._lock:
            for evt in self._events:
                if evt.seq == seq:
                    return evt
        return None

    def by_category(self, category: str) -> List[InvestigationEvent]:
        with self._lock:
            return [e for e in self._events if e.category == category]

    def has_category(self, category: str) -> bool:
        return len(self.by_category(category)) > 0

    def categories_present(self) -> List[str]:
        """Categories in the canonical order that actually occur."""
        seen = set(e.category for e in self.events)
        ordered = [c for c in CATEGORY_ORDER if c in seen]
        extra = sorted(seen - set(CATEGORY_ORDER))
        return ordered + extra

    def is_ordered(self) -> bool:
        """True when sequence numbers are strictly increasing from 1."""
        with self._lock:
            return all(self._events[i].seq == i + 1 for i in range(len(self._events)))

    def to_dicts(self) -> List[Dict]:
        return [e.to_dict() for e in self.events]

    # -- convenience ------------------------------------------------------
    def snapshot_summary(self) -> Dict:
        events = self.events
        return {
            "event_count": len(events),
            "ordered": self.is_ordered(),
            "categories": self.categories_present(),
            "simulated_events": sum(1 for e in events if e.source == SOURCE_SIMULATED),
            "injected_events": sum(1 for e in events if e.source == SOURCE_INJECTED),
            "real_events": sum(1 for e in events if e.source == SOURCE_REAL),
            "first_timestamp": events[0].timestamp if events else "",
            "last_timestamp": events[-1].timestamp if events else "",
        }


def now_timestamp() -> str:
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def elapsed_ms(t0: float) -> float:
    return round((time.time() - t0) * 1000.0, 1)
