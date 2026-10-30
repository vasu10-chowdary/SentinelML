"""
SentinelML V2 — Live SOC monitor.
=================================
A single background worker that refreshes host telemetry on a fixed-delay,
monotonic schedule (60 s by default).

Reliability contract:
  * One worker thread only; collection can never overlap itself.
  * Fixed-delay scheduling from the end of each run; missed cycles are skipped,
    never replayed (no catch-up storm after suspend/resume).
  * ``stop()`` cancels cooperatively and invalidates in-flight results via a
    generation token, so a slow collection cannot overwrite newer data.
  * The last successful update, next refresh, consecutive failures and error
    text are always available to the UI.
  * Identical events are deduplicated by key with a cooldown, and monitor
    alerts fire only on state transitions.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from livemon.telemetry import (
    QUALITY_FAILED,
    SOCTelemetry,
    SOCTelemetryCollector,
    _iso,
)

log = logging.getLogger("sentinel.livemon.monitor")

DEFAULT_INTERVAL_S = 60
MIN_INTERVAL_S = 10
MAX_INTERVAL_S = 3600
STALE_FACTOR = 2.5
EVENT_COOLDOWN_S = 600
MONITOR_ALERT_COOLDOWN_S = 900
MAX_ROLLING_EVENTS = 80


def clamp_interval(value: Any, default: int = DEFAULT_INTERVAL_S) -> int:
    try:
        seconds = int(value)
    except Exception:
        seconds = default
    return max(MIN_INTERVAL_S, min(MAX_INTERVAL_S, seconds))


class SOCMonitor:
    """Schedules ``SOCTelemetryCollector`` runs and publishes snapshots."""

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        collector: Optional[SOCTelemetryCollector] = None,
        on_snapshot: Optional[Callable[[SOCTelemetry], None]] = None,
        alert_manager=None,
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        soc_cfg = {}
        if isinstance(config, dict):
            soc_cfg = config.get("soc", {}) or {}
        self._collector = collector or SOCTelemetryCollector(
            file_depth=soc_cfg.get("file_depth", 1),
            max_files=soc_cfg.get("max_files", 2000),
            scan_stale_seconds=soc_cfg.get("scan_stale_seconds", 86400),
        )
        self._on_snapshot = on_snapshot
        self._alert_manager = alert_manager
        self._clock = clock
        self._monotonic = monotonic

        self._lock = threading.RLock()
        self._interval_s = clamp_interval(soc_cfg.get("interval_seconds", DEFAULT_INTERVAL_S))
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._wake_event = threading.Event()
        self._running = False
        self._collecting = False
        self._refresh_pending = False
        self._force_run = False
        self._generation = 0
        self._seq = 0
        self._started_mono: Optional[float] = None
        self._next_run_mono: Optional[float] = None
        self._snapshot: Optional[SOCTelemetry] = None
        self._last_success_wall: Optional[float] = None
        self._last_success_mono: Optional[float] = None
        self._consecutive_failures = 0
        self._last_error = ""
        self._events: List[Dict[str, Any]] = []
        self._event_keys: Dict[str, float] = {}
        self._alert_keys: Dict[str, float] = {}

    # ── Lifecycle ─────────────────────────────────────────────────────────
    def start(self) -> bool:
        with self._lock:
            if self._running:
                return False
            self._generation += 1
            self._stop_event.clear()
            self._wake_event.clear()
            self._running = True
            self._collecting = False
            self._refresh_pending = False
            self._force_run = False
            self._started_mono = self._monotonic()
            self._next_run_mono = self._started_mono
            self._thread = threading.Thread(
                target=self._run, name="SOCMonitor", daemon=True
            )
            thread = self._thread
        thread.start()
        log.info("SOC monitor started (interval=%ss)", self.interval_seconds)
        return True

    def stop(self, join_timeout: float = 2.0) -> bool:
        with self._lock:
            thread = self._thread
            if not self._running and (thread is None or not thread.is_alive()):
                self._next_run_mono = None
                return True
            self._stop_event.set()
            self._wake_event.set()
            self._generation += 1  # invalidate any in-flight collection
            self._running = False
            self._refresh_pending = False
            self._force_run = False
            self._next_run_mono = None
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=join_timeout)
        stopped = thread is None or not thread.is_alive()
        with self._lock:
            if stopped:
                self._thread = None
        log.info("SOC monitor stopped (clean=%s)", stopped)
        return stopped

    def destroy(self) -> None:
        self.stop()

    # ── Control ───────────────────────────────────────────────────────────
    def refresh_now(self) -> bool:
        with self._lock:
            if not self._running:
                return False
            if self._collecting:
                self._refresh_pending = True
                return False
            self._force_run = True
        self._wake_event.set()
        return True

    def set_interval(self, seconds: Any) -> int:
        new_interval = clamp_interval(seconds, self._interval_s)
        with self._lock:
            self._interval_s = new_interval
            if self._running and self._next_run_mono is not None:
                cap = self._monotonic() + new_interval
                if self._next_run_mono > cap:
                    self._next_run_mono = cap
        self._wake_event.set()
        return new_interval

    def apply_config(self, config: Optional[Dict[str, Any]]) -> int:
        soc_cfg = (config or {}).get("soc", {}) if isinstance(config, dict) else {}
        return self.set_interval(soc_cfg.get("interval_seconds", self._interval_s))

    @property
    def interval_seconds(self) -> int:
        with self._lock:
            return self._interval_s

    @property
    def running(self) -> bool:
        with self._lock:
            return self._running

    # ── Data access ───────────────────────────────────────────────────────
    def latest(self) -> Optional[SOCTelemetry]:
        with self._lock:
            return self._snapshot

    def record_scan(self, result) -> None:
        self._collector.record_scan(result)

    def events(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self._events)
        items.sort(key=lambda e: str(e.get("timestamp", "")), reverse=True)
        return items[:max(1, int(limit))]

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            now_m = self._monotonic()
            now_w = self._clock()
            running = self._running
            collecting = self._collecting
            interval = self._interval_s
            next_run = self._next_run_mono
            started = self._started_mono
            last_success_wall = self._last_success_wall
            last_success_mono = self._last_success_mono
            snapshot = self._snapshot
            failures = self._consecutive_failures
            last_error = self._last_error
            seq = self._seq
            generation = self._generation

        if last_success_wall is None:
            last_iso = ""
            age = None
        else:
            last_iso = _iso(last_success_wall)
            age = max(0.0, now_w - last_success_wall)

        next_in = None
        next_iso = ""
        if running and next_run is not None:
            next_in = max(0.0, next_run - now_m)
            next_iso = _iso(now_w + next_in)

        if last_success_mono is not None:
            stale = (now_m - last_success_mono) > (interval * STALE_FACTOR)
        else:
            stale = bool(
                running
                and started is not None
                and (now_m - started) > (interval * STALE_FACTOR)
            )

        return {
            "running": running,
            "collecting": collecting,
            "interval_s": interval,
            "last_success_iso": last_iso,
            "last_success_age_s": age,
            "next_refresh_in_s": next_in,
            "next_refresh_iso": next_iso,
            "stale": stale,
            "consecutive_failures": failures,
            "last_error": last_error,
            "seq": seq,
            "generation": generation,
            "quality": snapshot.quality if snapshot else "NO_DATA",
            "classification": snapshot.classification if snapshot else "NOT_SCANNED",
            "collected_at_iso": snapshot.collected_at_iso if snapshot else "",
            "events_count": len(self._events),
        }

    # ── Worker ────────────────────────────────────────────────────────────
    def _run(self) -> None:
        try:
            while True:
                with self._lock:
                    if self._stop_event.is_set():
                        break
                    next_run = self._next_run_mono
                    if next_run is None:
                        next_run = self._monotonic()
                    force = self._force_run
                    self._force_run = False
                if not force:
                    delay = next_run - self._monotonic()
                    if delay > 0:
                        self._wake_event.wait(delay)
                        self._wake_event.clear()
                        if self._stop_event.is_set():
                            break
                        with self._lock:
                            force = self._force_run
                            self._force_run = False
                            next_run = self._next_run_mono or self._monotonic()
                        if not force and self._monotonic() < next_run:
                            continue
                if self._stop_event.is_set():
                    break
                self._collect_once()
                with self._lock:
                    if self._stop_event.is_set():
                        break
                    # Fixed delay from the end of this run: slow collections
                    # push the schedule forward instead of queuing missed runs.
                    self._next_run_mono = self._monotonic() + self._interval_s
                    if self._refresh_pending:
                        self._refresh_pending = False
                        self._next_run_mono = self._monotonic()
        finally:
            with self._lock:
                if self._thread is threading.current_thread():
                    self._thread = None
                self._collecting = False
                if self._stop_event.is_set():
                    self._running = False

    def _collect_once(self) -> None:
        with self._lock:
            if self._collecting or not self._running:
                return
            self._collecting = True
            generation = self._generation
            self._seq += 1
            seq = self._seq

        snapshot: Optional[SOCTelemetry] = None
        error: Optional[str] = None
        try:
            snapshot = self._collector.collect(
                seq=seq,
                generation=generation,
                cancel_check=self._stop_event.is_set,
            )
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
        finally:
            with self._lock:
                self._collecting = False

        if self._stop_event.is_set():
            return
        with self._lock:
            if generation != self._generation:
                return

        if snapshot is None:
            self._note_failure(error or "Collector returned no snapshot")
            return

        snapshot.events = self._merge_events(snapshot.events)
        ok = snapshot.quality != QUALITY_FAILED

        with self._lock:
            if generation != self._generation:
                return
            self._snapshot = snapshot
            if ok:
                had_failures = self._consecutive_failures
                self._last_success_wall = self._clock()
                self._last_success_mono = self._monotonic()
                self._consecutive_failures = 0
                self._last_error = ""
            else:
                had_failures = self._consecutive_failures
                self._consecutive_failures += 1
                self._last_error = self._snapshot_error(snapshot)

        if ok and had_failures:
            self._raise_alert(
                "monitor:recovered",
                "INFO",
                "SOC telemetry recovered",
                f"Telemetry collection resumed after {had_failures} failed cycle(s).",
            )
        elif not ok and had_failures == 0:
            self._raise_alert(
                "monitor:failed",
                "MEDIUM",
                "SOC telemetry refresh failed",
                self._last_error or "Required telemetry sources are unavailable.",
            )
        self._emit(snapshot, generation)

    def _note_failure(self, message: str) -> None:
        with self._lock:
            had_failures = self._consecutive_failures
            self._consecutive_failures += 1
            self._last_error = message
        if had_failures == 0:
            self._raise_alert(
                "monitor:failed",
                "MEDIUM",
                "SOC telemetry refresh failed",
                message,
            )

    @staticmethod
    def _snapshot_error(snapshot: SOCTelemetry) -> str:
        if snapshot.errors:
            first = snapshot.errors[0]
            return f"{first.get('source', 'telemetry')}: {first.get('message', 'failed')}"
        return "Required telemetry sources are unavailable."

    def _merge_events(self, events: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        now = self._monotonic()
        accepted: List[Dict[str, Any]] = []
        with self._lock:
            for event in events or []:
                key = str(event.get("dedupe_key") or event.get("id") or "")
                if not key:
                    continue
                last = self._event_keys.get(key)
                if last is not None and (now - last) < EVENT_COOLDOWN_S:
                    continue
                self._event_keys[key] = now
                event["dedupe_key"] = key
                accepted.append(event)
                self._events.append(event)
            if len(self._event_keys) > 500:
                ordered = sorted(self._event_keys.items(), key=lambda kv: kv[1])
                self._event_keys = dict(ordered[-250:])
            if len(self._events) > MAX_ROLLING_EVENTS:
                self._events = self._events[-MAX_ROLLING_EVENTS:]
        return accepted

    def _emit(self, snapshot: SOCTelemetry, generation: int) -> None:
        callback = self._on_snapshot
        if callback is None or snapshot.generation != generation:
            return
        with self._lock:
            if generation != self._generation or self._stop_event.is_set():
                return
        try:
            callback(snapshot)
        except Exception:
            log.exception("SOC snapshot callback failed")

    def _raise_alert(self, key: str, severity: str, title: str, message: str) -> None:
        now = self._monotonic()
        with self._lock:
            last = self._alert_keys.get(key)
            if last is not None and (now - last) < MONITOR_ALERT_COOLDOWN_S:
                return
            self._alert_keys[key] = now
        try:
            if self._alert_manager is None:
                from alerts.alert_manager import get_alert_manager
                self._alert_manager = get_alert_manager()
            self._alert_manager.add_alert(
                severity=severity,
                category="system",
                title=title,
                message=message,
                source="SOCMonitor",
                metadata={"condition": key},
            )
        except Exception:
            log.exception("SOC monitor could not persist an alert")
