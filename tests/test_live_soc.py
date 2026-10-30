"""
SentinelML V2 — Live SOC refresh & platform capability acceptance tests.

Covers:
1. 60-second default interval and clamping.
2. Automatic refresh while the monitor is enabled.
3. Stop/shutdown cancellation with no post-stop callbacks.
4. No overlapping collection jobs.
5. Recovery after a telemetry error.
6. Stale / last-success indicators.
7. INCONCLUSIVE (never SAFE) when telemetry is missing or a scan aborted.
8. UI-thread marshalling and stale-snapshot rejection.
9. Event dedupe cooldown stability.
10. Windows/Linux capability adapters expose the same interface and honest statuses.
11. Model / report consistency (offline benchmark only).
"""

import json
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from livemon import SOCMonitor, SOCTelemetry, SOCTelemetryCollector
from livemon.monitor import DEFAULT_INTERVAL_S, MIN_INTERVAL_S, MAX_INTERVAL_S, clamp_interval
from livemon.telemetry import QUALITY_FAILED, QUALITY_LIVE
from scanner.scan_engine import ScanResult, ScanState, ScanType
from utils.platform_capabilities import (
    STATUS_AVAILABLE,
    STATUS_ERROR,
    STATUS_UNAVAILABLE,
    PlatformCapabilities,
    build_platform_capabilities,
)


class FakeClock:
    """Deterministic wall/monotonic clock so scheduler tests never sleep."""

    def __init__(self, start: float = 1_000_000.0):
        self._value = float(start)
        self._lock = threading.Lock()

    def __call__(self) -> float:
        with self._lock:
            return self._value

    def advance(self, seconds: float) -> None:
        with self._lock:
            self._value += float(seconds)


class StubAlertManager:
    def __init__(self):
        self.alerts = []

    def add_alert(self, **kwargs):
        self.alerts.append(kwargs)
        return kwargs

    def get_alerts(self, limit=100):
        return list(self.alerts)


class FakeCollector:
    """Collector double that records concurrency and can fail on demand."""

    def __init__(self, delay: float = 0.0, fail_times: int = 0):
        self.delay = delay
        self.fail_times = fail_times
        self.calls = 0
        self.concurrent = 0
        self.max_concurrent = 0
        self.recorded = []
        self.started = threading.Event()
        self._lock = threading.Lock()

    def record_scan(self, result) -> None:
        self.recorded.append(result)

    def collect(self, seq=0, generation=0, cancel_check=None):
        with self._lock:
            self.calls += 1
            call_no = self.calls
            self.concurrent += 1
            self.max_concurrent = max(self.max_concurrent, self.concurrent)
        self.started.set()
        try:
            if self.delay:
                time.sleep(self.delay)
            if call_no <= self.fail_times:
                raise RuntimeError("simulated telemetry failure")
            return SOCTelemetry(
                seq=seq,
                generation=generation,
                collected_at=time.time(),
                collected_at_iso="2026-10-29 00:00:00",
                quality=QUALITY_LIVE,
                capabilities={},
                threats={"counts": {}, "counts_24h": {}, "threats_24h": 0},
                events=[],
            )
        finally:
            with self._lock:
                self.concurrent -= 1


def wait_until(predicate, timeout=6.0, interval=0.01) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


class TestSOCMonitorScheduling(unittest.TestCase):
    def _make_monitor(self, collector, clock=None, interval=60, on_snapshot=None):
        clock = clock or FakeClock()
        monitor = SOCMonitor(
            config={"soc": {"interval_seconds": interval}},
            collector=collector,
            on_snapshot=on_snapshot,
            alert_manager=StubAlertManager(),
            clock=clock,
            monotonic=clock,
        )
        return monitor, clock

    def test_default_interval_is_60_seconds(self):
        import config as cfg

        self.assertEqual(DEFAULT_INTERVAL_S, 60)
        self.assertEqual(cfg.DEFAULTS["soc"]["interval_seconds"], 60)
        self.assertEqual(cfg.DEFAULTS["soc"]["auto_refresh"], True)
        collector = FakeCollector()
        monitor, _ = self._make_monitor(collector, interval=None)
        self.assertEqual(monitor.interval_seconds, 60)

    def test_interval_is_clamped(self):
        self.assertEqual(clamp_interval(None), 60)
        self.assertEqual(clamp_interval(1), MIN_INTERVAL_S)
        self.assertEqual(clamp_interval(99_999), MAX_INTERVAL_S)
        self.assertEqual(clamp_interval("45"), 45)

    def test_automatic_refresh_while_enabled(self):
        collector = FakeCollector()
        emitted = []
        monitor, clock = self._make_monitor(collector, on_snapshot=emitted.append)
        try:
            self.assertTrue(monitor.start())
            self.assertTrue(wait_until(lambda: collector.calls >= 1))
            self.assertTrue(wait_until(lambda: len(emitted) == 1))

            # Simulate the 60 s interval elapsing; the worker must re-run
            # without any manual refresh call.
            clock.advance(61)
            for _ in range(30):
                monitor._wake_event.set()
                if collector.calls >= 2:
                    break
                time.sleep(0.01)
            self.assertTrue(wait_until(lambda: collector.calls >= 2), "automatic second cycle did not run")
            self.assertTrue(wait_until(lambda: len(emitted) >= 2))
            self.assertTrue(wait_until(lambda: monitor.get_status()["next_refresh_in_s"] is not None))

            status = monitor.get_status()
            self.assertTrue(status["running"])
            self.assertIsNotNone(status["last_success_age_s"])
            self.assertIsNotNone(status["next_refresh_in_s"])
            self.assertGreaterEqual(status["next_refresh_in_s"], 0.0)
        finally:
            monitor.stop()

    def test_stop_cancels_pending_work(self):
        collector = FakeCollector(delay=0.25)
        emitted = []
        monitor, _ = self._make_monitor(collector, on_snapshot=emitted.append)
        self.assertTrue(monitor.start())
        self.assertTrue(collector.started.wait(4.0))
        self.assertTrue(monitor.stop(join_timeout=3.0))
        calls_at_stop = collector.calls
        time.sleep(0.4)
        self.assertEqual(collector.calls, calls_at_stop, "worker ran after stop")
        self.assertEqual(len(emitted), 0, "snapshot emitted after stop")
        self.assertFalse(monitor.running)
        self.assertIsNone(monitor.get_status()["next_refresh_in_s"])

    def test_no_overlapping_jobs(self):
        collector = FakeCollector(delay=0.15)
        monitor, _ = self._make_monitor(collector)
        try:
            monitor.start()
            self.assertTrue(collector.started.wait(4.0))
            for _ in range(8):
                monitor.refresh_now()
                time.sleep(0.01)
            self.assertTrue(wait_until(lambda: collector.calls >= 2, timeout=8.0))
            self.assertEqual(collector.max_concurrent, 1, "collection cycles overlapped")
        finally:
            monitor.stop()

    def test_recovers_after_telemetry_error(self):
        collector = FakeCollector(fail_times=1)
        emitted = []
        alerts = StubAlertManager()
        clock = FakeClock()
        monitor = SOCMonitor(
            config={"soc": {"interval_seconds": 60}},
            collector=collector,
            on_snapshot=emitted.append,
            alert_manager=alerts,
            clock=clock,
            monotonic=clock,
        )
        try:
            monitor.start()
            self.assertTrue(wait_until(lambda: collector.calls >= 1))
            self.assertTrue(wait_until(lambda: monitor.get_status()["consecutive_failures"] == 1))
            first = monitor.get_status()
            self.assertIsNone(first["last_success_age_s"])
            self.assertIn("simulated telemetry failure", first["last_error"])
            self.assertTrue(any(a.get("severity") == "MEDIUM" for a in alerts.alerts))

            clock.advance(61)
            for _ in range(30):
                monitor._wake_event.set()
                if collector.calls >= 2:
                    break
                time.sleep(0.01)
            self.assertTrue(wait_until(lambda: collector.calls >= 2))
            self.assertTrue(wait_until(lambda: monitor.get_status()["consecutive_failures"] == 0))
            recovered = monitor.get_status()
            self.assertEqual(recovered["quality"], QUALITY_LIVE)
            self.assertIsNotNone(recovered["last_success_age_s"])
            self.assertEqual(recovered["last_error"], "")
            self.assertTrue(any(a.get("title") == "SOC telemetry recovered" for a in alerts.alerts))
        finally:
            monitor.stop()

    def test_stale_flag_after_missed_window(self):
        collector = FakeCollector()
        monitor, clock = self._make_monitor(collector, interval=60)
        try:
            monitor.start()
            self.assertTrue(wait_until(lambda: collector.calls >= 1))
            self.assertTrue(wait_until(lambda: monitor.get_status()["quality"] == QUALITY_LIVE))
            self.assertFalse(monitor.get_status()["stale"])

            clock.advance(60 * 2.5 + 5)
            self.assertTrue(monitor.get_status()["stale"])
        finally:
            monitor.stop()

    def test_events_are_deduped_within_cooldown(self):
        collector = FakeCollector()
        monitor, clock = self._make_monitor(collector)
        event = {
            "id": "fs-1",
            "dedupe_key": "fs:1:0:0:x",
            "kind": "filesystem",
            "severity": "INFO",
            "title": "File metadata changes",
            "timestamp": "2026-10-29 00:00:00",
        }
        first = monitor._merge_events([dict(event)])
        second = monitor._merge_events([dict(event)])
        self.assertEqual(len(first), 1)
        self.assertEqual(second, [])
        self.assertEqual(len(monitor.events()), 1)

        clock.advance(700)
        third = monitor._merge_events([dict(event)])
        self.assertEqual(len(third), 1, "event should re-emit after cooldown")
        self.assertEqual(len(monitor.events()), 2)


class TestSOCCollectorHonesty(unittest.TestCase):
    def _collector_with_failed_process_probe(self):
        caps = PlatformCapabilities(
            "Windows",
            {
                "process_enumeration": lambda: (STATUS_ERROR, "access denied"),
                "system_cpu_memory": lambda: (STATUS_AVAILABLE, "ok"),
                "file_metadata": lambda: (STATUS_AVAILABLE, "ok"),
            },
        )
        tmp = tempfile.mkdtemp(prefix="sentinel_soc_test_")
        return SOCTelemetryCollector(
            capabilities=caps,
            scope_provider=lambda: [Path(tmp)],
            process_provider=lambda: [],
            alert_provider=lambda: [],
            guard_provider=lambda: {"running": False},
            file_depth=1,
            max_files=50,
        ), tmp

    def test_missing_telemetry_is_failed_never_safe(self):
        collector, tmp = self._collector_with_failed_process_probe()
        try:
            snapshot = collector.collect(seq=1, generation=1)
            self.assertEqual(snapshot.quality, QUALITY_FAILED)
            self.assertFalse(snapshot.process["available"])
            self.assertEqual(snapshot.process["count"], None)
            for value in (snapshot.process.get("count"), snapshot.process.get("suspicious_count")):
                self.assertIsNone(value, "unavailable process data must not be reported as zero")
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_aborted_scan_classified_inconclusive(self):
        collector, tmp = self._collector_with_failed_process_probe()
        try:
            aborted = ScanResult(
                scan_type=ScanType.QUICK,
                state=ScanState.SCAN_INCOMPLETE,
                cancelled=True,
                files_inspected=10,
                processes_analyzed=2,
                threat_level="INCOMPLETE",
            )
            collector.record_scan(aborted)
            snapshot = collector.collect(seq=2, generation=1)
            self.assertEqual(snapshot.classification, "INCONCLUSIVE")
            self.assertNotEqual(snapshot.classification, "SAFE")
            self.assertEqual(snapshot.last_scan["classification"], "INCONCLUSIVE")
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_simulation_never_reported_as_live_scan(self):
        collector, tmp = self._collector_with_failed_process_probe()
        try:
            sim = ScanResult(
                scan_type=ScanType.QUICK,
                state=ScanState.COMPLETE,
                threat_level="SAFE",
                is_simulation=True,
                scan_origin="CONTROLLED_SIMULATION",
            )
            collector.record_scan(sim)
            snapshot = collector.collect(seq=3, generation=1)
            self.assertEqual(snapshot.classification, "CONTROLLED_SIMULATION")
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


class TestPlatformCapabilityAdapters(unittest.TestCase):
    EXPECTED = {
        "process_enumeration",
        "process_memory",
        "system_cpu_memory",
        "network_connections",
        "file_metadata",
        "file_hash",
        "process_handles",
        "registry",
        "event_log",
        "security_services",
    }

    def test_windows_and_linux_share_interface(self):
        for name in ("Windows", "Linux"):
            caps = build_platform_capabilities(name)
            self.assertEqual(caps.platform_name, name)
            probed = caps.probe_all()
            self.assertEqual(set(probed), self.EXPECTED)
            for cap in probed.values():
                self.assertIn(
                    cap.status,
                    {STATUS_AVAILABLE, STATUS_UNAVAILABLE, "permission_required", STATUS_ERROR},
                )

    def test_injected_probes_report_honest_statuses(self):
        caps = PlatformCapabilities(
            "TestOS",
            {
                "process_enumeration": lambda: (STATUS_AVAILABLE, "ok"),
                "registry": lambda: (_ for _ in ()).throw(RuntimeError("denied")),
                "event_log": lambda: ("permission_required", "elevation required"),
            },
        )
        probed = caps.probe_all()
        self.assertEqual(probed["process_enumeration"].status, STATUS_AVAILABLE)
        self.assertEqual(probed["registry"].status, STATUS_ERROR)
        self.assertEqual(probed["event_log"].status, "permission_required")
        self.assertEqual(probed["security_services"].status, STATUS_UNAVAILABLE)
        self.assertEqual(caps.available_keys(), ("process_enumeration",))


class TestDashboardSOCWiring(unittest.TestCase):
    def test_stale_snapshot_is_rejected_and_thread_callback_is_queued(self):
        import customtkinter as ctk
        from gui.pages.dashboard import DashboardPage

        root = ctk.CTk()
        try:
            dashboard = DashboardPage(root, config={})
            root.update()

            newer = SOCTelemetry(
                seq=5,
                quality=QUALITY_LIVE,
                capabilities={},
                threats={"counts_24h": {}, "threats_24h": 0},
                events=[{
                    "kind": "alert",
                    "severity": "HIGH",
                    "title": "Test SOC event",
                    "timestamp": "2026-10-29 10:15:00",
                    "dedupe_key": "test:1",
                }],
            )
            older = SOCTelemetry(seq=4, quality=QUALITY_LIVE)

            dashboard._render_soc_snapshot(newer)
            dashboard._render_soc_snapshot(older)
            self.assertIs(dashboard._soc_latest, newer, "stale snapshot overwrote newer data")

            worker = threading.Thread(target=dashboard._on_soc_snapshot, args=(older,))
            worker.start()
            worker.join(2.0)
            self.assertGreater(dashboard._ui_queue.qsize(), 0, "worker callback was not queued")
            dashboard._drain_ui_queue()
            root.update()
            self.assertIs(dashboard._soc_latest, newer)
        finally:
            root.destroy()

    def test_dashboard_without_soc_config_does_not_auto_start(self):
        import customtkinter as ctk
        from gui.pages.dashboard import DashboardPage

        root = ctk.CTk()
        try:
            dashboard = DashboardPage(root, config={})
            for _ in range(20):
                root.update()
                time.sleep(0.02)
            dashboard._soc_bootstrap()
            self.assertFalse(dashboard._soc_monitor.running)
        finally:
            dashboard.stop_soc()
            root.destroy()


class TestModelReportConsistency(unittest.TestCase):
    def test_offline_benchmark_is_stated_as_offline(self):
        metrics = json.loads((PROJECT_ROOT / "models" / "metrics.json").read_text(encoding="utf-8"))
        self.assertAlmostEqual(metrics["Random Forest"]["accuracy"], 0.9567, places=4)

        from gui.pages.dashboard import REPORT_LIMITATIONS
        joined = " ".join(REPORT_LIMITATIONS).lower()
        self.assertIn("95.67%", joined)
        self.assertIn("offline", joined)
        self.assertIn("not a measured real-world", joined)

    def test_feature_order_preserved(self):
        from ml.predictor import FEATURE_NAMES
        from gui.pages.dashboard import FEATURE_META

        self.assertEqual(len(FEATURE_NAMES), 19)
        self.assertEqual(list(FEATURE_META.keys()), list(FEATURE_NAMES))


if __name__ == "__main__":
    unittest.main()
