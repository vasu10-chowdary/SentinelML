"""
SentinelML V2 — Live SOC lifecycle / UI reliability tests.

Covers the acceptance items not already exercised in ``test_live_soc.py``:
  * Start/Stop controls (monitor level and dashboard button wiring).
  * A second Start never creates a duplicate monitor instance.
  * Refresh Now queues while a pass is running and never overlaps.
  * Shutdown cancels scheduled work and joins the worker.
  * Failed telemetry renders DEGRADED, then recovers to MONITORING.
  * Stale telemetry renders STALE with a visible warning.
  * Outdated snapshots are rejected by the dashboard renderer.
  * Default interval stays 60 s.
"""

import sys
import threading
import time
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from livemon import SOCMonitor, SOCTelemetry
from livemon.monitor import DEFAULT_INTERVAL_S
from livemon.telemetry import QUALITY_FAILED, QUALITY_LIVE


class FakeClock:
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


class ScriptedCollector:
    """Collector double: optional delay, configurable failures, concurrency probe."""

    def __init__(self, delay: float = 0.0, fail_times: int = 0):
        self.delay = delay
        self.fail_times = fail_times
        self.calls = 0
        self.concurrent = 0
        self.max_concurrent = 0
        self.started = threading.Event()
        self._lock = threading.Lock()

    def record_scan(self, result):
        pass

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
                threats={"counts_24h": {}, "threats_24h": 0},
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


def make_monitor(collector, clock, interval=60):
    return SOCMonitor(
        config={"soc": {"interval_seconds": interval}},
        collector=collector,
        alert_manager=StubAlertManager(),
        clock=clock,
        monotonic=clock,
    )


class TestMonitorLifecycle(unittest.TestCase):
    def test_default_interval_is_still_60_seconds(self):
        self.assertEqual(DEFAULT_INTERVAL_S, 60)
        collector = ScriptedCollector()
        monitor = make_monitor(collector, FakeClock(), interval=None)
        self.assertEqual(monitor.interval_seconds, 60)

    def test_start_is_idempotent_no_duplicate_monitor(self):
        collector = ScriptedCollector()
        monitor = make_monitor(collector, FakeClock())
        try:
            self.assertTrue(monitor.start())
            thread = monitor._thread
            self.assertFalse(monitor.start(), "second start must be refused")
            self.assertIs(monitor._thread, thread, "a duplicate worker was created")
            alive = [t for t in threading.enumerate() if t is thread and t.is_alive()]
            self.assertEqual(len(alive), 1)
        finally:
            monitor.stop()

    def test_stop_then_start_again_works(self):
        collector = ScriptedCollector()
        monitor = make_monitor(collector, FakeClock())
        self.assertTrue(monitor.start())
        self.assertTrue(wait_until(lambda: collector.calls >= 1))
        self.assertTrue(monitor.stop(join_timeout=3.0))
        self.assertFalse(monitor.running)
        self.assertIsNone(monitor.get_status()["next_refresh_in_s"])
        self.assertTrue(monitor.start(), "monitor should restart cleanly after stop")
        try:
            self.assertTrue(wait_until(lambda: collector.calls >= 2))
        finally:
            monitor.stop()

    def test_refresh_now_queues_instead_of_overlapping(self):
        collector = ScriptedCollector(delay=0.25)
        monitor = make_monitor(collector, FakeClock())
        try:
            monitor.start()
            self.assertTrue(collector.started.wait(4.0))
            self.assertFalse(monitor.refresh_now(), "refresh must queue while collecting")
            self.assertTrue(monitor._refresh_pending)
            self.assertTrue(wait_until(lambda: collector.calls >= 2, timeout=8.0))
            self.assertEqual(collector.max_concurrent, 1, "collections overlapped")
        finally:
            monitor.stop()

    def test_shutdown_cancels_scheduled_work(self):
        collector = ScriptedCollector()
        clock = FakeClock()
        monitor = make_monitor(collector, clock)
        monitor.start()
        self.assertTrue(wait_until(lambda: collector.calls >= 1))
        self.assertTrue(monitor.stop(join_timeout=3.0))
        calls_at_stop = collector.calls

        clock.advance(120)
        monitor._wake_event.set()
        time.sleep(0.25)
        self.assertEqual(collector.calls, calls_at_stop, "worker ran after shutdown")
        self.assertFalse(monitor.running)

    def test_failure_marks_status_then_recovers(self):
        collector = ScriptedCollector(fail_times=1)
        clock = FakeClock()
        monitor = make_monitor(collector, clock)
        try:
            monitor.start()
            self.assertTrue(wait_until(lambda: monitor.get_status()["consecutive_failures"] == 1))
            degraded = monitor.get_status()
            self.assertIn("simulated telemetry failure", degraded["last_error"])
            self.assertNotEqual(degraded["quality"], QUALITY_LIVE)
            self.assertIsNone(degraded["last_success_age_s"])

            clock.advance(61)
            for _ in range(40):
                monitor._wake_event.set()
                if collector.calls >= 2:
                    break
                time.sleep(0.01)
            self.assertTrue(wait_until(lambda: monitor.get_status()["consecutive_failures"] == 0))
            recovered = monitor.get_status()
            self.assertEqual(recovered["quality"], QUALITY_LIVE)
            self.assertEqual(recovered["last_error"], "")
            self.assertIsNotNone(recovered["last_success_age_s"])

            clock.advance(60 * 2.5 + 5)
            self.assertTrue(monitor.get_status()["stale"])
        finally:
            monitor.stop()


class TestDashboardSOCControls(unittest.TestCase):
    def _page(self):
        import customtkinter as ctk
        from gui.pages.dashboard import DashboardPage

        try:
            root = ctk.CTk()
        except Exception as exc:  # environment-level Tk init failure
            self.skipTest(f"Tk unavailable: {exc}")
        page = DashboardPage(root, config={"soc": {"auto_refresh": False, "interval_seconds": 60}})
        root.update()
        return root, page

    def test_start_stop_toggle_controls_state(self):
        try:
            import customtkinter  # noqa: F401
        except Exception as exc:  # pragma: no cover
            self.skipTest(f"Tk unavailable: {exc}")

        root, page = self._page()
        real_monitor = page._soc_monitor
        fake = make_monitor(ScriptedCollector(), FakeClock())
        page._soc_monitor = fake
        try:
            page._soc_toggle()
            page._render_soc_status()
            self.assertTrue(fake.running)
            self.assertEqual(page._soc_state.cget("text"), "MONITORING")

            page._soc_toggle()
            page._render_soc_status()
            self.assertFalse(fake.running)
            self.assertEqual(page._soc_state.cget("text"), "STOPPED")
        finally:
            fake.stop()
            page._soc_monitor = real_monitor
            root.destroy()

    def test_degraded_then_monitoring_after_recovery(self):
        try:
            import customtkinter  # noqa: F401
        except Exception as exc:  # pragma: no cover
            self.skipTest(f"Tk unavailable: {exc}")

        root, page = self._page()
        real_monitor = page._soc_monitor
        clock = FakeClock()
        collector = ScriptedCollector(fail_times=1)
        fake = make_monitor(collector, clock)
        page._soc_monitor = fake
        try:
            fake.start()
            self.assertTrue(wait_until(lambda: fake.get_status()["consecutive_failures"] == 1))
            page._render_soc_status()
            self.assertEqual(page._soc_state.cget("text"), "DEGRADED")
            self.assertIn("failed", page._soc_warning.cget("text").lower())

            clock.advance(61)
            for _ in range(40):
                fake._wake_event.set()
                if collector.calls >= 2:
                    break
                time.sleep(0.01)
            self.assertTrue(wait_until(lambda: fake.get_status()["consecutive_failures"] == 0))
            page._render_soc_status()
            self.assertEqual(page._soc_state.cget("text"), "MONITORING")

            clock.advance(60 * 2.5 + 5)
            page._render_soc_status()
            self.assertEqual(page._soc_state.cget("text"), "STALE")
            self.assertIn("stale", page._soc_warning.cget("text").lower())
        finally:
            fake.stop()
            page._soc_monitor = real_monitor
            root.destroy()

    def test_older_snapshot_is_discarded(self):
        try:
            import customtkinter  # noqa: F401
        except Exception as exc:  # pragma: no cover
            self.skipTest(f"Tk unavailable: {exc}")

        root, page = self._page()
        try:
            newer = SOCTelemetry(seq=9, quality=QUALITY_LIVE, collected_at_iso="2026-10-29 10:00:09")
            older = SOCTelemetry(seq=8, quality=QUALITY_FAILED, collected_at_iso="2026-10-29 10:00:08")
            page._render_soc_snapshot(newer)
            page._render_soc_snapshot(older)
            self.assertIs(page._soc_latest, newer)
        finally:
            page.stop_soc(wait=False)
            root.destroy()

    def test_stop_soc_joins_worker_on_shutdown(self):
        try:
            import customtkinter  # noqa: F401
        except Exception as exc:  # pragma: no cover
            self.skipTest(f"Tk unavailable: {exc}")

        root, page = self._page()
        real_monitor = page._soc_monitor
        collector = ScriptedCollector(delay=0.3)
        fake = make_monitor(collector, FakeClock())
        page._soc_monitor = fake
        try:
            fake.start()
            self.assertTrue(collector.started.wait(4.0))
            page.stop_soc(wait=True)
            self.assertFalse(fake.running)
            self.assertTrue(fake._thread is None or not fake._thread.is_alive())
        finally:
            fake.stop()
            page._soc_monitor = real_monitor
            root.destroy()


if __name__ == "__main__":
    unittest.main()
