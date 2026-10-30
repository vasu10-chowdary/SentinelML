"""
SentinelML V2 — Persistent scan audit history tests.

Covers:
  1. First scan stored with accurate fields.
  2. Ten records available after restart (persistence).
  3. The 11th scan removes only the oldest active record.
  4. Failed / incomplete scans keep FAILED / INCONCLUSIVE (never SAFE).
  5. Duplicate callbacks do not create duplicate records.
  6. Live SOC refreshes never create scan-audit entries.
  7. Dashboard wiring: only scans that started are recorded.
  8. Corrupt audit storage is quarantined and does not crash.
  9. Model thresholds, feature order and artifacts are unchanged.
"""

import hashlib
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

from scanner.scan_engine import ScanResult, ScanState, ScanType
from utils.scan_audit import (
    AUDIT_SCHEMA_VERSION,
    MAX_AUDIT_RECORDS,
    ScanAuditStore,
    build_audit_record,
    classify_outcome,
)


def make_result(
    *,
    scan_id="SCN-TEST-1",
    state=ScanState.SAFE,
    probability=0.12,
    files=120,
    procs=250,
    suspicious=None,
    elapsed=1.5,
    **overrides,
):
    kwargs = dict(
        scan_type=ScanType.QUICK,
        state=state,
        scan_id=scan_id,
        ml_executed=True,
        ml_probability=probability,
        threat_level="SAFE" if state == ScanState.SAFE else "CRITICAL",
        elapsed_seconds=elapsed,
        files_inspected=files,
        processes_analyzed=procs,
        suspicious_files=list(suspicious or []),
    )
    kwargs.update(overrides)
    return ScanResult(**kwargs)


def record_for(result, *, completed_at, started_at=None, outcome="completed", **overrides):
    return build_audit_record(
        result,
        outcome=outcome,
        started_at=started_at if started_at is not None else completed_at - 2.0,
        completed_at=completed_at,
        scan_origin="LIVE_HOST_SCAN",
        app_version="2.0.0",
        **overrides,
    )


class TestAuditStore(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="sentinel_audit_"))
        self.path = self.tmp / "scan_audit_history.json"

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_first_scan_is_stored_with_accurate_fields(self):
        store = ScanAuditStore(self.path)
        result = make_result(probability=0.12, files=120, procs=250, suspicious=["a", "b"])
        rec = record_for(result, completed_at=1_800_000_000.0)
        stored, created = store.append(rec)

        self.assertTrue(created)
        self.assertEqual(store.count(), 1)
        self.assertTrue(self.path.exists())

        payload = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema_version"], AUDIT_SCHEMA_VERSION)
        self.assertEqual(len(payload["records"]), 1)

        row = payload["records"][0]
        self.assertEqual(row["classification"], "SAFE")
        self.assertEqual(row["severity"], "NONE")
        self.assertAlmostEqual(row["probability"], 0.12, places=4)
        self.assertEqual(row["files_examined"], 120)
        self.assertEqual(row["processes_examined"], 250)
        self.assertEqual(row["findings"], 2)
        self.assertEqual(row["provenance"], "LIVE_HOST_SCAN")
        self.assertEqual(row["app_version"], "2.0.0")
        self.assertEqual(row["scan_type"], "Manual quick scan")
        self.assertTrue(row["started_at"])
        self.assertTrue(row["completed_at"])
        self.assertAlmostEqual(row["duration_s"], 1.5, places=3)
        self.assertEqual(row["audit_id"], stored["audit_id"])

    def test_ten_records_survive_restart_newest_first(self):
        store = ScanAuditStore(self.path)
        ids = []
        for i in range(10):
            result = make_result(scan_id=f"SCN-{i}")
            rec = record_for(result, completed_at=1_800_000_000.0 + i)
            ids.append(rec["audit_id"])
            store.append(rec)

        reopened = ScanAuditStore(self.path)
        self.assertEqual(reopened.count(), 10)
        records = reopened.records()
        self.assertEqual([r["audit_id"] for r in records], list(reversed(ids)))
        self.assertEqual(records[0]["scan_id"], "SCN-9")

    def test_eleventh_removes_only_the_oldest(self):
        store = ScanAuditStore(self.path)
        ids = []
        for i in range(10):
            rec = record_for(make_result(scan_id=f"SCN-{i}"), completed_at=1_800_000_000.0 + i)
            ids.append(rec["audit_id"])
            store.append(rec)

        eleventh = record_for(make_result(scan_id="SCN-10"), completed_at=1_800_000_000.0 + 10)
        store.append(eleventh)
        ids.append(eleventh["audit_id"])

        self.assertEqual(store.count(), MAX_AUDIT_RECORDS)
        active = [r["audit_id"] for r in store.records()]
        self.assertNotIn(ids[0], active, "oldest record must leave the active list")
        for kept in ids[1:]:
            self.assertIn(kept, active, "only the oldest record may be removed")
        self.assertEqual(active[0], eleventh["audit_id"])
        self.assertEqual(ScanAuditStore(self.path).count(), MAX_AUDIT_RECORDS)

    def test_failed_and_incomplete_keep_true_status(self):
        cancelled = ScanResult(
            scan_type=ScanType.QUICK,
            state=ScanState.SCAN_INCOMPLETE,
            cancelled=True,
            scan_id="SCN-CANCEL",
            files_inspected=7,
            processes_analyzed=0,
        )
        level, reason = classify_outcome(cancelled, "cancelled")
        self.assertEqual(level, "INCONCLUSIVE")
        self.assertTrue(reason)

        failed = ScanResult(
            scan_type=ScanType.QUICK,
            state=ScanState.ANALYSIS_ERROR,
            scan_id="SCN-FAIL",
            error_message="model unavailable",
        )
        level, _ = classify_outcome(failed, "error")
        self.assertEqual(level, "FAILED")

        inconclusive = ScanResult(
            scan_type=ScanType.QUICK,
            state=ScanState.INCONCLUSIVE,
            scan_id="SCN-INC",
            threat_level="SAFE",
            is_inconclusive=True,
            inconclusive_reason="3 of 19 sensors missing",
        )
        level, _ = classify_outcome(inconclusive, "completed")
        self.assertEqual(level, "INCONCLUSIVE")

        no_result = build_audit_record(
            None, outcome="error", error_message="thread crashed", started_at=1.0, completed_at=2.0
        )
        self.assertEqual(no_result["classification"], "FAILED")
        self.assertIsNone(no_result["files_examined"], "unavailable counts must be None, not zero")
        self.assertIsNone(no_result["findings"])

        for value in (build_audit_record(cancelled, outcome="cancelled"), no_result):
            self.assertNotEqual(value["classification"], "SAFE")

    def test_duplicate_callbacks_do_not_duplicate(self):
        store = ScanAuditStore(self.path)
        result = make_result(scan_id="SCN-DUP")
        rec = record_for(result, completed_at=1_800_000_000.0)

        _, created_first = store.append(rec)
        _, created_second = store.append(rec)
        self.assertTrue(created_first)
        self.assertFalse(created_second)
        self.assertEqual(store.count(), 1)

        # Same scan, different audit id (UI callback fired twice).
        duplicate = record_for(result, completed_at=1_800_000_001.0)
        self.assertNotEqual(duplicate["audit_id"], rec["audit_id"])
        store.append(duplicate)
        self.assertEqual(store.count(), 1, "same scan_id must update in place")
        self.assertEqual(store.records()[0]["audit_id"], rec["audit_id"])

    def test_soc_refresh_does_not_create_audit_entries(self):
        from livemon import SOCMonitor, SOCTelemetry

        class _Collector:
            def __init__(self):
                self.calls = 0

            def record_scan(self, result):  # pragma: no cover - must not be called here
                pass

            def collect(self, seq=0, generation=0, cancel_check=None):
                self.calls += 1
                return SOCTelemetry(seq=seq, generation=generation, quality="LIVE", events=[])

        store = ScanAuditStore(self.path)
        collector = _Collector()
        monitor = SOCMonitor(config={"soc": {"interval_seconds": 10}}, collector=collector)
        try:
            monitor.start()
            deadline = time.time() + 5
            while collector.calls < 2 and time.time() < deadline:
                time.sleep(0.02)
            self.assertGreaterEqual(collector.calls, 1)
        finally:
            monitor.stop()
        self.assertEqual(store.count(), 0, "SOC refreshes must never become scan-audit records")

    def test_corrupt_storage_is_quarantined_safely(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("{ this is not json", encoding="utf-8")

        store = ScanAuditStore(self.path)
        self.assertEqual(store.count(), 0)
        self.assertTrue(store.load_error)
        quarantined = list(self.tmp.glob("scan_audit_history.json.corrupt-*"))
        self.assertEqual(len(quarantined), 1, "corrupt file must be preserved, not deleted")
        self.assertFalse(self.path.exists())

        rec = record_for(make_result(), completed_at=1_800_000_000.0)
        store.append(rec)
        self.assertEqual(store.count(), 1)
        self.assertTrue(self.path.exists())


class TestDashboardAuditWiring(unittest.TestCase):
    def _dashboard(self, audit_path):
        import customtkinter as ctk
        from gui.pages.dashboard import DashboardPage

        try:
            root = ctk.CTk()
        except Exception as exc:  # environment-level Tk init failure
            self.skipTest(f"Tk unavailable: {exc}")
        page = DashboardPage(root, config={"audit": {"path": str(audit_path)}})
        root.update()
        return root, page

    def test_completed_scan_recorded_once_and_persists(self):
        try:
            import customtkinter  # noqa: F401
        except Exception as exc:  # pragma: no cover
            self.skipTest(f"Tk unavailable: {exc}")

        tmp = Path(tempfile.mkdtemp(prefix="sentinel_dash_audit_"))
        audit_path = tmp / "audit.json"
        try:
            root, page = self._dashboard(audit_path)
            try:
                result = make_result(scan_id="SCN-DASH-1")
                page._scan_started = True
                page._scan_started_at = time.time() - 1.2
                page._on_scan_complete("SAFE", 0.12, result)
                self.assertEqual(page._audit_store.count(), 1)

                # Simulated duplicate UI callback for the same scan.
                page._scan_started = True
                page._scan_started_at = time.time() - 1.2
                page._on_scan_complete("SAFE", 0.12, result)
                self.assertEqual(page._audit_store.count(), 1, "duplicate callback created a record")
                root.update()
            finally:
                page.stop_soc(wait=False)
                root.destroy()

            root2, page2 = self._dashboard(audit_path)
            try:
                self.assertEqual(len(page2._scan_history), 1)
                self.assertEqual(page2._scan_history[0]["scan_id"], "SCN-DASH-1")
                self.assertEqual(page2._scan_history[0]["classification"], "SAFE")
            finally:
                page2.stop_soc(wait=False)
                root2.destroy()
        finally:
            import shutil

            shutil.rmtree(tmp, ignore_errors=True)

    def test_scan_that_never_started_is_not_recorded(self):
        try:
            import customtkinter  # noqa: F401
        except Exception as exc:  # pragma: no cover
            self.skipTest(f"Tk unavailable: {exc}")

        tmp = Path(tempfile.mkdtemp(prefix="sentinel_dash_audit_"))
        try:
            root, page = self._dashboard(tmp / "audit.json")
            try:
                page._on_scan_complete("SAFE", 0.1, make_result(scan_id="SCN-NOSTART"))
                self.assertEqual(page._audit_store.count(), 0)
                self.assertEqual(page._scan_history, [])
            finally:
                page.stop_soc(wait=False)
                root.destroy()
        finally:
            import shutil

            shutil.rmtree(tmp, ignore_errors=True)

    def test_cancelled_and_failed_recorded_with_true_status(self):
        try:
            import customtkinter  # noqa: F401
        except Exception as exc:  # pragma: no cover
            self.skipTest(f"Tk unavailable: {exc}")

        tmp = Path(tempfile.mkdtemp(prefix="sentinel_dash_audit_"))
        try:
            root, page = self._dashboard(tmp / "audit.json")
            try:
                cancelled = ScanResult(
                    scan_type=ScanType.QUICK,
                    state=ScanState.SCAN_INCOMPLETE,
                    scan_id="SCN-DASH-CANCEL",
                    files_inspected=4,
                )
                page._scan_started = True
                page._scan_started_at = time.time() - 0.5
                page._on_scan_cancelled(cancelled)

                failed = ScanResult(
                    scan_type=ScanType.QUICK,
                    state=ScanState.ANALYSIS_ERROR,
                    scan_id="SCN-DASH-FAIL",
                    error_message="inference failed",
                )
                page._scan_started = True
                page._scan_started_at = time.time() - 0.5
                page._on_scan_error("inference failed", failed)

                failed_sim = ScanResult(
                    scan_type=ScanType.QUICK,
                    state=ScanState.ANALYSIS_ERROR,
                    scan_id="SCN-DASH-SIMFAIL",
                    error_message="demo scenario aborted",
                    is_simulation=True,
                    model_source="DEMO_MODE_SIMULATED_DATA",
                )
                page._scan_started = True
                page._scan_started_at = time.time() - 0.4
                page._on_scan_error("demo scenario aborted", failed_sim)
                root.update()

                records = page._audit_store.records()
                by_id = {r["scan_id"]: r for r in records}
                self.assertEqual(by_id["SCN-DASH-CANCEL"]["classification"], "INCONCLUSIVE")
                self.assertEqual(by_id["SCN-DASH-FAIL"]["classification"], "FAILED")
                for rec in records:
                    self.assertNotEqual(rec["classification"], "SAFE")
                    self.assertTrue(rec["error"])

                # A failed simulation must stay labelled as a simulation, not a host scan.
                sim_rec = by_id["SCN-DASH-SIMFAIL"]
                self.assertEqual(sim_rec["classification"], "FAILED")
                self.assertEqual(sim_rec["provenance"], "CONTROLLED_SIMULATION")
                self.assertEqual(sim_rec["model_source"], "DEMO_MODE_SIMULATED_DATA")
                self.assertEqual(by_id["SCN-DASH-FAIL"]["provenance"], "LIVE_HOST_SCAN")
            finally:
                page.stop_soc(wait=False)
                root.destroy()
        finally:
            import shutil

            shutil.rmtree(tmp, ignore_errors=True)


class TestModelArtifactsUnchanged(unittest.TestCase):
    EXPECTED = {
        "models/saved_model.pkl": "936d9e3ff0b97d762751bdcba34ad3d247a4280e38f84e32dc4f31bfa1174e33",
        "models/scaler.pkl": "d993e26a313f743bbfc351912f2ac4a3be2642f4722c8c5451baf9eda26281cb",
        "models/metrics.json": "8a24b01aa0d5b38ea099f391afb486fa9310fe0ff39ae645c132172170227c88",
    }

    def test_artifacts_are_byte_identical(self):
        for rel, expected in self.EXPECTED.items():
            digest = hashlib.sha256((PROJECT_ROOT / rel).read_bytes()).hexdigest()
            self.assertEqual(digest, expected, f"{rel} changed")

    def test_thresholds_and_feature_order_unchanged(self):
        from ml.predictor import FEATURE_NAMES, MLPredictor

        self.assertEqual(MLPredictor._DEFAULT_THRESHOLD_WARNING, 0.5)
        self.assertEqual(MLPredictor._DEFAULT_THRESHOLD_CRITICAL, 0.9)
        self.assertEqual(len(FEATURE_NAMES), 19)
        metrics = json.loads((PROJECT_ROOT / "models" / "metrics.json").read_text(encoding="utf-8"))
        self.assertAlmostEqual(metrics["Random Forest"]["accuracy"], 0.9567, places=4)
        self.assertEqual(metrics["optimal_threshold"], 0.9)
        self.assertTrue(hasattr(MLPredictor, "predict"))


if __name__ == "__main__":
    unittest.main()
