"""
SentinelML — INCONCLUSIVE scan-result handling regression tests.

Covers:
  1. Successful ML inference with incomplete Linux telemetry yields INCONCLUSIVE.
  2. INCONCLUSIVE is displayed as a completed analysis, never ANALYSIS_ERROR.
  3. A real model exception still yields ANALYSIS_ERROR / audit FAILED.
  4. SAFE is never produced when telemetry sufficiency rules are unmet.
  5. WARNING/CRITICAL decision thresholds remain 0.50 / 0.90.
  6. Cancelled scans remain CANCELLED in the UI.
  7. Complete (Windows-style) scans keep their existing classification.
  8. Audit classification matches the final scan state.
"""

import sys
import unittest
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from gui.pages.dashboard import DashboardPage, _inconclusive_telemetry_notice
from ml.predictor import MLPredictor
from scanner.scan_engine import ScanEngine, ScanResult, ScanState, ScanType
from utils.scan_audit import build_audit_record, classify_outcome


# Static Linux sensor map matching the real Kali v3.0.0 runtime evidence:
# 4 sensors are UNAVAILABLE_PLATFORM, 2 are SUBSTITUTED, the rest are measured
# or heuristic proxies. Used only as a UI fixture; the live engine test below
# exercises genuine telemetry.
LINUX_AVAILABILITY = {
    "total_processes": "GENUINE_MEASURED",
    "suspicious_process_count": "GENUINE_MEASURED",
    "avg_entropy": "GENUINE_MEASURED",
    "max_entropy": "GENUINE_MEASURED",
    "high_entropy_region_count": "GENUINE_MEASURED",
    "malfind_injection_count": "HEURISTIC_PROXY",
    "crypto_dll_count": "SUBSTITUTED",
    "cmd_vssadmin_count": "SUBSTITUTED",
    "network_connection_count": "GENUINE_MEASURED",
    "unique_external_ips": "GENUINE_MEASURED",
    "file_handle_count": "UNAVAILABLE_PLATFORM",
    "registry_handle_count": "UNAVAILABLE_PLATFORM",
    "orphan_process_count": "GENUINE_MEASURED",
    "powershell_process_count": "GENUINE_MEASURED",
    "unsigned_module_count": "HEURISTIC_PROXY",
    "suspicious_mutex_count": "HEURISTIC_PROXY",
    "abnormal_privilege_count": "UNAVAILABLE_PLATFORM",
    "suspicious_thread_count": "HEURISTIC_PROXY",
    "defender_tampering_count": "UNAVAILABLE_PLATFORM",
}
LINUX_MISSING = [
    "file_handle_count",
    "registry_handle_count",
    "abnormal_privilege_count",
    "defender_tampering_count",
]

EXPECTED_NOTICE = _inconclusive_telemetry_notice()


def make_inconclusive_result(probability=0.34):
    """Representative completed-inconclusive result for UI/audit tests."""
    return ScanResult(
        scan_type=ScanType.QUICK,
        state=ScanState.INCONCLUSIVE,
        files_inspected=1,
        directories_inspected=8,
        processes_analyzed=112,
        ml_executed=True,
        ml_probability=probability,
        ml_prediction="SAFE",
        threat_level="INCONCLUSIVE",
        is_inconclusive=True,
        inconclusive_reason=(
            "Safety cannot be validated: 4 of 19 behavioral sensors are "
            "unavailable on linux. Incomplete telemetry cannot certify host as clean."
        ),
        telemetry_availability=dict(LINUX_AVAILABILITY),
        missing_features=list(LINUX_MISSING),
        available_feature_count=15,
        telemetry_coverage_ratio=round(15 / 19, 3),
        elapsed_seconds=12.3,
    )


class TestRealScanClassification(unittest.TestCase):
    """Genuine ScanEngine inference, not simulated telemetry."""

    @classmethod
    def setUpClass(cls):
        cls.result = ScanEngine().scan(ScanType.QUICK)

    def test_ml_success_with_incomplete_linux_telemetry_is_inconclusive(self):
        result = self.result
        self.assertTrue(result.ml_executed, "ML inference must have run")
        self.assertGreaterEqual(result.ml_probability, 0.0)
        self.assertLessEqual(result.ml_probability, 1.0)

        if sys.platform == "win32":
            self.assertEqual(result.missing_features, [])
            self.assertNotEqual(result.state, ScanState.INCONCLUSIVE)
            self.assertFalse(result.is_inconclusive)
            return

        self.assertTrue(result.missing_features, "Linux must expose unavailable sensors")
        self.assertEqual(len(result.missing_features), 4)
        self.assertEqual(result.state, ScanState.INCONCLUSIVE)
        self.assertTrue(result.is_inconclusive)
        self.assertEqual(result.threat_level, "INCONCLUSIVE")
        self.assertEqual(result.ml_prediction, "SAFE")
        self.assertFalse(result.was_successful())

        unified = result.get_unified_classification()
        self.assertEqual(unified["level"], "INCONCLUSIVE")
        self.assertFalse(unified["is_clean"])

    def test_safe_requires_sufficient_telemetry(self):
        result = self.result
        if sys.platform == "win32":
            # Windows has the full schema; INCONCLUSIVE must not be introduced.
            self.assertNotEqual(result.state, ScanState.INCONCLUSIVE)
            return

        self.assertNotEqual(result.state, ScanState.SAFE)
        self.assertFalse(result.get_unified_classification()["is_clean"])


class TestTerminalRouting(unittest.TestCase):
    """The dashboard must not convert INCONCLUSIVE into an error callback."""

    @staticmethod
    def _page():
        page = DashboardPage.__new__(DashboardPage)
        page._cancel_requested_flag = False
        page._active_engine = None
        page.calls = []
        page._dispatch_to_main = lambda cb, *args: page.calls.append((cb.__name__, args))
        return page

    def _run(self, result):
        page = self._page()
        engine = mock.Mock()
        engine.scan.return_value = result
        with mock.patch("gui.pages.dashboard.ScanEngine", return_value=engine), \
                mock.patch("demo_data.is_demo_mode", return_value=False):
            page._run_scan_thread("token-1")
        return page

    def test_inconclusive_routes_to_completion(self):
        result = make_inconclusive_result()
        page = self._run(result)

        self.assertEqual(len(page.calls), 1)
        callback, args = page.calls[0]
        self.assertEqual(callback, "_on_scan_complete")
        self.assertEqual(args[0], "INCONCLUSIVE")
        self.assertAlmostEqual(args[1], 0.34)
        self.assertIs(args[2], result)

    def test_model_exception_routes_to_error(self):
        result = ScanResult(
            scan_type=ScanType.QUICK,
            state=ScanState.ANALYSIS_ERROR,
            ml_executed=False,
            threat_level="ANALYSIS_ERROR",
            error_message="ML exception: boom",
        )
        page = self._run(result)

        self.assertEqual(len(page.calls), 1)
        callback, args = page.calls[0]
        self.assertEqual(callback, "_on_scan_error")
        self.assertEqual(args[0], "ML exception: boom")

        self.assertEqual(classify_outcome(result, "error")[0], "FAILED")
        cls = DashboardPage.__new__(DashboardPage)._classify_result(
            "ANALYSIS_ERROR", 0.0, result
        )
        self.assertEqual(cls["tag"], "ERROR")

    def test_cancelled_stays_cancelled(self):
        result = ScanResult(
            scan_type=ScanType.QUICK,
            state=ScanState.SCAN_INCOMPLETE,
            cancelled=True,
            threat_level="CANCELLED",
        )
        page = self._run(result)

        self.assertEqual(page.calls[0][0], "_on_scan_cancelled")

        cls = DashboardPage.__new__(DashboardPage)._classify_result(
            "SCAN_INCOMPLETE", 0.0, result
        )
        self.assertEqual(cls["tag"], "CANCELLED")
        self.assertEqual(cls["risk_label"], "CANCELLED")
        self.assertNotEqual(classify_outcome(result, "cancelled")[0], "SAFE")


class TestClassificationThresholds(unittest.TestCase):
    def setUp(self):
        self.page = DashboardPage.__new__(DashboardPage)
        self.complete_result = ScanResult(
            scan_type=ScanType.FULL,
            state=ScanState.SAFE,
            ml_executed=True,
            ml_probability=0.10,
            ml_prediction="SAFE",
            threat_level="SAFE",
        )

    def test_warning_and_critical_thresholds_unchanged(self):
        self.assertEqual(MLPredictor._DEFAULT_THRESHOLD_CRITICAL, 0.90)
        self.assertEqual(MLPredictor._DEFAULT_THRESHOLD_WARNING, 0.50)

        self.assertEqual(
            self.page._classify_result("SAFE", 0.49, self.complete_result)["tag"],
            "SYSTEM SAFE",
        )
        self.assertEqual(
            self.page._classify_result("WARNING", 0.50, self.complete_result)["tag"],
            "WARNING",
        )
        self.assertEqual(
            self.page._classify_result("WARNING", 0.899, self.complete_result)["tag"],
            "WARNING",
        )
        self.assertEqual(
            self.page._classify_result("CRITICAL", 0.90, self.complete_result)["tag"],
            "CRITICAL",
        )

    def test_complete_scan_without_missing_sensors_is_not_inconclusive(self):
        result = ScanResult(
            scan_type=ScanType.QUICK,
            state=ScanState.SAFE,
            ml_executed=True,
            ml_probability=0.34,
            ml_prediction="SAFE",
            threat_level="SAFE",
        )
        self.assertTrue(result.was_successful())
        self.assertFalse(result.is_inconclusive)
        self.assertNotEqual(
            self.page._classify_result("SAFE", 0.34, result)["tag"],
            "INCONCLUSIVE",
        )


class TestInconclusivePresentation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import customtkinter as ctk

        cls.root = ctk.CTk()
        cls.root.withdraw()
        cls.dashboard = DashboardPage(cls.root, config={})

    @classmethod
    def tearDownClass(cls):
        cls.root.destroy()

    def test_display_is_completed_analysis_not_error(self):
        result = make_inconclusive_result()
        with mock.patch.object(self.dashboard, "_record_scan_history") as record:
            self.dashboard._on_scan_complete(
                "INCONCLUSIVE", result.ml_probability, result
            )

        self.assertEqual(record.call_args.kwargs["outcome"], "completed")

        self.assertEqual(self.dashboard._threat_level, "INCONCLUSIVE")
        self.assertEqual(self.dashboard._status_title.cget("text"), "INCONCLUSIVE \u2014 LIMITED COVERAGE")
        self.assertEqual(self.dashboard._risk_level_label.cget("text"), "INCONCLUSIVE")

        desc = self.dashboard._status_desc.cget("text")
        self.assertIn(EXPECTED_NOTICE, desc)
        self.assertIn("34%", desc)
        self.assertIn("0.34", desc)
        self.assertIn("ML prediction: SAFE (model output only)", desc)
        self.assertIn("Final security assessment: INCONCLUSIVE", desc)
        self.assertIn("4 of 19 sensors unavailable", desc)
        self.assertIn("15 of 19 sensors", desc)
        self.assertNotIn("ANALYSIS_ERROR", desc)
        self.assertNotIn("Scan failed", desc)

        self.assertEqual(
            self.dashboard._stage_badge.cget("text"),
            "STAGE: COMPLETE \u2014 TELEMETRY LIMITED",
        )
        self.assertEqual(self.dashboard._active_path_label.cget("text"), EXPECTED_NOTICE)
        self.assertEqual(self.dashboard._threats_detected, 0)
        self.assertEqual(self.dashboard._core_3d.state, "INCONCLUSIVE")


class TestAuditStatus(unittest.TestCase):
    def test_completed_inconclusive_record_matches_final_state(self):
        result = make_inconclusive_result()
        record = build_audit_record(result, outcome="completed", scan_origin="LIVE_HOST_SCAN")

        self.assertEqual(record["classification"], "INCONCLUSIVE")
        self.assertNotEqual(record["classification"], "FAILED")
        self.assertEqual(record["severity"], "UNKNOWN")
        self.assertAlmostEqual(record["probability"], 0.34, places=4)
        self.assertAlmostEqual(record["coverage_ratio"], round(15 / 19, 3), places=3)
        self.assertEqual(len(record["missing_features"]), 4)

    def test_error_outcome_is_still_failed(self):
        result = ScanResult(
            scan_type=ScanType.QUICK,
            state=ScanState.ANALYSIS_ERROR,
            ml_executed=False,
            threat_level="ANALYSIS_ERROR",
            error_message="ML exception: boom",
        )
        self.assertEqual(classify_outcome(result, "error")[0], "FAILED")


if __name__ == "__main__":
    unittest.main()
