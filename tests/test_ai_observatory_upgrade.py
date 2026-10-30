"""AI Observatory explainability upgrade tests (Phase 4).

Verifies exact feature order, provenance statuses (MEASURED / SIMULATED /
UNAVAILABLE / ERROR), plain-English meanings, coverage reporting, model /
scaler availability, and the invariant that invalid scans are never SAFE.
"""

import sys
import unittest
from pathlib import Path

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from exhibition.ai_observatory import (
    FEATURE_DESCRIPTIONS,
    STATUS_ERROR,
    STATUS_MEASURED,
    STATUS_SIMULATED,
    STATUS_UNAVAILABLE,
    classification_from_scan,
    coverage_summary,
    feature_rows,
    model_availability,
    plain_english,
)
from ml.predictor import FEATURE_NAMES, MLPredictor
from scanner.scan_engine import ScanResult, ScanState, ScanType


def _scan(**overrides):
    values = dict(scan_type=ScanType.QUICK, state=ScanState.COMPLETE)
    values.update(overrides)
    return ScanResult(**values)


class TestFeatureOrderAndDescriptions(unittest.TestCase):

    def test_rows_follow_exact_trained_order(self):
        rows = feature_rows(np.zeros((1, 19)), None)
        self.assertEqual([r["name"] for r in rows], FEATURE_NAMES)
        self.assertEqual([r["index"] for r in rows], list(range(19)))

    def test_every_feature_has_plain_english_description(self):
        self.assertEqual(set(FEATURE_DESCRIPTIONS), set(FEATURE_NAMES))
        for name in FEATURE_NAMES:
            text = plain_english(name)
            self.assertTrue(text)
            self.assertNotIn("No description available", text)
            self.assertGreater(len(text), 10)


class TestProvenanceStatuses(unittest.TestCase):

    def test_error_source_never_reports_zero_values(self):
        rows = feature_rows(np.zeros((1, 19)), None, source="error")
        for r in rows:
            self.assertEqual(r["status"], STATUS_ERROR)
            self.assertIsNone(r["value"], "Failed scans must not display a measured zero")

    def test_unavailable_and_measured_mix(self):
        avail = {"avg_entropy": "UNAVAILABLE_PLATFORM"}
        rows = feature_rows(np.ones((1, 19)), avail, source="real")
        by_name = {r["name"]: r for r in rows}
        self.assertEqual(by_name["avg_entropy"]["status"], STATUS_UNAVAILABLE)
        self.assertIsNone(by_name["avg_entropy"]["value"])
        self.assertEqual(by_name["max_entropy"]["status"], STATUS_MEASURED)
        self.assertEqual(by_name["max_entropy"]["value"], 1.0)

    def test_simulated_rows_are_flagged(self):
        rows = feature_rows(np.ones((1, 19)), None, source="simulated")
        self.assertTrue(all(r["status"] == STATUS_SIMULATED for r in rows))


class TestCoverageSummary(unittest.TestCase):

    def test_full_coverage(self):
        rows = feature_rows(np.zeros((1, 19)), None, source="real")
        cov = coverage_summary(rows)
        self.assertEqual(cov["measured"], 19)
        self.assertEqual(cov["coverage_ratio"], 1.0)
        self.assertEqual(cov["not_measured"], [])

    def test_partial_coverage_lists_missing_features(self):
        avail = {"avg_entropy": "UNAVAILABLE_PLATFORM",
                 "max_entropy": "RESTRICTED_PERMISSION"}
        rows = feature_rows(np.ones((1, 19)), avail, source="real")
        cov = coverage_summary(rows)
        self.assertEqual(cov["measured"], 17)
        self.assertEqual(cov["unavailable"], 2)
        self.assertAlmostEqual(cov["coverage_ratio"], 17 / 19)
        self.assertIn("avg_entropy", cov["not_measured"])

    def test_simulated_inputs_are_not_measured_coverage(self):
        rows = feature_rows(np.ones((1, 19)), None, source="simulated")
        cov = coverage_summary(rows)
        self.assertEqual(cov["measured"], 0)
        self.assertEqual(cov["simulated"], 19)
        self.assertEqual(cov["coverage_ratio"], 0.0)

    def test_empty_rows(self):
        cov = coverage_summary([])
        self.assertEqual(cov["total"], 0)
        self.assertEqual(cov["coverage_ratio"], 0.0)


class TestModelAvailability(unittest.TestCase):

    def test_reports_model_scaler_and_thresholds(self):
        predictor = MLPredictor()
        loaded = predictor.load_model()
        avail = model_availability(predictor)
        self.assertEqual(avail["feature_count"], 19)
        self.assertEqual(avail["threshold_warning"], 0.5)
        self.assertEqual(avail["threshold_critical"], 0.9)
        if loaded:
            self.assertTrue(avail["model_loaded"])
            self.assertTrue(avail["scaler_loaded"])
            self.assertEqual(avail["expected_features"], 19)
        else:
            self.assertFalse(avail["model_loaded"])

    def test_unloaded_predictor_reports_not_loaded(self):
        avail = model_availability(MLPredictor())
        self.assertFalse(avail["model_loaded"])


class TestNeverSafeOnInvalidScans(unittest.TestCase):

    def test_limited_coverage_never_safe(self):
        sr = _scan(state=ScanState.LIMITED_COVERAGE, ml_executed=True,
                   ml_probability=0.99, threat_level="SAFE")
        label, prob, note = classification_from_scan(sr)
        self.assertNotEqual(label, "SAFE")
        self.assertIsNone(prob)

    def test_inconclusive_flag_never_safe(self):
        sr = _scan(state=ScanState.COMPLETE, is_inconclusive=True,
                   ml_executed=True, ml_probability=0.99, threat_level="SAFE")
        label, prob, note = classification_from_scan(sr)
        self.assertNotEqual(label, "SAFE")
        self.assertIsNone(prob)

    def test_incomplete_scan_never_safe(self):
        sr = _scan(state=ScanState.SCAN_INCOMPLETE, ml_executed=True,
                   ml_probability=0.99, threat_level="SAFE")
        label, prob, _ = classification_from_scan(sr)
        self.assertNotEqual(label, "SAFE")
        self.assertIsNone(prob)


class TestAIObservatoryPageUpgrade(unittest.TestCase):
    _root = None

    @classmethod
    def setUpClass(cls):
        try:
            import customtkinter as ctk
            cls._root = ctk.CTk()
            cls._root.withdraw()
        except Exception as exc:
            cls._root = None
            cls._skip_reason = str(exc)

    @classmethod
    def tearDownClass(cls):
        if cls._root is not None:
            try:
                cls._root.destroy()
            except Exception:
                pass

    def _skip(self):
        if self._root is None:
            self.skipTest(getattr(self, "_skip_reason", "Tk unavailable"))

    def _make_page(self):
        from gui.pages.ai_observatory_page import AIObservatoryPage
        return AIObservatoryPage(self._root, config={})

    def test_feature_labels_are_in_model_order(self):
        self._skip()
        page = self._make_page()
        try:
            names = list(page._feat_value_lbls.keys())
            self.assertEqual(names, FEATURE_NAMES)
            self.assertEqual(len(page._feat_name_lbls), 19)
        finally:
            page.destroy()

    def test_benchmark_accuracy_is_labelled_as_benchmark_only(self):
        self._skip()
        page = self._make_page()
        try:
            text = page._threshold_lbl.cget("text")
            self.assertIn("95.67%", text)
            self.assertIn("offline evaluation", text)
            self.assertIn("not a real-world", text)
            self.assertIn("0.50", text)
            self.assertIn("0.90", text)
        finally:
            page.destroy()

    def test_clicking_feature_shows_plain_english(self):
        self._skip()
        page = self._make_page()
        try:
            page._on_feature_click("avg_entropy")
            text = page._feat_detail_lbl.cget("text")
            self.assertIn("avg_entropy", text)
            self.assertIn("[02]", text)
            self.assertIn("entropy", text.lower())
        finally:
            page.destroy()

    def test_model_badge_reports_availability(self):
        self._skip()
        page = self._make_page()
        try:
            text = page._status_badge.cget("text")
            self.assertIn("MODEL:", text)
            self.assertTrue("NOT LOADED" in text or "features" in text)
        finally:
            page.destroy()

    def test_error_scan_shows_dash_not_zero(self):
        self._skip()
        page = self._make_page()
        try:
            page._active_token = "tok"
            page._on_scan_error("boom", "tok")
            self.assertEqual(page._cls_lbl.cget("text"), "ERROR")
            self.assertIn("Not available", page._prob_lbl.cget("text"))
            for name in FEATURE_NAMES:
                self.assertEqual(page._feat_value_lbls[name].cget("text"), "—")
                self.assertEqual(page._feat_status_lbls[name].cget("text"), STATUS_ERROR)
            self.assertIn("failed", page._coverage_lbl.cget("text").lower())
        finally:
            page.destroy()

    def test_inconclusive_scan_is_not_shown_safe(self):
        self._skip()
        page = self._make_page()
        try:
            result = _scan(state=ScanState.INCONCLUSIVE, ml_executed=True,
                           ml_probability=0.99, threat_level="SAFE")
            page._active_token = "tok"
            page._on_scan_complete(result, "tok")
            self.assertNotEqual(page._cls_lbl.cget("text"), "SAFE")
            self.assertIn("Not available", page._prob_lbl.cget("text"))
        finally:
            page.destroy()

    def test_simulated_run_reports_simulated_coverage(self):
        self._skip()
        page = self._make_page()
        try:
            page._source_seg.set("Benign baseline")
            page._on_run()
            self.assertIn("SIMULATED", page._coverage_lbl.cget("text"))
            self.assertIn("SIMULATED", page._origin_lbl.cget("text"))
        finally:
            page.destroy()


if __name__ == "__main__":
    unittest.main(verbosity=2)
