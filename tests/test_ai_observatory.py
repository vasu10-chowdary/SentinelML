"""
SentinelML V2 — Explainable AI Observatory tests (Phase 8 / Task 3)
====================================================================
Covers the pure-logic layer (exhibition/ai_observatory.py), the
get_feature_importances() accessor on MLPredictor, and basic Tk
construction of AIObservatoryPage.
"""

import sys
import unittest
from pathlib import Path

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from exhibition.ai_observatory import (
    STATUS_INJECTED,
    STATUS_MEASURED,
    STATUS_SIMULATED,
    STATUS_UNAVAILABLE,
    classification_from_prediction,
    classification_from_scan,
    feature_rows,
    global_feature_importance,
    importance_disclaimer,
)
from ml.predictor import FEATURE_NAMES, MLPredictor


# ---------------------------------------------------------------------------
# Pure-logic tests (no Tkinter)
# ---------------------------------------------------------------------------

class TestFeatureRows(unittest.TestCase):
    def test_19_rows_returned(self):
        rows = feature_rows(np.zeros((1, 19)), None)
        self.assertEqual(len(rows), 19)

    def test_simulated_source_all_simulated(self):
        rows = feature_rows(np.ones((1, 19)), None, source="simulated")
        for r in rows:
            self.assertEqual(r["status"], STATUS_SIMULATED)

    def test_measured_source_no_availability(self):
        rows = feature_rows(np.zeros((1, 19)), None, source="real")
        for r in rows:
            self.assertEqual(r["status"], STATUS_MEASURED)

    def test_unavailable_sensor_shows_none_value(self):
        avail = {"total_processes": "UNAVAILABLE_PLATFORM"}
        rows = feature_rows(np.ones((1, 19)), avail, source="real")
        row = next(r for r in rows if r["name"] == "total_processes")
        self.assertEqual(row["status"], STATUS_UNAVAILABLE)
        self.assertIsNone(row["value"],
                          "Unavailable sensor must show None, never a measured zero")

    def test_restricted_sensor_shows_unavailable(self):
        avail = {"suspicious_process_count": "RESTRICTED_PERMISSION"}
        rows = feature_rows(np.ones((1, 19)), avail, source="real")
        row = next(r for r in rows if r["name"] == "suspicious_process_count")
        self.assertEqual(row["status"], STATUS_UNAVAILABLE)
        self.assertIsNone(row["value"])

    def test_proxy_sensor_still_measured(self):
        avail = {"malfind_injection_count": "HEURISTIC_PROXY"}
        rows = feature_rows(np.ones((1, 19)), avail, source="real")
        row = next(r for r in rows if r["name"] == "malfind_injection_count")
        # Proxy sensors are still measurements (documented approximations)
        self.assertEqual(row["status"], STATUS_MEASURED)

    def test_none_vector_returns_none_values(self):
        rows = feature_rows(None, None)
        for r in rows:
            self.assertIsNone(r["value"])

    def test_flat_list_accepted(self):
        rows = feature_rows([float(i) for i in range(19)], None)
        self.assertEqual(len(rows), 19)
        self.assertAlmostEqual(rows[0]["value"], 0.0)
        self.assertAlmostEqual(rows[18]["value"], 18.0)

    def test_injected_source_marked_injected(self):
        rows = feature_rows(np.zeros((1, 19)), None, source="injected")
        for r in rows:
            self.assertEqual(r["status"], STATUS_INJECTED)


class TestClassificationFromPrediction(unittest.TestCase):
    def test_no_execution_never_safe(self):
        label, prob, note = classification_from_prediction("SAFE", 0.1, False)
        self.assertEqual(label, "NOT AVAILABLE")
        self.assertIsNone(prob)
        self.assertIn("not SAFE", note)

    def test_executed_safe_returns_safe(self):
        label, prob, note = classification_from_prediction("SAFE", 0.1, True)
        self.assertEqual(label, "SAFE")
        self.assertAlmostEqual(prob, 0.1)

    def test_executed_critical_returns_critical(self):
        label, prob, note = classification_from_prediction("CRITICAL", 0.95, True)
        self.assertEqual(label, "CRITICAL")
        self.assertAlmostEqual(prob, 0.95)

    def test_executed_invalid_prob_returns_none_prob(self):
        label, prob, note = classification_from_prediction("WARNING", float("nan"), True)
        self.assertIsNone(prob)
        self.assertIn("unavailable", note.lower())

    def test_none_label_returns_not_available(self):
        label, prob, note = classification_from_prediction(None, 0.5, True)
        self.assertEqual(label, "NOT AVAILABLE")

    def test_not_executed_with_none_prob(self):
        label, prob, note = classification_from_prediction("CRITICAL", None, False)
        self.assertEqual(label, "NOT AVAILABLE")
        self.assertIsNone(prob)


class TestClassificationFromScan(unittest.TestCase):
    def _make_scan(self, **kwargs):
        from scanner.scan_engine import ScanResult, ScanType, ScanState
        sr = ScanResult(scan_type=ScanType.QUICK, state=ScanState.COMPLETE)
        for k, v in kwargs.items():
            setattr(sr, k, v)
        return sr

    def test_none_scan_not_available(self):
        label, prob, note = classification_from_scan(None)
        self.assertEqual(label, "NOT AVAILABLE")
        self.assertIsNone(prob)

    def test_cancelled_scan_never_safe(self):
        sr = self._make_scan(cancelled=True, threat_level="CANCELLED")
        label, prob, note = classification_from_scan(sr)
        self.assertNotEqual(label, "SAFE")
        self.assertIsNone(prob)

    def test_no_ml_execution_no_probability(self):
        sr = self._make_scan(ml_executed=False, ml_probability=0.99, threat_level="SAFE")
        label, prob, note = classification_from_scan(sr)
        self.assertIsNone(prob)

    def test_ml_executed_reports_probability(self):
        sr = self._make_scan(ml_executed=True, ml_probability=0.75, threat_level="WARNING")
        label, prob, note = classification_from_scan(sr)
        self.assertIsNotNone(prob)
        self.assertAlmostEqual(prob, 0.75)

    def test_error_state_never_safe(self):
        from scanner.scan_engine import ScanResult, ScanType, ScanState
        sr = ScanResult(scan_type=ScanType.QUICK, state=ScanState.ERROR)
        label, prob, note = classification_from_scan(sr)
        self.assertNotEqual(label, "SAFE")
        self.assertIsNone(prob)

    def test_inconclusive_state_not_safe(self):
        from scanner.scan_engine import ScanResult, ScanType, ScanState
        sr = ScanResult(scan_type=ScanType.QUICK, state=ScanState.INCONCLUSIVE)
        label, prob, note = classification_from_scan(sr)
        self.assertNotEqual(label, "SAFE")
        self.assertIsNone(prob)


class TestFeatureImportances(unittest.TestCase):
    def setUp(self):
        self.predictor = MLPredictor()
        self.loaded = self.predictor.load_model()

    def test_importances_available_when_model_loaded(self):
        if not self.loaded:
            self.skipTest("Model not loaded")
        imp = self.predictor.get_feature_importances()
        self.assertIsNotNone(imp)
        self.assertEqual(imp.shape[0], 19)

    def test_importances_sum_to_one(self):
        if not self.loaded:
            self.skipTest("Model not loaded")
        imp = self.predictor.get_feature_importances()
        self.assertAlmostEqual(float(imp.sum()), 1.0, places=4)

    def test_importances_nonnegative(self):
        if not self.loaded:
            self.skipTest("Model not loaded")
        imp = self.predictor.get_feature_importances()
        self.assertTrue((imp >= 0).all())

    def test_model_not_mutated_by_accessor(self):
        if not self.loaded:
            self.skipTest("Model not loaded")
        before = self.predictor.get_model_info()
        _ = self.predictor.get_feature_importances()
        after = self.predictor.get_model_info()
        self.assertEqual(before, after)

    def test_global_importance_returns_19_pairs(self):
        if not self.loaded:
            self.skipTest("Model not loaded")
        pairs = global_feature_importance(self.predictor)
        self.assertIsNotNone(pairs)
        self.assertEqual(len(pairs), 19)
        # Sorted descending
        for i in range(len(pairs) - 1):
            self.assertGreaterEqual(pairs[i][1], pairs[i + 1][1])

    def test_importance_disclaimer_non_empty(self):
        msg = importance_disclaimer()
        self.assertTrue(msg)
        self.assertIn("model-level", msg.lower())
        self.assertNotIn("per-prediction", msg.lower().replace("not a per-prediction", ""))

    def test_unloaded_predictor_returns_none(self):
        p = MLPredictor()  # not loaded
        imp = p.get_feature_importances()
        self.assertIsNone(imp)
        pairs = global_feature_importance(p)
        self.assertIsNone(pairs)


# ---------------------------------------------------------------------------
# Tk UI tests
# ---------------------------------------------------------------------------

class TestAIObservatoryPageUI(unittest.TestCase):
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

    def test_page_constructs(self):
        self._skip()
        from gui.pages.ai_observatory_page import AIObservatoryPage
        page = AIObservatoryPage(self._root, config={})
        try:
            self.assertEqual(len(page._feat_value_lbls), 19)
            self.assertEqual(len(page._feat_status_lbls), 19)
        finally:
            page.destroy()

    def test_simulated_render_does_not_crash(self):
        self._skip()
        from gui.pages.ai_observatory_page import AIObservatoryPage
        page = AIObservatoryPage(self._root, config={})
        try:
            page._source_seg.set("Simulated suspicious")
            page._on_run()
            # cls_lbl should be updated (not still "—")
            txt = page._cls_lbl.cget("text")
            self.assertIn(txt, {"SAFE", "WARNING", "CRITICAL", "NOT AVAILABLE", "ERROR"})
        finally:
            page.destroy()

    def test_benign_baseline_never_reports_probability_as_real(self):
        self._skip()
        from gui.pages.ai_observatory_page import AIObservatoryPage
        page = AIObservatoryPage(self._root, config={})
        try:
            page._source_seg.set("Benign baseline")
            page._on_run()
            note = page._note_lbl.cget("text")
            # Simulated input must be labelled as such
            self.assertIn("Simulated", note)
        finally:
            page.destroy()

    def test_feature_importance_renders(self):
        self._skip()
        from gui.pages.ai_observatory_page import AIObservatoryPage
        page = AIObservatoryPage(self._root, config={})
        try:
            page._render_feature_importance()
            children = page._imp_scroll.winfo_children()
            self.assertGreater(len(children), 0)
        finally:
            page.destroy()

    def test_destroy_sets_flag(self):
        self._skip()
        from gui.pages.ai_observatory_page import AIObservatoryPage
        page = AIObservatoryPage(self._root, config={})
        page.destroy()
        self.assertTrue(page._is_destroyed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
