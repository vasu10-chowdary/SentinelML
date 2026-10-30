"""
SentinelML — Process-only scan regression tests.

Covers the defect where ScanType.PROCESS aborted with "No valid scan paths"
before process analysis because the filesystem-path gate ran for every scan type.

Guarantees:
  1. PROCESS scans run without filesystem paths.
  2. PROCESS scans never invoke filesystem scanning, even if paths are supplied.
  3. CUSTOM scans still require at least one existing path.
  4. Process extraction failure yields SCAN_INCOMPLETE / ANALYSIS_ERROR, never SAFE.
  5. ML failure yields SCAN_INCOMPLETE / ANALYSIS_ERROR, never SAFE.
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scanner.scan_engine import ScanEngine, ScanState, ScanType

_FEATURES = np.zeros((1, 19), dtype=float)
_AVAILABILITY = {f"feature_{i}": "AVAILABLE" for i in range(19)}
_STATS = {"processes_scanned": 42, "errors": 0}


def _patched_engine(process_result=_FEATURES, prediction=("SAFE", 0.12)):
    """Engine whose process scanner and ML predictor are deterministic stubs."""
    engine = ScanEngine()
    patches = [
        patch.object(engine._process_scanner, "scan_system", return_value=process_result),
        patch.object(engine._process_scanner, "get_scan_stats", return_value=dict(_STATS)),
        patch.object(engine._process_scanner, "get_feature_availability", return_value=dict(_AVAILABILITY)),
        patch("ml.predictor.MLPredictor.load_model", return_value=True),
        patch("ml.predictor.MLPredictor.predict", return_value=prediction),
        patch.object(engine, "_scan_filesystem", side_effect=AssertionError("filesystem scan must not run")),
    ]
    return engine, patches


class ProcessOnlyScanTests(unittest.TestCase):
    def _run_with(self, engine, *patches):
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        return engine

    def test_process_scan_runs_without_paths(self):
        engine, patches = _patched_engine()
        self._run_with(engine, *patches)
        result = engine.scan(ScanType.PROCESS)
        self.assertNotEqual(result.error_message, "No valid scan paths")
        self.assertEqual(result.state, ScanState.SAFE)
        self.assertEqual(result.processes_analyzed, 42)
        self.assertEqual(result.files_inspected, 0)
        self.assertEqual(result.phase_timings.get("filesystem_s"), 0.0)
        self.assertTrue(result.ml_executed)
        self.assertEqual(result.threat_level, "SAFE")

    def test_process_scan_ignores_supplied_paths(self):
        engine, patches = _patched_engine()
        self._run_with(engine, *patches)
        result = engine.scan(ScanType.PROCESS, custom_paths=[Path.cwd()])
        self.assertEqual(result.state, ScanState.SAFE)
        self.assertEqual(result.files_inspected, 0)
        self.assertEqual(result.directories_inspected, 0)

    def test_custom_scan_still_requires_paths(self):
        engine = ScanEngine()
        result = engine.scan(ScanType.CUSTOM)
        self.assertEqual(result.state, ScanState.SCAN_INCOMPLETE)
        self.assertEqual(result.error_message, "No valid scan paths")
        self.assertEqual(result.threat_level, "ANALYSIS_ERROR")

    def test_custom_scan_rejects_missing_path(self):
        engine = ScanEngine()
        result = engine.scan(ScanType.CUSTOM, custom_paths=[Path("/nonexistent/sentinelml/path")])
        self.assertEqual(result.state, ScanState.SCAN_INCOMPLETE)
        self.assertEqual(result.error_message, "No valid scan paths")
        self.assertNotEqual(result.state, ScanState.SAFE)

    def test_process_failure_is_analysis_error_not_safe(self):
        engine, patches = _patched_engine(process_result=None)
        self._run_with(engine, *patches)
        result = engine.scan(ScanType.PROCESS)
        self.assertEqual(result.state, ScanState.SCAN_INCOMPLETE)
        self.assertEqual(result.threat_level, "ANALYSIS_ERROR")
        self.assertEqual(result.ml_probability, 0.0)
        self.assertNotEqual(result.state, ScanState.SAFE)

    def test_ml_failure_is_analysis_error_not_safe(self):
        engine, patches = _patched_engine(prediction=None)
        self._run_with(engine, *patches)
        result = engine.scan(ScanType.PROCESS)
        self.assertEqual(result.state, ScanState.SCAN_INCOMPLETE)
        self.assertEqual(result.threat_level, "ANALYSIS_ERROR")
        self.assertFalse(result.ml_executed)
        self.assertNotEqual(result.state, ScanState.SAFE)


if __name__ == "__main__":
    unittest.main(verbosity=2)
