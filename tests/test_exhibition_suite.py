"""
SentinelML V2 — Automated Exhibition Test Suite
=================================================
Validates sandbox isolation, path traversal safety, simulation lifecycle,
security test lab scenarios, fail-safe state invariants, and report sanitization.
"""

import sys
import unittest
import numpy as np
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scanner.scan_engine import ScanEngine, ScanType, ScanState, ScanResult
from ml.predictor import MLPredictor, FEATURE_NAMES
from exhibition.sandbox_simulator import SandboxSimulator, SecurityError, SimulationResult
from exhibition.security_test_lab import SecurityTestLab, ScenarioOutcome
from exhibition.report_exporter import ExhibitionReportExporter, sanitize_path


class TestSandboxSafety(unittest.TestCase):
    """Verify strict sandbox boundaries and safety constraints."""

    def setUp(self):
        self.test_sandbox = PROJECT_ROOT / "temp_test_sandbox"
        self.simulator = SandboxSimulator(self.test_sandbox)
        self.simulator.reset_sandbox()

    def tearDown(self):
        self.simulator.reset_sandbox()
        if self.test_sandbox.exists():
            import shutil
            shutil.rmtree(self.test_sandbox, ignore_errors=True)

    def test_path_safety_valid(self):
        """Valid subpath inside sandbox must pass."""
        subpath = self.test_sandbox / "sample.txt"
        validated = self.simulator.validate_path_safety(subpath)
        self.assertEqual(validated, subpath.resolve())

    def test_path_safety_traversal_rejection(self):
        """Path traversal outside sandbox must raise SecurityError."""
        traversal = self.test_sandbox / ".." / "escaped.txt"
        with self.assertRaises(SecurityError):
            self.simulator.validate_path_safety(traversal)

    def test_path_safety_system_path_rejection(self):
        """Arbitrary system path must raise SecurityError."""
        system_path = Path("C:\\Windows\\System32\\calc.exe")
        with self.assertRaises(SecurityError):
            self.simulator.validate_path_safety(system_path)

    def test_simulation_lifecycle(self):
        """Test file creation, modification, renaming, and safe cleanup."""
        res = self.simulator.run_simulation(num_files=10, delay_between_ops=0.005)
        self.assertIsInstance(res, SimulationResult)
        self.assertEqual(res.total_files_created, 10)
        self.assertEqual(res.total_files_modified, 10)
        self.assertEqual(res.total_files_renamed, 10)
        self.assertGreater(res.avg_entropy_after, 7.0)

        # Confirm files exist in sandbox
        files_in_sandbox = list(self.test_sandbox.iterdir())
        self.assertGreaterEqual(len(files_in_sandbox), 10)

        # Test cleanup
        cleaned = self.simulator.reset_sandbox()
        self.assertGreaterEqual(cleaned, 10)
        self.assertEqual(len(list(self.test_sandbox.iterdir())), 0)


class TestSecurityTestLab(unittest.TestCase):
    """Verify worst-case scenarios and state machine invariants."""

    def setUp(self):
        self.test_sandbox = PROJECT_ROOT / "temp_lab_sandbox"
        self.lab = SecurityTestLab(self.test_sandbox)

    def tearDown(self):
        self.lab.simulator.reset_sandbox()
        if self.test_sandbox.exists():
            import shutil
            shutil.rmtree(self.test_sandbox, ignore_errors=True)

    def test_scenario_high_volume_file_mod(self):
        outcome = self.lab.run_scenario("HIGH_VOLUME_FILE_MOD")
        self.assertTrue(outcome.passed_test)
        self.assertEqual(outcome.scenario_id, "HIGH_VOLUME_FILE_MOD")

    def test_scenario_benign_bulk_ops(self):
        """Benign files must not trigger false positives."""
        outcome = self.lab.run_scenario("BENIGN_BULK_OPS")
        self.assertTrue(outcome.passed_test)
        self.assertEqual(outcome.scan_state, "SAFE")

    def test_scenario_incomplete_telemetry_invariant(self):
        """Failed telemetry must transition to SCAN_INCOMPLETE and never SAFE."""
        outcome = self.lab.run_scenario("INCOMPLETE_TELEMETRY")
        self.assertTrue(outcome.passed_test)
        self.assertEqual(outcome.scan_state, "SCAN_INCOMPLETE")
        self.assertEqual(outcome.classifier_output, "ANALYSIS_ERROR")

    def test_scenario_scan_cancellation(self):
        """Cancelled scan must transition to SCAN_INCOMPLETE."""
        outcome = self.lab.run_scenario("SCAN_CANCELLATION")
        self.assertTrue(outcome.passed_test)
        self.assertEqual(outcome.scan_state, "SCAN_INCOMPLETE")

    def test_scenario_missing_model_invariant(self):
        """Missing model must produce ANALYSIS_ERROR."""
        outcome = self.lab.run_scenario("MISSING_MODEL")
        self.assertTrue(outcome.passed_test)
        self.assertEqual(outcome.scan_state, "ANALYSIS_ERROR")

    def test_scenario_nan_feature_rejection(self):
        """NaN values in feature array must be safely caught."""
        outcome = self.lab.run_scenario("FEATURE_NAN_FAILURE")
        self.assertTrue(outcome.passed_test)
        self.assertEqual(outcome.scan_state, "ANALYSIS_ERROR")

    def test_scenario_ai_service_timeout_independence(self):
        """AI backend outage must leave local deterministic decision authoritative."""
        outcome = self.lab.run_scenario("AI_SERVICE_TIMEOUT")
        self.assertTrue(outcome.passed_test)
        self.assertIn(outcome.classifier_output, ["SAFE", "WARNING", "CRITICAL"])


class TestReportSanitization(unittest.TestCase):
    """Verify privacy preservation and report exports."""

    def test_sanitize_path_windows(self):
        raw = "Error accessing C:\\Users\\vasur\\Documents\\secret.docx"
        sanitized = sanitize_path(raw)
        self.assertNotIn("vasur", sanitized)
        self.assertIn("[USER_PROFILE]", sanitized)

    def test_sanitize_path_unix(self):
        raw = "Path /home/vasu/project/test.py"
        sanitized = sanitize_path(raw)
        self.assertNotIn("vasu", sanitized)
        self.assertIn("[USER_PROFILE]", sanitized)

    def test_export_report_files_created(self):
        exporter = ExhibitionReportExporter()
        paths = exporter.export_report(
            mode_title="Unit Test Mode",
            scan_state="SAFE",
            ml_prediction="SAFE",
            probability=0.08,
            duration_s=2.5,
            features={"total_processes": 120.0, "avg_entropy": 3.4},
            evidence_events=[{"timestamp": "12:00:00", "phase": "TEST", "action": "RUN", "details": "ok"}]
        )
        self.assertTrue(paths["json"].exists())
        self.assertTrue(paths["md"].exists())

        # Clean up test files
        paths["json"].unlink(missing_ok=True)
        paths["md"].unlink(missing_ok=True)


class TestModelPipelineIntegrity(unittest.TestCase):
    """Verify model attributes, feature counts, and score ranges."""

    def test_model_and_scaler_load(self):
        predictor = MLPredictor()
        loaded = predictor.load_model()
        self.assertTrue(loaded)
        self.assertEqual(predictor.get_model_info()["expected_features"], 19)

    def test_zero_vector_prediction(self):
        predictor = MLPredictor()
        predictor.load_model()
        res = predictor.predict(np.zeros((1, 19), dtype=np.float64))
        self.assertIsNotNone(res)
        threat_level, prob = res
        self.assertIn(threat_level, ["SAFE", "WARNING", "CRITICAL"])
        self.assertGreaterEqual(prob, 0.0)
        self.assertLessEqual(prob, 1.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
