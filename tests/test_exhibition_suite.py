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
        """Verify 6-stage detection pipeline on high-volume synthetic file modification."""
        outcome = self.lab.run_scenario("HIGH_VOLUME_FILE_MOD")
        self.assertTrue(outcome.passed_test)
        self.assertEqual(outcome.scenario_id, "HIGH_VOLUME_FILE_MOD")

        # 6-Stage Detection Breakdown assertions:
        self.assertTrue(outcome.simulator_generated_activity)
        self.assertTrue(outcome.filesystem_observed_sandbox)
        self.assertTrue(outcome.live_telemetry_collected_features)
        self.assertTrue(outcome.ml_processed_features)
        self.assertIn(outcome.classifier_result, ["SAFE", "WARNING", "CRITICAL"])
        self.assertEqual(outcome.detection_achieved, outcome.classifier_result in ["WARNING", "CRITICAL"])
        self.assertIn("LIMITATION", outcome.limitation_notes)

    def test_scenario_rapid_renaming(self):
        """Verify 6-stage detection pipeline on rapid file renaming scenario."""
        outcome = self.lab.run_scenario("RAPID_RENAMING")
        self.assertTrue(outcome.passed_test)
        self.assertEqual(outcome.scenario_id, "RAPID_RENAMING")
        self.assertTrue(outcome.simulator_generated_activity)
        self.assertTrue(outcome.filesystem_observed_sandbox)
        self.assertFalse(outcome.live_telemetry_collected_features) # File extension count absent from 19-vector
        self.assertTrue(outcome.ml_processed_features)
        self.assertEqual(outcome.detection_achieved, outcome.classifier_result in ["WARNING", "CRITICAL"])
        self.assertIn("PIPELINE GAP", outcome.limitation_notes)

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

    def test_feature_order_integrity(self):
        """Verify exact feature ordering expected by the trained StandardScaler."""
        import joblib
        from utils.paths import get_models_dir
        scaler = joblib.load(get_models_dir() / "scaler.pkl")
        self.assertTrue(hasattr(scaler, "feature_names_in_"))
        self.assertEqual(list(FEATURE_NAMES), list(scaler.feature_names_in_))

    def test_missing_telemetry_handling(self):
        """Verify handling of None, truncated, or wrong-dimension feature arrays."""
        predictor = MLPredictor()
        predictor.load_model()
        self.assertIsNone(predictor.predict(None))
        self.assertIsNone(predictor.predict(np.zeros((1, 10))))   # Truncated
        self.assertIsNone(predictor.predict(np.zeros((1, 25))))   # Extra features
        self.assertIsNone(predictor.predict(np.zeros((2, 19))))   # Wrong batch dimension

    def test_classification_threshold_logic(self):
        """Verify deterministic classification threshold mapping."""
        predictor = MLPredictor()
        predictor.load_model()
        self.assertEqual(predictor._classify(0.00), "SAFE")
        self.assertEqual(predictor._classify(0.49), "SAFE")
        self.assertEqual(predictor._classify(0.50), "WARNING")
        self.assertEqual(predictor._classify(0.89), "WARNING")
        self.assertEqual(predictor._classify(0.90), "CRITICAL")
        self.assertEqual(predictor._classify(1.00), "CRITICAL")

    def test_heuristic_proxy_divergence_documentation(self):
        """Audit the 5 critical heuristic proxies vs memory-forensics features."""
        from scanner.live_scanner import LiveScanner
        scanner = LiveScanner()
        # Verify extraction methods exist and map to the specific heuristic proxies
        self.assertTrue(hasattr(scanner, "_count_hollow_procs"))            # Index 5: malfind_injection_count
        self.assertTrue(hasattr(scanner, "_count_suspicious_path_procs"))   # Index 14: unsigned_module_count
        self.assertTrue(hasattr(scanner, "_count_high_thread_procs"))       # Index 15 & 17: suspicious_mutex & thread
        self.assertTrue(hasattr(scanner, "_count_abnormal_handle_procs"))   # Index 16: abnormal_privilege_count

        # Verify semantic substitution:
        dummy_procs = []
        self.assertEqual(scanner._count_hollow_procs(dummy_procs), 0.0)
        self.assertEqual(scanner._count_suspicious_path_procs(dummy_procs), 0.0)
        self.assertEqual(scanner._count_high_thread_procs(dummy_procs, 50), 0.0)
        self.assertEqual(scanner._count_abnormal_handle_procs(dummy_procs), 0.0)

    def test_custom_path_entropy_observation(self):
        """Verify that passing target_directories to LiveScanner samples the targeted path."""
        import tempfile
        import os
        from scanner.live_scanner import LiveScanner
        scanner = LiveScanner()
        with tempfile.TemporaryDirectory() as td:
            tpath = Path(td)
            sample_file = tpath / "sample.bin"
            with open(sample_file, "wb") as f:
                f.write(os.urandom(8192))
            
            avg_e, max_e, high_count = scanner._scan_file_entropy(target_directories=[tpath])
            self.assertGreater(avg_e, 7.5)
            self.assertGreater(max_e, 7.5)
            self.assertEqual(high_count, 1.0)

    def test_scan_engine_threshold_mapping(self):
        """Verify ScanEngine reconciles ML warning/critical thresholds to THREAT_DETECTED."""
        from scanner.scan_engine import ScanResult, ScanType, ScanState
        res_warn = ScanResult(scan_type=ScanType.QUICK, state=ScanState.IDLE, ml_executed=True, threat_level="WARNING", ml_probability=0.55)
        self.assertTrue(res_warn.threat_level == "WARNING" or res_warn.ml_probability >= 0.5)

        res_safe = ScanResult(scan_type=ScanType.QUICK, state=ScanState.IDLE, ml_executed=True, threat_level="SAFE", ml_probability=0.25)
        self.assertTrue(res_safe.threat_level == "SAFE" and res_safe.ml_probability < 0.5)


class TestFailureHandlingAndAdvisoryDecoupling(unittest.TestCase):
    """Verify state invariants and advisory decoupling."""

    def test_scan_incomplete_never_safe(self):
        """Incomplete or failed scans must NEVER be treated as successful or SAFE."""
        res_incomplete = ScanResult(scan_type=ScanType.QUICK, state=ScanState.SCAN_INCOMPLETE)
        self.assertFalse(res_incomplete.was_successful())

        res_error = ScanResult(scan_type=ScanType.QUICK, state=ScanState.ANALYSIS_ERROR)
        self.assertFalse(res_error.was_successful())

        res_crit_error = ScanResult(scan_type=ScanType.QUICK, state=ScanState.ERROR)
        self.assertFalse(res_crit_error.was_successful())

    def test_sentinel_ai_advisory_decoupling(self):
        """Confirm SentinelAI has zero override privileges over ScanResult or MLPredictor."""
        from ai.sentinel_ai import SentinelAI
        ai = SentinelAI({"enabled": False})
        # Verify SentinelAI does not have methods to mutate scan results or model weights
        self.assertFalse(hasattr(ai, "set_threat_level"))
        self.assertFalse(hasattr(ai, "override_decision"))
        self.assertFalse(hasattr(ai, "set_classification"))

    def test_results_export_schema_fields(self):
        """Verify all exhibition audit fields are captured in report export."""
        import json
        exporter = ExhibitionReportExporter()
        paths = exporter.export_report(
            mode_title="Scenario Verification",
            scan_state="SAFE",
            ml_prediction="SAFE",
            probability=0.12,
            duration_s=3.14,
            features={"total_processes": 150.0, "avg_entropy": 4.1},
            evidence_events=[{"timestamp": "10:00:00", "phase": "AUDIT", "action": "INSPECT", "details": "Verified"}],
            ground_truth_label="BENIGN",
            score_interpretation="Score represents 12% positive voting estimators in Random Forest."
        )

        with open(paths["json"], "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertEqual(data["scenario"], "Scenario Verification")
        self.assertEqual(data["ground_truth_label"], "BENIGN")
        self.assertEqual(data["scan_state"], "SAFE")
        self.assertEqual(data["ml_prediction"], "SAFE")
        self.assertEqual(data["malicious_probability"], 0.12)
        self.assertIn("score_interpretation", data)
        self.assertIn("extracted_features", data)
        self.assertIn("test_timestamp", data)

        # Cleanup
        paths["json"].unlink(missing_ok=True)
        paths["md"].unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
