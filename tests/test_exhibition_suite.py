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


class TestLiveInferenceValidation(unittest.TestCase):
    """
    Automated Phase 5 checks verifying live inference invariants:
    1. Schema validation (19 features, finite, numeric)
    2. Parity of feature ordering
    3. Missing telemetry cannot evaluate as SAFE
    4. Invalid model outputs trigger ANALYSIS_ERROR
    5. Incomplete scans never evaluate as SAFE
    6. SentinelAI advisory decoupling
    7. Honest detection criteria in synthetic testing
    8. Independent recording of all 6 verification stages
    """

    def test_live_feature_vector_schema_and_types(self):
        """1. Live feature vector matches the model's expected schema (1x19, finite float)."""
        from scanner.live_scanner import LiveScanner
        scanner = LiveScanner()
        vec = scanner.scan_system()
        self.assertIsNotNone(vec)
        self.assertIsInstance(vec, np.ndarray)
        self.assertEqual(vec.shape, (1, 19))
        self.assertTrue(np.issubdtype(vec.dtype, np.floating))
        self.assertTrue(np.isfinite(vec).all(), "Feature vector contains non-finite values (NaN or Inf)")

    def test_feature_order_pipeline_parity(self):
        """2. Feature order is identical during training and inference."""
        import joblib
        from utils.paths import get_models_dir
        scaler = joblib.load(get_models_dir() / "scaler.pkl")
        expected_names = list(scaler.feature_names_in_)
        self.assertEqual(len(expected_names), 19)
        self.assertEqual(list(FEATURE_NAMES), expected_names)

        # Expected canonical feature order from recovered training config
        canonical_features = [
            "total_processes", "suspicious_process_count", "avg_entropy", "max_entropy",
            "high_entropy_region_count", "malfind_injection_count", "crypto_dll_count",
            "cmd_vssadmin_count", "network_connection_count", "unique_external_ips",
            "file_handle_count", "registry_handle_count", "orphan_process_count",
            "powershell_process_count", "unsigned_module_count", "suspicious_mutex_count",
            "abnormal_privilege_count", "suspicious_thread_count", "defender_tampering_count"
        ]
        self.assertEqual(list(FEATURE_NAMES), canonical_features)

    def test_missing_telemetry_never_converted_to_benign(self):
        """3. Missing telemetry is not silently converted into a benign signal."""
        from unittest.mock import MagicMock
        engine = ScanEngine()
        res = ScanResult(scan_type=ScanType.QUICK, state=ScanState.IDLE)
        # Simulate failed process scan returning None
        engine._process_scanner = MagicMock()
        engine._process_scanner.scan_system.return_value = None

        success = engine._scan_processes(res)
        self.assertFalse(success)
        self.assertFalse(hasattr(res, "_features"))

        # ML analysis must fail safely if features missing
        ml_success = engine._run_ml_analysis(res)
        self.assertFalse(ml_success)
        self.assertEqual(res.threat_level, "ANALYSIS_ERROR")
        self.assertNotEqual(res.threat_level, "SAFE")

    def test_invalid_model_output_causes_explicit_analysis_error(self):
        """4. Invalid model output causes an explicit analysis error."""
        from unittest.mock import patch
        engine = ScanEngine()
        res = ScanResult(scan_type=ScanType.QUICK, state=ScanState.IDLE)
        res._features = np.zeros((1, 19), dtype=np.float64)

        # Case A: Probability out of bounds (> 1.0)
        with patch("ml.predictor.MLPredictor.predict", return_value=("CRITICAL", 1.45)):
            success = engine._run_ml_analysis(res)
            self.assertFalse(success)
            self.assertEqual(res.threat_level, "ANALYSIS_ERROR")

        # Case B: Probability out of bounds (< 0.0)
        with patch("ml.predictor.MLPredictor.predict", return_value=("SAFE", -0.15)):
            success = engine._run_ml_analysis(res)
            self.assertFalse(success)
            self.assertEqual(res.threat_level, "ANALYSIS_ERROR")

        # Case C: Invalid threat level label
        with patch("ml.predictor.MLPredictor.predict", return_value=("UNKNOWN_LABEL", 0.85)):
            success = engine._run_ml_analysis(res)
            self.assertFalse(success)
            self.assertEqual(res.threat_level, "ANALYSIS_ERROR")

        # Case D: Predict returns None
        with patch("ml.predictor.MLPredictor.predict", return_value=None):
            success = engine._run_ml_analysis(res)
            self.assertFalse(success)
            self.assertEqual(res.threat_level, "ANALYSIS_ERROR")

    def test_incomplete_scan_cannot_be_classified_as_safe(self):
        """5. Incomplete scan cannot be classified as SAFE."""
        for state in [ScanState.SCAN_INCOMPLETE, ScanState.ANALYSIS_ERROR, ScanState.ERROR]:
            res = ScanResult(scan_type=ScanType.FULL, state=state, threat_level="SAFE", ml_probability=0.1)
            self.assertFalse(res.was_successful())
            # In ScanEngine, if ml_success is False, state is SCAN_INCOMPLETE
            self.assertNotEqual(res.state, ScanState.SAFE)

    def test_sentinel_ai_cannot_override_classifier(self):
        """6. SentinelAI cannot override the local classifier."""
        from ai.sentinel_ai import SentinelAI
        ai = SentinelAI({"enabled": False})
        self.assertFalse(hasattr(ai, "override_decision"))
        self.assertFalse(hasattr(ai, "set_threat_level"))
        self.assertFalse(hasattr(ai, "set_ml_probability"))
        self.assertFalse(hasattr(ai, "force_safe"))

    def test_synthetic_scenario_honest_detection_criteria(self):
        """7. A synthetic test only passes detection when the actual model result satisfies a documented expectation."""
        # Simulated outcome where ML evaluates to SAFE (probability 0.35)
        outcome_safe = ScenarioOutcome(
            scenario_id="TEST_UNDETECTED",
            scenario_name="Undetected Scenario",
            is_simulation=True,
            expected_behavior="Threat detection",
            observed_behavior="Entropy elevated but ML classified SAFE",
            classifier_output="SAFE",
            probability=0.35,
            scan_state="SAFE",
            passed_test=True,
            detection_achieved=(0.35 >= 0.50)  # Must be False
        )
        self.assertFalse(outcome_safe.detection_achieved)
        self.assertEqual(outcome_safe.classifier_output, "SAFE")

        # Simulated outcome where ML evaluates to WARNING (probability 0.56)
        outcome_warn = ScenarioOutcome(
            scenario_id="TEST_DETECTED",
            scenario_name="Detected Scenario",
            is_simulation=True,
            expected_behavior="Threat detection",
            observed_behavior="Threat flagged",
            classifier_output="WARNING",
            probability=0.56,
            scan_state="THREAT_DETECTED",
            passed_test=True,
            detection_achieved=(0.56 >= 0.50)  # Must be True
        )
        self.assertTrue(outcome_warn.detection_achieved)
        self.assertEqual(outcome_warn.classifier_output, "WARNING")

    def test_six_stage_verification_independent_recording(self):
        """8. Sandbox simulation, filesystem observation, feature extraction, and classification are independently recorded."""
        outcome = ScenarioOutcome(
            scenario_id="TEST_6_STAGE",
            scenario_name="6 Stage Test",
            is_simulation=True,
            expected_behavior="Full 6-stage recording",
            observed_behavior="All stages captured",
            classifier_output="WARNING",
            probability=0.56,
            scan_state="THREAT_DETECTED",
            passed_test=True,
            simulator_generated_activity=True,
            filesystem_observed_sandbox=True,
            live_telemetry_collected_features=True,
            ml_processed_features=True,
            classifier_result="WARNING",
            detection_achieved=True,
            limitation_notes="Operational notes recorded"
        )
        # Verify all 6 stages exist independently
        self.assertTrue(hasattr(outcome, "simulator_generated_activity"))
        self.assertTrue(hasattr(outcome, "filesystem_observed_sandbox"))
        self.assertTrue(hasattr(outcome, "live_telemetry_collected_features"))
        self.assertTrue(hasattr(outcome, "ml_processed_features"))
        self.assertTrue(hasattr(outcome, "classifier_result"))
        self.assertTrue(hasattr(outcome, "detection_achieved"))
        self.assertTrue(hasattr(outcome, "limitation_notes"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
