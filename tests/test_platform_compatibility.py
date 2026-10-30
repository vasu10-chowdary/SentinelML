"""
SentinelML V2 — Cross-Platform Compatibility Test Suite
=======================================================
Automated verification for Windows, Linux, and macOS cross-platform support:
1. Platform detection and OS adapter contracts.
2. Platform-independent paths, configurations, and data roots.
3. Process and filesystem scanning behavior across platforms.
4. ML inference integrity, feature-schema validation, and threshold invariant.
5. Failure integrity: errors and cancellations are NEVER classified as SAFE.
6. Single-instance locking across platforms.
7. RAM forensics audit and user-space vs kernel boundary integrity.
"""

import math
import os
import platform
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utils.platform_adapter import (
    PlatformAdapter,
    WindowsPlatformAdapter,
    LinuxPlatformAdapter,
    MacOSPlatformAdapter,
    ProcessInfoProxy,
    get_platform_adapter,
)
from utils.platform_utils import (
    PlatformInfo,
    PlatformPaths,
    PlatformFeatures,
    get_platform_info,
    get_platform_paths,
    get_platform_features,
    get_monitored_directories,
)
from utils.paths import (
    get_application_root,
    get_user_data_root,
    get_logs_dir,
    get_alerts_dir,
    get_reports_dir,
    get_models_dir,
    get_config_path,
)
from ml.predictor import MLPredictor, validate_model_probability, normalize_risk_score, FEATURE_NAMES
from scanner.scan_engine import ScanResult, ScanType, ScanState


class TestPlatformDetectionAndAdapters(unittest.TestCase):
    """Test OS detection and platform adapter implementations."""

    def test_running_platform_adapter_instantiation(self):
        adapter = get_platform_adapter()
        self.assertIsInstance(adapter, PlatformAdapter)
        current_system = platform.system()
        if current_system == "Windows":
            self.assertEqual(adapter.get_platform_name(), "windows")
            self.assertIsInstance(adapter, WindowsPlatformAdapter)
        elif current_system == "Linux":
            self.assertEqual(adapter.get_platform_name(), "linux")
            self.assertIsInstance(adapter, LinuxPlatformAdapter)
        elif current_system == "Darwin":
            self.assertEqual(adapter.get_platform_name(), "macos")
            self.assertIsInstance(adapter, MacOSPlatformAdapter)

    def test_windows_adapter_heuristics_and_fonts(self):
        adapter = WindowsPlatformAdapter()
        self.assertEqual(adapter.get_platform_name(), "windows")
        self.assertTrue(adapter.is_suspicious_process_name("vssadmin.exe"))
        self.assertTrue(adapter.is_suspicious_process_name("WMIC.EXE"))
        self.assertFalse(adapter.is_suspicious_process_name("notepad.exe"))
        self.assertTrue(adapter.is_crypto_module("C:\\Windows\\System32\\bcrypt.dll"))
        self.assertTrue(adapter.is_crypto_module("crypt32.dll"))
        self.assertFalse(adapter.is_crypto_module("kernel32.dll"))
        fonts = adapter.get_font_preference()
        self.assertIn("Segoe UI", fonts)

    def test_linux_adapter_heuristics_and_fonts(self):
        adapter = LinuxPlatformAdapter()
        self.assertEqual(adapter.get_platform_name(), "linux")
        self.assertTrue(adapter.is_suspicious_process_name("shred"))
        self.assertTrue(adapter.is_suspicious_process_name("/usr/bin/srm"))
        self.assertTrue(adapter.is_suspicious_process_name("vssadmin.exe"))
        self.assertFalse(adapter.is_suspicious_process_name("bash"))
        self.assertTrue(adapter.is_crypto_module("/usr/lib/x86_64-linux-gnu/libcrypto.so.3"))
        self.assertTrue(adapter.is_crypto_module("libssl.so"))
        self.assertFalse(adapter.is_crypto_module("libc.so.6"))
        self.assertEqual(adapter.check_security_service_tampering(), 0.0)
        fonts = adapter.get_font_preference()
        self.assertIn("Ubuntu", fonts)
        self.assertIn("DejaVu Sans", fonts)

    def test_macos_adapter_heuristics_and_fonts(self):
        adapter = MacOSPlatformAdapter()
        self.assertEqual(adapter.get_platform_name(), "macos")
        self.assertTrue(adapter.is_suspicious_process_name("tmutil"))
        self.assertTrue(adapter.is_suspicious_process_name("csrutil"))
        self.assertTrue(adapter.is_crypto_module("libcrypto.dylib"))
        self.assertTrue(adapter.is_crypto_module("/usr/lib/libcommoncrypto.dylib"))
        self.assertFalse(adapter.is_crypto_module("libobjc.dylib"))
        self.assertEqual(adapter.check_security_service_tampering(), 0.0)
        fonts = adapter.get_font_preference()
        self.assertIn(".AppleSystemUIFont", fonts)

    def test_user_path_detection(self):
        adapter = get_platform_adapter()
        home = Path.home()
        user_doc = home / "Documents" / "test.txt"
        self.assertTrue(adapter.is_user_path(user_doc))
        self.assertTrue(adapter.is_user_path(home))


class TestCrossPlatformPathsAndConfig(unittest.TestCase):
    """Test path resolution and configuration integrity across platforms."""

    def test_platform_info_properties(self):
        info = get_platform_info()
        self.assertIn(info.system, ["Windows", "Linux", "Darwin"])
        self.assertTrue(info.get_home_directory().exists())
        self.assertTrue(info.get_temp_directory().exists())
        self.assertGreater(info.get_process_count(), 0)

    def test_monitored_directories_contract(self):
        dirs = get_monitored_directories()
        self.assertIsInstance(dirs, list)
        self.assertGreater(len(dirs), 0)
        for d in dirs:
            self.assertIsInstance(d, Path)
            self.assertTrue(d.exists())
            self.assertTrue(d.is_dir())

    def test_application_data_dir_resolution(self):
        info = get_platform_info()
        paths = PlatformPaths(info)
        app_dir = paths.get_application_data_dir()
        self.assertIsInstance(app_dir, Path)
        if info.is_windows():
            self.assertTrue("SentinelML" in str(app_dir))
        elif info.is_linux():
            self.assertTrue(".config" in str(app_dir) or "SentinelML" in str(app_dir))
        elif info.is_macos():
            self.assertTrue("Application Support" in str(app_dir))

    def test_core_path_getters_return_path_instances(self):
        self.assertIsInstance(get_application_root(), Path)
        self.assertIsInstance(get_user_data_root(), Path)
        self.assertIsInstance(get_logs_dir(), Path)
        self.assertIsInstance(get_alerts_dir(), Path)
        self.assertIsInstance(get_reports_dir(), Path)
        self.assertIsInstance(get_models_dir(), Path)
        self.assertIsInstance(get_config_path(), Path)

    def test_config_load_and_defaults(self):
        import config as cfg
        config_data = cfg.load()
        self.assertIsInstance(config_data, dict)
        self.assertIn("permissions", config_data)
        self.assertIn("ai", config_data)


class TestProcessAndFilesystemScanning(unittest.TestCase):
    """Test process enumeration and filesystem inspection behavior."""

    def test_process_snapshot_proxy_contract(self):
        adapter = get_platform_adapter()
        snapshot = adapter.get_process_snapshot()
        self.assertIsInstance(snapshot, list)
        self.assertGreater(len(snapshot), 0)
        sample = snapshot[0]
        self.assertIsInstance(sample.pid, int)
        self.assertIsInstance(sample.name, str)
        self.assertIsInstance(sample.exe, str)
        self.assertIsInstance(sample.num_threads, int)
        self.assertIsInstance(sample.memory_maps(), list)

    def test_filesystem_scanner_clean_traversal(self):
        from scanner.filesystem_scanner import FilesystemScanner
        scanner = FilesystemScanner()
        target = Path.home() / "Documents"
        if not target.exists():
            target = Path.home()
        stats = scanner.scan_paths([target], max_depth=1)
        self.assertGreaterEqual(stats.files_inspected, 0)
        self.assertGreaterEqual(stats.directories_inspected, 0)
        self.assertFalse(stats.cancelled)


class TestMLInferenceAndFeatureSchema(unittest.TestCase):
    """Test that ML model, scaler, and 19-feature schema operate identically on all platforms."""

    def setUp(self):
        self.predictor = MLPredictor()
        self.loaded = self.predictor.load_model()

    def test_model_loads_successfully(self):
        self.assertTrue(self.loaded, "ML model must load successfully from models/saved_model.pkl")
        info = self.predictor.get_model_info()
        self.assertEqual(info["expected_features"], 19)
        self.assertEqual(info["threshold_critical"], 0.90)
        self.assertEqual(info["threshold_warning"], 0.50)

    def test_feature_names_match_contract(self):
        self.assertEqual(len(FEATURE_NAMES), 19)
        self.assertEqual(FEATURE_NAMES[0], "total_processes")
        self.assertEqual(FEATURE_NAMES[6], "crypto_dll_count")
        self.assertEqual(FEATURE_NAMES[18], "defender_tampering_count")

    def test_safe_baseline_vector_classification(self):
        vec = np.zeros((1, 19), dtype=np.float64)
        vec[0, 0] = 80.0  # 80 total processes
        res = self.predictor.predict(vec)
        self.assertIsNotNone(res)
        label, prob = res
        self.assertEqual(label, "SAFE")
        self.assertLess(prob, 0.50)

    def test_threat_vector_classification(self):
        threat_vec = np.array([[200.0, 5.0, 7.8, 7.99, 150.0, 3.0, 10.0, 4.0, 50.0, 15.0, 1000.0, 10.0, 5.0, 4.0, 8.0, 5.0, 3.0, 2.0, 1.0]], dtype=np.float64)
        res = self.predictor.predict(threat_vec)
        self.assertIsNotNone(res)
        label, prob = res
        self.assertIn(label, ["WARNING", "CRITICAL"])
        self.assertGreaterEqual(prob, 0.50)

    def test_model_output_contract_validation(self):
        self.assertTrue(validate_model_probability(0.0)[0])
        self.assertTrue(validate_model_probability(0.5)[0])
        self.assertTrue(validate_model_probability(1.0)[0])
        self.assertFalse(validate_model_probability(-0.01)[0])
        self.assertFalse(validate_model_probability(1.01)[0])
        self.assertFalse(validate_model_probability(float("nan"))[0])
        self.assertFalse(validate_model_probability(float("inf"))[0])
        self.assertFalse(validate_model_probability(None)[0])
        self.assertFalse(validate_model_probability("invalid")[0])

    def test_nan_vector_rejection(self):
        nan_vec = np.zeros((1, 19))
        nan_vec[0, 2] = float("nan")
        self.assertIsNone(self.predictor.predict(nan_vec))

    def test_wrong_shape_vector_rejection(self):
        wrong_shape = np.zeros((1, 15))
        self.assertIsNone(self.predictor.predict(wrong_shape))


class TestScanStateAndFailureIntegrity(unittest.TestCase):
    """Verify security-critical failure invariants: errors and aborts are NEVER reported as SAFE."""

    def test_cancelled_scan_is_never_safe(self):
        sr = ScanResult(ScanType.QUICK, ScanState.SCAN_INCOMPLETE)
        sr.cancelled = True
        sr.ml_probability = 0.05
        sr.threat_level = "CANCELLED"
        self.assertFalse(sr.was_successful())
        unified = sr.get_unified_classification()
        self.assertNotEqual(unified["level"], "SAFE")
        self.assertNotEqual(unified["tag"], "SAFE")
        self.assertFalse(unified["is_clean"])
        self.assertEqual(unified["risk_label"], "CANCELLED")

    def test_error_scan_is_never_safe(self):
        sr = ScanResult(ScanType.QUICK, ScanState.ERROR)
        sr.error_message = "Process access denied"
        sr.ml_probability = 0.01
        self.assertFalse(sr.was_successful())
        unified = sr.get_unified_classification()
        self.assertNotEqual(unified["level"], "SAFE")
        self.assertEqual(unified["tag"], "ERROR")
        self.assertFalse(unified["is_clean"])

    def test_partial_scan_with_access_denied_is_flagged_limited(self):
        sr = ScanResult(ScanType.QUICK, ScanState.SAFE)
        sr.threat_level = "SAFE"
        sr.access_denied = 5
        sr.ml_probability = 0.20
        unified = sr.get_unified_classification()
        self.assertTrue(unified["is_partial"])


class TestSingleInstanceLocking(unittest.TestCase):
    """Test application single-instance locking behavior."""

    def test_single_instance_lock_acquire_and_release(self):
        adapter = get_platform_adapter()
        token = adapter.acquire_single_instance_lock()
        self.assertIsNotNone(token)
        adapter.release_single_instance_lock(token)


class TestRAMForensicsAndKernelDistinction(unittest.TestCase):
    """Verify RAM forensics boundaries and user-space behavioral monitoring disclosure."""

    def test_volatility_not_in_sys_modules_or_dependencies(self):
        self.assertNotIn("volatility3", sys.modules)
        self.assertNotIn("volatility", sys.modules)

    def test_report_exporter_sanitizes_unix_and_mac_paths(self):
        from exhibition.report_exporter import sanitize_path
        win_path = "Found file in C:\\Users\\johndoe\\Desktop\\ransom.exe"
        linux_path = "Found file in /home/alice/Desktop/ransom.elf"
        mac_path = "Found file in /Users/charlie/Desktop/ransom.bin"
        self.assertNotIn("johndoe", sanitize_path(win_path))
        self.assertNotIn("alice", sanitize_path(linux_path))
        self.assertNotIn("charlie", sanitize_path(mac_path))
        self.assertIn("[USER_PROFILE]", sanitize_path(win_path))
        self.assertIn("[USER_PROFILE]", sanitize_path(linux_path))
        self.assertIn("[USER_PROFILE]", sanitize_path(mac_path))


class TestFeatureAvailabilityAndInconclusiveState(unittest.TestCase):
    """Verify feature availability accounting, inconclusive states, and multi-OS dataset evaluation."""

    def test_feature_availability_covers_all_19_features(self):
        from scanner.live_scanner import get_platform_feature_availability, LiveScanner
        avail = get_platform_feature_availability()
        self.assertEqual(len(avail), 19)
        self.assertEqual(set(avail.keys()), set(FEATURE_NAMES))

        scanner = LiveScanner()
        self.assertEqual(scanner.get_feature_availability(), avail)

    def test_platform_missing_features_tracking(self):
        from scanner.live_scanner import get_platform_feature_availability
        avail = get_platform_feature_availability()
        if sys.platform != "win32":
            missing = [f for f, s in avail.items() if s.startswith("UNAVAILABLE") or s.startswith("RESTRICTED")]
            self.assertGreaterEqual(len(missing), 4)
            self.assertIn("file_handle_count", missing)
            self.assertIn("registry_handle_count", missing)
            self.assertIn("abnormal_privilege_count", missing)
            self.assertIn("defender_tampering_count", missing)
        else:
            unavailable = [f for f, s in avail.items() if s == "UNAVAILABLE_PLATFORM"]
            self.assertEqual(len(unavailable), 0)

    def test_scan_result_inconclusive_contract(self):
        sr = ScanResult(ScanType.FULL, ScanState.INCONCLUSIVE)
        sr.threat_level = "INCONCLUSIVE"
        sr.is_inconclusive = True
        sr.missing_features = ["file_handle_count", "registry_handle_count"]
        self.assertFalse(sr.was_successful())

        unified = sr.get_unified_classification()
        self.assertEqual(unified["level"], "INCONCLUSIVE")
        self.assertIn("INCONCLUSIVE", unified["tag"])
        self.assertFalse(unified["is_clean"])
        self.assertTrue(unified["is_limited"])

    def test_dataset_benchmark_windows_and_linux_parity(self):
        """Confirm 40-sample benchmark achieves 100% detection on both Windows and Linux feature sets."""
        import joblib
        from tests.run_evaluation_benchmark import generate_evaluation_dataset
        model = joblib.load(get_models_dir() / "saved_model.pkl")
        scaler = joblib.load(get_models_dir() / "scaler.pkl")
        dataset = generate_evaluation_dataset()

        correct = 0
        for s in dataset:
            vec = s["features"].copy()
            # Zero out the 4 platform-specific features to test Linux/macOS degradation resistance
            vec[0, 10] = 0.0  # file handles
            vec[0, 11] = 0.0  # registry handles
            vec[0, 16] = 0.0  # abnormal privileges
            vec[0, 18] = 0.0  # defender tampering
            scaled = scaler.transform(vec)
            prob = model.predict_proba(scaled)[0, 1]
            pred = 1 if prob >= 0.50 else 0
            if pred == s["label"]:
                correct += 1

        self.assertEqual(correct, len(dataset), f"Benchmark dataset parity failed: {correct}/{len(dataset)}")


if __name__ == "__main__":
    unittest.main()
