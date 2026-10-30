"""
SentinelML V2 — Unified Dashboard & Safe Simulation Regression Suite
=====================================================================
Validates:
1. Normal application startup and unified navigation structure.
2. Dashboard initial state, components, and live telemetry layout.
3. Strict sandbox path containment and traversal rejection.
4. Safe simulation execution, Shannon entropy elevation, and cleanup.
5. Repeated simulations and concurrency prevention.
6. Honest distinction between live host telemetry and sandbox simulation evidence.
7. Fail-safe invariant: incomplete/error states NEVER report SAFE.
8. Model inference authenticity via genuine ScanEngine and Random Forest classifier.
9. Incident report generation with full feature vector and scientific disclosures.
"""

import sys
import unittest
from pathlib import Path
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scanner.scan_engine import ScanEngine, ScanType, ScanState, ScanResult
from ml.predictor import MLPredictor, FEATURE_NAMES
from exhibition.sandbox_simulator import SandboxSimulator, SecurityError, SimulationResult
from exhibition.security_test_lab import SecurityTestLab
from alerts.alert_manager import get_alert_manager


class TestUnifiedDashboardRegression(unittest.TestCase):
    """Regression tests for the unified dashboard and integrated simulation."""

    def setUp(self):
        self.sandbox_dir = PROJECT_ROOT / "temp_test_unified_sandbox"
        self.simulator = SandboxSimulator(self.sandbox_dir)
        self.simulator.reset_sandbox()

    def tearDown(self):
        self.simulator.reset_sandbox()
        if self.sandbox_dir.exists():
            import shutil
            shutil.rmtree(self.sandbox_dir, ignore_errors=True)

    def test_navigation_items_unified(self):
        """Verify that the primary navigation contains the product pages and no disconnected exhibition button."""
        from gui.main_window import MainWindow
        import customtkinter as ctk

        # Create headless window instance
        app = MainWindow()
        try:
            # Check nav items
            nav_keys = list(app._nav_btns.keys())
            expected_keys = ["dashboard", "threats", "sentinel_ai", "ransomware", "settings"]
            self.assertEqual(nav_keys, expected_keys)
            self.assertNotIn("exhibition", nav_keys, "Exhibition button must not be a disconnected sidebar item")

            # Check dashboard is default
            self.assertEqual(app._current_page, "dashboard")
            self.assertIn("dashboard", app._pages)
        finally:
            app.destroy()

    def test_dashboard_initial_components(self):
        """Verify that DashboardPage initializes with truthful READY TO SCAN / NOT YET SCANNED state."""
        import customtkinter as ctk
        from gui.pages.dashboard import DashboardPage

        root = ctk.CTk()
        try:
            dashboard = DashboardPage(root, config={})
            self.assertEqual(dashboard._threat_level, "NOT_SCANNED")
            self.assertEqual(dashboard._status_title.cget("text"), "READY TO SCAN")
            self.assertIn("NOT YET SCANNED", dashboard._status_badge.cget("text"))
            self.assertEqual(dashboard._cancel_scan_btn.cget("state"), "disabled")
            self.assertEqual(dashboard._risk_score, 0.0)
            self.assertFalse(dashboard._scanning)
            self.assertFalse(dashboard._is_simulation)

            # Check buttons exist
            self.assertTrue(hasattr(dashboard, "_scan_btn"))
            self.assertTrue(hasattr(dashboard, "_sim_btn"))
            self.assertTrue(hasattr(dashboard, "_evidence_btn"))
            self.assertTrue(hasattr(dashboard, "_clean_btn"))
            self.assertTrue(hasattr(dashboard, "_feed_scroll"))
        finally:
            root.destroy()

    def test_sandbox_path_containment_and_rejection(self):
        """Verify strict path validation prevents access outside the designated sandbox."""
        subfile = self.sandbox_dir / "valid_test.txt"
        validated = self.simulator.validate_path_safety(subfile)
        self.assertEqual(validated, subfile.resolve())

        # Path traversal rejection
        escape_path = self.sandbox_dir / ".." / "outside.txt"
        with self.assertRaises(SecurityError):
            self.simulator.validate_path_safety(escape_path)

        # Arbitrary system path rejection
        system_path = Path("C:\\Windows\\System32\\cmd.exe")
        with self.assertRaises(SecurityError):
            self.simulator.validate_path_safety(system_path)

    def test_simulation_lifecycle_and_cleanup(self):
        """Verify simulation generates files, elevates entropy, and resets cleanly."""
        res = self.simulator.run_simulation(num_files=10, delay_between_ops=0.002)
        self.assertIsInstance(res, SimulationResult)
        self.assertEqual(res.total_files_created, 10)
        self.assertEqual(res.total_files_modified, 10)
        self.assertEqual(res.total_files_renamed, 10)
        self.assertGreater(res.avg_entropy_after, 7.0, "Entropy after modification should exceed 7.0 bits/byte")

        # Verify cleanup (num_files created + 1 ransom note)
        cleaned = self.simulator.reset_sandbox()
        self.assertEqual(cleaned, 11)
        remaining = list(self.sandbox_dir.glob("*"))
        self.assertEqual(len(remaining), 0, "Sandbox must be completely clean after reset")

    def test_repeated_simulations_stability(self):
        """Verify running consecutive simulations works reliably without file accumulation."""
        for run_idx in range(3):
            res = self.simulator.run_simulation(num_files=5, delay_between_ops=0.002)
            self.assertEqual(res.total_files_created, 5)
            cleaned = self.simulator.reset_sandbox()
            self.assertEqual(cleaned, 6)

    def test_distinction_between_simulation_and_host_evidence(self):
        """Verify UI updates clearly distinguish between host scans and sandbox simulations."""
        import customtkinter as ctk
        from gui.pages.dashboard import DashboardPage

        root = ctk.CTk()
        try:
            dashboard = DashboardPage(root, config={})

            # 1. Update with Live Host Scan (clean full scan)
            dashboard.update_threat_status("SAFE", probability=0.10, is_simulation=False)
            self.assertIn("SYSTEM SAFE", dashboard._status_title.cget("text"))
            self.assertIn("LIVE HOST", dashboard._status_badge.cget("text"))
            self.assertIn("Full System Scan clean", dashboard._status_desc.cget("text"))

            # 2. Update with Simulation
            dashboard.update_threat_status("WARNING", probability=0.57, is_simulation=True)
            self.assertIn("SIMULATION", dashboard._status_title.cget("text"))
            self.assertIn("SANDBOX SIMULATION", dashboard._status_badge.cget("text"))
            self.assertEqual(dashboard._risk_score_label.cget("text"), "57%")
        finally:
            root.destroy()

    def test_permission_limited_scan_status_disclosure(self):
        """Verify that a scan encountering access-denied paths does NOT report full SYSTEM SAFE."""
        import customtkinter as ctk
        from gui.pages.dashboard import DashboardPage

        root = ctk.CTk()
        try:
            dashboard = DashboardPage(root, config={})
            sr = ScanResult(
                scan_type=ScanType.QUICK,
                state=ScanState.COMPLETE,
                files_inspected=150,
                access_denied=3,
                threat_level="SAFE"
            )
            sr.scan_id = "SCN-PERM-DENIED-TEST"
            dashboard._last_scan_result = sr

            dashboard.update_threat_status("SAFE", probability=0.08, is_simulation=False)
            self.assertEqual(dashboard._status_title.cget("text"), "NO THREATS DETECTED — LIMITED SCAN")
            self.assertIn("LIMITED", dashboard._status_badge.cget("text"))
            self.assertIn("access denied", dashboard._status_desc.cget("text"))
            self.assertIn("Full coverage not guaranteed", dashboard._status_desc.cget("text"))
            self.assertEqual(dashboard._risk_level_label.cget("text"), "LIMITED (PARTIAL)")
        finally:
            root.destroy()

    def test_scan_error_fail_safe_invariant(self):
        """Verify that an error during scanning NEVER displays a clean SAFE state."""
        import customtkinter as ctk
        from gui.pages.dashboard import DashboardPage

        root = ctk.CTk()
        try:
            dashboard = DashboardPage(root, config={})
            # Trigger an error
            dashboard._on_scan_error("Test permission denied failure")

            self.assertEqual(dashboard._status_title.cget("text"), "SCAN ERROR")
            self.assertEqual(dashboard._risk_score_label.cget("text"), "ERR")
            self.assertIn("Analysis failed", dashboard._status_desc.cget("text"))
            self.assertNotEqual(dashboard._threat_level, "SAFE")
        finally:
            root.destroy()

    def test_model_inference_authenticity(self):
        """Verify that the detection pipeline executes the genuine model and scaler."""
        lab = SecurityTestLab()
        # Verify demo health
        health = lab.check_demo_health()
        self.assertTrue(health["healthy"])
        self.assertTrue(health["model_ok"])
        self.assertTrue(health["sandbox_ok"])

        # Execute safe demo inside temp_sandbox/
        res = lab.run_safe_demo(num_files=10)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertIn("stages", res)
        self.assertEqual(len(res["stages"]), 6)
        self.assertTrue(res["stages"][4]["passed"])  # Stage 5: Model Inference
        self.assertTrue(res["scan_result"].ml_executed)

        # The v1 baseline model was trained on Windows telemetry. On POSIX,
        # registry/file-handle and Defender sensors are unavailable and evaluate
        # to 0.0 (see test_exhibition_suite.test_run_safe_demo_full_6_stages),
        # so the genuine classifier can honestly return SAFE. Never fabricate a
        # detection to satisfy a fixed expectation; verify the threshold mapping.
        prob = res["probability"]
        self.assertIsNotNone(prob)
        if sys.platform == "win32":
            self.assertEqual(res["threat_level"], "WARNING")
            self.assertGreater(prob, 0.50)
        else:
            expected = "CRITICAL" if prob >= 0.90 else ("WARNING" if prob >= 0.50 else "SAFE")
            self.assertEqual(res["threat_level"], expected)

        # Ensure cleanup
        lab.simulator.reset_sandbox()

    def test_alert_manager_recording(self):
        """Verify that AlertManager records structured events for simulation and scan."""
        mgr = get_alert_manager()
        before_count = len(mgr.get_alerts())

        # Add a simulation alert
        success = mgr.add_alert(
            severity="HIGH",
            category="simulation",
            title="[SIMULATION] Controlled Ransomware Behavior Detected",
            message="Test simulation event for unit test",
            source="Sandbox Simulation",
            metadata={"test": True}
        )
        self.assertTrue(success)

        alerts = mgr.get_alerts(limit=5)
        self.assertGreater(len(alerts), 0)
        self.assertEqual(alerts[0]["category"], "simulation")
        self.assertIn("[SIMULATION]", alerts[0]["title"])

    def test_scan_cancellation_and_engine_interruption(self):
        """Verify that cancelling a scan halts the engine and marks state as SCAN_INCOMPLETE."""
        import customtkinter as ctk
        from gui.pages.dashboard import DashboardPage

        engine = ScanEngine()
        engine.cancel()
        # Scan with pre-cancelled engine
        res = engine.scan(ScanType.QUICK)
        self.assertTrue(res.cancelled, "Engine must record cancellation")
        self.assertEqual(res.state, ScanState.SCAN_INCOMPLETE, "Cancelled scan must report SCAN_INCOMPLETE")
        self.assertFalse(res.was_successful(), "Cancelled scan must not be marked successful")

        # Test DashboardPage cancellation handler
        root = ctk.CTk()
        try:
            dashboard = DashboardPage(root, config={})
            dashboard._scanning = True
            dashboard._active_engine = engine
            dashboard._on_scan_cancelled(res)

            self.assertFalse(dashboard._scanning)
            self.assertEqual(dashboard._threat_level, "SCAN_INCOMPLETE")
            self.assertEqual(dashboard._status_title.cget("text"), "SCAN CANCELLED")
            self.assertIn("INCOMPLETE", dashboard._status_badge.cget("text"))
            self.assertEqual(dashboard._risk_level_label.cget("text"), "CANCELLED")
        finally:
            root.destroy()

    def test_scan_progress_and_current_path_propagation(self):
        """Verify that live scanning propagates genuine current_path and valid scan_id."""
        engine = ScanEngine()
        captured_paths = []

        def on_progress(sr: ScanResult):
            if sr.current_path:
                captured_paths.append(sr.current_path)

        # Run custom scan on temporary sandbox
        self.simulator.run_simulation(num_files=3, delay_between_ops=0.001)
        res = engine.scan(ScanType.CUSTOM, custom_paths=[self.sandbox_dir], progress_callback=on_progress)

        self.assertTrue(bool(res.scan_id), "Every scan execution must have a non-empty unique scan_id")
        self.assertGreater(len(res.scan_id), 10, "scan_id must be a UUID")
        self.assertGreater(len(captured_paths), 0, "current_path must be populated during traversal")
        self.simulator.reset_sandbox()

    def test_scan_history_and_view_switching(self):
        """Verify that DashboardPage records audit entries and switches views cleanly."""
        import tempfile
        import time
        import customtkinter as ctk
        from gui.pages.dashboard import DashboardPage

        root = ctk.CTk()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                dashboard = DashboardPage(root, config={"audit": {"path": str(Path(tmp) / "audit.json")}})
                self.assertEqual(len(dashboard._scan_history), 0)

                # Record a completed scan. Audit entries only exist for scans
                # that actually started, so register the start first.
                sr = ScanResult(
                    scan_type=ScanType.QUICK,
                    state=ScanState.SAFE,
                    files_inspected=150,
                    processes_analyzed=40,
                    threat_level="SAFE",
                    ml_probability=0.12,
                )
                sr.scan_id = "test-uuid-1234"
                dashboard._scan_started = True
                dashboard._scan_started_at = time.time() - 1.23
                dashboard._record_scan_history(scan_result=sr)
                self.assertEqual(len(dashboard._scan_history), 1)
                self.assertEqual(dashboard._scan_history[0]["scan_id"], "test-uuid-1234")

                # Switch view to Scan Audit History
                dashboard._on_switch_view("Scan Audit History")
                self.assertEqual(dashboard._view_segmented.get(), "Live SOC Feed")  # function sets view
                dashboard._view_segmented.set("Scan Audit History")
                dashboard._render_scan_history_table()

                # Switch back to Live SOC Feed
                dashboard._on_switch_view("Live SOC Feed")
        finally:
            root.destroy()

    def test_stale_report_prevention_on_new_or_aborted_scan(self):
        """Verify that reports bound to incomplete/cancelled scans explicitly disclose lack of safety."""
        cancelled_res = ScanResult(
            scan_type=ScanType.QUICK,
            state=ScanState.SCAN_INCOMPLETE,
            cancelled=True,
            files_inspected=120,
            processes_analyzed=15,
            threat_level="INCOMPLETE"
        )
        cancelled_res.scan_id = "cancelled-uuid-9999"

        self.assertFalse(cancelled_res.was_successful())
        self.assertEqual(cancelled_res.state, ScanState.SCAN_INCOMPLETE)
        self.assertNotEqual(cancelled_res.threat_level, "SAFE")

    def test_ui_dispatch_from_background_thread(self):
        """Verify that _dispatch_to_main safely queues work from background threads without cross-thread Tk calls."""
        import customtkinter as ctk
        import threading
        from gui.pages.dashboard import DashboardPage

        root = ctk.CTk()
        try:
            dashboard = DashboardPage(root, config={})
            executed = []

            def worker_task(val):
                executed.append(val)

            # Call from background worker thread
            t = threading.Thread(target=lambda: dashboard._dispatch_to_main(worker_task, 42))
            t.start()
            t.join()

            # Verify item is enqueued without crash
            self.assertFalse(dashboard._ui_queue.empty())
            dashboard._drain_ui_queue()
            self.assertEqual(executed, [42])
            self.assertTrue(dashboard._ui_queue.empty())
        finally:
            root.destroy()

    def test_scan_history_deduplication(self):
        """Verify that duplicate scan recordings with the same scan_id update in-place rather than duplicating."""
        import tempfile
        import time
        import customtkinter as ctk
        from gui.pages.dashboard import DashboardPage

        root = ctk.CTk()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                dashboard = DashboardPage(root, config={"audit": {"path": str(Path(tmp) / "audit.json")}})

                def record(files, duration):
                    sr = ScanResult(
                        scan_type=ScanType.QUICK,
                        state=ScanState.SAFE,
                        files_inspected=files,
                        processes_analyzed=10,
                        threat_level="SAFE",
                        ml_probability=0.05,
                    )
                    sr.scan_id = "SCN-DEDUP-TEST"
                    sr.elapsed_seconds = duration
                    dashboard._scan_started = True
                    dashboard._scan_started_at = time.time() - duration
                    dashboard._on_scan_complete("SAFE", 0.05, sr, is_simulation=False)

                record(50, 1.0)
                self.assertEqual(len(dashboard._scan_history), 1)

                # Call again with same scan_id (e.g., race or duplicate callback)
                record(55, 1.5)
                self.assertEqual(len(dashboard._scan_history), 1, "Duplicate scan_id must not create duplicate row")
                self.assertEqual(dashboard._scan_history[0]["duration_s"], 1.5)
                self.assertEqual(dashboard._scan_history[0]["files_examined"], 55)
        finally:
            root.destroy()

    def test_report_generation_scope_and_disclosure(self):
        """Verify that incident report text includes scan scope mode, exclusions, and limitations."""
        import customtkinter as ctk
        from unittest.mock import patch
        import tempfile
        from gui.pages.dashboard import DashboardPage

        root = ctk.CTk()
        try:
            dashboard = DashboardPage(root, config={})
            sr = ScanResult(
                scan_type=ScanType.QUICK,
                state=ScanState.COMPLETE,
                files_inspected=450,
                directories_inspected=25,
                processes_analyzed=180,
                threat_level="SAFE"
            )
            sr.scan_id = "SCN-SCOPE-TEST-99"
            sr.is_simulation = False
            sr.ml_probability = 0.08
            sr.ml_executed = True

            with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tf:
                out_path = tf.name

            try:
                with patch("tkinter.filedialog.asksaveasfilename", return_value=out_path), \
                     patch("tkinter.messagebox.askyesno", return_value=False):
                    dashboard._do_generate_report(target_result=sr)

                with open(out_path, "r", encoding="utf-8") as f:
                    content = f.read()

                self.assertIn("Scan Scope Mode     : Fast Live Scan (Quick: Target Depth = 1)", content)
                self.assertIn("Coverage Definition : Monitored root directories", content)
                self.assertIn("Excluded Folders    : Noise/build directories", content)
                self.assertIn("Coverage Limitation : Depth=1 focuses on surface drops", content)
                self.assertIn("Model Provenance    : EXPERIMENTAL_SYNTHETIC_BASELINE_V1", content)
                self.assertIn("SCN-SCOPE-TEST-99", content)
            finally:
                if Path(out_path).exists():
                    Path(out_path).unlink()
        finally:
            root.destroy()

    def test_full_scan_report_scope_and_disclosure(self):
        """Verify that Full Scan incident report accurately reflects depth=6 traversal and limitations."""
        import customtkinter as ctk
        from unittest.mock import patch
        import tempfile
        from gui.pages.dashboard import DashboardPage

        root = ctk.CTk()
        try:
            dashboard = DashboardPage(root, config={})
            sr = ScanResult(
                scan_type=ScanType.FULL,
                state=ScanState.COMPLETE,
                files_inspected=3200,
                directories_inspected=140,
                processes_analyzed=180,
                threat_level="SAFE"
            )
            sr.scan_id = "SCN-FULL-TEST-88"
            sr.is_simulation = False
            sr.ml_probability = 0.12
            sr.ml_executed = True

            with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tf:
                out_path = tf.name

            try:
                with patch("tkinter.filedialog.asksaveasfilename", return_value=out_path), \
                     patch("tkinter.messagebox.askyesno", return_value=False):
                    dashboard._do_generate_report(target_result=sr)

                with open(out_path, "r", encoding="utf-8") as f:
                    content = f.read()

                self.assertIn("Scan Scope Mode     : Full System Scan (Deep: Target Depth = 6)", content)
                self.assertIn("Coverage Definition : Monitored root directories plus User Home Root Directory", content)
                self.assertIn("Excluded Folders    : Noise/build directories", content)
                self.assertIn("Coverage Limitation : Depth=6 audits nested subfolders", content)
                self.assertIn("SCN-FULL-TEST-88", content)
            finally:
                if Path(out_path).exists():
                    Path(out_path).unlink()
        finally:
            root.destroy()

    def test_cancel_button_state_lifecycle(self):
        """Verify that Cancel button is disabled initially, enabled during scan, and disabled on cancel/complete/error."""
        import customtkinter as ctk
        from gui.pages.dashboard import DashboardPage

        root = ctk.CTk()
        try:
            dashboard = DashboardPage(root, config={})
            # 1. At startup (idle / ready to scan)
            self.assertEqual(dashboard._cancel_scan_btn.cget("state"), "disabled")

            # 2. Simulate scan starting
            dashboard._scanning = True
            dashboard._cancel_scan_btn.configure(text="✕ Cancel", state="normal")
            self.assertEqual(dashboard._cancel_scan_btn.cget("state"), "normal")

            # 3. Simulate cancel requested
            dashboard.cancel_scan()
            self.assertEqual(dashboard._cancel_scan_btn.cget("state"), "disabled")
            self.assertIn("Cancelling", dashboard._cancel_scan_btn.cget("text"))

            # 4. On scan cancelled
            sr_cancel = ScanResult(scan_type=ScanType.QUICK, state=ScanState.SCAN_INCOMPLETE, cancelled=True)
            dashboard._on_scan_cancelled(sr_cancel)
            self.assertEqual(dashboard._cancel_scan_btn.cget("state"), "disabled")
            self.assertEqual(dashboard._cancel_scan_btn.cget("text"), "✕ Cancel")

            # 5. On scan complete
            dashboard._cancel_scan_btn.configure(state="normal")
            sr_ok = ScanResult(scan_type=ScanType.QUICK, state=ScanState.COMPLETE, threat_level="SAFE")
            dashboard._on_scan_complete("SAFE", 0.05, sr_ok, is_simulation=False)
            self.assertEqual(dashboard._cancel_scan_btn.cget("state"), "disabled")

            # 6. On scan error
            dashboard._cancel_scan_btn.configure(state="normal")
            dashboard._on_scan_error("I/O error", sr_ok)
            self.assertEqual(dashboard._cancel_scan_btn.cget("state"), "disabled")
        finally:
            root.destroy()

    def test_scan_origin_and_evidence_separation(self):
        """Verify explicit scan_origin distinction between live host scans and sandbox simulations."""
        import tempfile
        import time
        import shutil
        from unittest.mock import patch
        import customtkinter as ctk
        from gui.pages.dashboard import DashboardPage

        audit_dir = tempfile.mkdtemp(prefix="sentinel_audit_")
        root = ctk.CTk()
        try:
            dashboard = DashboardPage(
                root, config={"audit": {"path": str(Path(audit_dir) / "audit.json")}}
            )

            # Host scan result
            host_sr = ScanResult(
                scan_type=ScanType.QUICK,
                state=ScanState.SAFE,
                files_inspected=450,
                directories_inspected=25,
                processes_analyzed=110,
                threat_level="SAFE",
                scan_origin="LIVE_HOST_SCAN"
            )
            host_sr.scan_id = "SCN-HOST-01"
            host_sr.is_simulation = False

            # Simulation scan result
            sim_sr = ScanResult(
                scan_type=ScanType.CUSTOM,
                state=ScanState.COMPLETE,
                files_inspected=20,
                directories_inspected=1,
                processes_analyzed=110,
                threat_level="WARNING",
                scan_origin="CONTROLLED_SIMULATION"
            )
            sim_sr.scan_id = "SCN-SIM-01"
            sim_sr.is_simulation = True

            # Register both in history (a start must precede a real scan outcome)
            dashboard._scan_started = True
            dashboard._scan_started_at = time.time() - 0.5
            dashboard._on_scan_complete("SAFE", 0.02, host_sr, is_simulation=False)
            dashboard._scan_started = True
            dashboard._scan_started_at = time.time() - 0.5
            dashboard._on_scan_complete("WARNING", 0.65, sim_sr, is_simulation=True)

            self.assertEqual(dashboard._last_host_scan_result, host_sr)
            self.assertEqual(dashboard._last_sim_scan_result, sim_sr)
            self.assertEqual(dashboard._scan_history[0]["provenance"], "CONTROLLED_SIMULATION")
            self.assertEqual(dashboard._scan_history[1]["provenance"], "LIVE_HOST_SCAN")
            self.assertEqual(dashboard._scan_history[0]["classification"], "WARNING")
            self.assertEqual(dashboard._scan_history[1]["classification"], "SAFE")

            # Test report generation origin labeling
            with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tf:
                sim_rep = tf.name
            with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tf2:
                host_rep = tf2.name

            try:
                with patch("gui.pages.dashboard.filedialog.asksaveasfilename", return_value=sim_rep),                      patch("gui.pages.dashboard.messagebox.askyesno", return_value=False),                      patch("tkinter.filedialog.asksaveasfilename", return_value=sim_rep),                      patch("tkinter.messagebox.askyesno", return_value=False):
                    dashboard._do_generate_report(target_result=sim_sr)

                with patch("gui.pages.dashboard.filedialog.asksaveasfilename", return_value=host_rep),                      patch("gui.pages.dashboard.messagebox.askyesno", return_value=False),                      patch("tkinter.filedialog.asksaveasfilename", return_value=host_rep),                      patch("tkinter.messagebox.askyesno", return_value=False):
                    dashboard._do_generate_report(target_result=host_sr)

                with open(sim_rep, "r", encoding="utf-8") as f:
                    sim_content = f.read()
                with open(host_rep, "r", encoding="utf-8") as f:
                    host_content = f.read()

                self.assertIn("Scan Origin  : CONTROLLED_SIMULATION", sim_content)
                self.assertIn("Execution Mode: Controlled Sandbox Simulation", sim_content)
                self.assertIn("Scan Scope Mode     : Controlled Sandbox Simulation", sim_content)

                self.assertIn("Scan Origin  : LIVE_HOST_SCAN", host_content)
                self.assertIn("Execution Mode: Live Host Scan", host_content)
                self.assertIn("Scan Scope Mode     : Fast Live Scan (Quick: Target Depth = 1)", host_content)
            finally:
                Path(sim_rep).unlink(missing_ok=True)
                Path(host_rep).unlink(missing_ok=True)
        finally:
            root.destroy()
            shutil.rmtree(audit_dir, ignore_errors=True)

    def test_ransomware_page_dynamic_wrapping(self):
        """Verify that RansomwarePage initializes responsive wrap labels and resizes gracefully."""
        import customtkinter as ctk
        from gui.pages.ransomware import RansomwarePage

        root = ctk.CTk()
        try:
            page = RansomwarePage(root, config={})
            self.assertTrue(len(getattr(page, "_wrap_labels", [])) >= 8)
            page._on_resize()
            page.destroy()
        finally:
            root.destroy()


    def test_cancel_button_visual_dimming(self):
        """Verify Cancel button visual dimming across states (idle, scanning, cancelling)."""
        import customtkinter as ctk
        from gui.pages.dashboard import DashboardPage

        root = ctk.CTk()
        try:
            dashboard = DashboardPage(root, config={})
            # 1. Idle state
            self.assertEqual(dashboard._cancel_scan_btn.cget("state"), "disabled")
            self.assertEqual(dashboard._cancel_scan_btn.cget("border_color"), "#262c36")
            self.assertEqual(dashboard._cancel_scan_btn.cget("text"), "✕ Cancel")

            # 2. Scanning state
            dashboard._set_cancel_button_state("scanning")
            self.assertEqual(dashboard._cancel_scan_btn.cget("state"), "normal")
            self.assertEqual(dashboard._cancel_scan_btn.cget("border_color"), "#f85149")
            self.assertEqual(dashboard._cancel_scan_btn.cget("fg_color"), "#2b1a1a")

            # 3. Cancelling state
            dashboard._set_cancel_button_state("cancelling")
            self.assertEqual(dashboard._cancel_scan_btn.cget("state"), "disabled")
            self.assertEqual(dashboard._cancel_scan_btn.cget("text"), "Cancelling…")

            # 4. Return to idle
            dashboard._set_cancel_button_state("idle")
            self.assertEqual(dashboard._cancel_scan_btn.cget("state"), "disabled")
            self.assertEqual(dashboard._cancel_scan_btn.cget("border_color"), "#262c36")
        finally:
            root.destroy()

    def test_quick_scan_limited_status_display(self):
        """Verify Quick Scan (depth=1) with no threats displays honest LIMITED status."""
        import customtkinter as ctk
        from gui.pages.dashboard import DashboardPage

        root = ctk.CTk()
        try:
            dashboard = DashboardPage(root, config={})
            quick_sr = ScanResult(
                scan_type=ScanType.QUICK,
                state=ScanState.COMPLETE,
                files_inspected=120,
                directories_inspected=5,
                processes_analyzed=80,
                threat_level="SAFE"
            )
            quick_sr.scan_id = "SCN-QUICK-TEST-01"
            dashboard._last_scan_result = quick_sr

            dashboard.update_threat_status("SAFE", probability=0.03, is_simulation=False)
            self.assertEqual(dashboard._status_title.cget("text"), "NO THREATS DETECTED — LIMITED SCAN")
            self.assertIn("LIMITED", dashboard._status_badge.cget("text"))
            self.assertEqual(dashboard._risk_level_label.cget("text"), "CLEAN (LIMITED)")
            self.assertIn("Quick Scan (depth=1) clean", dashboard._status_desc.cget("text"))
            self.assertIn("Synthetic baseline ML model", dashboard._status_desc.cget("text"))
        finally:
            root.destroy()

    def test_sentinel_ai_status_on_failure_and_timeout(self):
        """Verify SentinelAI updates copilot status to TIMEOUT/OFFLINE on network failure."""
        from ai.sentinel_ai import SentinelAI
        from unittest.mock import MagicMock

        ai = SentinelAI({"enabled": True})
        ai.status = "READY"
        mock_provider = MagicMock()
        ai.provider = mock_provider

        # Simulate timeout in provider
        mock_provider.generate.return_value = (False, "Request timed out after 30 seconds.")
        ans = ai.ask("Test timeout prompt")
        self.assertIn("unavailable", ans.lower())
        self.assertEqual(ai.status, "TIMEOUT")
        self.assertIn("timeout", ai.status_detail.lower())

        # Simulate connection error
        mock_provider.generate.return_value = (False, "Unable to reach server. Connection refused.")
        ans = ai.ask("Test connection prompt")
        self.assertIn("unavailable", ans.lower())
        self.assertEqual(ai.status, "OFFLINE")


    def test_unified_classification_across_all_views(self):
        """Verify the exact same ScanResult (45% score, Quick Scan) yields identical status in Dashboard, Threat Log, and Reports."""
        import customtkinter as ctk
        from gui.pages.dashboard import DashboardPage
        from gui.pages.threats import ThreatsPage

        sr = ScanResult(
            scan_type=ScanType.QUICK,
            state=ScanState.SAFE,
            files_inspected=88,
            directories_inspected=4,
            processes_analyzed=112,
            threat_level="SAFE"
        )
        sr.ml_probability = 0.45
        sr.scan_id = "SCN-UNIFIED-45-TEST"

        # 1. Authoritative ScanResult method
        classification = sr.get_unified_classification()
        self.assertEqual(classification["tag"], "NO THREATS DETECTED — LIMITED SCAN")
        self.assertEqual(classification["status_title"], "NO THREATS DETECTED — LIMITED SCAN")
        self.assertTrue(classification["is_borderline"])
        self.assertIn("45.0%", classification["borderline_note"])

        # 2. Check Dashboard display
        root = ctk.CTk()
        try:
            dashboard = DashboardPage(root, config={})
            dashboard._last_scan_result = sr
            dashboard.update_threat_status("SAFE", probability=0.45, is_simulation=False)
            self.assertEqual(dashboard._status_title.cget("text"), "NO THREATS DETECTED — LIMITED SCAN")
            self.assertIn("LIMITED", dashboard._status_badge.cget("text"))

            # 3. Check ThreatsPage display with same result
            threats = ThreatsPage(root, config={})
            threats._build_report(sr)
            # Find the threat level label in threats page
            lvl_labels = [w for w in threats.content_frame.winfo_children() if isinstance(w, ctk.CTkFrame)]
            # Verify threats report does NOT say [SAFE]
            threat_texts = []
            def collect_texts(widget):
                if hasattr(widget, "cget"):
                    try:
                        t = widget.cget("text")
                        if t:
                            threat_texts.append(t)
                    except Exception:
                        pass
                for c in widget.winfo_children():
                    collect_texts(c)
            collect_texts(threats.content_frame)

            self.assertIn("[NO THREATS DETECTED — LIMITED SCAN]", threat_texts)
            self.assertNotIn("[SAFE]", threat_texts, "Threat Log must NOT display [SAFE] for a limited Quick Scan")

            # 4. Check Report text generation uses identical tag
            import tempfile
            from unittest.mock import patch
            with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tf:
                rep_path = tf.name
            try:
                with patch("gui.pages.dashboard.filedialog.asksaveasfilename", return_value=rep_path), \
                     patch("gui.pages.dashboard.messagebox.askyesno", return_value=False), \
                     patch("tkinter.filedialog.asksaveasfilename", return_value=rep_path), \
                     patch("tkinter.messagebox.askyesno", return_value=False):
                    dashboard._do_generate_report(target_result=sr)

                with open(rep_path, "r", encoding="utf-8") as f:
                    rep_content = f.read()

                self.assertIn("Threat Level        : NO THREATS DETECTED — LIMITED SCAN", rep_content)
                self.assertIn("Borderline Notice", rep_content)
            finally:
                Path(rep_path).unlink(missing_ok=True)
        finally:
            root.destroy()

    def test_ransomware_page_no_text_clipping_and_responsive(self):
        """Verify RansomwarePage labels have anchor='w' and safe wrapping bounds."""
        import customtkinter as ctk
        from gui.pages.ransomware import RansomwarePage

        root = ctk.CTk()
        try:
            root.geometry("1366x768")
            page = RansomwarePage(root, config={})
            page.grid(row=0, column=0, sticky="nsew")
            root.update_idletasks()
            for lbl in page._wrap_labels:
                # Every wrapping label must anchor west to prevent left edge clipping
                self.assertEqual(lbl.cget("anchor"), "w")
                self.assertLessEqual(lbl.cget("wraplength"), 450)
            page._on_resize()
            self.assertTrue(hasattr(page, "_last_wrap_w"))
        finally:
            root.destroy()

    def test_page_transition_and_prewarming(self):
        """Verify MainWindow page transition keeps existing page visible and prewarms cleanly."""
        from gui.main_window import MainWindow

        app = MainWindow()
        try:
            app.update_idletasks()
            # Dashboard is initially active
            self.assertEqual(app._current_page, "dashboard")
            dash = app._pages["dashboard"]
            self.assertEqual(dash.winfo_manager(), "grid")

            # Switch to threats
            app._show_page("threats")
            self.assertEqual(app._current_page, "threats")
            self.assertIn("threats", app._pages)

            # Switch to ransomware
            app._show_page("ransomware")
            self.assertEqual(app._current_page, "ransomware")
            self.assertIn("ransomware", app._pages)

            # Repeated transitions do not recreate frames
            threats_frame = app._pages["threats"]
            app._show_page("threats")
            self.assertIs(app._pages["threats"], threats_frame)
        finally:
            app.destroy()

    def test_startup_animation_layering_and_cleanup(self):
        """Verify startup animation layers cleanly without 'wrong # args' error and destroys canvas on cleanup."""
        import tkinter as tk
        from gui.main_window import MainWindow
        from gui.startup_animation import show_startup_animation_inline

        app = MainWindow()
        try:
            app.update_idletasks()
            anim_canvas = show_startup_animation_inline(app, duration=5000)
            self.assertIsNotNone(anim_canvas)
            self.assertTrue(anim_canvas.winfo_exists())
            self.assertEqual(anim_canvas.winfo_manager(), "place")

            # Calling cleanup removes the canvas completely and restores dashboard
            anim_canvas._cleanup()
            app.update_idletasks()
            self.assertFalse(anim_canvas.winfo_exists(), "Animation canvas must be destroyed after cleanup")

            # Verify dashboard and sidebar remain gridded
            dash = app._pages.get("dashboard")
            self.assertIsNotNone(dash)
            self.assertEqual(dash.winfo_manager(), "grid")
            self.assertEqual(app._sidebar.winfo_manager(), "grid")
        finally:
            app.destroy()

    def test_safe_ransomware_demo_removed_from_normal_dashboard(self):
        """Verify Safe Ransomware Demo and Sandbox Cleanup buttons are removed from the visible UI."""
        import customtkinter as ctk
        from gui.pages.dashboard import DashboardPage
        root = ctk.CTk()
        try:
            dashboard = DashboardPage(root, config={})
            dashboard.grid(row=0, column=0, sticky="nsew")
            root.update_idletasks()

            # The visible scan action button must be Fast Live Scan
            self.assertEqual(dashboard._scan_btn.cget("text"), "⚡ Fast Live Scan")
            self.assertEqual(dashboard._evidence_btn.cget("text"), "📄 View Incident Report")

            # _sim_btn and _clean_btn are removed from normal user experience
            self.assertIsNone(dashboard._sim_btn)
            self.assertIsNone(dashboard._clean_btn)

            # Description should direct user to Fast Live Scan only
            desc_text = dashboard._status_desc.cget("text")
            self.assertNotIn("Safe Ransomware Demo", desc_text)
            self.assertNotIn("Safe Simulation", desc_text)
            self.assertIn("Fast Live Scan", desc_text)
        finally:
            dashboard.destroy()
            root.destroy()

    def test_dashboard_3d_core_live_state_transitions(self):
        """Verify 3D Sentinel Core canvas is present on Dashboard and reacts accurately to scan states."""
        import customtkinter as ctk
        from gui.pages.dashboard import DashboardPage
        root = ctk.CTk()
        try:
            dashboard = DashboardPage(root, config={})
            dashboard.grid(row=0, column=0, sticky="nsew")
            root.update_idletasks()

            self.assertTrue(hasattr(dashboard, "_core_3d"))
            core = dashboard._core_3d
            self.assertIsNotNone(core)

            # Initial state must be IDLE (never SAFE before scan)
            self.assertEqual(core.state, "IDLE")

            # Start scanning
            core.set_state("SCANNING")
            self.assertEqual(core.state, "SCANNING")

            # Telemetry progress updates
            core.update_progress(files=1420, procs=285, stage="FILESYSTEM")
            self.assertEqual(core.files_inspected, 1420)
            self.assertEqual(core.processes_analyzed, 285)

            # Completed with SAFE / NO THREATS
            core.set_state("SAFE", 0.15)
            self.assertEqual(core.state, "SAFE")
            self.assertAlmostEqual(core.risk_score, 0.15)

            # Cancellation
            core.set_state("SCAN_INCOMPLETE")
            self.assertEqual(core.state, "SCAN_INCOMPLETE")

            # Error
            core.set_state("ANALYSIS_ERROR")
            self.assertEqual(core.state, "ANALYSIS_ERROR")
        finally:
            dashboard.destroy()
            root.destroy()


    def test_model_output_contract_and_rejection(self):
        """Verify strict model contract: validates in [0, 1], rejects out-of-bounds/invalid values."""
        from ml.predictor import validate_model_probability, normalize_risk_score

        # Valid 0.0
        ok, p, err = validate_model_probability(0)
        self.assertTrue(ok)
        self.assertEqual(p, 0.0)

        # Valid 0.46
        ok, p, err = validate_model_probability(0.46)
        self.assertTrue(ok)
        self.assertAlmostEqual(p, 0.46)

        # Valid 1.0
        ok, p, err = validate_model_probability(1.0)
        self.assertTrue(ok)
        self.assertEqual(p, 1.0)

        # Rejection of 16.46 (Contract violation: outside [0.0, 1.0], no heuristic guessing)
        ok, p, err = validate_model_probability(16.46)
        self.assertFalse(ok)
        self.assertIn("violates model contract bounds", err)

        # Rejection of None (Missing value)
        ok, p, err = validate_model_probability(None)
        self.assertFalse(ok)
        self.assertIn("Missing", err)

        # Rejection of NaN / Inf (Non-finite values)
        ok, p, err = validate_model_probability(float("nan"))
        self.assertFalse(ok)
        self.assertIn("Non-finite", err)

        ok, p, err = validate_model_probability(float("inf"))
        self.assertFalse(ok)
        self.assertIn("Non-finite", err)

        # Rejection of non-numeric string
        ok, p, err = validate_model_probability("invalid_str")
        self.assertFalse(ok)
        self.assertIn("Non-numeric", err)

    def test_repeated_dashboard_create_update_destroy_lifecycle(self):
        """Verify repeatedly creating, updating, and destroying dashboard cancels timers and drops worker dispatches."""
        import customtkinter as ctk
        from gui.pages.dashboard import DashboardPage

        for cycle in range(5):
            root = ctk.CTk()
            dashboard = DashboardPage(root, config={})
            dashboard.grid(row=0, column=0, sticky="nsew")
            root.update_idletasks()

            # Trigger an update
            dashboard.update_threat_status("SAFE", probability=0.25)
            self.assertEqual(dashboard._risk_score_label.cget("text"), "25%")

            # Now destroy dashboard
            dashboard.destroy()
            try:
                for aid in root.tk.eval("after info").split():
                    try:
                        root.after_cancel(aid)
                    except Exception:
                        pass
            except Exception:
                pass
            root.destroy()

            # Ensure worker thread dispatch after destruction is safely dropped
            dashboard._dispatch_to_main(lambda: None)
            self.assertTrue(dashboard._is_destroyed)
            self.assertEqual(len(dashboard._pending_after_ids), 0)

    def test_scan_completion_independent_of_risk_score(self):
        """Verify scan completion percent (100%) is completely independent of ML risk score."""
        import customtkinter as ctk
        from gui.pages.dashboard import DashboardPage

        root = ctk.CTk()
        try:
            dashboard = DashboardPage(root, config={})
            dashboard.grid(row=0, column=0, sticky="nsew")
            root.update_idletasks()

            # When scan completes, completion must be 100% regardless of risk score
            dashboard.update_threat_status("SAFE", probability=0.1646)
            dashboard._on_scan_complete("SAFE", 0.1646)

            # Risk score must be 16% (never 1646%)
            self.assertEqual(dashboard._risk_score_label.cget("text"), "16%")
            self.assertAlmostEqual(dashboard._risk_score, 0.1646, places=4)

            # Scan completion must be 100%
            self.assertEqual(dashboard._scan_completion_percent, 100)
            self.assertEqual(dashboard._scan_progress.get(), 1.0)
            self.assertIn("100%", dashboard._stage_badge.cget("text"))

            # If an invalid contract value like 16.46 is passed, reports ANALYSIS_ERROR
            dashboard.update_threat_status("SAFE", probability=16.46)
            self.assertEqual(dashboard._risk_score_label.cget("text"), "ERR")
            self.assertEqual(dashboard._threat_level, "ANALYSIS_ERROR")
            self.assertEqual(dashboard._scan_completion_percent, 100)
        finally:
            dashboard.destroy()
            root.destroy()

    def test_incident_evidence_dialog_bounds(self):
        """Verify Incident Evidence dialog initial dimensions are bounded relative to screen."""
        import customtkinter as ctk
        from gui.pages.dashboard import DashboardPage
        from scanner.scan_engine import ScanResult, ScanType, ScanState

        root = ctk.CTk()
        try:
            dashboard = DashboardPage(root, config={})
            dashboard.grid(row=0, column=0, sticky="nsew")
            root.update_idletasks()

            res = ScanResult(
                scan_id="test_scan_bounds",
                scan_type=ScanType.QUICK,
                state=ScanState.SAFE,
                threat_level="SAFE",
                ml_probability=0.1646,
                files_inspected=100,
                processes_analyzed=50,
                elapsed_seconds=1.2
            )

            dlg = dashboard._open_evidence_dialog(res, is_sim_override=False)
            self.assertIsNotNone(dlg)

            screen_w = dlg.winfo_screenwidth()
            screen_h = dlg.winfo_screenheight()

            # Verify geometry string
            geom = dlg.geometry()
            import re
            m = re.match(r"(\d+)x(\d+)\+(\d+)\+(\d+)", geom)
            self.assertIsNotNone(m)
            w, h = int(m.group(1)), int(m.group(2))

            self.assertLessEqual(w, min(900, screen_w))
            self.assertLessEqual(h, min(650, screen_h))

            dlg.destroy()
        finally:
            dashboard.destroy()
            root.destroy()


if __name__ == "__main__":
    unittest.main()
