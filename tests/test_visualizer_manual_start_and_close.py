"""
Regression Test Suite for SentinelML V2:
Manual Scan Start (IDLE state) & Persistent Top Bar Close Button Lifecycle.

Proves:
1. Opening the visualizer leaves it in IDLE and does not start the scan engine.
2. The Close button is present and invokes the safe return-to-dashboard path.
3. Clicking Start Live Scan starts one scan exactly once.
4. Repeated clicks cannot start duplicate scans.
5. Cancellation and closing do not leave orphaned workers or Tkinter callbacks.
6. Completed scans can be closed and reopened without automatically starting another scan.
"""

import unittest
import time
import threading
import customtkinter as ctk

from gui.pages.dashboard import DashboardPage
from gui.pages.scan_visualizer import ScanVisualizer
from scanner.scan_engine import ScanResult, ScanState, ScanType


class TestVisualizerManualStartAndClose(unittest.TestCase):

    def setUp(self):
        import tempfile
        from pathlib import Path

        self._audit_tmp = tempfile.mkdtemp(prefix="sentinel_audit_")
        self.root = ctk.CTk()
        self.root.withdraw()
        self.config = {
            "scan": {"auto_start": False},
            # Keep real scan audits out of the user's data directory.
            "audit": {"path": str(Path(self._audit_tmp) / "scan_audit_history.json")},
        }
        self.dashboard = DashboardPage(self.root, config=self.config)
        self.dashboard.place(relx=0, rely=0, relwidth=1, relheight=1)
        self.root.update_idletasks()

    def tearDown(self):
        try:
            if getattr(self.dashboard, "visualizer", None):
                self.dashboard._close_visualizer()
            self.dashboard.destroy()
            self.root.destroy()
        except Exception:
            pass
        import shutil

        shutil.rmtree(getattr(self, "_audit_tmp", ""), ignore_errors=True)

    def test_1_opening_visualizer_leaves_it_in_idle_and_no_scan_running(self):
        """1. Opening the visualizer leaves it in IDLE and does not start the scan engine."""
        self.dashboard._on_scan()
        self.root.update_idletasks()

        vis = self.dashboard.visualizer
        self.assertIsNotNone(vis, "Visualizer must be opened on _on_scan")
        self.assertTrue(vis.winfo_exists())

        # Verify IDLE state
        self.assertEqual(vis.scan_state_str, "IDLE")
        self.assertEqual(vis._bar_stage.cget("text"), "IDLE")
        self.assertEqual(vis._status_card_verdict.cget("text"), "READY TO SCAN")
        self.assertIn("Ready when you are", vis._status_card_desc.cget("text"))

        # Verify no scan is running on the dashboard or visualizer
        self.assertFalse(self.dashboard._scanning, "Dashboard _scanning must remain False in IDLE")
        self.assertFalse(vis._scan_in_flight, "Visualizer _scan_in_flight must remain False in IDLE")
        self.assertIsNone(self.dashboard._active_engine, "No ScanEngine should be running")

        # Verify Start Live Scan button is visible and enabled
        self.assertEqual(vis._start_scan_btn.cget("text"), "⚡ Start Live Scan")
        self.assertEqual(vis._start_scan_btn.cget("state"), "normal")
        self.assertEqual(vis._start_scan_btn.winfo_manager(), "pack")

        # Verify cancel button is hidden in IDLE
        self.assertEqual(vis._cancel_btn.winfo_manager(), "")

    def test_2_close_button_present_and_returns_safely(self):
        """2. The Close button is present in the top bar and returns safely to dashboard."""
        self.dashboard._on_scan()
        self.root.update_idletasks()

        vis = self.dashboard.visualizer
        self.assertIsNotNone(vis)

        # Check top bar close button exists and is packed
        self.assertTrue(hasattr(vis, "_top_close_btn"))
        self.assertEqual(vis._top_close_btn.winfo_manager(), "pack")
        self.assertIn("Back to Dashboard", vis._top_close_btn.cget("text"))

        # Click top close button in IDLE state -> should return immediately without dialog
        vis._handle_top_close()
        self.root.update()
        time.sleep(0.05)
        self.root.update()

        # Visualizer must be closed cleanly and dashboard must be visible
        self.assertIsNone(self.dashboard.visualizer, "Visualizer should be dismissed")
        self.assertFalse(self.dashboard._scanning)

    def test_3_start_live_scan_starts_exactly_one_scan(self):
        """3. Clicking Start Live Scan starts one scan exactly once."""
        self.dashboard._on_scan()
        self.root.update_idletasks()

        vis = self.dashboard.visualizer
        self.assertEqual(vis.scan_state_str, "IDLE")

        # Trigger manual start scan
        vis._handle_start_scan()
        self.root.update_idletasks()

        # Now it should be SCANNING
        self.assertTrue(self.dashboard._scanning, "Dashboard must enter scanning mode")
        self.assertTrue(vis._scan_in_flight, "Visualizer must record scan in-flight")
        self.assertEqual(vis.scan_state_str, "SCANNING")
        self.assertIn("SCANNING", vis._bar_stage.cget("text"))

        # Cancel button is now packed and enabled
        self.assertEqual(vis._cancel_btn.winfo_manager(), "pack")
        self.assertEqual(vis._cancel_btn.cget("state"), "normal")

        # Start button must be hidden during active scan
        self.assertEqual(vis._start_scan_btn.winfo_manager(), "")

        # Safely cancel scan to clean up thread
        self.dashboard.cancel_scan()
        time.sleep(0.1)
        self.root.update()

    def test_4_repeated_clicks_cannot_start_duplicate_scans(self):
        """4. Repeated clicks on Start Live Scan cannot start duplicate scans."""
        self.dashboard._on_scan()
        self.root.update_idletasks()

        vis = self.dashboard.visualizer

        # First click
        vis._handle_start_scan()
        self.root.update_idletasks()

        active_token_1 = self.dashboard._active_scan_token
        self.assertIsNotNone(active_token_1)

        # Second and third clicks while scanning
        vis._handle_start_scan()
        vis._handle_start_scan()
        self.root.update_idletasks()

        active_token_2 = self.dashboard._active_scan_token
        self.assertEqual(active_token_1, active_token_2, "Token must not change; duplicate scan must not start")

        # Clean up
        self.dashboard.cancel_scan()
        time.sleep(0.1)
        self.root.update()

    def test_5_cancellation_and_closing_clean_up_without_orphaned_workers(self):
        """5. Cancellation and closing do not leave orphaned workers or Tkinter callbacks."""
        self.dashboard._on_scan()
        self.root.update_idletasks()

        vis = self.dashboard.visualizer
        vis._handle_start_scan()
        self.root.update_idletasks()

        # Cancel the scan
        self.dashboard.cancel_scan()

        # Wait for cancellation callback dispatch
        timeout = time.time() + 3.0
        while self.dashboard._scanning and time.time() < timeout:
            self.root.update()
            time.sleep(0.05)

        self.assertFalse(self.dashboard._scanning, "Scan must stop after cancellation")

        # Close visualizer
        vis.close()
        self.root.update()
        time.sleep(0.05)
        self.root.update()

        # Ensure no pending animation callbacks on destroyed visualizer
        self.assertFalse(vis.running)
        self.assertTrue(vis._is_closing)
        self.assertIsNone(vis._anim_job)

    def test_6_completed_scans_can_be_closed_and_reopened_without_auto_start(self):
        """6. Completed scans can be closed and reopened without automatically starting another scan."""
        # Open visualizer
        self.dashboard._on_scan()
        self.root.update_idletasks()
        vis1 = self.dashboard.visualizer
        self.assertEqual(vis1.scan_state_str, "IDLE")

        # Complete a scan
        sr = ScanResult(scan_type=ScanType.QUICK, state=ScanState.SAFE)
        sr.threat_level = "SAFE"
        sr.ml_probability = 0.43
        sr.files_inspected = 40
        sr.processes_analyzed = 300
        vis1.on_complete("SAFE", 0.43, sr)
        self.root.update_idletasks()

        self.assertEqual(vis1.scan_state_str, "SAFE")
        self.assertEqual(vis1._cancel_btn.winfo_manager(), "", "Cancel button must not coexist with SAFE")

        # Close visualizer
        vis1._handle_top_close()
        self.root.update()
        time.sleep(0.05)
        self.root.update()
        self.assertIsNone(self.dashboard.visualizer)

        # Reopen visualizer by clicking Fast Live Scan again
        self.dashboard._on_scan()
        self.root.update_idletasks()

        vis2 = self.dashboard.visualizer
        self.assertIsNotNone(vis2)
        # MUST reopen in IDLE, NOT running another scan automatically!
        self.assertEqual(vis2.scan_state_str, "IDLE", "Reopening visualizer must be in IDLE state")
        self.assertFalse(self.dashboard._scanning, "Must not auto-start a scan upon reopening")
        self.assertEqual(vis2._start_scan_btn.cget("state"), "normal")


if __name__ == "__main__":
    unittest.main()
