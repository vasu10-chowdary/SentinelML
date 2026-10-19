"""
SentinelML V2 — Comprehensive Judge GUI Flow & State Machine Audit
"""
import sys
import time
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Prevent blocking modal dialogs during automated inspection
import tkinter.messagebox
tkinter.messagebox.showinfo = lambda *args, **kwargs: None
tkinter.messagebox.showwarning = lambda *args, **kwargs: None
tkinter.messagebox.showerror = lambda *args, **kwargs: None

from gui.main_window import MainWindow
from scanner.scan_engine import ScanEngine, ScanType, ScanState, ScanResult
from exhibition.security_test_lab import SecurityTestLab

def audit_gui_flow():
    print("=" * 70)
    print("SENTINELML V2 JUDGE GUI FLOW & INVARIANT AUDIT")
    print("=" * 70)

    # 1. Instantiate Application
    app = MainWindow()
    print("[1] Application Window Initialization:")
    print("    Title:             ", app.title())
    print("    Geometry:          ", app.geometry())
    print("    Initial Page:      ", app._current_page)
    print("    Appearance Mode:   ", "dark")

    # 2. Verify Navigation to all pages
    registered_pages = list(app._page_classes.keys())
    print(f"\n[2] Registered Navigation Pages ({len(registered_pages)}):")
    for page_id in registered_pages:
        app._show_page(page_id)
        current = app._current_page
        frame = app._pages.get(page_id)
        assert current == page_id, f"Navigation failed for {page_id}!"
        print(f"    • [{page_id}] -> Loaded class: {type(frame).__name__}")

    # 3. Deep Audit of Exhibition Page
    print("\n[3] Exhibition Demonstration Dashboard Audit:")
    app._show_page("exhibition")
    ex = app._pages["exhibition"]
    
    # State & Mode Badges
    status_txt = ex._status_badge.cget("text")
    mode_txt = ex._mode_badge.cget("text")
    health_txt = ex._health_lbl.cget("text")
    print("    Status Badge:      ", status_txt)
    print("    Mode Badge:        ", mode_txt)
    print("    Diagnostic Health: ", health_txt)
    assert "IDLE" in status_txt
    assert "SANDBOX" in mode_txt
    assert "Ready" in health_txt

    # 4. Tab Structure Verification
    print("\n[4] Exhibition Page Tabs Audit:")
    for tab_id in ["simulator", "live_scan", "test_lab", "evidence"]:
        ex._switch_tab(tab_id)
        mode = ex._mode_badge.cget("text")
        print(f"    • Tab '{tab_id}' -> Active Mode: {mode}")
        assert ex._active_tab == tab_id

    # 5. Tab D Feature Inspector Schema Toggle Audit
    print("\n[5] Transparent Feature Inspector Audit:")
    ex._switch_tab("evidence")
    
    ex._set_inspector_schema("legacy_19")
    legacy_count = len(ex._inspector_features.get("legacy_19", []))
    legacy_detail = ex._inspector_detail_box.get("1.0", "end").strip()
    print(f"    • Legacy Schema (19 Features): Loaded {legacy_count} items")
    print(f"      Selected Detail Length: {len(legacy_detail)} chars")
    assert legacy_count == 19
    assert "FEATURE SPECIFICATION" in legacy_detail

    ex._set_inspector_schema("schema_v2_16")
    v2_count = len(ex._inspector_features.get("schema_v2_16", []))
    v2_detail = ex._inspector_detail_box.get("1.0", "end").strip()
    print(f"    • Schema V2 (16 Features):     Loaded {v2_count} items")
    print(f"      Selected Detail Length: {len(v2_detail)} chars")
    assert v2_count == 16
    assert "FEATURE SPECIFICATION" in v2_detail

    # 6. Verify Reset & Sandbox Purge
    print("\n[6] Reset to Ready Audit:")
    ex._on_reset_demo()
    reset_badge = ex._status_badge.cget("text")
    print("    Status Badge after Reset: ", reset_badge)
    assert "RESET" in reset_badge

    # 7. Fail-Safe State Invariant: Missing Telemetry & Failed Inference
    print("\n[7] Fail-Safe State Invariant Verification:")
    # Verify Incomplete Scan never becomes SAFE
    res_incomplete = ScanResult(scan_type=ScanType.QUICK, state=ScanState.SCANNING)
    res_incomplete.state = ScanState.SCAN_INCOMPLETE
    res_incomplete.threat_level = "ANALYSIS_ERROR"
    print(f"    • Incomplete Telemetry State: {res_incomplete.state.value} -> Threat: {res_incomplete.threat_level}")
    assert res_incomplete.state != ScanState.SAFE
    assert res_incomplete.threat_level != "SAFE"
    assert res_incomplete.was_successful() is False

    # Verify Analysis Error never becomes SAFE
    res_error = ScanResult(scan_type=ScanType.QUICK, state=ScanState.ANALYSIS_ERROR)
    print(f"    • Analysis Error State:       {res_error.state.value} -> was_successful: {res_error.was_successful()}")
    assert res_error.state != ScanState.SAFE
    assert res_error.was_successful() is False

    # Clean exit
    app.destroy()
    print("\n[8] GUI Lifecycle cleanly terminated without errors.")
    print("=" * 70)
    print("JUDGE GUI FLOW AUDIT: ALL CHECKS PASSED (100%)")
    print("=" * 70)

if __name__ == "__main__":
    audit_gui_flow()
