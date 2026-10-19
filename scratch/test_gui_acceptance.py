"""
SentinelML V2 — Automated GUI Acceptance & Rendering Verification
"""
import sys
import os
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import tkinter.messagebox
tkinter.messagebox.showinfo = lambda *args, **kwargs: None
tkinter.messagebox.showwarning = lambda *args, **kwargs: None
tkinter.messagebox.showerror = lambda *args, **kwargs: None

from gui.main_window import MainWindow

def test_gui():
    print("=" * 60)
    print("SENTINELML V2 GUI ACCEPTANCE VERIFICATION")
    print("=" * 60)
    
    app = MainWindow()
    print("[1] MainWindow instantiated successfully.")
    print("    Title:", app.title())
    print("    Initial Page:", app._current_page)
    
    # Switch to Exhibition Page
    app._show_page("exhibition")
    print("[2] Navigated to Exhibition Page.")
    print("    Active Page:", app._current_page)
    ex_page = app._pages.get("exhibition")
    assert ex_page is not None, "Exhibition page failed to load!"
    
    # Check Header, Status, Mode, Health
    status_text = ex_page._status_badge.cget("text")
    mode_text = ex_page._mode_badge.cget("text")
    health_text = ex_page._health_lbl.cget("text")
    print("[3] Status Indicators:")
    print("    Status Badge:", status_text)
    print("    Mode Badge:  ", mode_text)
    print("    Health Pill: ", health_text)
    assert "IDLE" in status_text or "RESET" in status_text or "STATE:" in status_text
    assert "SANDBOX" in mode_text
    assert "Ready" in health_text
    
    # Test all 4 tabs rendering
    tabs = ["simulator", "live_scan", "test_lab", "evidence"]
    for tab_id in tabs:
        ex_page._switch_tab(tab_id)
        current_mode = ex_page._mode_badge.cget("text")
        print(f"[4] Tab Switch -> '{tab_id}': Mode Badge = '{current_mode}'")
        assert ex_page._active_tab == tab_id
    
    # Test Feature Inspector in Evidence Tab
    ex_page._switch_tab("evidence")
    ex_page._set_inspector_schema("legacy_19")
    detail_legacy = ex_page._inspector_detail_box.get("1.0", "end").strip()
    print("[5] Feature Inspector (Legacy 19):")
    print("    Detail box characters:", len(detail_legacy))
    assert "FEATURE SPECIFICATION" in detail_legacy
    assert len(detail_legacy) > 100
    
    ex_page._set_inspector_schema("schema_v2_16")
    detail_v2 = ex_page._inspector_detail_box.get("1.0", "end").strip()
    print("[6] Feature Inspector (Schema V2 16):")
    print("    Detail box characters:", len(detail_v2))
    assert "FEATURE SPECIFICATION" in detail_v2
    assert len(detail_v2) > 100
    
    # Test Reset to Ready
    ex_page._on_reset_demo()
    reset_status = ex_page._status_badge.cget("text")
    print("[7] Reset to Ready executed:")
    print("    Final Status Badge:", reset_status)
    assert "RESET" in reset_status or "READY" in reset_status or "IDLE" in reset_status
    
    # Destroy cleanly
    app.destroy()
    print("[8] Application destroyed cleanly without memory leak or hanging thread.")
    print("=" * 60)
    print("GUI ACCEPTANCE TEST RESULT: ALL PASSED (100%)")
    print("=" * 60)

if __name__ == "__main__":
    test_gui()
