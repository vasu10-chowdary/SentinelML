import sys, os, time
sys.path.insert(0, '.')
import customtkinter as ctk
from gui.pages.dashboard import DashboardPage
from scanner.scan_engine import ScanType

print("Starting TEST C: Real Dashboard Fast Live Scan")

class DummyApp:
    def __init__(self):
        self.after_callbacks = []
        self._current_page = None

    def switch_page(self, page_name, **kwargs):
        print(f"SWITCH PAGE: {page_name} | args={kwargs}")

    def update_idletasks(self):
        pass

    def after(self, delay, callback, *args):
        # execute immediately instead of waiting
        callback(*args)

app = DummyApp()
root = ctk.CTk()
root.withdraw() # hide window

dashboard = DashboardPage(root, app)
print("Dashboard instantiated.")

# Mock the _update_scan_progress so it prints
orig_update = dashboard._update_scan_progress
def mock_update(result):
    print(f"Progress: {result.state.value} | Files: {result.files_inspected} | Dirs: {result.directories_inspected} | Procs: {result.processes_analyzed}")
    orig_update(result)
dashboard._update_scan_progress = mock_update

print("Starting scan...")
# This will spawn a thread
dashboard._on_scan()

# Wait for scan to finish
while dashboard._scan_thread and dashboard._scan_thread.is_alive():
    time.sleep(0.5)
    root.update()

# Finalize
dashboard._on_scan_complete()
root.update()

print("Scan finished.")
if dashboard._current_scan_result:
    res = dashboard._current_scan_result
    print(f"Final State: {res.state.value}")
    print(f"Threat Level: {res.threat_level}")
    print(f"ML Probability: {res.ml_probability}")
    print(f"Files Inspected: {res.files_inspected}")
    print(f"Processes Analyzed: {res.processes_analyzed}")
    print(f"Features Generated: {res._features if hasattr(res, '_features') else 'None'}")
    assert len(res._features.flatten()) == 19
else:
    print("No scan result found.")
