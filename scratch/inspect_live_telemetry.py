import sys
from pathlib import Path
import json

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scanner.live_scanner import LiveScanner, FEATURE_NAMES
from ml.predictor import MLPredictor

scanner = LiveScanner()
feat_arr = scanner.scan_system()
stats = scanner.get_scan_stats()
feat_vals = stats.get("feature_values", {})

predictor = MLPredictor()
predictor.load_model()
pred = predictor.predict(feat_arr)

print("=== LIVE TELEMETRY ON CURRENT MACHINE ===")
for i, name in enumerate(FEATURE_NAMES):
    print(f"[{i:02d}] {name:30s} = {feat_vals.get(name, 0.0)}")

print("\n=== LIVE SCAN INFERENCE ===")
print("Prediction:", pred)
print("Duration:", stats.get("duration"), "seconds")
print("Processes scanned:", stats.get("processes_scanned"))
print("Errors encountered:", stats.get("errors"))
