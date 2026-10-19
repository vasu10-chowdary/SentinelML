import sys
sys.path.insert(0, '.')

from ai.sentinel_ai import SentinelAI
from scanner.scan_engine import ScanResult, ScanType, ScanState
from config import load as load_config

import numpy as np

# Create mock scan result
scan_result = ScanResult(ScanType.QUICK, ScanState.SAFE)
scan_result.threat_level = "SAFE"
scan_result.ml_executed = True
scan_result.ml_probability = 0.44
scan_result.files_inspected = 1913
scan_result.directories_inspected = 279
scan_result.processes_analyzed = 27

# Create mock 19-feature vector (approximate)
features = [27, 0, 5.98, 7.95, 51, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
scan_result._features = np.array([features])

cfg = load_config()
ai = SentinelAI(config=cfg.get("ai", {}))
# Force enable
ai.enabled = True
ai.initialize()

print("Status:", ai.status)

response = ai.explain_scan(scan_result)
print("\n--- RESPONSE ---")
print(response)

# Test empty scan
print("\n--- EMPTY SCAN RESPONSE ---")
print(ai.ask("Explain my latest scan", None))
