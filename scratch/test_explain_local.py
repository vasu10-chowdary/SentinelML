import sys
sys.path.insert(0, '.')

from ai.sentinel_ai import SentinelAI
from scanner.scan_engine import ScanResult, ScanType, ScanState
import numpy as np

# Create mock scan result
scan_result = ScanResult(ScanType.QUICK, ScanState.SAFE)
scan_result.threat_level = "SAFE"
scan_result.ml_executed = True
scan_result.ml_probability = 0.44
scan_result.files_inspected = 10913
scan_result.directories_inspected = 280
scan_result.processes_analyzed = 28

# Create mock 19-feature vector (approximate)
features = [28, 0, 5.98, 7.95, 51, 0, 0, 0, 9, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]
scan_result._features = np.array([features])

ai = SentinelAI(config={"enabled": True, "mode": "backend", "backend_url": "http://127.0.0.1:8000"})
ai.enabled = True
ai.initialize()

print("Status:", ai.status)

print("--- GENERIC QUESTION ---")
print(ai.ask("What is ransomware?", None))

print("\n--- EXPLAIN SCAN ---")
print(ai.explain_scan(scan_result))

print("\n--- LARGE CONTEXT (Simulated) ---")
print(ai.ask("Analyze my latest scan and explain the important indicators.", scan_result))

print("\n--- EMPTY SCAN ---")
print(ai.ask("Explain my latest scan", None))

print("\n--- UNICODE ---")
print(ai.ask("Explain ransomware's impact — especially why paying a ransom does not guarantee recovery.", None))
