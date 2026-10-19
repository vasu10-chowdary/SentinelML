import sys
import time
sys.path.insert(0, '.')

from ai.sentinel_ai import SentinelAI
from scanner.scan_engine import ScanResult, ScanType, ScanState
import numpy as np
from config import load as load_config

cfg = load_config()
ai = SentinelAI(config=cfg.get("ai", {}))
ai.enabled = True
ai.initialize()

print("--- 1. Generic AI ---")
print(ai.ask("What is ransomware?", None))
time.sleep(2)

print("\n--- 2. Explain Latest Scan ---")
scan_result = ScanResult(ScanType.QUICK, ScanState.SAFE)
scan_result.threat_level = "SAFE"
scan_result.ml_executed = True
scan_result.ml_probability = 0.44
scan_result.files_inspected = 10913
scan_result.directories_inspected = 280
scan_result.processes_analyzed = 28
features = [28, 0, 5.98, 7.95, 51, 0, 0, 0, 9, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]
scan_result._features = np.array([features])
scan_result.elapsed_seconds = 1.2

print(ai.ask("Explain my latest scan", scan_result))
time.sleep(2)

print("\n--- 3. High Entropy Question ---")
print(ai.ask("What does high entropy mean in ransomware detection?", None))
time.sleep(2)

print("\n--- 4. Empty Scan (Restart) ---")
ai2 = SentinelAI(config=cfg.get("ai", {}))
ai2.enabled = True
ai2.initialize()
print(ai2.ask("Explain my latest scan", None))
