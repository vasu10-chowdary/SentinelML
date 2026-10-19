import sys, os
from pathlib import Path
sys.path.insert(0, '.')

from scanner.scan_engine import ScanEngine, ScanType, ScanState

engine = ScanEngine()
result = engine.scan(ScanType.QUICK)

print("Scan State:", result.state)
print("Files Inspected:", result.files_inspected)
print("Directories Inspected:", result.directories_inspected)
print("Processes Inspected:", result.processes_analyzed)
if getattr(result, 'ml_executed', False):
    print("ML Probability:", result.ml_probability)
    features = getattr(result, '_features', None)
    if features is not None:
        f_list = features[0].tolist()
        print("Average Entropy:", f_list[2])
        print("Max Entropy:", f_list[3])
        print("High Entropy Regions:", f_list[4])
