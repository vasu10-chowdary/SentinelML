import sys, time
sys.path.insert(0, '.')
from scanner.scan_engine import ScanEngine, ScanType

print("START RAW SCAN ENGINE")
engine = ScanEngine()

t0 = time.time()
print("START", t0)
result = engine.scan(ScanType.QUICK, progress_callback=lambda r: None)
t1 = time.time()
print("END", t1)
print("ELAPSED", t1 - t0)

print("FILES", result.files_inspected)
print("DIRECTORIES", result.directories_inspected)
print("PROCESSES", result.processes_analyzed)
print("FEATURES", result._features if hasattr(result, '_features') else 'None')
print("PROBABILITY", result.ml_probability)
print("STATE", result.state.value)
