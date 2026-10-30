import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from scanner.scan_engine import ScanEngine, ScanType

FIXTURE = Path.home() / "sentinelml_demo_fixture"
FIXTURE.mkdir(parents=True, exist_ok=True)
(FIXTURE / "notes.txt").write_text("harmless demo notes\n" * 20, encoding="utf-8")
(FIXTURE / "data.bin").write_bytes(bytes(range(256)) * 64)
(FIXTURE / "hello.sh").write_text("#!/bin/sh\necho harmless-demo\n", encoding="utf-8")

FIELDS = [
    "scan_id", "scan_type", "state", "threat_level", "scan_origin",
    "files_inspected", "directories_inspected", "files_skipped",
    "access_denied", "filesystem_errors", "suspicious_files",
    "processes_analyzed", "process_errors",
    "ml_executed", "ml_probability", "ml_prediction",
    "model_source", "is_inconclusive", "inconclusive_reason",
    "error_message", "elapsed_seconds", "phase_timings",
]

def run(label, scan_type, paths=None):
    result = ScanEngine().scan(scan_type, custom_paths=paths, scan_origin="DEMO_FIXTURE")
    payload = {}
    for name in FIELDS:
        if hasattr(result, name):
            value = getattr(result, name)
            payload[name] = value.value if hasattr(value, "value") else value
    print(f"===== {label} =====")
    print(json.dumps(payload, default=str, indent=2, sort_keys=True))

run("FILESYSTEM CUSTOM SCAN (harmless fixture)", ScanType.CUSTOM, [FIXTURE])
run("PROCESS-ONLY SCAN (live host)", ScanType.PROCESS)
