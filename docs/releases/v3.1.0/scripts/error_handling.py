"""Controlled failure scenarios for the Kali demo audit.

Uses mocks and a NaN feature vector only. The real model files are never
modified, deleted, or replaced.
"""
import json
import sys
from pathlib import Path
from unittest.mock import patch

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from scanner.scan_engine import ScanEngine, ScanType

FEATURES = np.zeros((1, 19), dtype=float)
AVAILABLE = {f"feature_{i}": "AVAILABLE" for i in range(19)}
MISSING = dict(AVAILABLE)
for i in range(5):
    MISSING[f"feature_{i}"] = "UNAVAILABLE_SENSOR"
STATS = {"processes_scanned": 50, "errors": 0}
FIELDS = ["state", "threat_level", "ml_executed", "ml_probability",
          "ml_prediction", "is_inconclusive", "inconclusive_reason",
          "error_message", "filesystem_errors", "process_errors"]


def _report(label, result, extra=None):
    payload = {}
    for name in FIELDS:
        if hasattr(result, name):
            value = getattr(result, name)
            payload[name] = value.value if hasattr(value, "value") else value
    if extra:
        payload.update(extra)
    print(f"===== {label} =====")
    print(json.dumps(payload, default=str, indent=2, sort_keys=True))


def _process_patches(engine, features=FEATURES, availability=AVAILABLE):
    return [
        patch.object(engine._process_scanner, "scan_system", return_value=features),
        patch.object(engine._process_scanner, "get_scan_stats", return_value=dict(STATS)),
        patch.object(engine._process_scanner, "get_feature_availability", return_value=availability),
    ]


def scenario_process_failure():
    engine = ScanEngine()
    with patch.object(engine._process_scanner, "scan_system", return_value=None):
        result = engine.scan(ScanType.PROCESS, scan_origin="DEMO_FIXTURE")
    _report("A. PROCESS EXTRACTION FAILURE", result)


def scenario_model_load_failure():
    engine = ScanEngine()
    patches = _process_patches(engine)
    with patches[0], patches[1], patches[2], \
         patch("ml.predictor.MLPredictor.load_model", return_value=False):
        result = engine.scan(ScanType.PROCESS, scan_origin="DEMO_FIXTURE")
    _report("B. ML MODEL LOADING FAILURE", result)


def scenario_invalid_features():
    engine = ScanEngine()
    patches = _process_patches(engine, features=np.full((1, 19), np.nan))
    with patches[0], patches[1], patches[2]:
        result = engine.scan(ScanType.PROCESS, scan_origin="DEMO_FIXTURE")
    _report("C. INVALID FEATURE VECTOR (NaN)", result)


def scenario_missing_sensors():
    engine = ScanEngine()
    patches = _process_patches(engine, availability=MISSING)
    with patches[0], patches[1], patches[2], \
         patch.object(engine, "_determine_scan_paths", return_value=[Path("/tmp")]), \
         patch.object(engine, "_scan_filesystem", return_value=True), \
         patch("ml.predictor.MLPredictor.load_model", return_value=True), \
         patch("ml.predictor.MLPredictor.predict", return_value=("SAFE", 0.12)):
        result = engine.scan(ScanType.QUICK, scan_origin="LIVE_HOST_SCAN")
    _report("D. MISSING SENSOR DATA (QUICK, LINUX)", result,
            extra={"available_feature_count": getattr(result, "available_feature_count", None)})


def scenario_ml_exception():
    engine = ScanEngine()
    patches = _process_patches(engine)
    with patches[0], patches[1], patches[2], \
         patch("ml.predictor.MLPredictor.load_model", return_value=True), \
         patch("ml.predictor.MLPredictor.predict", side_effect=RuntimeError("simulated inference failure")):
        result = engine.scan(ScanType.PROCESS, scan_origin="DEMO_FIXTURE")
    _report("E. ML EXCEPTION (INCOMPLETE ANALYSIS)", result)


if __name__ == "__main__":
    scenario_process_failure()
    scenario_model_load_failure()
    scenario_invalid_features()
    scenario_missing_sensors()
    scenario_ml_exception()
