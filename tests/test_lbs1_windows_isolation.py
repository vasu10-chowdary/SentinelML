"""LBS-1 Stage B — prove the Windows pipeline is untouched and isolated."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np
import pytest

import lbs1_support as support

from ml import linux_schema as schema


def sha256_file(relative: str) -> str:
    return hashlib.sha256((PROJECT_ROOT / relative).read_bytes()).hexdigest()


@pytest.mark.parametrize("relative,expected", sorted(support.FROZEN_WINDOWS_HASHES.items()))
def test_frozen_windows_artifacts_are_byte_identical(relative, expected):
    assert sha256_file(relative) == expected


def test_windows_feature_names_unchanged():
    from ml.predictor import FEATURE_NAMES

    assert FEATURE_NAMES == support.FROZEN_WINDOWS_FEATURES
    assert len(FEATURE_NAMES) == 19
    assert FEATURE_NAMES != list(schema.LBS1_FEATURE_NAMES)


def test_windows_metrics_unchanged():
    metrics = json.loads((PROJECT_ROOT / "models" / "metrics.json").read_text(encoding="utf-8"))
    assert metrics["optimal_threshold"] == 0.9
    assert metrics["best_model"] == "Random Forest"
    assert metrics["Random Forest"]["accuracy"] == 0.9567


def test_windows_predictor_thresholds_and_benchmark_output_unchanged():
    from ml.predictor import MLPredictor

    predictor = MLPredictor()
    assert predictor.load_model() is True
    assert predictor.get_thresholds() == {"critical": 0.9, "warning": 0.5}
    assert predictor.get_model_info()["expected_features"] == 19

    zeros = predictor.predict(np.zeros((1, 19), dtype=float))
    ones = predictor.predict(np.ones((1, 19), dtype=float))
    assert zeros is not None and zeros[0] == "SAFE"
    assert zeros[1] == pytest.approx(0.3, abs=1e-9)
    assert ones is not None and ones[0] == "SAFE"
    assert ones[1] == pytest.approx(0.26, abs=1e-9)


def test_windows_predictor_has_no_linux_knowledge():
    source = (PROJECT_ROOT / "ml" / "predictor.py").read_text(encoding="utf-8").lower()
    for token in ("linux", "lbs-1", "lbs1", "linux_schema"):
        assert token not in source


PROJECT_LINUX_MODULE_PREFIXES = ("scanner.linux_", "ml.linux_")


def _project_linux_modules(module_names):
    return sorted(name for name in module_names if name.startswith(PROJECT_LINUX_MODULE_PREFIXES))


def test_windows_prediction_imports_no_linux_module_in_a_clean_interpreter():
    code = "import sys, ml.predictor;print('\\n'.join(sorted(sys.modules)))"
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    imported = [line for line in result.stdout.splitlines() if line]
    if sys.platform.startswith("win"):
        # Windows guarantee: the prediction path imports nothing Linux-specific at all.
        linux_named = sorted(name for name in imported if "linux" in name.lower())
        assert linux_named == [], f"Windows prediction path imported Linux modules: {linux_named}"
    else:
        # Linux stdlib and psutil legitimately expose linux-named platform modules
        # (_sysconfigdata__linux_*, psutil._pslinux, psutil._psutil_linux). The isolation
        # guarantee is that the Windows prediction path imports no LBS-1 Linux module.
        leaked = _project_linux_modules(imported)
        assert leaked == [], f"Windows prediction path imported LBS-1 Linux modules: {leaked}"


def test_project_linux_module_filter_flags_lbs1_modules():
    assert _project_linux_modules(
        [
            "scanner.linux_inotify",
            "scanner.linux_telemetry",
            "ml.linux_schema",
            "ml.predictor",
            "numpy",
        ]
    ) == ["ml.linux_schema", "scanner.linux_inotify", "scanner.linux_telemetry"]


def test_project_linux_module_filter_ignores_platform_runtime_names():
    platform_names = [
        "_sysconfigdata__linux_x86_64-linux-gnu",
        "psutil._pslinux",
        "psutil._psutil_linux",
        "ml.predictor",
        "scanner.scan_engine",
    ]
    assert _project_linux_modules(platform_names) == []


def test_scan_engine_has_no_lbs1_dispatch():
    source = (PROJECT_ROOT / "scanner" / "scan_engine.py").read_text(encoding="utf-8").lower()
    for token in ("linux_telemetry", "linux_schema", "linux_predictor", "lbs-1", "lbs1"):
        assert token not in source


def test_linux_modules_do_not_import_the_windows_predictor():
    files = sorted((PROJECT_ROOT / "ml").glob("linux_*.py"))
    files += sorted((PROJECT_ROOT / "scanner").glob("linux_*.py"))
    assert files
    for path in files:
        import_lines = [
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip().startswith(("import ", "from "))
        ]
        assert import_lines
        for line in import_lines:
            assert "predictor" not in line, f"{path.name} imports the Windows predictor: {line}"


def test_verifier_does_not_import_the_predictor():
    source = (PROJECT_ROOT / "tools" / "lbs1" / "verify_artifacts.py").read_text(encoding="utf-8")
    assert "linux_predictor" not in source
    assert "joblib" not in source


def test_linux_collector_still_refuses_non_linux():
    from scanner.linux_telemetry import LinuxCollectionUnsupported, collect_observation

    if sys.platform.startswith("linux"):
        pytest.skip("refusal is only observable on non-Linux hosts")
    with pytest.raises(LinuxCollectionUnsupported):
        collect_observation(targets=[str(PROJECT_ROOT)], window_seconds=1.0)
