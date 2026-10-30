"""LBS-1 Stage A — Windows import isolation and collector refusal."""

import importlib
import os
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest

LINUX_MODULES = [
    "scanner.linux_fs_types",
    "scanner.linux_inotify",
    "scanner.linux_entropy",
    "scanner.linux_processes",
    "scanner.linux_telemetry",
]


@pytest.mark.parametrize("module_name", LINUX_MODULES)
def test_import_is_side_effect_free(module_name):
    before = set(os.listdir(PROJECT_ROOT))
    module = importlib.import_module(module_name)
    importlib.reload(module)
    after = set(os.listdir(PROJECT_ROOT))
    assert before == after


def test_all_linux_modules_import_in_a_clean_interpreter(tmp_path):
    script = "import " + ", ".join(LINUX_MODULES)
    env = dict(os.environ)
    env["PYTHONPATH"] = str(PROJECT_ROOT)
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    assert list(tmp_path.iterdir()) == []


@pytest.mark.skipif(sys.platform.startswith("linux"), reason="refusal contract is for non-Linux hosts")
def test_collector_refuses_non_linux():
    from scanner.linux_telemetry import LinuxCollectionUnsupported, collect_observation

    with pytest.raises(LinuxCollectionUnsupported):
        collect_observation()


@pytest.mark.skipif(sys.platform.startswith("linux"), reason="refusal contract is for non-Linux hosts")
def test_watcher_refuses_non_linux():
    from scanner.linux_inotify import InotifyUnavailable, InotifyWatcher

    with pytest.raises(InotifyUnavailable):
        InotifyWatcher()


def test_process_snapshot_of_absent_procfs_is_empty_not_fabricated():
    from scanner.linux_processes import take_snapshot

    missing = PROJECT_ROOT / "__no_such_proc__"
    assert take_snapshot(str(missing)) == {}
