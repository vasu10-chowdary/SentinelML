# -*- mode: python ; coding: utf-8 -*-
"""
SentinelML V3 — Linux Production Build Specification (onedir)
=============================================================
Must be run on Linux; PyInstaller cannot cross-compile from Windows.

Build from the project root:
    pyinstaller --clean --noconfirm \
        --distpath dist_linux --workpath build_linux \
        packaging/linux/SentinelML_Linux.spec

Output: dist_linux/SentinelML/SentinelML (Linux ELF executable).
The Windows spec (SentinelML_Production.spec) is intentionally untouched.
"""

import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files

if sys.platform.startswith("win"):
    raise RuntimeError("SentinelML_Linux.spec must be run on Linux, not Windows.")

PROJECT_ROOT = Path(SPECPATH).resolve().parent.parent

datas = [
    (str(PROJECT_ROOT / "sentinel_icon.ico"), "."),
    (str(PROJECT_ROOT / "sentinel_icon.png"), "."),
    (str(PROJECT_ROOT / "models"), "models"),
    (str(PROJECT_ROOT / "constants.py"), "."),
    (str(PROJECT_ROOT / "config.py"), "."),
    (str(PROJECT_ROOT / "demo_data.py"), "."),
]
datas += collect_data_files("customtkinter")

hiddenimports = [
    # AI / SentinelAI
    "ai", "ai.provider", "ai.sentinel_ai",
    "requests", "urllib3", "certifi", "charset_normalizer", "idna",
    # Scikit-learn runtime pieces required by the Random Forest
    "sklearn.ensemble", "sklearn.ensemble._forest",
    "sklearn.tree", "sklearn.tree._tree",
    "sklearn.preprocessing",
    "sklearn.metrics._pairwise_distances_reduction._datasets_pair",
    "sklearn.metrics._pairwise_distances_reduction._middle_term_computer",
    "sklearn.utils._chunking",
    "sklearn.utils._param_validation",
    "sklearn.utils._typedefs",
    "sklearn.utils._heap",
    "sklearn.utils._sorting",
    "sklearn.utils._vector_sentinel",
    "sklearn.neighbors._partition_nodes",
    # SciPy pieces sklearn may touch while loading the persisted model
    "scipy", "scipy.special", "scipy.special._ufuncs",
    "scipy.sparse",
    "scipy.sparse.csgraph._flow",
    "scipy.sparse.csgraph._min_spanning_tree",
    "scipy.sparse.csgraph._reachability",
    "scipy.sparse.csgraph._tools",
    "scipy.sparse.csgraph._traversal",
    "scipy.sparse.linalg",
    # GUI — shell and visualisation
    "gui.main_window",
    "gui.startup_animation",
    "gui.dashboard_3d",
    "gui.command_center_3d",
    "gui.story_mode_3d",
    "gui.exhibition_theme",
    # GUI — pages (lazy-loaded)
    "gui.pages.dashboard",
    "gui.pages.threats",
    "gui.pages.settings",
    "gui.pages.sentinel_ai_page",
    "gui.pages.ransomware",
    "gui.pages.scan_visualizer",
    "gui.pages.exhibition_page",
    "gui.pages.exhibition_lab",
    "gui.pages.guided_tour",
    "gui.pages.attack_replay_page",
    "gui.pages.ai_observatory_page",
    "gui.pages.integrity_watchtower_page",
    "gui.pages.applications_center",
    "gui.pages.command_center_page",
    "gui.pages.story_mode_page",
    "gui.pages.challenge_mode_page",
    # Exhibition / investigation modules
    "exhibition.ai_observatory",
    "exhibition.applications_data",
    "exhibition.attack_replay",
    "exhibition.challenge_mode",
    "exhibition.evidence_correlation",
    "exhibition.incident_report",
    "exhibition.integrity_watchtower",
    "exhibition.investigation_timeline",
    "exhibition.result_explainer",
    "exhibition.scenario_lab",
    "exhibition.report_exporter",
    "exhibition.sandbox_simulator",
    "exhibition.security_test_lab",
    # Live SOC monitor, audit store, platform layer
    "livemon", "livemon.monitor", "livemon.telemetry",
    "utils.scan_audit",
    "utils.platform_capabilities",
    "utils.platform_adapter",
    "utils.platform_utils",
    "utils.paths",
    "utils.logging_config",
    "alerts.alert_manager",
    "ml.predictor",
    "ml.schema_v2",
    # Other runtime dependencies
    "customtkinter",
    "psutil",
    "numpy",
    "joblib",
    "PIL",
    "PIL._tkinter_finder",
    "webbrowser",
]

a = Analysis(
    [str(PROJECT_ROOT / "app.py")],
    pathex=[str(PROJECT_ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "matplotlib",
        "pandas",
        "pytest",
        "IPython",
        "jupyter",
        "win32gui",
        "win32api",
        "win32con",
        "winreg",
    ],
    noarchive=False,
    optimize=2,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="SentinelML",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="SentinelML",
)
