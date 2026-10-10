"""
SentinelML V2 — Path Management
=================================
Robust path resolution for both development and packaged execution.

CRITICAL: Never assume CWD == application directory.

Path Types:
-----------
1. APPLICATION RESOURCES (read-only)
   - models/
   - bundled assets
   - code files

2. USER DATA (read-write)
   - logs/
   - alerts/
   - reports/
   - configuration

Location Strategy:
------------------
- Development: Use project directory for everything
- Packaged: Use %LOCALAPPDATA%\\SentinelML\\ for user data
"""

import os
import sys
from pathlib import Path


def get_application_root() -> Path:
    """
    Get the application root directory.
    
    Returns:
        Path to application root (contains app.py or .exe)
    """
    if getattr(sys, 'frozen', False):
        # Packaged with PyInstaller
        # CRITICAL: PyInstaller extracts bundled files to sys._MEIPASS temp dir
        # Use _MEIPASS for bundled resources (models, etc.)
        if hasattr(sys, '_MEIPASS'):
            return Path(sys._MEIPASS)
        else:
            # Fallback: sys.executable points to SentinelML.exe
            return Path(sys.executable).parent
    else:
        # Running as script
        # __file__ is utils/paths.py, so parent.parent gets project root
        return Path(__file__).parent.parent


def get_user_data_root() -> Path:
    """
    Get the user data directory (logs, alerts, reports).
    
    Returns:
        Path to user data root (creates if missing)
    """
    if getattr(sys, 'frozen', False):
        from utils.platform_utils import get_platform_paths
        data_dir = get_platform_paths().get_application_data_dir()
    else:
        # Development: Use project directory
        data_dir = get_application_root()
    
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


def get_logs_dir() -> Path:
    """Get logs directory (creates if missing)."""
    logs_dir = get_user_data_root() / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    return logs_dir


def get_alerts_dir() -> Path:
    """Get alerts directory (creates if missing)."""
    alerts_dir = get_user_data_root() / "alerts"
    alerts_dir.mkdir(parents=True, exist_ok=True)
    return alerts_dir


def get_reports_dir() -> Path:
    """Get reports directory (creates if missing)."""
    reports_dir = get_user_data_root() / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    return reports_dir


def get_models_dir() -> Path:
    """Get models directory (read-only resources)."""
    return get_application_root() / "models"


def get_config_path() -> Path:
    """Get configuration file path."""
    return get_user_data_root() / ".sentinelml_v2.json"


# ── For debugging ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("SentinelML V2 — Path Resolution")
    print("=" * 70)
    print(f"Frozen: {getattr(sys, 'frozen', False)}")
    print(f"Application root: {get_application_root()}")
    print(f"User data root:   {get_user_data_root()}")
    print(f"Logs directory:   {get_logs_dir()}")
    print(f"Alerts directory: {get_alerts_dir()}")
    print(f"Reports directory: {get_reports_dir()}")
    print(f"Models directory: {get_models_dir()}")
    print(f"Config file:      {get_config_path()}")
