"""
SentinelML V2 — Configuration Management
=========================================
Handles reading and writing the persistent app configuration.
Uses utils.paths for robust path resolution.
"""

import json
import logging
from pathlib import Path

from utils.paths import get_config_path

log = logging.getLogger("sentinel.config")

# ---------------------------------------------------------------------------
# Location: Determined by utils.paths (development vs packaged)
# ---------------------------------------------------------------------------
CONFIG_FILE = get_config_path()

# ---------------------------------------------------------------------------
# Defaults — used on first run when no config file exists
# ---------------------------------------------------------------------------
DEFAULTS: dict = {
    "setup_done": False,
    "permissions": {
        "process_scan": True,
        "file_watch": True,
        "registry_watch": True,
        "autostart": False,
    },
    "theme": "dark",
    "appearance_mode": "dark",
    "color_theme": "blue",
    "ai": {
        "enabled": False,
        "mode": "backend",
        "backend_url": "https://sentinelml-ai-backend.onrender.com",
        "backend": "auto",
        "gemini_api_key": ""
    }
}


def load() -> dict:
    """Load config from disk, falling back to DEFAULTS if missing or corrupt."""
    config_file = get_config_path()
    if not config_file.exists():
        log.info("No config file found — using defaults.")
        return dict(DEFAULTS)
    try:
        with open(config_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        # Merge with defaults so new keys added in future versions are present
        merged = dict(DEFAULTS)
        _deep_merge(merged, data)
        return merged
    except Exception as exc:
        log.warning("Config load failed (%s) — using defaults.", exc)
        return dict(DEFAULTS)


def save(data: dict) -> None:
    """Write config to disk atomically (write to .tmp then rename)."""
    config_file = get_config_path()
    tmp = Path(str(config_file) + ".tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        tmp.replace(config_file)
        log.debug("Config saved to %s", config_file)
    except Exception as exc:
        log.error("Config save failed: %s", exc)


def is_first_run() -> bool:
    """Return True if no config file exists (very first launch)."""
    return not get_config_path().exists()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------
def _deep_merge(base: dict, override: dict) -> None:
    """Recursively merge override into base (modifies base in place)."""
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
