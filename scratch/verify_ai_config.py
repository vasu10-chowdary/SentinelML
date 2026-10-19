import sys, json, os, logging
from pathlib import Path
sys.path.insert(0, '.')

import config
from utils.paths import get_config_path
from ai.sentinel_ai import SentinelAI

logging.basicConfig(level=logging.INFO)

print("=== CONFIG CHECK ===")
conf_path = get_config_path()
print(f"Loaded config path: {conf_path}")
if conf_path.exists():
    try:
        with open(conf_path, 'r') as f:
            cfg = json.load(f)
        print("Config content:", json.dumps(cfg.get('ai', {}), indent=2))
    except Exception as e:
        print("Error reading config:", e)
else:
    print("Config file does not exist, using defaults.")

print("\n=== AI COPILOT INITIALIZATION ===")
cfg = config.load()
ai = SentinelAI(config=cfg.get("ai", {}))
print(f"AI Enabled: {ai.enabled}")
print(f"AI Mode: {ai.mode}")
print(f"AI Status: {ai.status}")
if hasattr(ai, 'provider') and ai.provider:
    print(f"Provider Class: {ai.provider.__class__.__name__}")
    print(f"Provider Name: {ai.provider.get_name()}")
    if hasattr(ai.provider, 'backend_url'):
        print(f"Backend URL: {ai.provider.backend_url}")
else:
    print("No provider initialized.")
