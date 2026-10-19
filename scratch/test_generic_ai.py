import sys
sys.path.insert(0, '.')

from ai.sentinel_ai import SentinelAI
from config import load as load_config

cfg = load_config()
ai = SentinelAI(config=cfg.get("ai", {}))
ai.enabled = True
ai.initialize()

print("TEST A: Generic question (No context)")
resp = ai.ask("What is ransomware?", None)
print("Response:", resp[:100] + "...")

print("\nTEST E: Unicode")
resp = ai.ask("Explain ransomware's impact — especially why paying a ransom does not guarantee recovery.", None)
print("Response:", resp[:100] + "...")
