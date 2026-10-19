import sys, json

with open('ai/sentinel_ai.py', 'r', encoding='utf-8') as f:
    ai = f.read()

# We need to completely rewrite explain_scan and ask to build the requested dictionary and prompt.

import re

# Replace explain_scan
new_explain = '''    def explain_scan(self, scan_result) -> str:
        if not self.provider or self.status != "READY":
            return "SentinelAI is currently unavailable. Ensure it is enabled and configured in Settings."

        try:
            return self.ask("Explain my latest scan", scan_result)
        except Exception as e:
            return self._generate_fallback_summary(scan_result, str(e))'''

pattern_explain = re.compile(r'    def explain_scan\(self, scan_result\) -> str:.*?        except Exception as e:\n            return self._generate_fallback_summary\(scan_result, str\(e\)\)', re.DOTALL)
if pattern_explain.search(ai):
    ai = pattern_explain.sub(new_explain, ai)
else:
    # Just in case my regex didn't match the whole block, I'll replace it carefully.
    # Actually, let's just replace both ask and explain_scan with a single script that targets their definitions.
    pass
