import sys
import re

with open('ai/provider.py', 'r', encoding='utf-8') as f:
    prov = f.read()

# Target generate method of SentinelBackendProvider
target = '''    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> Tuple[bool, str]:
        """Send prompt to Render production backend."""
        if not self.backend_url:
            return False, "Backend URL not configured."'''

replacement = '''    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> Tuple[bool, str]:
        """Send prompt to Render production backend."""
        import time, logging
        log = logging.getLogger(__name__)
        start_ts = time.time()
        log.info(f"AI_PROVIDER_GENERATE_START | TS: {start_ts} | URL: {getattr(self, 'backend_url', 'UNKNOWN')}")
        
        if not self.backend_url:
            return False, "Backend URL not configured."'''

prov = prov.replace(target, replacement)
if target.replace('\n', '\r\n') in prov:
    prov = prov.replace(target.replace('\n', '\r\n'), replacement.replace('\n', '\r\n'))

target2 = '''        try:
            r = requests.post(url, json=payload, timeout=35)
            r.encoding = 'utf-8'
            if r.status_code == 200:
                data = r.json()
                if data.get("success"):
                    return True, data.get("response", "")
                return False, data.get("response", "Unknown error from backend.")'''

replacement2 = '''        try:
            r = requests.post(url, json=payload, timeout=35)
            r.encoding = 'utf-8'
            log.info(f"AI_PROVIDER_GENERATE_END | ELAPSED: {time.time()-start_ts:.3f}s | STATUS: {r.status_code}")
            if r.status_code == 200:
                data = r.json()
                if data.get("success"):
                    return True, data.get("response", "")
                return False, data.get("response", "Unknown error from backend.")'''
prov = prov.replace(target2, replacement2)
if target2.replace('\n', '\r\n') in prov:
    prov = prov.replace(target2.replace('\n', '\r\n'), replacement2.replace('\n', '\r\n'))

target3 = '''        except requests.exceptions.Timeout:
            return False, "SentinelML AI service did not respond within 35 seconds."'''
replacement3 = '''        except requests.exceptions.Timeout:
            log.error(f"AI_PROVIDER_GENERATE_END | ELAPSED: {time.time()-start_ts:.3f}s | ERROR: Timeout")
            return False, "SentinelML AI service did not respond within 35 seconds."'''
prov = prov.replace(target3, replacement3)
if target3.replace('\n', '\r\n') in prov:
    prov = prov.replace(target3.replace('\n', '\r\n'), replacement3.replace('\n', '\r\n'))

with open('ai/provider.py', 'w', encoding='utf-8') as f:
    f.write(prov)
print("Updated ai/provider.py with tracing")
