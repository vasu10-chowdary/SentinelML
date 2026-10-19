import sys
import re

with open('ai/provider.py', 'r', encoding='utf-8') as f:
    prov = f.read()

# Update AIProvider
prov = prov.replace(
    '    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> Tuple[bool, str]:\n        pass',
    '    def generate(self, prompt: str, system_prompt: Optional[str] = None, scan_context: Optional[dict] = None) -> Tuple[bool, str]:\n        pass'
)

# Update OllamaProvider
prov = prov.replace(
    '    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> Tuple[bool, str]:\n        payload = {',
    '    def generate(self, prompt: str, system_prompt: Optional[str] = None, scan_context: Optional[dict] = None) -> Tuple[bool, str]:\n        payload = {'
)

# Update GeminiProvider
prov = prov.replace(
    '    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> Tuple[bool, str]:\n        if not self.api_key:',
    '    def generate(self, prompt: str, system_prompt: Optional[str] = None, scan_context: Optional[dict] = None) -> Tuple[bool, str]:\n        if not self.api_key:'
)

# Update SentinelBackendProvider
target = '''    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> Tuple[bool, str]:
        import time, logging
        log = logging.getLogger(__name__)
        start_ts = time.time()
        log.info(f"AI_PROVIDER_GENERATE_START | TS: {start_ts} | URL: {getattr(self, 'backend_url', 'UNKNOWN')}")
        if not self.backend_url:
            return False, "Backend URL not configured."

        url = f"{self.backend_url}/api/v1/ai/chat"
        payload = {
            "message": prompt
        }'''

replacement = '''    def generate(self, prompt: str, system_prompt: Optional[str] = None, scan_context: Optional[dict] = None) -> Tuple[bool, str]:
        import time, logging
        log = logging.getLogger(__name__)
        start_ts = time.time()
        log.info(f"AI_PROVIDER_GENERATE_START | TS: {start_ts} | URL: {getattr(self, 'backend_url', 'UNKNOWN')}")
        if not self.backend_url:
            return False, "Backend URL not configured."

        url = f"{self.backend_url}/api/v1/ai/chat"
        payload = {
            "message": prompt
        }
        if scan_context:
            payload["context"] = scan_context'''

prov = prov.replace(target, replacement)
if target.replace('\n', '\r\n') in prov:
    prov = prov.replace(target.replace('\n', '\r\n'), replacement.replace('\n', '\r\n'))

with open('ai/provider.py', 'w', encoding='utf-8') as f:
    f.write(prov)

print("Updated provider.py interfaces")
