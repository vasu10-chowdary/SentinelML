import sys

with open('ai/provider.py', 'r', encoding='utf-8') as f:
    text = f.read()

# 1. Health check timeout
text = text.replace('r = requests.get(f"{self.backend_url}/health", timeout=10)', 'r = requests.get(f"{self.backend_url}/health", timeout=30)')
text = text.replace('"TIMEOUT", "SentinelML AI service did not respond within 15 seconds."', '"TIMEOUT", "SentinelML AI service did not respond within 30 seconds."')

# 2. Generate timeout
text = text.replace('r = requests.post(url, json=payload, timeout=20)', 'r = requests.post(url, json=payload, timeout=35)')
text = text.replace('return False, "SentinelML AI service did not respond within 15 seconds."', 'return False, "SentinelML AI service did not respond within 35 seconds."')

with open('ai/provider.py', 'w', encoding='utf-8') as f:
    f.write(text)

print('Applied timeouts to provider')
