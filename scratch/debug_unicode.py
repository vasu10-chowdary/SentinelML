import urllib.request, json

base = 'https://sentinelml-ai-backend.onrender.com'

# Send unicode message and check if it hits the diagnostic-test endpoint OK
msg = "Explain ransomware\u2019s impact \u2014 especially why paying a ransom does not guarantee recovery."
print(f"Message: {msg!r}")
print(f"JSON encoded: {json.dumps({'message': msg})!r}")

data = json.dumps({'message': msg}, ensure_ascii=False).encode('utf-8')
print(f"UTF-8 encoded bytes[:80]: {data[:80]}")

req = urllib.request.Request(
    base + '/api/v1/ai/chat',
    data=data,
    headers={'Content-Type': 'application/json; charset=utf-8'}
)
try:
    r = urllib.request.urlopen(req, timeout=60)
    raw = r.read().decode('utf-8')
    print(f"HTTP {r.status}")
    print(f"Response[:500]: {raw[:500]}")
except urllib.error.HTTPError as e:
    raw = e.read().decode('utf-8')
    print(f"HTTP {e.code}")
    print(f"Error response: {raw}")
