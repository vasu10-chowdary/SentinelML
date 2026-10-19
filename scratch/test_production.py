import urllib.request, json, time

base = 'https://sentinelml-ai-backend.onrender.com'

def post_json(path, body):
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        base + path, data=data,
        headers={'Content-Type': 'application/json'}
    )
    try:
        t0 = time.time()
        r = urllib.request.urlopen(req, timeout=30)
        elapsed = round(time.time() - t0, 2)
        return r.status, json.loads(r.read()), elapsed
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read()), -1

print('Waiting 90s for Render to deploy...')
time.sleep(90)
print('Testing production endpoint...')

# TEST: Generic question — must get a real Gemini answer
s, d, t = post_json('/api/v1/ai/chat', {'message': 'What is ransomware?'})
print(f'[TEST A] Generic question')
print(f'  HTTP {s}, {t}s')
print(f'  success = {d.get("success")}')
resp_a = d.get("response", "")
print(f'  response[:250] = {resp_a[:250]}')
no_data_phrases = ["no scan data", "no active scan", "no data available"]
a_ok = d.get("success") and not any(p in resp_a.lower() for p in no_data_phrases)
print(f'  PASS = {a_ok}')

print()

# TEST: Scan-specific question with no context — must say no data
s2, d2, t2 = post_json('/api/v1/ai/chat', {'message': 'Explain my latest scan'})
print(f'[TEST B] Scan question, no context')
print(f'  HTTP {s2}, {t2}s')
print(f'  success = {d2.get("success")}')
resp_b = d2.get("response", "")
print(f'  response[:250] = {resp_b[:250]}')
