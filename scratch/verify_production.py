import urllib.request, json, time

base = 'https://sentinelml-ai-backend.onrender.com'

def post_json(path, body):
    data = json.dumps(body, ensure_ascii=False).encode('utf-8')
    req = urllib.request.Request(
        base + path, data=data,
        headers={'Content-Type': 'application/json; charset=utf-8'}
    )
    try:
        t0 = time.time()
        r = urllib.request.urlopen(req, timeout=60)
        elapsed = round(time.time() - t0, 2)
        raw = r.read().decode('utf-8')
        return r.status, json.loads(raw), elapsed
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode('utf-8')), -1

results = {}

# TEST 1: Generic question
print('TEST 1: Generic question')
s, d, t = post_json('/api/v1/ai/chat', {'message': 'What is ransomware?'})
resp = d.get('response', '')
no_scan_phrases = ['no scan data', 'no active scan', 'no data available']
pass1 = (s == 200 and d.get('success') and
         not any(p in resp.lower() for p in no_scan_phrases) and len(resp) > 50)
results['TEST1_generic'] = pass1
print(f'  HTTP {s}, {t}s, success={d.get("success")}, PASS={pass1}')
print(f'  response[:150]: {resp[:150]}')

print()

# TEST 2: Unicode em-dash
msg2 = "Explain ransomware\u2019s impact \u2014 especially why paying a ransom does not guarantee recovery."
print('TEST 2: Unicode em-dash')
s2, d2, t2 = post_json('/api/v1/ai/chat', {'message': msg2})
resp2 = d2.get('response', '')
pass2 = (s2 == 200 and d2.get('success') and len(resp2) > 50)
results['TEST2_unicode'] = pass2
print(f'  HTTP {s2}, {t2}s, success={d2.get("success")}, PASS={pass2}')
print(f'  response[:150]: {resp2[:150]}')

print()

# TEST 3: Scan-specific without context
print('TEST 3: Scan-specific, no context')
s3, d3, t3 = post_json('/api/v1/ai/chat', {'message': 'Explain my latest scan.'})
resp3 = d3.get('response', '')
pass3 = (s3 == 200 and d3.get('success') and
         any(p in resp3.lower() for p in ['no active scan', 'no scan data', 'no scan results', 'no active scan data']))
results['TEST3_no_scan'] = pass3
print(f'  HTTP {s3}, {t3}s, success={d3.get("success")}, PASS={pass3}')
print(f'  response[:150]: {resp3[:150]}')

print()
print('=== SUMMARY ===')
for k, v in results.items():
    print(f'  {k}: {"PASS" if v else "FAIL"}')
all_pass = all(results.values())
print(f'  ALL PASS: {all_pass}')
