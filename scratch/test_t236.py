import sys, time, json, urllib.request
sys.path.insert(0, '.')

# -- Test 2: Backend health --
t0 = time.time()
resp = urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=10)
t1 = time.time()
data = json.loads(resp.read())
rtime_ms = round((t1-t0)*1000)
print(f'T2 Backend health: HTTP {resp.status}, {rtime_ms}ms, status={data.get("status")}, service={data.get("service")}')

# -- Test 3: Real AI request (no scan context) --
payload = json.dumps({'message': 'What is ransomware?'}).encode()
req = urllib.request.Request(
    'http://127.0.0.1:8000/api/v1/ai/chat',
    data=payload,
    headers={'Content-Type': 'application/json'}
)
t0 = time.time()
resp3 = urllib.request.urlopen(req, timeout=30)
t1 = time.time()
data3 = json.loads(resp3.read())
rid = resp3.headers.get('X-Request-ID', 'MISSING')
raw3 = json.dumps(data3)
key_leaked = 'AQ.Ab' in raw3 or 'AIzaSy' in raw3
print(f'T3 AI request: success={data3["success"]}, time={round(t1-t0,2)}s, X-Request-ID={rid}')
print(f'   key_in_response={key_leaked}')
print(f'   Response (first 250): {data3["response"][:250]}')

# -- Test 6: No-scan protection --
payload6 = json.dumps({'message': 'Explain my latest scan.'}).encode()
req6 = urllib.request.Request(
    'http://127.0.0.1:8000/api/v1/ai/chat',
    data=payload6,
    headers={'Content-Type': 'application/json'}
)
resp6 = urllib.request.urlopen(req6, timeout=30)
data6 = json.loads(resp6.read())
invented = any(x in data6['response'] for x in ['47835', '0.4700', '314 processes', '47839'])
print(f'T6 No-scan protection: invented_data={invented}')
print(f'   Response (first 250): {data6["response"][:250]}')
