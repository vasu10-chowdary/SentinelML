import urllib.request, json, time

base = 'https://sentinelml-ai-backend.onrender.com'

def post_chat(msg, timeout=60):
    data = json.dumps({'message': msg}, ensure_ascii=False).encode('utf-8')
    req = urllib.request.Request(
        base + '/api/v1/ai/chat', data=data,
        headers={'Content-Type': 'application/json; charset=utf-8'}
    )
    t0 = time.time()
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        elapsed = round(time.time() - t0, 2)
        body = json.loads(r.read().decode('utf-8'))
        return r.status, body, elapsed
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode('utf-8')), -1

print('=== FULL E2E BACKEND TEST ===')
print()

# T1: Generic question
print('[T1] Generic question: "What is ransomware?"')
s, d, t = post_chat('What is ransomware?')
no_scan = any(p in d.get('response','').lower() for p in ['no active scan', 'no scan data'])
passed = s == 200 and d.get('success') and not no_scan and len(d.get('response','')) > 50
print('  HTTP %s | %ss | success=%s | PASS=%s' % (s, t, d.get('success'), passed))
print('  Response[:100]: %s' % d.get('response','')[:100])
print()

# T2: Unicode
print('[T2] Unicode: ransomware\u2019s impact \u2014 em dash')
s2, d2, t2 = post_chat('Explain ransomware\u2019s impact \u2014 especially why paying a ransom does not guarantee recovery.')
passed2 = s2 == 200 and d2.get('success') and len(d2.get('response','')) > 50
print('  HTTP %s | %ss | success=%s | PASS=%s' % (s2, t2, d2.get('success'), passed2))
print('  Response[:100]: %s' % d2.get('response','')[:100])
print()

# T3: Scan-specific no context
print('[T3] Scan-specific without context: "Explain my latest scan"')
s3, d3, t3 = post_chat('Explain my latest scan.')
resp3 = d3.get('response','').lower()
scan_refused = any(p in resp3 for p in ['no active scan', 'no scan data', 'no scan results'])
passed3 = s3 == 200 and d3.get('success') and scan_refused
print('  HTTP %s | %ss | refused_without_context=%s | PASS=%s' % (s3, t3, scan_refused, passed3))
print('  Response[:120]: %s' % d3.get('response','')[:120])
print()

# T4: Health check
print('[T4] Health endpoint')
req_h = urllib.request.Request(base + '/health')
rh = urllib.request.urlopen(req_h, timeout=10)
hd = json.loads(rh.read().decode('utf-8'))
print('  HTTP %s | status=%s | PASS=%s' % (rh.status, hd.get('status'), rh.status == 200))
print()

print('=== WEBSITE DOWNLOAD URL TEST ===')
download_url = 'https://github.com/vasu10-chowdary/SentinelML/releases/latest/download/SentinelML_Setup.exe'
req_d = urllib.request.Request(download_url, method='HEAD', headers={'User-Agent': 'SentinelML-Test'})
try:
    rd = urllib.request.urlopen(req_d, timeout=20)
    cl = rd.headers.get('Content-Length','Unknown')
    print('  URL: %s' % download_url)
    print('  HTTP %s | Content-Length: %s bytes | PASS=True' % (rd.status, cl))
except urllib.error.HTTPError as e:
    print('  HTTP %s FAIL' % e.code)

print()
print('All E2E tests complete.')
