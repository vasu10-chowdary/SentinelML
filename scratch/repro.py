import urllib.request
import json
import threading
import time
import uvicorn
from app.main import app

def run_server():
    uvicorn.run(app, host='127.0.0.1', port=8004, log_level='error')

t = threading.Thread(target=run_server, daemon=True)
t.start()
time.sleep(2)

try:
    req = urllib.request.Request(
        'http://127.0.0.1:8004/api/v1/ai/chat', 
        data=json.dumps({'message': 'Explain ransomware’s impact — especially why paying a ransom does not guarantee recovery.'}).encode('utf-8'), 
        headers={'Content-Type': 'application/json'},
        method='POST'
    )
    r = urllib.request.urlopen(req)
    print(r.status, json.loads(r.read()))
except urllib.error.HTTPError as e:
    print('Failed:', e.code, e.read().decode('utf-8'))
