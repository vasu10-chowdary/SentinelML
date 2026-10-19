import sys, time, json, urllib.request
sys.path.insert(0, '.')

from scanner.scan_engine import ScanEngine, ScanType, ScanState
import numpy as np

print('Running real scan...')
t0 = time.time()
engine = ScanEngine()
result = engine.scan(ScanType.QUICK, progress_callback=lambda r: None)
elapsed = round(time.time()-t0, 1)
arr = np.array(result._features).flatten()
print(f'T4 Real scan: state={result.state.value}, prob={result.ml_probability:.4f}')
print(f'   files={result.files_inspected}, procs={result.processes_analyzed}, time={elapsed}s, features={len(arr)}')

# -- Test 5: AI explains real scan --
names = ['entropy','cpu_usage','mem_usage','net_connections','file_write_rate',
         'file_delete_rate','file_create_rate','file_rename_rate','shadow_copy_del',
         'registry_mods','process_inj','unusual_privs','parent_mismatch',
         'service_tampering','antivirus_kill','ransom_ext_written','network_anomaly',
         'lateral_movement','c2_beacon']
features_dict = {names[i]: float(arr[i]) for i in range(min(len(arr), len(names)))}

payload5 = json.dumps({
    'message': 'Explain my latest scan.',
    'context': {
        'scan_state': result.state.value,
        'threat_level': result.state.value.upper(),
        'ml_probability': result.ml_probability,
        'ml_executed': True,
        'files_inspected': result.files_inspected,
        'processes_analyzed': result.processes_analyzed,
        'features': features_dict,
    }
}).encode()

req5 = urllib.request.Request(
    'http://127.0.0.1:8000/api/v1/ai/chat',
    data=payload5,
    headers={'Content-Type': 'application/json'}
)
t0 = time.time()
resp5 = urllib.request.urlopen(req5, timeout=30)
t1 = time.time()
data5 = json.loads(resp5.read())
raw5 = json.dumps(data5)
key_leaked = 'AQ.Ab' in raw5 or 'AIzaSy' in raw5
txt = data5['response'].lower()
references_state = result.state.value.lower() in txt or 'probability' in txt or str(round(result.ml_probability,2)) in txt
print(f'T5 AI explains scan: success={data5["success"]}, time={round(t1-t0,2)}s')
print(f'   references_real_data={references_state}, key_leaked={key_leaked}')
print(f'   ScanState after AI call={result.state.value} (must remain unchanged)')
print(f'   Response (first 400): {data5["response"][:400]}')
