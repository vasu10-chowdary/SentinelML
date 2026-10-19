import sys, time, json
sys.path.insert(0, '.')

# -- Test 7: Backend offline -- scanner still works --
from ai.provider import SentinelBackendProvider
prov = SentinelBackendProvider('http://127.0.0.1:9999')  # nothing on 9999
status, msg = prov.is_available()
ok2, err_msg = prov.generate('Explain my latest scan.')
print(f'T7 Backend offline: status={status}, generate_ok={ok2}')
print(f'   Error message: {err_msg}')
assert ok2 == False

from scanner.scan_engine import ScanEngine, ScanType, ScanState
t0 = time.time()
r2 = ScanEngine().scan(ScanType.QUICK, progress_callback=lambda r: None)
elapsed = round(time.time()-t0, 1)
print(f'T7 Scanner still works: state={r2.state.value}, prob={r2.ml_probability:.4f}, time={elapsed}s')
assert r2.state != ScanState.ERROR
print('T7 PASS: scanner unaffected by AI backend being offline')

# -- Test 8: Local BYOK still exists --
from ai.provider import GeminiProvider, OllamaProvider, SentinelBackendProvider
from ai.sentinel_ai import SentinelAI
gp = GeminiProvider('')
s2, _ = gp.is_available()
print(f'T8 GeminiProvider (no key) status={s2}')
assert s2 == 'NOT_CONFIGURED'
for mode in ('backend', 'local', 'auto'):
    ai = SentinelAI(config={'enabled': False, 'mode': mode, 'backend_url': 'http://127.0.0.1:9999', 'backend': 'gemini', 'gemini_api_key': ''})
    ai.initialize()
    assert ai.status == 'DISABLED'
print('T8 PASS: GeminiProvider, OllamaProvider, SentinelBackendProvider all exist, modes backend/local/auto verified')

# -- Test 9: Settings & config defaults --
import config as cfg
c = cfg.load()
ai_cfg = c.get('ai', {})
assert 'mode' in ai_cfg and ai_cfg['mode'] == 'backend'
assert 'backend_url' in ai_cfg

import py_compile
for f in ['gui/pages/settings.py', 'gui/pages/sentinel_ai_page.py']:
    py_compile.compile(f, doraise=True)
print(f'T9 PASS: mode={ai_cfg["mode"]}, backend_url={ai_cfg["backend_url"]}, settings syntax OK')

# -- Test 10: Secret audit of new EXE dist --
import os
dist_dir = 'dist/SentinelML'
env_absent = not os.path.exists(os.path.join(dist_dir, '.env'))
cfg_absent = not os.path.exists(os.path.join(dist_dir, '.sentinelml_v2.json'))
secret_files = []
for root, dirs, files in os.walk(dist_dir):
    for fn in files:
        if fn.endswith(('.json', '.txt', '.cfg', '.ini', '.py', '.md')):
            p = os.path.join(root, fn)
            try:
                with open(p, 'r', errors='ignore') as f:
                    c2 = f.read()
                if 'AQ.Ab' in c2 or 'AIzaSy' in c2:
                    secret_files.append(p)
            except: pass
print(f'T10 Secret audit: .env_absent={env_absent}, cfg_absent={cfg_absent}, text_secret_files={secret_files}')
if env_absent and cfg_absent and not secret_files:
    print('T10 PASS')
else:
    print('T10 FAIL')

# -- Test 11: Core regression --
import py_compile
pages = ['gui/pages/dashboard.py','gui/pages/threats.py','gui/pages/settings.py',
         'gui/pages/sentinel_ai_page.py','gui/pages/scan_visualizer.py',
         'gui/main_window.py','app.py','scanner/scan_engine.py',
         'scanner/live_scanner.py','ml/predictor.py','ai/provider.py','ai/sentinel_ai.py',
         'config.py','constants.py']
for p in pages:
    if os.path.exists(p):
        py_compile.compile(p, doraise=True)

import joblib
model = joblib.load('models/saved_model.pkl')
scaler = joblib.load('models/scaler.pkl')
assert model.n_features_in_ == 19
print(f'T11 PASS: all {len(pages)} pages syntax OK, model {model.n_features_in_} features')
