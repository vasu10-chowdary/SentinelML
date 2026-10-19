import os, hashlib

install_dir = r'C:\SentinelML_Final_Test'
exe_path = os.path.join(install_dir, 'SentinelML.exe')
internal = os.path.join(install_dir, '_internal')

print('=== INSTALLED PACKAGE VERIFICATION ===')

exe_exists = os.path.exists(exe_path)
print(f'SentinelML.exe exists: {exe_exists}')

expected_sha = 'c1e44af84eac25d646c22f1c3f10576043c4680bfc7a0a6707656ee2f9872b1a'
if exe_exists:
    with open(exe_path, 'rb') as f:
        got_sha = hashlib.sha256(f.read()).hexdigest()
    match = got_sha == expected_sha
    print(f'Installed EXE SHA-256 : {got_sha}')
    print(f'Expected  EXE SHA-256 : {expected_sha}')
    print(f'Hash match            : {match}')

critical = [
    ('models/saved_model.pkl',  '_internal/models/saved_model.pkl'),
    ('models/scaler.pkl',       '_internal/models/scaler.pkl'),
    ('certifi/cacert.pem',      '_internal/certifi/cacert.pem'),
    ('sklearn/',                '_internal/sklearn'),
    ('scipy/',                  '_internal/scipy'),
    ('customtkinter/',          '_internal/customtkinter'),
]
print()
print('Critical dependencies:')
for label, rel in critical:
    path = os.path.join(install_dir, rel)
    status = 'PRESENT' if os.path.exists(path) else 'MISSING'
    print(f'  {label}: {status}')

print()
print('=== SECURITY SCAN ===')
found_any = False
patterns = [b'AIzaSy', b'AQ.Ab', b'127.0.0.1:8000', b'localhost:8000']
for root, _, files in os.walk(install_dir):
    for fname in files:
        if fname.endswith(('.pyc', '.pyd', '.dll', '.exe', '.py')):
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, 'rb') as f:
                    content = f.read()
                for p in patterns:
                    if p in content:
                        print(f'WARNING: {p} found in {fpath}')
                        found_any = True
            except Exception:
                pass

if not found_any:
    print('PASS: No API keys or dev URLs found in installed package.')

# Look for production URL baked into bundled config
print()
print('=== BACKEND URL CHECK ===')
import glob
pyc_files = glob.glob(os.path.join(internal, '**', 'config*.pyc'), recursive=True)
pyc_files += glob.glob(os.path.join(internal, 'config.py'))
for pf in pyc_files:
    with open(pf, 'rb') as f:
        content = f.read()
    if b'sentinelml-ai-backend.onrender.com' in content:
        print(f'PASS: Production backend URL confirmed in {pf}')
    if b'127.0.0.1' in content:
        print(f'WARNING: localhost URL in {pf}')
