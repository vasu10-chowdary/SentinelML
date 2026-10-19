import subprocess, time, os

exe = r'C:\SentinelML_Final_Test\SentinelML.exe'
log_dir = os.path.expandvars(r'%LOCALAPPDATA%\SentinelML\logs')
log_file = os.path.join(log_dir, 'app.log')

# Clear old logs
for f in os.listdir(log_dir) if os.path.exists(log_dir) else []:
    try:
        os.remove(os.path.join(log_dir, f))
    except Exception:
        pass

def wait_for_log(timeout=40):
    t0 = time.time()
    content = ''
    for _ in range(timeout * 10):
        if os.path.exists(log_file):
            try:
                with open(log_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                if 'entering mainloop' in content:
                    return time.time() - t0, content
            except Exception:
                pass
        time.sleep(0.1)
    return None, content

print('=== INSTALLED EXE LAUNCH TEST ===')

# Cold launch
print('Cold launch 1...')
p = subprocess.Popen([exe, '--no-animation'])
cold_t, log1 = wait_for_log()
p.kill(); time.sleep(1)
print(f'Cold startup: {cold_t}s' if cold_t else 'FAILED - did not reach mainloop')

# Warm launch 1
print('Warm launch 2...')
p = subprocess.Popen([exe, '--no-animation'])
warm1_t, log2 = wait_for_log()
p.kill(); time.sleep(1)
print(f'Warm startup 1: {warm1_t}s')

# Warm launch 2 (restart test)
print('Warm launch 3 (restart)...')
p = subprocess.Popen([exe, '--no-animation'])
warm2_t, log3 = wait_for_log()
p.kill(); time.sleep(1)
print(f'Warm startup 2: {warm2_t}s')

# Log audit
bad_patterns = ['ModuleNotFoundError', 'AttributeError', 'FileNotFoundError']
print()
print('=== LOG AUDIT ===')
found_errors = False
for pat in bad_patterns:
    if pat.lower() in log3.lower():
        print(f'ERROR found: {pat}')
        found_errors = True
if not found_errors:
    print('PASS: No Python errors in installed EXE logs.')

# Check key log markers
markers = [
    ('Guard started', 'Background Guard started'),
    ('ML loaded', 'ML Model preloaded'),
    ('frozen=True', 'frozen=True'),
]
print()
print('=== KEY LOG MARKERS ===')
for label, marker in markers:
    found = marker in log3
    print(f'  [{\"PASS\" if found else \"FAIL\"}] {label}: {marker}')
