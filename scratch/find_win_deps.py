import os
import re

search_dirs = ['app.py', 'ai', 'config.py', 'gui', 'ml', 'reports', 'scanner', 'utils', 'guard']
patterns = {
    'winreg': r'import\s+winreg',
    'win32': r'import\s+win32',
    'wmi': r'import\s+wmi',
    'vssadmin': r'vssadmin',
    'powershell': r'powershell',
    'psutil.win': r'psutil\.win_',
    'APPDATA': r'APPDATA',
    'LOCALAPPDATA': r'LOCALAPPDATA',
    'C:\\': r'C:\\\\',
    'C:/': r'C:/',
    '.exe': r'\.exe',
    'os.name==nt': r'os\.name\s*==\s*[\'\"]nt[\'\"]',
    'platform==Windows': r'platform\.system\(\)\s*==\s*[\'\"]Windows[\'\"]'
}

for d in search_dirs:
    if not os.path.exists(d): continue
    if os.path.isfile(d):
        files = [d]
    else:
        files = []
        for root, _, fs in os.walk(d):
            if '__pycache__' in root: continue
            for f in fs:
                if f.endswith('.py'):
                    files.append(os.path.join(root, f))
    
    for f in files:
        try:
            with open(f, 'r', encoding='utf-8') as fp:
                for i, line in enumerate(fp):
                    for name, p in patterns.items():
                        if re.search(p, line, re.IGNORECASE):
                            print(f"{f}:{i+1} [{name}] {line.strip()}")
        except Exception:
            pass
