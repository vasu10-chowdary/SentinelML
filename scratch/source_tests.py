import sys
sys.path.insert(0, r'C:\Users\vasur\Desktop\SentinalMl')

print('=== SOURCE-LEVEL TESTS ===')

# T1: config.py DEFAULTS have correct production URL
import config
default_url = config.DEFAULTS['ai']['backend_url']
assert default_url == 'https://sentinelml-ai-backend.onrender.com', f'Wrong default URL: {default_url}'
assert default_url.startswith('https://'), 'Must be HTTPS'
print(f'[T1] PASS: config.DEFAULTS backend_url = {default_url!r}')

# T2: config.DEFAULTS have no API key
default_key = config.DEFAULTS['ai']['gemini_api_key']
assert default_key == '', f'API key in DEFAULTS: {default_key!r}'
print(f'[T2] PASS: config.DEFAULTS has no API key stored')

# T3: config.py source has no API key literal
with open('config.py', encoding='utf-8') as f:
    src = f.read()
for pattern in ['AIza', 'AIzaSy', 'AQ.Ab']:
    assert pattern not in src, f'Pattern {pattern!r} found in config.py source!'
print(f'[T3] PASS: config.py source contains no API key')

# T4: loaded config now uses production backend URL
cfg = config.load()
loaded_url = cfg['ai']['backend_url']
assert loaded_url == 'https://sentinelml-ai-backend.onrender.com', f'Loaded URL wrong: {loaded_url}'
assert loaded_url.startswith('https://'), 'Must be HTTPS'
print(f'[T4] PASS: config.load() returns production URL = {loaded_url!r}')

# T5: SentinelBackendProvider routes correctly to production URL
from ai.provider import SentinelBackendProvider, GeminiProvider
provider = SentinelBackendProvider(loaded_url)
assert provider.backend_url == 'https://sentinelml-ai-backend.onrender.com'
assert 'AIza' not in provider.backend_url
print(f'[T5] PASS: SentinelBackendProvider targets production backend, no key in URL')

# T6: BYOK fallback (GeminiProvider) still available
g = GeminiProvider('test-byok-key')
assert g.api_key == 'test-byok-key'
print(f'[T6] PASS: GeminiProvider BYOK fallback is intact and importable')

# T7: No API key in ai/provider.py source
with open('ai/provider.py', encoding='utf-8') as f:
    provider_src = f.read()
for pattern in ['AIza', 'AIzaSy', 'AQ.Ab']:
    assert pattern not in provider_src, f'Pattern {pattern!r} found in ai/provider.py!'
print(f'[T7] PASS: ai/provider.py source contains no hardcoded API key')

# T8: mode is 'backend' in merged config
assert cfg['ai']['mode'] == 'backend', f"mode should be 'backend', got {cfg['ai']['mode']!r}"
print('[T8] PASS: ai.mode = backend (routes through SentinelML cloud backend)')

# T9: provider.generate() request targets the correct backend endpoint (URL validation)
import urllib.parse
parsed = urllib.parse.urlparse(provider.backend_url)
assert parsed.scheme == 'https', 'Backend URL scheme must be https'
assert 'onrender.com' in parsed.netloc, 'Backend must be on production host'
print(f'[T9] PASS: Backend URL scheme=https, host={parsed.netloc}')

# T10: config.DEFAULTS backend key not in git-tracked source files
import os
for fname in ['config.py', 'ai/provider.py', 'app.py']:
    if os.path.exists(fname):
        with open(fname, encoding='utf-8') as f:
            content = f.read()
        assert 'AQ.Ab' not in content, f'Key prefix found in {fname}!'
print('[T10] PASS: No API key in config.py, ai/provider.py, or app.py source files')

print()
print('=== ALL 10 SOURCE-LEVEL TESTS PASSED ===')
