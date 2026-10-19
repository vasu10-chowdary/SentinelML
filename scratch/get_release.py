import urllib.request, json

url = 'https://api.github.com/repos/vasu10-chowdary/SentinelML/releases/latest'
req = urllib.request.Request(url, headers={
    'Accept': 'application/vnd.github+json',
    'User-Agent': 'SentinelML-Deploy'
})
try:
    r = urllib.request.urlopen(req, timeout=20)
    data = json.loads(r.read())
    print('Release name:', data.get('name'))
    print('Tag:', data.get('tag_name'))
    print('Release ID:', data.get('id'))
    print('Assets:')
    for a in data.get('assets', []):
        size_mb = a['size'] / (1024*1024)
        print('  ID=%s name=%s size=%.1fMB' % (a['id'], a['name'], size_mb))
except Exception as e:
    print('Error:', e)
