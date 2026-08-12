"""Drive a real HTTP session against the locally running Master (port 5000)
exactly like a browser would: fetch the login page for a CSRF token, log
in, then hit /experiment for the seeded booking and inspect the response."""
import re
import sys
import requests

BASE = 'http://127.0.0.1:5000'
SESSION_KEY = sys.argv[1] if len(sys.argv) > 1 else None

s = requests.Session()

r = s.get(f'{BASE}/login')
m = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
csrf = m.group(1)
print(f'[1] GET /login -> {r.status_code}, csrf={csrf[:12]}...')

r = s.post(f'{BASE}/login', data={
    'csrf_token': csrf,
    'email': 'student@test.local',
    'password': 'TestPass123!',
}, allow_redirects=False)
print(f'[2] POST /login -> {r.status_code}, location={r.headers.get("Location")}')

r = s.get(f'{BASE}/experiment', params={'key': SESSION_KEY})
print(f'[3] GET /experiment?key={SESSION_KEY} -> {r.status_code}, final_url={r.url}, len={len(r.text)}')
title_match = re.search(r'<title[^>]*>(.*?)</title>', r.text) or re.search(r'<h1[^>]*>(.*?)</h1>', r.text)
print(f'    page heading: {title_match.group(1) if title_match else "(none found)"}')
if 'Session Expired' in r.text:
    msg = re.search(r'class="warning">(.*?)</p>', r.text)
    print(f'    SESSION EXPIRED PAGE. message: {msg.group(1) if msg else "(no message)"}')
