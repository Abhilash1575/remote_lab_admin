import re
import sys
import requests

session_key = sys.argv[1]
s = requests.Session()
r = s.get('http://127.0.0.1:5000/login')
csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text).group(1)
s.post('http://127.0.0.1:5000/login', data={'csrf_token': csrf, 'email': 'student@test.local', 'password': 'TestPass123!'})

r = s.get('http://127.0.0.1:5000/experiment', params={'key': session_key})
page_csrf = re.search(r'name="csrf-token" content="([^"]+)"', r.text)
print('CSRF meta tag present on page:', bool(page_csrf))
token = page_csrf.group(1) if page_csrf else None

# Without the token -- should reproduce the exact 400 the user saw
r1 = s.post('http://127.0.0.1:5000/toggle_relay', json={'state': 'off', 'session_key': session_key})
print(f'[no token]   POST /toggle_relay -> {r1.status_code} {r1.text[:120]}')

# With the token, like the fixed page's fetch() override sends it
r2 = s.post('http://127.0.0.1:5000/toggle_relay',
             json={'state': 'off', 'session_key': session_key},
             headers={'X-CSRFToken': token})
print(f'[with token] POST /toggle_relay -> {r2.status_code} {r2.text[:200]}')
