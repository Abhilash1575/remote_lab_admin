import re
import requests

s = requests.Session()
r = s.get('http://127.0.0.1:5000/login')
csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text).group(1)
s.post('http://127.0.0.1:5000/login', data={'csrf_token': csrf, 'email': 'student@test.local', 'password': 'TestPass123!'})
r = s.get('http://127.0.0.1:5000/experiment', params={'key': 'OBZ95B4T'})
html = r.text

checks = [
    ('flashBtn disabled', 'id="flashBtn"' in html and re.search(r'id="flashBtn"[^>]*disabled', html) is not None),
    ('factoryResetBtn disabled', re.search(r'id="factoryResetBtn"[^>]*disabled', html) is not None),
    ('serialMonitorCard hidden', 'id="serialMonitorCard" style="display:none"' in html),
    ('oscilloscope option absent from mainUiMode', '<option value="oscilloscope"' not in html),
    ('plotter option present', '<option value="plotter"' in html),
    ('required control "Voltage" readout rendered', 'Voltage' in html),
    ('experiment name "Power Supply" in header', 'Power Supply' in html),
    ('Teacher MCU port NOT shown (hidden from students)', 'Teacher MCU' not in html),
]
for label, ok in checks:
    print(('PASS' if ok else 'FAIL'), '-', label)
