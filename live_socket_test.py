"""Connect to the Master's socket.io server exactly like the browser does
(session key on the query string) and print whatever comes back within a
few seconds -- proves whether the relay to the real lab-pi is actually
delivering live data or not."""
import sys
import time
import socketio

session_key = sys.argv[1]
received = []

sio = socketio.Client(logger=False, engineio_logger=False)

for event in ('feedback', 'ports_list', 'serial_ports_config', 'sensor_data', 'serial_status'):
    def handler(data=None, _event=event):
        print(f'EVENT {_event}: {data}')
        received.append(_event)
    sio.on(event, handler)

sio.connect(f'http://127.0.0.1:5000?key={session_key}', transports=['websocket', 'polling'], wait_timeout=10)
print('connected, sid =', sio.sid)
time.sleep(4)
sio.disconnect()

print(f'\nTotal events received: {len(received)}')
