"""
Per-session relay between the Master PC and each Lab Pi's hardware SocketIO server.

Why this exists: browsers must only ever talk to the Master PC (see
lab-pi/MASTER_UI_MIGRATION_PLAN.md). Live data (serial readings, oscilloscope
waveforms, flashing progress) used to stream straight from a Lab Pi's own
SocketIO server to the student's browser. Now the Master PC holds one
SocketIO *client* connection per active session to that session's Lab Pi, and
re-emits whatever the Lab Pi sends into a Server room named after the
session_key — every browser tab for that session joins that same room.

One Lab Pi == one physical experiment == at most one active session, but the
Master PC fleet-wide may be relaying 100+ of these client connections at
once (one per concurrently active experiment), which is why this is a
dict keyed by session_key rather than a single global connection like the
code it replaces.
"""
import threading

import socketio as socketio_client_lib

# Events a Lab Pi pushes to whoever is running its experiment. Kept as a
# passthrough list (not hardcoded per-event handling) so a new event added on
# the Lab Pi side only needs to be added here, not re-plumbed by hand.
RELAYED_EVENTS = [
    'sensor_data',
    'feedback',
    'serial_status',
    'ports_list',
    'flashing_status',
    'osc_data',
    'osc_settings_sync',
    'board_type_updated',
    'ui_config_updated',
]

class LabPiRelayManager:
    def __init__(self, socketio_server, master_api_key):
        self.socketio = socketio_server
        self.master_api_key = master_api_key
        self._clients = {}  # session_key -> socketio_client_lib.Client
        self._lock = threading.Lock()

    def ensure_connected(self, session_key, lab_pi_url):
        """Return a connected client for this session, connecting (or
        reconnecting, if a stale connection died) if needed."""
        with self._lock:
            client = self._clients.get(session_key)
            if client is not None and client.connected:
                return client
            if client is not None:
                self._disconnect_locked(session_key)

            client = socketio_client_lib.Client(reconnection=True, reconnection_attempts=5)
            self._register_relay_handlers(client, session_key)
            try:
                client.connect(
                    lab_pi_url,
                    auth={'key': self.master_api_key},
                    transports=['websocket', 'polling'],
                    wait_timeout=5,
                )
            except Exception as e:
                print(f"[LabPiRelay] Could not connect to Lab Pi at {lab_pi_url} for session {session_key}: {e}")
                return None

            self._clients[session_key] = client
            return client

    def _register_relay_handlers(self, client, session_key):
        # Straight passthrough — the Master's page is now the same conn_id/
        # port-aware template the Lab Pi itself renders, so the wire format
        # it expects is exactly what the Lab Pi already sends.
        for event_name in RELAYED_EVENTS:
            def handler(data=None, _event=event_name):
                self.socketio.emit(_event, data, room=session_key)

            client.on(event_name, handler)

    def forward(self, session_key, lab_pi_url, event, data):
        """Send a browser-originated command through to the session's Lab Pi.
        Connects on demand so a page refresh / reconnect doesn't need a
        separate 'please connect' step first."""
        client = self.ensure_connected(session_key, lab_pi_url)
        if client is None:
            self.socketio.emit(
                'feedback',
                f'[relay] Lab Pi unreachable — "{event}" was not delivered',
                room=session_key,
            )
            return
        try:
            client.emit(event, data or {})
        except Exception as e:
            print(f"[LabPiRelay] emit '{event}' failed for session {session_key}: {e}")

    def disconnect(self, session_key):
        with self._lock:
            self._disconnect_locked(session_key)

    def _disconnect_locked(self, session_key):
        client = self._clients.pop(session_key, None)
        if client is not None:
            try:
                client.disconnect()
            except Exception:
                pass

    def active_session_count(self):
        with self._lock:
            return len(self._clients)
