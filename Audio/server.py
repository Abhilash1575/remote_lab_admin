#!/usr/bin/env python3
"""
Audio Streaming Server for Virtual Lab
Handles audio streaming between Lab Pi and Admin/Student clients via SocketIO
"""

import json
import threading
import base64
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.config['SECRET_KEY'] = 'virtual-lab-audio-secret'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Store active audio sessions
audio_sessions = {}

# Store latest audio chunks for each Lab Pi (for new connections)
latest_audio = {}

# Store connected clients
connected_clients = set()


@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'service': 'audio'})


@app.route('/api/audio/stream', methods=['POST'])
def receive_audio():
    """Receive audio stream from Lab Pi"""
    try:
        data = request.json
        lab_pi_id = data.get('lab_pi_id')
        audio_b64 = data.get('audio')
        sample_rate = data.get('sample_rate', 16000)
        channels = data.get('channels', 1)
        
        if not lab_pi_id or not audio_b64:
            return jsonify({'error': 'Missing lab_pi_id or audio'}), 400
        
        # Store latest audio for this Lab Pi
        latest_audio[lab_pi_id] = {
            'audio': audio_b64,
            'sample_rate': sample_rate,
            'channels': channels
        }
        
        # Broadcast to all connected clients for this Lab Pi
        socketio.emit('audio_data', {
            'lab_pi_id': lab_pi_id,
            'audio': audio_b64,
            'sample_rate': sample_rate,
            'channels': channels
        }, namespace='/audio')
        
        return jsonify({'success': True})
        
    except Exception as e:
        print(f"Error receiving audio: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/audio/status')
def audio_status():
    """Get audio server status"""
    return jsonify({
        'status': 'running',
        'sessions': len(audio_sessions),
        'clients': len(connected_clients),
        'active_lab_pis': list(latest_audio.keys())
    })


# SocketIO event handlers
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    connected_clients.add(request.sid)
    print(f"Client connected: {request.sid}, Total: {len(connected_clients)}")
    
    # Send welcome message
    emit('audio_connected', {'status': 'connected'})


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    connected_clients.discard(request.sid)
    print(f"Client disconnected: {request.sid}, Total: {len(connected_clients)}")
    
    # Remove from sessions
    for session_id in list(audio_sessions.keys()):
        if audio_sessions.get(session_id, {}).get('sid') == request.sid:
            del audio_sessions[session_id]


@socketio.on('audio_subscribe')
def handle_audio_subscribe(data):
    """Handle audio subscription request"""
    lab_pi_id = data.get('lab_pi_id')
    session_id = data.get('session_id', 'default')
    
    audio_sessions[session_id] = {
        'sid': request.sid,
        'lab_pi_id': lab_pi_id,
        'active': True
    }
    
    # Send latest audio if available
    if lab_pi_id and lab_pi_id in latest_audio:
        emit('audio_data', latest_audio[lab_pi_id], namespace='/audio')
    
    print(f"Audio session started: {session_id} for Lab Pi: {lab_pi_id}")
    emit('audio_started', {'session_id': session_id, 'lab_pi_id': lab_pi_id})


@socketio.on('audio_unsubscribe')
def handle_audio_unsubscribe(data):
    """Handle audio unsubscribe request"""
    session_id = data.get('session_id', 'default')
    if session_id in audio_sessions:
        del audio_sessions[session_id]
        print(f"Audio session stopped: {session_id}")
    emit('audio_stopped', {'session_id': session_id})


def run_server(port=9000):
    """Run the audio server"""
    print(f"Starting Audio Streaming Server on port {port}...")
    socketio.run(app, host='0.0.0.0', port=port, debug=False, allow_unsafe_werkzeug=True)


if __name__ == '__main__':
    run_server()
