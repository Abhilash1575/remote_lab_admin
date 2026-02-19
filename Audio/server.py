#!/usr/bin/env python3
"""
Audio Streaming Server for Virtual Lab
Handles WebRTC audio streaming between Lab Pi and Admin/Student clients
"""

import json
import asyncio
import threading
import base64
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, send, emit

app = Flask(__name__)
app.config['SECRET_KEY'] = 'virtual-lab-audio-secret'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Store active audio sessions
audio_sessions = {}

# Store latest audio chunks for each Lab Pi (for new connections)
latest_audio = {}

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

@app.route('/offer', methods=['POST'])
def handle_offer():
    """Handle WebRTC offer from client"""
    try:
        data = request.json
        sdp = data.get('sdp')
        session_id = data.get('session_id', 'default')
        
        print(f"Received audio offer for session: {session_id}")
        
        # For now, return a basic answer
        # In production, this would connect to the Lab Pi's audio stream
        answer = {
            'type': 'answer',
            'sdp': sdp,  # In production, this would be the actual answer from Lab Pi
            'session_id': session_id
        }
        
        return jsonify(answer)
    except Exception as e:
        print(f"Error handling offer: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/status')
def status():
    """Get audio server status"""
    return jsonify({
        'status': 'running',
        'sessions': len(audio_sessions),
        'active': len([s for s in audio_sessions.values() if s.get('active', False)])
    })

@socketio.on('connect')
def handle_connect():
    print(f"Client connected: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    print(f"Client disconnected: {request.sid}")
    # Remove from sessions
    for session_id, session in list(audio_sessions.items()):
        if session.get('sid') == request.sid:
            del audio_sessions[session_id]
            break

@socketio.on('audio_start')
def handle_audio_start(data):
    """Handle audio start request"""
    session_id = data.get('session_id', 'default')
    lab_pi_id = data.get('lab_pi_id')
    
    audio_sessions[session_id] = {
        'sid': request.sid,
        'active': True,
        'lab_pi_id': lab_pi_id
    }
    
    # Send latest audio if available
    if lab_pi_id and lab_pi_id in latest_audio:
        emit('audio_data', latest_audio[lab_pi_id], namespace='/audio')
    
    print(f"Audio session started: {session_id} for Lab Pi: {lab_pi_id}")
    emit('audio_started', {'session_id': session_id})

@socketio.on('audio_stop')
def handle_audio_stop(data):
    """Handle audio stop request"""
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
