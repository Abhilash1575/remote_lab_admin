#!/usr/bin/env python3
import sys
import os
import time
import subprocess
import threading
import queue
import tempfile
import re
import random
import hmac
import json
import math
import asyncio
import string
import secrets
import requests
import csv
import io
from collections import Counter
from dotenv import load_dotenv
from datetime import datetime, timedelta
from flask import Flask, send_from_directory, request, jsonify, render_template, abort, flash, redirect, url_for, Response, current_app, session
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import CSRFProtect
from werkzeug.utils import secure_filename

# Import GPIO and Serial modules with fallback
try:
    # DISABLED GPIO - relay is controlled by lab-pi only
    import lgpio
    RELAY_PIN = None  # Disabled - lab-pi controls relay
    print("⚠️ GPIO disabled in admin-pi - lab-pi controls relay")
except Exception as e:
    print(f"GPIO import error: {e}")
    lgpio = None
    RELAY_PIN = None

try:
    import serial
    from serial.tools import list_ports
except Exception as e:
    serial = None
    list_ports = None

# Threading based async (no eventlet)

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================
def calculate_uptime(start_time):
    """Calculate uptime from start time to now"""
    if not start_time:
        return '-'
    
    delta = datetime.utcnow() - start_time
    total_seconds = int(delta.total_seconds())
    
    days = total_seconds // 86400
    hours = (total_seconds % 86400) // 3600
    minutes = (total_seconds % 3600) // 60
    
    if days > 0:
        return f"{days}d {hours}h"
    elif hours > 0:
        return f"{hours}h {minutes}m"
    else:
        return f"{minutes}m"

# Import database models
from models import db, bcrypt, User, Experiment, Booking, Session, Device, OTAUpdate, PasswordResetToken, DeviceMetric, SystemLog, LabPi, LabPiHeartbeat, Department

# Import UPS monitoring
try:
    import dfrobot_ups
    UPS_AVAILABLE = True
except ImportError:
    UPS_AVAILABLE = False

# System monitoring
import psutil

# ---------- CONFIG ----------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, 'templates')
UPLOAD_DIR = os.path.join(BASE_DIR, 'uploads')
DEFAULT_FW_DIR = os.path.join(BASE_DIR, 'default_fw')
SOP_DIR = os.path.join(BASE_DIR, 'static')
DATA_DIR = os.path.join(BASE_DIR, 'data')
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(DEFAULT_FW_DIR, exist_ok=True)
os.makedirs(SOP_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

load_dotenv(os.path.join(BASE_DIR, '.env'))


def _get_or_create_secret_key():
    """Session-signing key. Reads SECRET_KEY from the environment if set;
    otherwise persists a randomly generated one to disk so it survives restarts
    without ever being a hardcoded, publicly-visible value."""
    env_key = os.environ.get('SECRET_KEY')
    if env_key:
        return env_key
    key_path = os.path.join(DATA_DIR, 'secret_key')
    if os.path.isfile(key_path):
        with open(key_path) as f:
            key = f.read().strip()
        if key:
            return key
    key = secrets.token_hex(32)
    with open(key_path, 'w') as f:
        f.write(key)
    os.chmod(key_path, 0o600)
    return key


def _require_env(name):
    value = os.environ.get(name, '')
    if not value:
        print(f"[CONFIG] {name} is not set in the environment/.env — features that need it "
              f"(mail sending, Google login) will fail until it's configured.")
    return value


app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = _get_or_create_secret_key()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'vlab.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = _require_env('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = _require_env('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', app.config['MAIL_USERNAME'])

# Google OAuth configuration
app.config['GOOGLE_CLIENT_ID'] = _require_env('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = _require_env('GOOGLE_CLIENT_SECRET')

# Shared secret proving commands to a Lab Pi's /api/lab-pi/* endpoints really
# came from this Admin Pi. Must match MASTER_API_KEY in each Lab Pi's .env.
MASTER_API_KEY = os.environ.get('MASTER_API_KEY', '')
if not MASTER_API_KEY:
    print("[CONFIG] MASTER_API_KEY is not set — Lab Pi command endpoints that "
          "enforce it will reject requests from this Admin Pi until it's configured "
          "to match the value in each Lab Pi's .env.")


def _verify_lab_pi_request():
    """Confirm a POST to /api/lab-pi/register or /api/lab-pi/heartbeat really
    came from a real Lab Pi (which must send the same MASTER_API_KEY in an
    X-Master-Api-Key header), not just anyone on the network claiming an ID.
    Without this, a spoofed heartbeat could redirect a real Lab Pi's session
    traffic to an attacker-controlled IP. Same fail-open-with-warning
    behavior as the Lab Pi side: if MASTER_API_KEY isn't configured yet,
    allow through so this doesn't break an in-progress setup."""
    if not MASTER_API_KEY:
        return True
    provided = request.headers.get('X-Master-Api-Key', '')
    return hmac.compare_digest(provided, MASTER_API_KEY)

socketio = SocketIO(app, async_mode='threading')

from lab_pi_relay import LabPiRelayManager
lab_pi_relay = LabPiRelayManager(socketio, MASTER_API_KEY)

from audio_relay import AudioRelayManager
audio_relay = AudioRelayManager()

# Maps a browser's socket.io sid to the session_key it's operating under, so
# every relayed event (connect_serial, send_command, ...) knows which Lab Pi
# to forward to without the page having to repeat session_key on every emit.
sid_session_map = {}
sid_session_lock = threading.Lock()

limiter = Limiter(get_remote_address, app=app, default_limits=[], storage_uri='memory://')
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Register template filters
@app.template_filter('uptime')
def uptime_filter(start_time):
    return calculate_uptime(start_time)
mail = Mail(app)

# Initialize database
db.init_app(app)
bcrypt.init_app(app)

def migrate_lab_pi_columns():
    """Add missing columns to lab_pi and user tables if they don't exist"""
    from sqlalchemy import text
    
    # Migrate lab_pi table
    try:
        db.session.execute(text('ALTER TABLE lab_pi ADD COLUMN device_type VARCHAR(50) DEFAULT "Raspberry Pi"'))
        db.session.commit()
    except Exception:
        db.session.rollback()
    
    try:
        db.session.execute(text('ALTER TABLE lab_pi ADD COLUMN firmware_version VARCHAR(20) DEFAULT "1.0"'))
        db.session.commit()
    except Exception:
        db.session.rollback()
    
    try:
        db.session.execute(text('ALTER TABLE lab_pi ADD COLUMN hardware_version VARCHAR(20)'))
        db.session.commit()
    except Exception:
        db.session.rollback()
    
    try:
        db.session.execute(text('ALTER TABLE lab_pi ADD COLUMN location VARCHAR(100)'))
        db.session.commit()
    except Exception:
        db.session.rollback()
    
    # Migrate user table - new profile fields
    try:
        db.session.execute(text('ALTER TABLE user ADD COLUMN username VARCHAR(50)'))
        db.session.commit()
    except Exception:
        db.session.rollback()
    
    try:
        db.session.execute(text('ALTER TABLE user ADD COLUMN phone_number VARCHAR(20)'))
        db.session.commit()
    except Exception:
        db.session.rollback()
    
    try:
        db.session.execute(text('ALTER TABLE user ADD COLUMN profile_picture VARCHAR(255)'))
        db.session.commit()
    except Exception:
        db.session.rollback()
    
    try:
        db.session.execute(text('ALTER TABLE user ADD COLUMN sr_number VARCHAR(50)'))
        db.session.commit()
    except Exception:
        db.session.rollback()
    
    try:
        db.session.execute(text('ALTER TABLE user ADD COLUMN course_id VARCHAR(50)'))
        db.session.commit()
    except Exception:
        db.session.rollback()
    
    try:
        db.session.execute(text('ALTER TABLE user ADD COLUMN course_name VARCHAR(100)'))
        db.session.commit()
    except Exception:
        db.session.rollback()
    
    try:
        db.session.execute(text('ALTER TABLE user ADD COLUMN department_id INTEGER'))
        db.session.commit()
    except Exception:
        db.session.rollback()
    
    try:
        db.session.execute(text('ALTER TABLE user ADD COLUMN company_college_name VARCHAR(200)'))
        db.session.commit()
    except Exception:
        db.session.rollback()
    
    try:
        db.session.execute(text('ALTER TABLE user ADD COLUMN google_id VARCHAR(100)'))
        db.session.commit()
    except Exception:
        db.session.rollback()
    
    try:
        db.session.execute(text('ALTER TABLE user ADD COLUMN oauth_provider VARCHAR(20)'))
        db.session.commit()
    except Exception:
        db.session.rollback()
    
    try:
        db.session.execute(text('ALTER TABLE user ADD COLUMN profile_complete BOOLEAN DEFAULT 0'))
        db.session.commit()
    except Exception:
        db.session.rollback()
    
    # Migrate lab_pi table - camera support
    try:
        db.session.execute(text('ALTER TABLE lab_pi ADD COLUMN pi_camera_enabled BOOLEAN DEFAULT 0'))
        db.session.commit()
    except Exception:
        db.session.rollback()
    
    try:
        db.session.execute(text('ALTER TABLE lab_pi ADD COLUMN pi_camera_port INTEGER DEFAULT 8080'))
        db.session.commit()
    except Exception:
        db.session.rollback()
    
    try:
        db.session.execute(text('ALTER TABLE lab_pi ADD COLUMN usb_camera_enabled BOOLEAN DEFAULT 0'))
        db.session.commit()
    except Exception:
        db.session.rollback()
    
    try:
        db.session.execute(text('ALTER TABLE lab_pi ADD COLUMN usb_camera_device VARCHAR(50)'))
        db.session.commit()
    except Exception:
        db.session.rollback()
    
    try:
        db.session.execute(text('ALTER TABLE lab_pi ADD COLUMN usb_camera_port INTEGER DEFAULT 8081'))
        db.session.commit()
    except Exception:
        db.session.rollback()
    
    try:
        db.session.execute(text('ALTER TABLE lab_pi ADD COLUMN active_camera VARCHAR(20) DEFAULT "none"'))
        db.session.commit()
    except Exception:
        db.session.rollback()
    
    # Migrate lab_pi table - department
    try:
        db.session.execute(text('ALTER TABLE lab_pi ADD COLUMN department_id INTEGER'))
        db.session.commit()
    except Exception:
        db.session.rollback()

with app.app_context():
    db.create_all()
    migrate_lab_pi_columns()
    # Create default admin user if not exists
    if not User.query.filter_by(email='admin@vlab.edu').first():
        admin = User(
            email='admin@vlab.edu',
            full_name='Administrator',
            is_admin=True,
            active=True
        )
        admin.password = 'Admin@123'
        db.session.add(admin)
        db.session.commit()
    
    # Create default experiments if not exists
    if not Experiment.query.first():
        experiments = [
            {
                'name': 'DC Motor Speed Control',
                'description': 'Control DC motor speed using PWM with real-time RPM feedback. Ensure stable, precise, and reliable motor performance.',
                'max_duration': 60,
                'price': 0.0
            },
            {
                'name': 'Temperature & Humidity Monitoring',
                'description': 'Interface with a DHT sensor, read environmental data, and log/visualize the readings on a real-time data chart.',
                'max_duration': 60,
                'price': 0.0
            },
            {
                'name': 'Stepper Motor Control',
                'description': 'Implement precise sequence control logic to manage angular rotation, speed, and direction of a stepper motor.',
                'max_duration': 60,
                'price': 0.0
            }
        ]
        for exp in experiments:
            experiment = Experiment(**exp)
            db.session.add(experiment)
        db.session.commit()

# Global active sessions for authorization
active_sessions = {}


def get_session_lab_pi_url(session_key):
    """Which Lab Pi backs this session, as http://ip:10000 — the one thing
    every relay/proxy route needs to know before it can act. Tries the
    in-memory active_sessions cache first (fast path, set by /experiment);
    falls back to the database so this still works after a Master restart
    (in-memory state is gone, but the booking/Session/LabPi rows aren't)."""
    if not session_key:
        return None
    cached = active_sessions.get(session_key, {}).get('lab_pi_url')
    if cached:
        return cached

    booking = Booking.query.filter_by(session_key=session_key).first()
    if not booking:
        return None
    lab_pi = LabPi.query.filter_by(experiment_id=booking.experiment_id, status='ONLINE').first()
    if not lab_pi or not lab_pi.ip_address:
        return None
    return f"http://{lab_pi.ip_address}:10000"


# Safe fallback if the Lab Pi's /api/ui-config can't be reached — controls
# default to empty (Jinja reads e.g. ui_config.controls.board_select as
# Undefined/falsy), so a fetch failure hides/disables controls rather than
# rendering them as if nothing were restricted.
FALLBACK_UI_CONFIG = {
    'controls': {},
    'defaults': {'main_view': 'plotter', 'dynamic_controls_visible': False,
                 'serial_plotter_allow_port_switch': False, 'serial_plotter_default_port_id': ''},
    'required_controls': [],
    'serial_ports': [],
    'experiment_name': None,
}


def get_lab_pi_ui_config(lab_pi_url):
    """The Lab Pi's admin-configured UI restrictions — which boards/controls
    are enabled, serial port profiles, required controls — fetched fresh on
    every /experiment load so an admin change to the Lab Pi's own settings
    takes effect on the very next session, not just the next Master deploy."""
    try:
        response = requests.get(
            f"{lab_pi_url}/api/ui-config",
            headers={'X-Master-Api-Key': MASTER_API_KEY},
            timeout=5,
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"[EXPERIMENT] Could not fetch ui-config from {lab_pi_url}: {e}")
        return FALLBACK_UI_CONFIG


def _lab_pi_admin_api(lab_pi, method, path, json_body=None):
    """Proxy an admin-config call to a Lab Pi's Tier-A JSON API (/api/admin/*)
    so the Master's admin console can edit a Lab Pi's UI/layout config without
    an admin ever visiting that Pi's own IP. Returns (ok, payload_or_error)."""
    if not lab_pi.ip_address:
        return False, "This Lab Pi has no IP address on file."
    url = f"http://{lab_pi.ip_address}:10000{path}"
    try:
        response = requests.request(
            method, url, json=json_body,
            headers={'X-Master-Api-Key': MASTER_API_KEY}, timeout=5,
        )
        response.raise_for_status()
        return True, response.json()
    except Exception as e:
        return False, f"Could not reach Lab Pi at {lab_pi.ip_address}: {e}"


def _remap_port_id_by_label(port_id, source_ports, target_ports):
    """A serial-port-profile id only means something on the Lab Pi that
    minted it — each Pi generates its own ids independently, and the actual
    device path behind a given label is different hardware per physical Pi.
    So when copying a config that references a port (a required control's
    portId, the default plotter port) to a different Lab Pi, re-resolve the
    equivalent port there by matching label, never by copying the id as-is.
    Returns (new_id_or_empty_string, warning_message_or_None)."""
    if not port_id:
        return '', None
    source_label = next((p['label'] for p in source_ports if p['id'] == port_id), None)
    if source_label is None:
        return '', None
    target_id = next((p['id'] for p in target_ports if p['label'] == source_label), None)
    if target_id is None:
        return '', f'no port labeled "{source_label}" on the target Lab Pi — cleared, set it manually'
    return target_id, None


def _control_to_rc_form(control):
    """Translate a required-control object as returned by GET /api/admin/ui-config
    (keys: type, label, portId, min, max, ...) into the rc_* field names
    POST/PUT /api/admin/controls expects (same names admin_settings.html's
    form posts) — the stored shape and the write API's input shape differ."""
    form = {
        'rc_type': control.get('type', ''),
        'rc_label': control.get('label', ''),
        'rc_port_id': control.get('portId', ''),
    }
    if control.get('type') == 'slider':
        form.update({
            'rc_min': control.get('min', 0),
            'rc_max': control.get('max', 1023),
            'rc_precision': control.get('precision', 0),
            'rc_cmd_format': control.get('cmdFormat', '{value}'),
        })
    elif control.get('type') == 'button':
        form.update({'rc_on_cmd': control.get('onCmd', '1'), 'rc_off_cmd': control.get('offCmd', '0')})
    elif control.get('type') == 'readout':
        form.update({
            'rc_data_key': control.get('dataKey', ''),
            'rc_unit': control.get('unit', ''),
            'rc_decimals': control.get('decimals', ''),
        })
    return form


def _ui_config_body_from_form(form):
    """Build the POST /api/admin/ui-config body from the shared settings
    form's fields. Shared by the plain Save action and by Copy-to (which
    saves the source Lab Pi's current on-screen edits before copying them
    onward — otherwise Copy would silently ship whatever was last saved to
    disk, not whatever's checked in the browser right now)."""
    all_keys = [k for k in (form.get('all_control_keys') or '').split(',') if k]
    controls = {key: (form.get(f'control_{key}') == 'on') for key in all_keys}
    required_prefixes = [
        kw.strip() for kw in (form.get('serial_plotter_required_prefixes') or '').split(',')
        if kw.strip()
    ]
    return {
        'controls': controls,
        'defaults': {
            'main_view': form.get('main_view'),
            'dynamic_controls_visible': form.get('dynamic_controls_visible') == 'on',
            'serial_plotter_allow_port_switch': form.get('serial_plotter_allow_port_switch') == 'on',
            'serial_plotter_default_port_id': form.get('serial_plotter_default_port_id') or '',
            'serial_plotter_required_prefixes': required_prefixes,
        },
        'experiment_name': form.get('experiment_name') or '',
    }


def end_lab_pi_session(session_key, lab_pi_url=None):
    """Tell the Lab Pi actually running this session that it's over — it
    clears its own active_sessions entry and turns its relay off — and tear
    down the Master's relay connection for it. This replaces calling the
    Master's own (long-disabled, RELAY_PIN=None) relay_off(): the relay is
    real hardware on the Lab Pi, not the Master, so only the Lab Pi can
    actually turn it off. Best-effort — a session should still be considered
    ended locally even if the Lab Pi can't be reached right now."""
    url = lab_pi_url or get_session_lab_pi_url(session_key)
    if url:
        try:
            requests.post(
                f"{url}/api/lab-pi/session-end",
                json={'session_key': session_key},
                headers={'X-Master-Api-Key': MASTER_API_KEY},
                timeout=5,
            )
        except Exception as e:
            print(f"[Session] Could not notify Lab Pi at {url} that session {session_key} ended: {e}")
    lab_pi_relay.disconnect(session_key)
    audio_relay.disconnect(session_key)


server_ready = False

# Background task for checking expired sessions
def run_session_monitor():
    """Background task to monitor and clean up expired sessions"""
    global server_ready
    
    # Wait for server to be ready before using GPIO
    print("Session monitor waiting for server to be ready...")
    while not server_ready:
        time.sleep(0.5)
    print("Session monitor ready - will check for expired sessions")
    
    while True:
        try:
            with app.app_context():
                # Check and cleanup expired sessions
                expired_keys = check_expired_sessions()
                
                # Also check database sessions that might have expired
                now = datetime.now()
                expired_db_sessions = Session.query.filter(
                    Session.status == 'ACTIVE',
                    Session.end_time < now
                ).all()
                
                for session in expired_db_sessions:
                    session.status = 'EXPIRED'
                    session_key = session.session_key
                    active_sessions.pop(session_key, None)

                    # Update the associated booking status to COMPLETED
                    if session.booking:
                        session.booking.status = 'COMPLETED'
                        session.booking.completed_at = datetime.now()

                    print(f"DB Session {session_key} expired, notifying its Lab Pi, booking marked as COMPLETED")

                    # Send session report email for expired sessions
                    try:
                        user = User.query.get(session.user_id)
                        booking = Booking.query.filter_by(session_key=session_key).first()
                        experiment_name = booking.experiment.name if booking and booking.experiment else 'Unknown'
                        
                        # Find Lab Pi for data retrieval
                        csv_data = None
                        if booking:
                            lab_pi = LabPi.query.filter_by(experiment_id=booking.experiment_id).first()
                            if lab_pi and lab_pi.ip_address:
                                csv_data = fetch_session_data_from_lab_pi(lab_pi.ip_address, session_key)
                        
                        if user and user.email:
                            send_session_report_email(
                                user_email=user.email,
                                session_key=session_key,
                                experiment_name=experiment_name,
                                booking_id=booking.id if booking else 'N/A',
                                start_time=session.start_time,
                                end_time=session.end_time,
                                duration=session.duration,
                                csv_data=csv_data,
                                experiment_id=booking.experiment_id if booking else None
                            )
                    except Exception as e:
                        print(f"[SESSION REPORT] Failed to send report for expired session {session_key}: {e}")

                    end_lab_pi_session(session_key)

                if expired_db_sessions:
                    db.session.commit()

        except Exception as e:
            print(f"Error in session monitor: {e}")
        
        # Check every 5 seconds (reduced for faster session expiry detection)
        time.sleep(5)

# Start the session monitor in background
session_monitor_thread = None

def start_session_monitor():
    global session_monitor_thread
    if session_monitor_thread is None:
        session_monitor_thread = threading.Thread(target=run_session_monitor, daemon=True)
        session_monitor_thread.start()
        print("Session monitor started")

# Lab Pi Heartbeat Monitor
LAB_PI_HEARTBEAT_TIMEOUT = 60  # seconds - considered offline if no heartbeat for 60 seconds
lab_pi_monitor_thread = None

def run_lab_pi_heartbeat_monitor():
    """Background task to check Lab Pi heartbeat and update offline status"""
    while True:
        try:
            with app.app_context():
                now = datetime.utcnow()
                timeout_threshold = now - timedelta(seconds=LAB_PI_HEARTBEAT_TIMEOUT)
                
                # Find Lab Pis that are ONLINE but haven't sent heartbeat within timeout
                offline_lab_pis = LabPi.query.filter(
                    LabPi.status == 'ONLINE',
                    LabPi.last_heartbeat < timeout_threshold
                ).all()
                
                for lab_pi in offline_lab_pis:
                    # Update status to OFFLINE
                    old_status = lab_pi.status
                    lab_pi.status = 'OFFLINE'
                    
                    # Log the offline event
                    log_entry = SystemLog(
                        level='WARNING',
                        category='SYSTEM',
                        message=f'Lab Pi {lab_pi.lab_pi_id} ({lab_pi.name}) went OFFLINE - No heartbeat received for {LAB_PI_HEARTBEAT_TIMEOUT} seconds',
                        device_id=lab_pi.id
                    )
                    db.session.add(log_entry)
                    
                    # Clear sensitive data when going offline
                    lab_pi.cpu_usage = None
                    lab_pi.ram_usage = None
                    lab_pi.temperature = None
                    lab_pi.battery_soc = None
                    lab_pi.battery_voltage = None
                    lab_pi.uptime = None
                    
                    print(f"Lab Pi {lab_pi.lab_pi_id} ({lab_pi.name}) marked as OFFLINE - No heartbeat since {lab_pi.last_heartbeat}")
                
                if offline_lab_pis:
                    db.session.commit()
                    
        except Exception as e:
            print(f"Error in Lab Pi heartbeat monitor: {e}")
        
        # Check every 10 seconds
        time.sleep(10)

def start_lab_pi_heartbeat_monitor():
    global lab_pi_monitor_thread
    if lab_pi_monitor_thread is None:
        lab_pi_monitor_thread = threading.Thread(target=run_lab_pi_heartbeat_monitor, daemon=True)
        lab_pi_monitor_thread.start()
        print("Lab Pi heartbeat monitor started")


# Relay control and serial I/O both live on the Lab Pi that owns the
# hardware now, not here — see MASTER_UI_MIGRATION_PLAN.md. What used to be
# local GPIO control (relay_on/relay_off via lgpio) and a local pyserial
# connection (ser/serial_reader_worker) were removed in favor of
# end_lab_pi_session() and lab_pi_relay, which act on the correct Lab Pi for
# each session instead of hardware attached to the Master itself.

# ---------- UTIL FUNCTIONS ----------
def check_expired_sessions():
    """Check for expired sessions and remove them from active_sessions.
    Notifies each session's own Lab Pi so it turns its relay off and tears
    down the Master's relay connection for it."""
    now = datetime.now()
    expired = []

    for session_key, session_data in active_sessions.items():
        expires_at = session_data.get('expires_at')
        if expires_at and now.timestamp() > expires_at:
            expired.append((session_key, session_data.get('lab_pi_url')))
            print(f"Session {session_key} expired, will be removed and its Lab Pi notified")

    for session_key, lab_pi_url in expired:
        active_sessions.pop(session_key, None)
        end_lab_pi_session(session_key, lab_pi_url)

    return [key for key, _ in expired]

def generate_session_key():
    return ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))

def generate_ics_calendar(experiment_name, start_time, end_time, booking_id, session_key, access_link):
    """Generate ICS calendar file content for the booking"""
    from datetime import datetime
    
    # Format times for ICS (UTC format)
    start_dt = start_time.strftime('%Y%m%dT%H%M%S') if isinstance(start_time, datetime) else start_time.replace('-', '').replace(':', '')
    end_dt = end_time.strftime('%Y%m%dT%H%M%S') if isinstance(end_time, datetime) else end_time.replace('-', '').replace(':', '')
    
    ics_content = f"""BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Virtual Lab Booking//EN
BEGIN:VEVENT
UID:booking-{booking_id}@virtuallab.com
DTSTAMP:{datetime.utcnow().strftime('%Y%m%dT%H%M%S')}Z
DTSTART:{start_dt}
DTEND:{end_dt}
SUMMARY:Virtual Lab - {experiment_name}
DESCRIPTION:Your virtual lab booking is confirmed.\\nExperiment: {experiment_name}\\nBooking ID: {booking_id}\\nSession Key: {session_key}\\nAccess Link: {access_link}
LOCATION:{access_link}
STATUS:CONFIRMED
BEGIN:VALARM
TRIGGER:-PT30M
ACTION:DISPLAY
DESCRIPTION:Reminder: Your virtual lab session starts in 30 minutes
END:VALARM
END:VEVENT
END:VCALENDAR"""
    return ics_content

def send_email(to, subject, template, attachment=None, attachment_filename=None, attachment_content_type=None):
    try:
        msg = Message(subject, recipients=[to])
        msg.html = template
        
        # Add attachment if provided (supports ICS calendar, CSV, or custom content type)
        if attachment and attachment_filename:
            content_type = attachment_content_type or 'text/calendar'
            msg.attach(filename=attachment_filename, content_type=content_type, data=attachment)
        
        mail.send(msg)
        print(f"[EMAIL] Sent successfully to: {to}")
        return True
    except Exception as e:
        print(f"[EMAIL ERROR] Failed to send to {to}: {e}")
        import traceback
        traceback.print_exc()
        return False

# ---------- SESSION REPORT EMAIL ----------
def send_session_report_email(user_email, session_key, experiment_name, booking_id, start_time, end_time, duration, csv_data=None, experiment_id=None):
    """
    Send a session report email to the user after a session closes.
    Includes session details, sensor data CSV, SOP manual, and experiment screenshot.
    """
    try:
        user = User.query.filter_by(email=user_email).first()
        user_name = user.full_name if user and user.full_name else user_email.split('@')[0]
        
        subject = f'Virtual Lab Session Report - {experiment_name}'
        
        # Format times
        start_str = start_time.strftime('%Y-%m-%d %H:%M:%S') if start_time else 'N/A'
        end_str = end_time.strftime('%Y-%m-%d %H:%M:%S') if end_time else 'N/A'
        duration_str = f'{duration} minutes' if duration else 'N/A'
        
        # Get SOP URL and Lab Pi IP for attachments
        sop_url = None
        lab_pi_ip = None
        screenshot_data = None
        sop_data = None  # Initialize for template
        
        # Get SOP from lab_pi device level (not experiment level)
        lab_pi = None
        if experiment_id:
            experiment = Experiment.query.get(experiment_id)
            if experiment:
                # Get Lab Pi for this experiment
                lab_pi = LabPi.query.filter_by(experiment_id=experiment_id).first()
                if lab_pi and lab_pi.ip_address:
                    lab_pi_ip = lab_pi.ip_address
                # Get SOP from device level (lab_pi.sop_file takes precedence)
                sop_filename = lab_pi.sop_file if lab_pi and lab_pi.sop_file else None
                if sop_filename:
                    if lab_pi_ip:
                        sop_url = f"http://{lab_pi_ip}:10000/sop/{sop_filename}"
                    else:
                        sop_url = f"http://10.114.62.73:10000/sop/{sop_filename}"
                # Fetch screenshot from Lab Pi if we have lab_pi_ip
                if lab_pi_ip:
                    try:
                        screenshot_data = fetch_screenshot_from_lab_pi(lab_pi_ip, session_key)
                        if screenshot_data:
                            print(f"[SESSION REPORT] Fetched screenshot, size: {len(screenshot_data)} bytes")
                    except Exception as e:
                        print(f"[SESSION REPORT] Failed to fetch screenshot: {e}")
        
        template = f'''
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #2c3e50;">Virtual Lab Session Report</h2>
            
            <p>Dear {user_name},</p>
            
            <p>Your virtual lab session has been completed. Here is a summary of your session:</p>
            
            <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
                <tr>
                    <td style="padding: 10px; border: 1px solid #ddd;"><strong>Experiment</strong></td>
                    <td style="padding: 10px; border: 1px solid #ddd;">{experiment_name}</td>
                </tr>
                <tr>
                    <td style="padding: 10px; border: 1px solid #ddd;"><strong>Booking ID</strong></td>
                    <td style="padding: 10px; border: 1px solid #ddd;">{booking_id}</td>
                </tr>
                <tr>
                    <td style="padding: 10px; border: 1px solid #ddd;"><strong>Session Key</strong></td>
                    <td style="padding: 10px; border: 1px solid #ddd;">{session_key}</td>
                </tr>
                <tr>
                    <td style="padding: 10px; border: 1px solid #ddd;"><strong>Start Time</strong></td>
                    <td style="padding: 10px; border: 1px solid #ddd;">{start_str}</td>
                </tr>
                <tr>
                    <td style="padding: 10px; border: 1px solid #ddd;"><strong>End Time</strong></td>
                    <td style="padding: 10px; border: 1px solid #ddd;">{end_str}</td>
                </tr>
                <tr>
                    <td style="padding: 10px; border: 1px solid #ddd;"><strong>Duration</strong></td>
                    <td style="padding: 10px; border: 1px solid #ddd;">{duration_str}</td>
                </tr>
            </table>
            
            {"<p style='color: #27ae60;'><strong>Sensor data from your session is attached as a CSV file.</strong></p>" if csv_data else "<p style='color: #e67e22;'>No sensor data was recorded during this session.</p>"}
            
            {"<p style='color: #3498db;'><strong>📄 Experiment Manual (SOP) is attached to this email.</strong></p>" if sop_data else ""}
            
            {"<p style='color: #9b59b6;'><strong>📊 Experiment screenshot is attached to this email.</strong></p>" if screenshot_data else ""}
            
            <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0;">
                <p style="margin: 0;"><strong>Session Summary:</strong></p>
                <ul style="margin: 10px 0 0 0;">
                    <li>Your experiment session has been completed successfully</li>
                    {"<li>Session sensor data has been exported and attached</li>" if csv_data else ""}
                    {"<li>Experiment manual (SOP) is attached for your reference</li>" if sop_url else ""}
                    <li>You can book another session from the Virtual Lab portal</li>
                </ul>
            </div>
            
            <p style="color: #7f8c8d; font-size: 14px;">Thank you for choosing Virtual Lab!</p>
            
            <p style="color: #7f8c8d; font-size: 14px;">Best regards,<br>Virtual Lab Team</p>
        </div>
        '''
        
        # Fetch SOP file from Lab Pi
        sop_data = None
        sop_filename = None
        if sop_url:
            try:
                sop_response = requests.get(sop_url, timeout=10)
                if sop_response.status_code == 200:
                    sop_data = sop_response.content
                    sop_filename = sop_url.split('/')[-1]
                    print(f"[SESSION REPORT] Fetched SOP: {sop_filename}")
            except Exception as e:
                print(f"[SESSION REPORT] Failed to fetch SOP: {e}")
        
        # Send email with attachments (multiple emails for multiple attachments)
        # CSV data
        if csv_data:
            send_email(user_email, subject, template,
                      attachment=csv_data, attachment_filename=f'session_{session_key}_data.csv',
                      attachment_content_type='text/csv')
        
        # SOP PDF
        if sop_data:
            send_email(user_email, subject, template,
                      attachment=sop_data, attachment_filename=f'SOP_{experiment_name}.pdf',
                      attachment_content_type='application/pdf')
        
        # Screenshot PNG
        if screenshot_data:
            send_email(user_email, subject, template,
                      attachment=screenshot_data, attachment_filename=f'experiment_screenshot.png',
                      attachment_content_type='image/png')
        
        # If no attachments, just send the email
        if not csv_data and not sop_data and not screenshot_data:
            send_email(user_email, subject, template)
        
        print(f"[SESSION REPORT] Report email sent to {user_email} for session {session_key}")
        return True
        
    except Exception as e:
        print(f"[SESSION REPORT ERROR] Failed to send session report email: {e}")
        import traceback
        traceback.print_exc()
        return False


def fetch_session_data_from_lab_pi(lab_pi_ip, session_key):
    """
    Fetch sensor data CSV from Lab Pi for a given session.
    Returns the CSV content as string, or None if unavailable.
    """
    try:
        lab_pi_url = f"http://{lab_pi_ip}:10000"
        response = requests.get(
            f"{lab_pi_url}/api/lab-pi/session-data/{session_key}",
            timeout=10
        )
        if response.status_code == 200:
            return response.text
        else:
            print(f"[SESSION DATA] No data returned from Lab Pi for session {session_key}: {response.status_code}")
            return None
    except Exception as e:
        print(f"[SESSION DATA] Failed to fetch session data from Lab Pi: {e}")
        return None


def fetch_screenshot_from_lab_pi(lab_pi_ip, session_key):
    """
    Fetch screenshot PNG from Lab Pi for a given session.
    Returns the image content as bytes, or None if unavailable.
    """
    try:
        lab_pi_url = f"http://{lab_pi_ip}:10000"
        response = requests.get(
            f"{lab_pi_url}/api/lab-pi/screenshot/{session_key}",
            timeout=10
        )
        if response.status_code == 200:
            return response.content
        else:
            print(f"[SCREENSHOT] No screenshot returned from Lab Pi for session {session_key}: {response.status_code}")
            return None
    except Exception as e:
        print(f"[SCREENSHOT] Failed to fetch screenshot from Lab Pi: {e}")
        return None


# ---------- USER AUTHENTICATION ----------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email.lower()).first()
        
        if user and user.active and user.check_password(password):
            login_user(user)
            user.last_login_at = datetime.utcnow()
            user.last_login_ip = request.remote_addr
            db.session.commit()
            
            next_page = request.args.get('next')
            return redirect(next_page if next_page else url_for('index'))
        else:
            flash('Invalid email or password', 'danger')
    
    return render_template('login.html')

# ============ GOOGLE OAUTH 2.0 LOGIN ============
@app.route('/login/google')
def google_login():
    """Initiate Google OAuth login flow"""
    google_client_id = current_app.config.get('GOOGLE_CLIENT_ID')
    if not google_client_id:
        flash('Google OAuth not configured', 'danger')
        return redirect(url_for('login'))
    
    # Generate state token for security
    state = secrets.token_hex(16)
    session['oauth_state'] = state
    
    # Build Google OAuth URL
    redirect_uri = url_for('google_callback', _external=True)
    google_auth_url = (
        'https://accounts.google.com/o/oauth2/v2/auth?'
        f'client_id={google_client_id}&'
        f'redirect_uri={redirect_uri}&'
        f'response_type=code&'
        f'scope=openid email profile&'
        f'state={state}&'
        f'access_type=offline'
    )
    return redirect(google_auth_url)

@app.route('/login/google/callback')
def google_callback():
    """Handle Google OAuth callback"""
    # Verify state token
    state = session.get('oauth_state')
    if not state or state != request.args.get('state'):
        flash('Invalid OAuth state', 'danger')
        return redirect(url_for('login'))
    
    session.pop('oauth_state', None)
    
    # Exchange authorization code for tokens
    code = request.args.get('code')
    if not code:
        flash('Authorization failed', 'danger')
        return redirect(url_for('login'))
    
    google_client_id = current_app.config.get('GOOGLE_CLIENT_ID')
    google_client_secret = current_app.config.get('GOOGLE_CLIENT_SECRET')
    redirect_uri = url_for('google_callback', _external=True)
    
    # Get tokens from Google
    token_url = 'https://oauth2.googleapis.com/token'
    token_data = {
        'code': code,
        'client_id': google_client_id,
        'client_secret': google_client_secret,
        'redirect_uri': redirect_uri,
        'grant_type': 'authorization_code'
    }
    
    try:
        token_response = requests.post(token_url, data=token_data)
        token_json = token_response.json()
        
        if 'access_token' not in token_json:
            flash('Failed to authenticate with Google', 'danger')
            return redirect(url_for('login'))
        
        access_token = token_json['access_token']
        id_token = token_json.get('id_token', '')
        
        # Get user info from Google
        user_info_url = 'https://www.googleapis.com/oauth2/v2/userinfo'
        headers = {'Authorization': f'Bearer {access_token}'}
        user_response = requests.get(user_info_url, headers=headers)
        google_user = user_response.json()
        
        if 'email' not in google_user:
            flash('Failed to get user info from Google', 'danger')
            return redirect(url_for('login'))
        
        # Only pre-existing accounts (created by an admin) may log in via
        # Google -- unlike the old behavior, an unrecognized email is never
        # auto-registered. This is what actually makes "only the uploaded
        # list can get in" true; without it, Google login was a second open
        # sign-up path regardless of what /signup did.
        user = User.query.filter_by(email=google_user['email'].lower()).first()

        if not user:
            flash('No account found for this Google account. Contact your administrator to be added.', 'danger')
            return redirect(url_for('login'))

        if not user.active:
            flash('This account has been deactivated. Contact your administrator.', 'danger')
            return redirect(url_for('login'))

        # Update existing user with Google info
        user.google_id = google_user.get('id', '')
        user.oauth_provider = 'google'

        user.last_login_at = datetime.utcnow()
        user.last_login_ip = request.remote_addr
        db.session.commit()
        
        login_user(user)
        flash('Successfully logged in with Google!', 'success')
        return redirect(url_for('index'))
        
    except Exception as e:
        print(f"Google OAuth error: {e}")
        flash('Authentication failed', 'danger')
        return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def signup():
    # Public self-registration is disabled: accounts are only created by an
    # admin (Manage Users -> Bulk Upload), which emails the person a link to
    # set their own password via the existing forgot-password flow. This
    # route is kept (rather than removed) so old bookmarked/shared links to
    # /signup get a clear explanation instead of a bare 404.
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    flash('Public sign-up is disabled. Accounts are created by an administrator — contact yours to be added, or use "Forgot password" if you already have an account.', 'info')
    return redirect(url_for('login'))

# ---------- USER PROFILE ----------
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """User profile page with edit functionality"""
    user = User.query.get(current_user.id)
    
    if request.method == 'POST':
        user.full_name = request.form.get('full_name', '').strip()
        user.username = request.form.get('username', '').strip()
        user.phone_number = request.form.get('phone_number', '').strip()
        user.sr_number = request.form.get('sr_number', '').strip() or None
        user.course_id = request.form.get('course_id', '').strip() or None
        user.course_name = request.form.get('course_name', '').strip() or None
        user.company_college_name = request.form.get('company_college', '').strip() or None
        
        # Handle profile picture upload
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and file.filename:
                filename = secure_filename(f"user_{user.id}_{file.filename}")
                upload_path = os.path.join('static', 'uploads', 'profiles')
                os.makedirs(upload_path, exist_ok=True)
                file.save(os.path.join(upload_path, filename))
                user.profile_picture = f'/static/uploads/profiles/{filename}'
        
        user.profile_complete = True
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))

    return render_template('profile.html', user=user)

@app.route('/account/password', methods=['POST'])
@login_required
def change_password():
    user = User.query.get(current_user.id)
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')

    if not user.check_password(current_password):
        flash('Current password is incorrect.', 'danger')
    elif new_password != confirm_password:
        flash('New password and confirmation do not match.', 'danger')
    elif not User.validate_password(new_password):
        flash('New password does not meet the security requirements.', 'danger')
    else:
        user.password = new_password
        db.session.commit()
        flash('Password updated successfully.', 'success')

    return redirect(url_for('profile'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'success')
    return redirect(url_for('index'))

@app.route('/forgot_password', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email.lower()).first()
        
        if user:
            token = secrets.token_urlsafe(32)
            reset_token = PasswordResetToken(user.id, token)
            db.session.add(reset_token)
            db.session.commit()
            
            reset_url = url_for('reset_password', token=token, _external=True)
            subject = 'Reset Your Password'
            template = f'''
                <h1>Password Reset Request</h1>
                <p>Click the link below to reset your password:</p>
                <a href="{reset_url}">Reset Password</a>
                <p>This link will expire in 1 hour.</p>
            '''
            
            if send_email(user.email, subject, template):
                flash('Password reset email sent. Check your inbox.', 'success')
            else:
                flash('Failed to send reset email', 'danger')
        else:
            flash('Email not registered', 'danger')
    
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    reset_token = PasswordResetToken.query.filter_by(token=token).first()
    
    if not reset_token or reset_token.is_expired():
        flash('Invalid or expired reset token', 'danger')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('reset_password', token=token))
        
        if not User.validate_password(password):
            flash('Password must be at least 8 characters long and include uppercase, lowercase, number, and special character', 'danger')
            return redirect(url_for('reset_password', token=token))
        
        user = User.query.get(reset_token.user_id)
        user.password = password
        db.session.delete(reset_token)
        db.session.commit()
        
        flash('Your password has been reset', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)

# ---------- ADMIN DASHBOARD ----------
@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        abort(403)

    try:
        # Update session statuses
        now = datetime.now()
        active_sessions_db = Session.query.filter_by(status='ACTIVE').all()
        for session in active_sessions_db:
            if now > session.end_time:
                session.status = 'EXPIRED'

        db.session.commit()

        users = User.query.all()
        experiments = Experiment.query.all()
        bookings = Booking.query.all()
        devices = Device.query.all()
        lab_pis = LabPi.query.all()
        sessions = Session.query.all()

        # Calculate online/offline/maintenance device counts from LabPi table
        online_devices = sum(1 for d in lab_pis if d.status == 'ONLINE')
        offline_devices = sum(1 for d in lab_pis if d.status == 'OFFLINE')
        maintenance_devices = sum(1 for d in lab_pis if d.status == 'MAINTENANCE')

        return render_template('admin/dashboard.html',
                             users=users,
                             experiments=experiments,
                             bookings=bookings,
                             devices=devices,
                             lab_pis=lab_pis,
                             sessions=sessions,
                             online_devices=online_devices,
                             offline_devices=offline_devices,
                             maintenance_devices=maintenance_devices)
    except Exception as e:
        print(f"Error in admin dashboard: {str(e)}")
        db.session.rollback()
        # Provide fallback data to prevent template errors
        return render_template('admin/dashboard.html',
                             users=[],
                             experiments=[],
                             bookings=[],
                             devices=[],
                             lab_pis=[],
                             sessions=[],
                             online_devices=0,
                             offline_devices=0,
                             maintenance_devices=0)

@app.route('/admin/devices', methods=['GET', 'POST'])
@login_required
def manage_devices():
    if not current_user.is_admin:
        abort(403)
    
    if request.method == 'POST':
        device = Device(
            mac_address=request.form['mac_address'],
            ip_address=request.form['ip_address'],
            device_name=request.form['device_name'],
            device_type=request.form['device_type'],
            location=request.form['location'],
            status='ONLINE',
            last_seen=datetime.utcnow()
        )
        db.session.add(device)
        db.session.commit()
        flash('Device added successfully', 'success')
        return redirect(url_for('manage_devices'))
    
    # Check Lab Pi heartbeat timeout and update status
    now = datetime.utcnow()
    timeout_threshold = now - timedelta(seconds=LAB_PI_HEARTBEAT_TIMEOUT)
    
    # Update Lab Pi statuses
    offline_lab_pis = LabPi.query.filter(
        LabPi.status == 'ONLINE',
        LabPi.last_heartbeat < timeout_threshold
    ).all()
    
    for lab_pi in offline_lab_pis:
        lab_pi.status = 'OFFLINE'
        log_entry = SystemLog(
            level='WARNING',
            category='SYSTEM',
            message=f'Lab Pi {lab_pi.lab_pi_id} ({lab_pi.name}) went OFFLINE - No heartbeat received for {LAB_PI_HEARTBEAT_TIMEOUT} seconds',
            device_id=lab_pi.id
        )
        db.session.add(log_entry)
        # Clear metrics when offline
        lab_pi.cpu_usage = None
        lab_pi.ram_usage = None
        lab_pi.temperature = None
        lab_pi.battery_soc = None
        lab_pi.battery_voltage = None
        lab_pi.uptime = None
    
    if offline_lab_pis:
        db.session.commit()
    
    devices = Device.query.all()
    lab_pis = LabPi.query.all()
    return render_template('admin/devices.html', devices=devices, lab_pis=lab_pis)

@app.route('/admin/devices/delete/<int:device_id>', methods=['POST'])
@login_required
def delete_device(device_id):
    if not current_user.is_admin:
        abort(403)
    
    device = Device.query.get(device_id)
    if device:
        db.session.delete(device)
        db.session.commit()
        flash('Device deleted successfully', 'success')
    else:
        flash('Device not found', 'danger')
    
    return redirect(url_for('manage_devices'))

@app.route('/admin/devices/edit/<int:device_id>', methods=['GET', 'POST'])
@login_required
def edit_device(device_id):
    if not current_user.is_admin:
        abort(403)
    
    device = Device.query.get(device_id)
    if not device:
        flash('Device not found', 'danger')
        return redirect(url_for('manage_devices'))
    
    if request.method == 'POST':
        device.mac_address = request.form['mac_address']
        device.ip_address = request.form['ip_address']
        device.device_name = request.form['device_name']
        device.device_type = request.form['device_type']
        device.location = request.form['location']
        db.session.commit()
        flash('Device updated successfully', 'success')
        return redirect(url_for('manage_devices'))
    
    return render_template('admin/edit_device.html', device=device, experiments=[], mapped_experiment_counts={})

@app.route('/admin/devices/view/<int:device_id>')
@login_required
def view_device(device_id):
    if not current_user.is_admin:
        abort(403)
    
    device = Device.query.get(device_id)
    if not device:
        flash('Device not found', 'danger')
        return redirect(url_for('manage_devices'))
    
    return render_template('admin/view_device.html', device=device)

@app.route('/admin/devices/toggle_maintenance/<int:device_id>', methods=['POST'])
@login_required
def toggle_maintenance_mode(device_id):
    if not current_user.is_admin:
        abort(403)
    
    device = Device.query.get(device_id)
    if device:
        device.maintenance_mode = not device.maintenance_mode
        device.status = 'MAINTENANCE' if device.maintenance_mode else 'ONLINE'
        db.session.commit()
        flash('Maintenance mode toggled successfully', 'success')
    else:
        flash('Device not found', 'danger')
    
    return redirect(url_for('manage_devices'))

@app.route('/admin/devices/restart/<int:device_id>', methods=['POST'])
@login_required
def restart_device(device_id):
    if not current_user.is_admin:
        abort(403)
    
    device = Device.query.get(device_id)
    if device:
        # In a real implementation, you would send a restart command to the device
        # For now, we'll just log it and update the last seen time
        log_entry = SystemLog(
            level='INFO',
            category='SYSTEM',
            message=f'Device restart initiated: {device.device_name}',
            device_id=device.id,
            user_id=current_user.id
        )
        db.session.add(log_entry)
        device.last_seen = datetime.utcnow()
        db.session.commit()
        flash('Device restart initiated', 'success')
    else:
        flash('Device not found', 'danger')
    
    return redirect(url_for('manage_devices'))

@app.route('/admin/devices/reboot/<int:device_id>', methods=['POST'])
@login_required
def reboot_device(device_id):
    if not current_user.is_admin:
        abort(403)
    
    device = Device.query.get(device_id)
    if device:
        # In a real implementation, you would send a reboot command to the device
        # For now, we'll just log it and update the last seen time
        log_entry = SystemLog(
            level='INFO',
            category='SYSTEM',
            message=f'Device reboot initiated: {device.device_name}',
            device_id=device.id,
            user_id=current_user.id
        )
        db.session.add(log_entry)
        device.last_seen = datetime.utcnow()
        db.session.commit()
        flash('Device reboot initiated', 'success')
    else:
        flash('Device not found', 'danger')
    
    return redirect(url_for('manage_devices'))

@app.route('/admin/devices/toggle_status/<int:device_id>', methods=['POST'])
@login_required
def toggle_device_status(device_id):
    """Toggle device between ONLINE and OFFLINE status"""
    if not current_user.is_admin:
        abort(403)
    
    device = Device.query.get(device_id)
    if device:
        # Toggle status
        if device.status == 'ONLINE':
            device.status = 'OFFLINE'
        else:
            device.status = 'ONLINE'
        
        device.last_seen = datetime.utcnow()
        db.session.commit()
        flash(f'Device {device.device_name} set to {device.status}', 'success')
    else:
        flash('Device not found', 'danger')
    
    return redirect(url_for('manage_devices'))

@app.route('/admin/devices/metrics/<int:device_id>')
@login_required
def get_device_metrics(device_id):
    if not current_user.is_admin:
        abort(403)
    
    device = Device.query.get(device_id)
    if not device:
        abort(404)
    
    # Get last 24 hours of metrics
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=24)
    
    metrics = DeviceMetric.query.filter(
        DeviceMetric.device_id == device_id,
        DeviceMetric.timestamp >= start_time,
        DeviceMetric.timestamp <= end_time
    ).order_by(DeviceMetric.timestamp).all()
    
    return jsonify({
        'device': {
            'id': device.id,
            'name': device.device_name,
            'status': device.status
        },
        'metrics': [{
            'timestamp': metric.timestamp.isoformat(),
            'cpu_usage': metric.cpu_usage,
            'ram_usage': metric.ram_usage,
            'temperature': metric.temperature,
            'battery_level': metric.battery_level,
            'battery_voltage': metric.battery_voltage,
            'ac_status': metric.ac_status,
            'charging_status': metric.charging_status
        } for metric in metrics]
    })

@app.route('/admin/logs')
@login_required
def manage_logs():
    if not current_user.is_admin:
        abort(403)
    
    category = request.args.get('category', 'ALL')
    level = request.args.get('level', 'ALL')
    device_id = request.args.get('device_id', None)
    user_id = request.args.get('user_id', None)
    
    # Build query
    logs_query = SystemLog.query
    
    if category != 'ALL':
        logs_query = logs_query.filter(SystemLog.category == category)
    
    if level != 'ALL':
        logs_query = logs_query.filter(SystemLog.level == level)
    
    if device_id:
        logs_query = logs_query.filter(SystemLog.device_id == int(device_id))
    
    if user_id:
        logs_query = logs_query.filter(SystemLog.user_id == int(user_id))
    
    logs = logs_query.order_by(SystemLog.timestamp.desc()).limit(1000).all()
    
    # Add sample logs if no logs exist
    if not logs:
        from datetime import datetime, timedelta
        
        # Check if we already have real logs
        existing_logs = SystemLog.query.count()
        if existing_logs > 0:
            # Only add sample logs if no real logs exist
            pass
        else:
            # Sample log entries (only for first-time setup)
            sample_logs = [
                {
                    'level': 'INFO',
                    'category': 'SYSTEM',
                    'message': 'System startup complete',
                    'timestamp': datetime.now() - timedelta(minutes=5)
                },
                {
                    'level': 'INFO',
                    'category': 'SYSTEM',
                    'message': 'Device Raspberry Pi 4 (ID: 1) connected',
                    'timestamp': datetime.now() - timedelta(minutes=3)
                }
            ]
            
            # Add sample logs to database
            for log in sample_logs:
                system_log = SystemLog(
                    level=log['level'],
                    category=log['category'],
                    message=log['message'],
                    timestamp=log['timestamp'],
                    device_id=1 if log['category'] in ['SYSTEM', 'EXPERIMENT'] else None,
                    user_id=1 if log['category'] in ['EXPERIMENT', 'SSH'] else None
                )
                db.session.add(system_log)
            
            db.session.commit()
        
        # Refresh logs
        logs = SystemLog.query.order_by(SystemLog.timestamp.desc()).limit(1000).all()
    
    devices = Device.query.all()
    users = User.query.all()
    
    return render_template('admin/logs.html', 
                         logs=logs,
                         devices=devices,
                         users=users,
                         selected_category=category,
                         selected_level=level,
                         selected_device=device_id,
                         selected_user=user_id)

@app.route('/admin/logs/download')
@login_required
def download_logs():
    if not current_user.is_admin:
        abort(403)
    
    category = request.args.get('category', 'ALL')
    level = request.args.get('level', 'ALL')
    device_id = request.args.get('device_id', None)
    user_id = request.args.get('user_id', None)
    
    # Build query
    logs_query = SystemLog.query
    
    if category != 'ALL':
        logs_query = logs_query.filter(SystemLog.category == category)
    
    if level != 'ALL':
        logs_query = logs_query.filter(SystemLog.level == level)
    
    if device_id:
        logs_query = logs_query.filter(SystemLog.device_id == int(device_id))
    
    if user_id:
        logs_query = logs_query.filter(SystemLog.user_id == int(user_id))
    
    logs = logs_query.order_by(SystemLog.timestamp.desc()).all()
    
    # Generate CSV content
    import csv
    from io import StringIO
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['Timestamp', 'Level', 'Category', 'Device', 'User', 'Message'])
    
    for log in logs:
        device_name = log.device.device_name if log.device else '-'
        user_name = log.user.full_name if log.user else '-'
        writer.writerow([
            log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            log.level,
            log.category,
            device_name,
            user_name,
            log.message
        ])
    
    output.seek(0)
    
    return output.getvalue(), 200, {
        'Content-Type': 'text/csv',
        'Content-Disposition': 'attachment; filename="system_logs.csv"'
    }

@app.route('/admin/analytics')
@login_required
def view_analytics():
    if not current_user.is_admin:
        abort(403)
    
    # Calculate analytics
    now = datetime.utcnow()
    
    # Devices by status (from LabPi table)
    online_devices = LabPi.query.filter_by(status='ONLINE').count()
    offline_devices = LabPi.query.filter_by(status='OFFLINE').count()
    maintenance_devices = LabPi.query.filter_by(status='MAINTENANCE').count()
    
    # Users by activity
    active_users = User.query.filter_by(active=True).count()
    total_users = User.query.count()
    
    # Experiments by activity
    active_experiments = Experiment.query.filter_by(active=True).count()
    total_experiments = Experiment.query.count()
    
    # Sessions by status
    active_sessions = Session.query.filter_by(status='ACTIVE').count()
    total_sessions = Session.query.count()
    
    # Bookings by status
    active_bookings = Booking.query.filter_by(status='ACTIVE').count()
    total_bookings = Booking.query.count()
    
    # Session analytics (active, recent, upcoming, total)
    # Active sessions (currently running)
    active_sessions_count = Session.query.filter_by(status='ACTIVE').count()
    
    # Recent sessions (last 7 days)
    seven_days_ago = now - timedelta(days=7)
    recent_sessions_count = Session.query.filter(
        Session.start_time >= seven_days_ago,
        Session.status.in_(['ACTIVE', 'EXPIRED', 'TERMINATED'])
    ).count()
    
    # Upcoming sessions (future bookings that will have sessions)
    upcoming_sessions_count = Booking.query.filter(
        Booking.start_time > now,
        Booking.status == 'UPCOMING'
    ).count()
    
    # Total sessions (all time)
    total_sessions_count = Session.query.count()
    
    # Get real data for charts (last 7 days)
    chart_data = []
    for i in range(6, -1, -1):
        day = now - timedelta(days=i)
        start_of_day = day.replace(hour=0, minute=0, second=0, microsecond=0)
        end_of_day = day.replace(hour=23, minute=59, second=59, microsecond=999999)
        
        # Device status counts for each day (from LabPi table)
        day_online = LabPi.query.filter(
            LabPi.last_heartbeat >= start_of_day,
            LabPi.last_heartbeat <= end_of_day,
            LabPi.status == 'ONLINE'
        ).count()
        
        day_offline = LabPi.query.filter(
            LabPi.last_heartbeat >= start_of_day,
            LabPi.last_heartbeat <= end_of_day,
            LabPi.status == 'OFFLINE'
        ).count()
        
        day_maintenance = LabPi.query.filter(
            LabPi.last_heartbeat >= start_of_day,
            LabPi.last_heartbeat <= end_of_day,
            LabPi.status == 'MAINTENANCE'
        ).count()
        
        # User activity for each day
        day_active_users = User.query.filter(
            User.last_login_at >= start_of_day,
            User.last_login_at <= end_of_day
        ).count()
        
        # New users for each day
        day_new_users = User.query.filter(
            User.created_at >= start_of_day,
            User.created_at <= end_of_day
        ).count()
        
        chart_data.append({
            'date': day.strftime('%a'),
            'online_devices': day_online,
            'offline_devices': day_offline,
            'maintenance_devices': day_maintenance,
            'active_users': day_active_users,
            'new_users': day_new_users
        })
    
    return render_template('admin/analytics.html',
                         online_devices=online_devices,
                         offline_devices=offline_devices,
                         maintenance_devices=maintenance_devices,
                         active_users=active_users,
                         total_users=total_users,
                         active_experiments=active_experiments,
                         total_experiments=total_experiments,
                         active_sessions=active_sessions,
                         total_sessions=total_sessions,
                         active_bookings=active_bookings,
                         total_bookings=total_bookings,
                         active_sessions_count=active_sessions_count,
                         recent_sessions_count=recent_sessions_count,
                         upcoming_sessions_count=upcoming_sessions_count,
                         total_sessions_count=total_sessions_count,
                         chart_data=chart_data)

# ---------- SYSTEM MONITORING ----------
def update_system_metrics():
    """Background task to update system metrics"""
    while True:
        try:
            with app.app_context():
                # Get system metrics
                cpu_usage = psutil.cpu_percent()
                ram_usage = psutil.virtual_memory().percent
                temperature = None
                
                # Try to get temperature (platform specific)
                if hasattr(psutil, 'sensors_temperatures'):
                    try:
                        temps = psutil.sensors_temperatures()
                        if 'cpu_thermal' in temps:
                            temperature = temps['cpu_thermal'][0].current
                        elif 'coretemp' in temps:
                            temperature = temps['coretemp'][0].current
                    except:
                        pass
                
                # Get UPS metrics
                battery_level = None
                battery_voltage = None
                ac_status = None
                charging_status = None
                
                if UPS_AVAILABLE:
                    try:
                        # First try direct reading
                        battery_level = dfrobot_ups.read_soc()
                        battery_voltage = dfrobot_ups.read_voltage()
                        ac_status_str = dfrobot_ups.ac_status()
                        ac_status = ac_status_str == "AC_CONNECTED"
                        charging_status_str = dfrobot_ups.charging_status(ac_status_str, battery_voltage)
                        charging_status = charging_status_str == "CHARGING"
                        
                        # If GPIO not available (UNKNOWN), read from UPS log file
                        if ac_status_str == "UNKNOWN":
                            # Check both admin-pi and lab-pi locations
                            base_dir = os.path.dirname(os.path.abspath(__file__))
                            project_name = os.path.basename(base_dir)
                            log_file = f"/home/{os.environ.get('USER', 'abhi')}/{project_name}/ups_log.csv"
                            if os.path.exists(log_file):
                                with open(log_file, 'r') as f:
                                    lines = f.readlines()
                                    if len(lines) > 1:
                                        last_line = lines[-1].strip()
                                        parts = last_line.split(',')
                                        if len(parts) >= 4:
                                            ac_status_str = parts[3]
                                            ac_status = ac_status_str == "AC_CONNECTED"
                                            charging_status_str = parts[4] if len(parts) > 4 else "DISCHARGING"
                                            charging_status = charging_status_str == "CHARGING"
                        
                        # If on battery, always show discharging
                        if not ac_status:
                            charging_status = False
                        
                        print(f"UPS read: SOC={battery_level}%, V={battery_voltage}, AC={ac_status_str}, CHG={charging_status_str}")
                    except Exception as e:
                        print(f"UPS read error: {e}")
                
                # Update main device metrics (assuming single device for now)
                device = Device.query.first()
                if device:
                    device.cpu_usage = cpu_usage
                    device.ram_usage = ram_usage
                    device.temperature = temperature
                    device.battery_level = battery_level
                    device.battery_voltage = battery_voltage
                    device.ac_status = ac_status
                    device.charging_status = charging_status
                    device.last_seen = datetime.utcnow()
                    
                    # Create metric history entry
                    metric = DeviceMetric(
                        device_id=device.id,
                        cpu_usage=cpu_usage,
                        ram_usage=ram_usage,
                        temperature=temperature,
                        battery_level=battery_level,
                        battery_voltage=battery_voltage,
                        ac_status=ac_status,
                        charging_status=charging_status
                    )
                    db.session.add(metric)
                    db.session.commit()
            
            # Sleep for 10 seconds before next update
            time.sleep(10)
            
        except Exception as e:
            print(f"Error updating system metrics: {e}")
            time.sleep(60)

# Start background task for system monitoring
def start_monitoring_thread():
    if not hasattr(app, 'metric_thread'):
        app.metric_thread = threading.Thread(target=update_system_metrics, daemon=True)
        app.metric_thread.start()
        print("✅ System metrics monitoring started")

# Run the monitoring thread when the application starts
with app.app_context():
    start_monitoring_thread()

@app.route('/admin/experiments', methods=['GET', 'POST'])
@login_required
def manage_experiments():
    if not current_user.is_admin:
        abort(403)
    
    if request.method == 'POST':
        experiment = Experiment(
            name=request.form['name'],
            description=request.form['description'],
            max_duration=int(request.form['max_duration'])
        )
        db.session.add(experiment)
        db.session.commit()
        flash('Experiment added successfully', 'success')
        return redirect(url_for('manage_experiments'))
    
    experiments = Experiment.query.all()
    return render_template('admin/experiments.html', experiments=experiments)

@app.route('/admin/experiments/delete/<int:exp_id>', methods=['POST'])
@login_required
def delete_experiment(exp_id):
    if not current_user.is_admin:
        abort(403)
    
    experiment = Experiment.query.get(exp_id)
    if experiment:
        # Check if there are any bookings for this experiment
        if experiment.bookings and len(experiment.bookings) > 0:
            flash(f'Cannot delete experiment "{experiment.name}" - it has {len(experiment.bookings)} associated booking(s). Please cancel or delete the bookings first.', 'danger')
            return redirect(url_for('manage_experiments'))
        
        # Also check Lab Pis assigned to this experiment
        if experiment.lab_pis and len(experiment.lab_pis) > 0:
            flash(f'Cannot delete experiment "{experiment.name}" - it is assigned to {len(experiment.lab_pis)} Lab Pi device(s). Please unassign them first.', 'danger')
            return redirect(url_for('manage_experiments'))
        
        db.session.delete(experiment)
        db.session.commit()
        flash('Experiment deleted successfully', 'success')
    else:
        flash('Experiment not found', 'danger')
    
    return redirect(url_for('manage_experiments'))

@app.route('/admin/experiments/view/<int:exp_id>')
@login_required
def view_experiment(exp_id):
    if not current_user.is_admin:
        abort(403)
    
    experiment = Experiment.query.get_or_404(exp_id)
    return render_template('admin/view_experiment.html', experiment=experiment)

@app.route('/admin/experiments/edit/<int:exp_id>', methods=['GET', 'POST'])
@login_required
def edit_experiment(exp_id):
    if not current_user.is_admin:
        abort(403)
    
    experiment = Experiment.query.get(exp_id)
    if not experiment:
        flash('Experiment not found', 'danger')
        return redirect(url_for('manage_experiments'))
    
    if request.method == 'POST':
        experiment.name = request.form['name']
        experiment.description = request.form['description']
        experiment.max_duration = int(request.form['max_duration'])
        experiment.active = 'active' in request.form
        db.session.commit()
        flash('Experiment updated successfully', 'success')
        return redirect(url_for('manage_experiments'))
    
    return render_template('admin/edit_experiment.html', experiment=experiment)

@app.route('/admin/sop/upload', methods=['POST'])
@login_required
def upload_sop_file():
    if not current_user.is_admin:
        abort(403)
    
    if 'sop_file' not in request.files:
        return jsonify({'success': False, 'error': 'No file provided'})
    
    file = request.files['sop_file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'})
    
    if not file.filename.lower().endswith('.pdf'):
        return jsonify({'success': False, 'error': 'Only PDF files are allowed'})
    
    # Sanitize filename
    filename = secure_filename(file.filename)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"{timestamp}_{filename}"
    
    # Get the assigned lab-pi for this experiment (if any)
    experiment_id = request.form.get('experiment_id')
    lab_pi = None
    if experiment_id:
        lab_pi = LabPi.query.filter_by(experiment_id=experiment_id).first()
    
    # Upload to lab-pi if we have its IP
    if lab_pi and lab_pi.ip_address:
        try:
            files = {'file': (filename, file.read(), 'application/pdf')}
            # Reset file pointer
            file.seek(0)
            files = {'file': (filename, file.read(), 'application/pdf')}
            response = requests.post(
                f"http://{lab_pi.ip_address}:10000/upload-sop",
                files=files,
                timeout=10
            )
            if response.status_code == 200:
                return jsonify({'success': True, 'filename': filename})
            else:
                return jsonify({'success': False, 'error': f'Lab Pi upload failed: {response.status_code}'})
        except Exception as e:
            return jsonify({'success': False, 'error': f'Failed to upload to lab-pi: {str(e)}'})
    else:
        # No lab-pi assigned - just save filename to experiment
        return jsonify({'success': True, 'filename': filename})

@app.route('/admin/users')
@login_required
def manage_users():
    if not current_user.is_admin:
        abort(403)
    
    # Get search query
    search_query = request.args.get('search', '').strip()
    
    # Base query
    query = User.query
    
    # Apply search filter
    if search_query:
        query = query.filter(
            db.or_(
                User.full_name.ilike(f'%{search_query}%'),
                User.email.ilike(f'%{search_query}%')
            )
        )
    
    users = query.order_by(User.created_at.desc()).all()
    return render_template('admin/users.html', users=users, search_query=search_query)

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        abort(403)
    
    user = User.query.get(user_id)
    if user and not user.is_admin:  # Prevent deleting admin
        try:
            # Delete associated bookings first
            Booking.query.filter_by(user_id=user_id).delete()
            
            # Delete associated sessions
            Session.query.filter_by(user_id=user_id).delete()
            
            # Delete password reset tokens
            PasswordResetToken.query.filter_by(user_id=user_id).delete()
            
            # Now delete the user
            db.session.delete(user)
            db.session.commit()
            flash('User deleted successfully', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error deleting user: {str(e)}', 'danger')
    else:
        flash('User not found or cannot be deleted', 'danger')
    
    return redirect(url_for('manage_users'))

@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_admin:
        abort(403)
    
    user = User.query.get(user_id)
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('manage_users'))
    
    if request.method == 'POST':
        user.full_name = request.form.get('full_name', user.full_name)
        user.phone_number = request.form.get('phone_number', None) or None
        user.sr_number = request.form.get('sr_number', None) or None
        user.course_id = request.form.get('course_id', None) or None
        user.course_name = request.form.get('course_name', None) or None
        user.company_college_name = request.form.get('company_college_name', None) or None
        user.active = 'active' in request.form
        
        # Handle password reset
        new_password = request.form.get('new_password', '')
        if new_password:
            user.password = new_password
        
        db.session.commit()
        flash('User updated successfully', 'success')
        return redirect(url_for('manage_users'))
    
    return render_template('admin/edit_user.html', user=user)

@app.route('/admin/users/view/<int:user_id>')
@login_required
def view_user(user_id):
    if not current_user.is_admin:
        abort(403)
    
    user = User.query.get(user_id)
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('manage_users'))
    
    return render_template('admin/view_user.html', user=user)

# ============ BULK USER REGISTRATION ============
@app.route('/admin/users/bulk-upload', methods=['GET', 'POST'])
@login_required
def bulk_user_upload():
    """Bulk upload users via CSV file"""
    if not current_user.is_admin:
        abort(403)
    
    if request.method == 'POST':
        if 'csv_file' not in request.files:
            flash('No file selected', 'danger')
            return redirect(request.url)
        
        file = request.files['csv_file']
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(request.url)
        
        if not file.filename.endswith('.csv'):
            flash('Please upload a CSV file', 'danger')
            return redirect(request.url)
        
        try:
            # Parse CSV file
            stream = io.StringIO(file.stream.read().decode('UTF8'))
            csv_reader = csv.DictReader(stream)
            
            users_created = 0
            users_skipped = 0
            errors = []
            
            # Track password for each successful user
            user_passwords = []
            
            for row_num, row in enumerate(csv_reader, start=2):
                try:
                    # Required fields
                    email = row.get('Email', '').strip().lower()
                    name = row.get('Name', '').strip()
                    sr_number = row.get('SR Number', '').strip()
                    
                    if not email or not name:
                        errors.append(f"Row {row_num}: Missing required fields (Email/Name)")
                        users_skipped += 1
                        continue
                    
                    # Check if user already exists
                    if User.query.filter_by(email=email).first():
                        errors.append(f"Row {row_num}: Email '{email}' already exists")
                        users_skipped += 1
                        continue
                    
                    # Optional fields
                    phone = row.get('Phone Number', '').strip()
                    course_id = row.get('Course ID', '').strip()
                    course_name = row.get('Course Name', '').strip()
                    department_name = row.get('Department Name', '').strip()
                    company_college = row.get('Company/College Name', '').strip()
                    
                    # Find or create department
                    department = None
                    if department_name:
                        department = Department.query.filter(
                            db.or_(
                                Department.name == department_name,
                                Department.code == department_name.upper()
                            )
                        ).first()
                    
                    # Note: Users will set their own password using forgot password
                    # No temporary password generated
                    
                    try:
                        # Create user without setting password (user will use forgot password)
                        user = User(
                            email=email,
                            full_name=name,
                            sr_number=sr_number or None,
                            phone_number=phone or None,
                            course_id=course_id or None,
                            course_name=course_name or None,
                            department=department,
                            company_college_name=company_college or None,
                            active=True,
                            profile_complete=False,
                            password_hash='PENDING_RESET'  # Placeholder until user sets password
                        )
                        db.session.add(user)
                        db.session.flush()
                        
                        # Send welcome email with password reset link
                        email_subject = "Welcome to Virtual Lab - Account Created"
                        email_body = f"""
                        <html>
                        <body>
                            <h2>Welcome to Virtual Lab!</h2>
                            <p>Hello {name},</p>
                            <p>Your account has been created successfully by the administrator.</p>
                            <p>To set your password, please use the forgot password feature:</p>
                            <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; text-align: center;">
                                <a href="{request.host_url}forgot_password" style="background: #00C4FF; color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px; display: inline-block;">
                                    Set Your Password
                                </a>
                            </div>
                            <p>Or copy this link to your browser:<br>{request.host_url}forgot_password</p>
                            <p><strong>Note:</strong> Click "Set Your Password" above, enter your email ({email}), and you'll receive a password reset link to create your own password.</p>
                            <br>
                            <p>Best regards,<br>Virtual Lab Team</p>
                        </body>
                        </html>
                        """
                        send_email(email, email_subject, email_body)
                        users_created += 1
                        user_passwords.append({'email': email, 'name': name, 'password': 'Use forgot password'})
                    except ValueError as ve:
                        # Password validation failed, create user with placeholder password
                        user = User(
                            email=email,
                            full_name=name,
                            sr_number=sr_number or None,
                            phone_number=phone or None,
                            course_id=course_id or None,
                            course_name=course_name or None,
                            department=department,
                            company_college_name=company_college or None,
                            active=True,
                            profile_complete=False,
                            password_hash='PENDING_RESET'  # Placeholder until user sets password
                        )
                        db.session.add(user)
                        db.session.flush()
                        
                        # Send welcome email with password reset link
                        email_subject = "Welcome to Virtual Lab - Account Created"
                        email_body = f"""
                        <html>
                        <body>
                            <h2>Welcome to Virtual Lab!</h2>
                            <p>Hello {name},</p>
                            <p>Your account has been created successfully by the administrator.</p>
                            <p>To set your password, please use the forgot password feature:</p>
                            <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; text-align: center;">
                                <a href="{request.host_url}forgot_password" style="background: #00C4FF; color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px; display: inline-block;">
                                    Set Your Password
                                </a>
                            </div>
                            <p>Or copy this link to your browser:<br>{request.host_url}forgot_password</p>
                            <p><strong>Note:</strong> Click "Set Your Password" above, enter your email ({email}), and you'll receive a password reset link to create your own password.</p>
                            <br>
                            <p>Best regards,<br>Virtual Lab Team</p>
                        </body>
                        </html>
                        """
                        send_email(email, email_subject, email_body)
                        users_created += 1
                        user_passwords.append({'email': email, 'name': name, 'password': 'Use forgot password'})
                    
                except Exception as e:
                    errors.append(f"Row {row_num}: {str(e)}")
                    users_skipped += 1
            
            db.session.commit()
            
            message = f'Created {users_created} users. Skipped {users_skipped} users.'
            emails_sent = sum(1 for up in user_passwords if up.get('email_sent', False))
            
            if user_passwords:
                # Save passwords to a file for admin to download
                import csv as csv_module
                password_file = os.path.join('uploads', f'user_passwords_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv')
                with open(password_file, 'w', newline='') as f:
                    writer = csv_module.writer(f)
                    writer.writerow(['Email', 'Name', 'Generated Password'])
                    for up in user_passwords:
                        writer.writerow([up['email'], up['name'], up['password']])
                flash(f'{message} Welcome emails have been sent to all users.', 'success')
            elif errors:
                flash(f'{message} See logs for details.', 'warning')
                print(f"CSV Import Errors: {errors}")
            else:
                flash(message, 'success')
            
            return redirect(url_for('manage_users'))
            
        except Exception as e:
            flash(f'Error processing CSV: {str(e)}', 'danger')
            print(f"CSV Import Error: {e}")
    
    return render_template('admin/bulk_user_upload.html')

@app.route('/admin/users/download-template')
@login_required
def download_csv_template():
    """Download CSV template for bulk user registration"""
    if not current_user.is_admin:
        abort(403)
    
    template = "Name,Email,Phone Number,SR Number,Course ID,Course Name,Department Name,Company/College Name\n"
    template += "John Doe,john.doe@example.com,9876543210,SR001,CSE101,B.Tech Computer Science,Computer Science,University Name"
    
    return Response(
        template,
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=user_registration_template.csv'}
    )

# ============ DEPARTMENT MANAGEMENT ============
@app.route('/admin/departments')
@login_required
def manage_departments():
    """Manage departments"""
    if not current_user.is_admin:
        abort(403)
    
    departments = Department.query.all()
    total_lab_pis = sum(len(d.lab_pis) for d in departments)
    total_users = sum(len(d.users) for d in departments)
    return render_template('admin/departments.html', departments=departments, total_lab_pis=total_lab_pis, total_users=total_users)

@app.route('/admin/departments/add', methods=['POST'])
@login_required
def add_department():
    """Add new department"""
    if not current_user.is_admin:
        abort(403)
    
    name = request.form.get('name', '').strip()
    code = request.form.get('code', '').strip().upper()
    description = request.form.get('description', '').strip()
    
    if not name or not code:
        flash('Name and Code are required', 'danger')
        return redirect(url_for('manage_departments'))
    
    if Department.query.filter_by(code=code).first():
        flash('Department code already exists', 'danger')
        return redirect(url_for('manage_departments'))
    
    department = Department(
        name=name,
        code=code,
        description=description or None
    )
    db.session.add(department)
    db.session.commit()
    
    flash('Department added successfully', 'success')
    return redirect(url_for('manage_departments'))

@app.route('/admin/departments/edit/<int:dept_id>', methods=['POST'])
@login_required
def edit_department(dept_id):
    """Edit department"""
    if not current_user.is_admin:
        abort(403)
    
    department = Department.query.get(dept_id)
    if not department:
        flash('Department not found', 'danger')
        return redirect(url_for('manage_departments'))
    
    name = request.form.get('name', '').strip()
    code = request.form.get('code', '').strip().upper()
    description = request.form.get('description', '').strip()
    active = request.form.get('active') == 'on'
    
    if not name or not code:
        flash('Name and Code are required', 'danger')
        return redirect(url_for('manage_departments'))
    
    # Check if code already exists (excluding this department)
    existing = Department.query.filter(
        Department.code == code,
        Department.id != dept_id
    ).first()
    if existing:
        flash('Department code already exists', 'danger')
        return redirect(url_for('manage_departments'))
    
    department.name = name
    department.code = code
    department.description = description or None
    department.active = active
    db.session.commit()
    
    flash('Department updated successfully', 'success')
    return redirect(url_for('manage_departments'))

@app.route('/admin/departments/delete/<int:dept_id>', methods=['POST'])
@login_required
def delete_department(dept_id):
    """Delete department"""
    if not current_user.is_admin:
        abort(403)
    
    department = Department.query.get(dept_id)
    if not department:
        flash('Department not found', 'danger')
        return redirect(url_for('manage_departments'))
    
    # Check if department has associated users or lab pis
    if department.users.count() > 0 or department.lab_pis.count() > 0:
        flash('Cannot delete department with associated users or Lab Pis. Please reassign them first.', 'danger')
        return redirect(url_for('manage_departments'))
    
    db.session.delete(department)
    db.session.commit()
    
    flash('Department deleted successfully', 'success')
    return redirect(url_for('manage_departments'))

@app.route('/admin/bookings')
@login_required
def manage_bookings():
    if not current_user.is_admin:
        abort(403)
    
    # Get filter parameters
    status_filter = request.args.get('status', '')
    user_filter = request.args.get('user', '')
    experiment_filter = request.args.get('experiment', '')
    date_filter = request.args.get('date', '')
    
    # Base query
    query = Booking.query
    
    # Apply filters
    if status_filter:
        query = query.filter(Booking.status == status_filter)
    if user_filter:
        query = query.join(User).filter(User.full_name.ilike(f'%{user_filter}%'))
    if experiment_filter:
        query = query.join(Experiment).filter(Experiment.name.ilike(f'%{experiment_filter}%'))
    if date_filter:
        query = query.filter(db.func.date(Booking.start_time) == date_filter)
    
    bookings = query.order_by(Booking.start_time.desc()).all()
    
    # Get all users and experiments for filter dropdowns
    users = User.query.all()
    experiments = Experiment.query.all()
    
    return render_template('admin/bookings.html', bookings=bookings, users=users, experiments=experiments,
                         current_status=status_filter, current_user=user_filter, current_experiment=experiment_filter, current_date=date_filter)

@app.route('/admin/bookings/delete/<int:booking_id>', methods=['POST'])
@login_required
def delete_booking(booking_id):
    if not current_user.is_admin:
        abort(403)
    
    booking = Booking.query.get(booking_id)
    if booking:
        try:
            # Delete related session first if exists
            if booking.session:
                db.session.delete(booking.session)
            db.session.delete(booking)
            db.session.commit()
            flash('Booking deleted successfully', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error deleting booking: {str(e)}', 'danger')
    else:
        flash('Booking not found', 'danger')
    
    return redirect(url_for('manage_bookings'))

@app.route('/admin/sessions')
@login_required
def manage_sessions():
    if not current_user.is_admin:
        abort(403)
    
    # Update session statuses
    now = datetime.now()
    active_sessions_db = Session.query.filter_by(status='ACTIVE').all()
    for session in active_sessions_db:
        if now > session.end_time:
            session.status = 'EXPIRED'
    
    db.session.commit()
    
    # Get filter parameters
    status_filter = request.args.get('status', '')
    user_filter = request.args.get('user', '')
    date_filter = request.args.get('date', '')
    
    # Base query
    query = Session.query
    
    # Apply filters
    if status_filter:
        query = query.filter(Session.status == status_filter)
    if user_filter:
        query = query.join(User).filter(User.full_name.ilike(f'%{user_filter}%'))
    if date_filter:
        query = query.filter(db.func.date(Session.start_time) == date_filter)
    
    sessions = query.order_by(Session.start_time.desc()).all()
    
    # Get all users for filter dropdown
    users = User.query.all()
    
    return render_template('admin/sessions.html', sessions=sessions, users=users,
                         current_status=status_filter, current_user=user_filter, current_date=date_filter)

@app.route('/admin/sessions/delete/<int:session_id>', methods=['POST'])
@login_required
def delete_session(session_id):
    if not current_user.is_admin:
        abort(403)
    
    session = Session.query.get(session_id)
    if session:
        db.session.delete(session)
        db.session.commit()
        flash('Session deleted successfully', 'success')
    else:
        flash('Session not found', 'danger')
    
    return redirect(url_for('manage_sessions'))

@app.route('/admin/booking/<int:booking_id>')
@login_required
def view_booking(booking_id):
    if not current_user.is_admin:
        abort(403)
    
    booking = Booking.query.get(booking_id)
    if not booking:
        abort(404)
    
    return render_template('admin/view_booking.html', booking=booking)

@app.route('/admin/session/<int:session_id>')
@login_required
def view_session(session_id):
    if not current_user.is_admin:
        abort(403)
    
    session = Session.query.get(session_id)
    if not session:
        abort(404)
    
    return render_template('admin/view_session.html', session=session)

# ---------- MAIN ROUTES ----------
def _experiment_bench_status(exp_id):
    """'online' if any assigned LabPi is online, 'offline' if benches exist but none online,
    'none' if no bench is assigned to this experiment yet."""
    benches = LabPi.query.filter_by(experiment_id=exp_id).all()
    if not benches:
        return 'none'
    if any(b.status == 'ONLINE' for b in benches):
        return 'online'
    return 'offline'

@app.route('/')
def index():
    experiments = Experiment.query.filter_by(active=True).all()
    bench_status = {exp.id: _experiment_bench_status(exp.id) for exp in experiments}
    bookings = []
    if current_user.is_authenticated:
        bookings = Booking.query.filter_by(user_id=current_user.id).order_by(Booking.start_time.desc()).all()
        
        # Update booking statuses
        now = datetime.now()
        for booking in bookings:
            if booking.status == 'UPCOMING':
                if now < booking.start_time:
                    booking.status = 'UPCOMING'
                elif booking.start_time <= now <= booking.end_time:
                    booking.status = 'ACTIVE'
                elif now > booking.end_time:
                    booking.status = 'EXPIRED'
            elif booking.status == 'ACTIVE':
                if now > booking.end_time:
                    booking.status = 'EXPIRED'
            elif booking.status == 'IN_PROGRESS':
                # Calculate duration from start and end time
                duration = (booking.end_time - booking.start_time).total_seconds() // 60
                # Mark as COMPLETED only if end_time has passed OR if started_at + duration has passed
                if now > booking.end_time:
                    booking.status = 'COMPLETED'
                    booking.completed_at = datetime.now()
                elif booking.started_at and now > booking.started_at + timedelta(minutes=duration):
                    booking.status = 'COMPLETED'
                    booking.completed_at = datetime.now()
        
        # Update session statuses
        active_sessions_db = Session.query.filter_by(status='ACTIVE').all()
        for session in active_sessions_db:
            if now > session.end_time:
                session.status = 'EXPIRED'
        
        db.session.commit()
    
    # Separate bookings by status for homepage
    upcoming_statuses = ['UPCOMING', 'ACTIVE', 'IN_PROGRESS']
    upcoming_bookings = [b for b in bookings if b.status in upcoming_statuses] if current_user.is_authenticated else []
    completed_bookings = [b for b in bookings if b.status == 'COMPLETED'] if current_user.is_authenticated else []
    
    return render_template('homepage.html', experiments=experiments, bench_status=bench_status, upcoming_bookings=upcoming_bookings, bookings_count={'upcoming': len(upcoming_bookings), 'completed': len(completed_bookings)})

@app.route('/experiment')
@login_required
def experiment():
    session_key = request.args.get('key')
    
    if not session_key:
        return render_template('expired_session.html')
    
    # Clean up any expired sessions and turn off relay
    check_expired_sessions()
    
    # First check if there's a booking with this session key
    booking = Booking.query.filter_by(session_key=session_key).first()
    
    if not booking:
        return render_template('expired_session.html')
    
    # Check if user owns the booking
    if booking.user_id != current_user.id:
        return render_template('expired_session.html')
    
    # Check if booking is active (using naive datetime for simplicity)
    now = datetime.now()
    if not (booking.start_time <= now <= booking.end_time):
        return redirect(url_for('index'))
    
    # Check if there's a session entry, create if not
    session = Session.query.filter_by(session_key=session_key).first()
    if not session:
        # Check if booking is already completed - prevent re-entering completed session
        if booking.status == 'COMPLETED':
            print(f"[Session] Booking already completed, blocking access: {session_key}")
            return render_template('expired_session.html', message="This session has already been completed.")
        
        # Naive local time, matching booking.start_time/end_time (parsed from the
        # booking form as local wall-clock time, not UTC) and the session-expiry
        # monitor (which compares Session.end_time against datetime.now(), also
        # local). Using utcnow() here — a naive value read back as if it *were*
        # local — made every session appear to have expired hours in the past
        # the instant it was created, on any server not set to UTC.
        session_start = datetime.now()
        # The session must never run past the booked slot's own end time —
        # it was previously given a fresh full-length window starting from
        # whenever the student actually clicked in, so joining 30 minutes
        # into a 60-minute booking gave another full 60 minutes instead of
        # the 30 actually left. Duration is however much of the booked slot
        # remains right now, which is 0 (not negative) if they're right at
        # the edge of it — booking.start_time <= now <= booking.end_time is
        # already guaranteed above.
        session_end = booking.end_time
        session_duration_minutes = max(0, (session_end - session_start).total_seconds() // 60)
        
        print(f"[Session] Creating session: duration={session_duration_minutes} min, start={session_start}, end={session_end}")
        
        session = Session(
            booking_id=booking.id,
            user_id=current_user.id,
            session_key=booking.session_key,
            duration=session_duration_minutes,
            end_time=session_end,
            ip_address=request.remote_addr,
            status='ACTIVE'
        )
        db.session.add(session)
        booking.status = 'IN_PROGRESS'
        db.session.commit()
    else:
        # Session exists - check if already completed
        if session.status == 'COMPLETED':
            print(f"[Session] Session already COMPLETED in DB, blocking access: {session_key}, status={session.status}")
            return render_template('expired_session.html', message="This session has already been completed.")
        elif session.status == 'EXPIRED':
            print(f"[Session] Session EXPIRED, blocking access: {session_key}")
            return render_template('expired_session.html', message="This session has expired.")
        else:
            print(f"[Session] Rejoining existing session: {session_key}, status={session.status}")
    
    # Find Lab Pi for this experiment. Several Lab Pis can now serve the same
    # experiment concurrently, so this can't just be "the first online one"
    # (today's own `.first()` behavior) — that would shove every overlapping
    # booking onto the same physical Pi while a second free one sits idle.
    #
    # Tier 1: this session already has a Lab Pi bound (page refresh mid-session)
    # — reuse it, never re-pick, so a rejoin can't land on different hardware.
    bound_lab_pi_id = active_sessions.get(session_key, {}).get('lab_pi_id')
    lab_pi = LabPi.query.filter_by(lab_pi_id=bound_lab_pi_id, status='ONLINE').first() if bound_lab_pi_id else None
    # Tier 2: same, but survives a Master restart (active_sessions is
    # in-memory) — the Lab Pi's own heartbeat already reported this
    # session_key as the one it's running.
    if not lab_pi:
        lab_pi = LabPi.query.filter_by(
            experiment_id=booking.experiment_id, current_session_key=session_key, status='ONLINE'
        ).first()
    # Tier 3: fresh assignment — any online Lab Pi for this experiment that
    # isn't already busy with a *different* session. `async_mode='threading'`
    # means two students' /experiment requests genuinely run concurrently
    # (this app is multi-threaded, and the network call to a Lab Pi further
    # down blocks and releases the GIL) — a plain "read candidates, pick one
    # in Python" has a window where two requests both see the same Lab Pi as
    # free and both pick it, especially if that network call is slow. Closing
    # that window needs the claim itself to be atomic: a single UPDATE ...
    # WHERE current_session_key IS NULL only succeeds for whichever request's
    # claim actually lands first — a second request racing for the same row
    # gets rowcount 0 and moves on to the next candidate.
    fresh_claim = False
    if not lab_pi:
        candidates = LabPi.query.filter_by(experiment_id=booking.experiment_id, status='ONLINE').all()
        busy_elsewhere = {
            info.get('lab_pi_id') for key, info in active_sessions.items()
            if key != session_key and info.get('lab_pi_id')
        }
        for candidate in candidates:
            if candidate.lab_pi_id in busy_elsewhere:
                continue
            claimed = LabPi.query.filter_by(id=candidate.id, current_session_key=None).update(
                {'current_session_key': session_key, 'session_start_time': datetime.utcnow()},
                synchronize_session=False,
            )
            db.session.commit()
            if claimed:
                lab_pi = candidate
                fresh_claim = True
                break

    print(f"[EXPERIMENT] Looking for Lab Pi: experiment_id={booking.experiment_id}, found={lab_pi}")

    if not lab_pi or not lab_pi.ip_address:
        # No hardware currently reachable for this experiment. Do NOT send the
        # browser to a Lab Pi's own address (see MASTER_UI_MIGRATION_PLAN.md —
        # the browser must only ever talk to the Master PC) and do not render
        # a page that looks live but has nothing behind it either.
        return render_template('expired_session.html', message="No hardware is currently online for this experiment. Please try again shortly or contact support.")

    lab_pi_url = f"http://{lab_pi.ip_address}:10000"  # Lab Pi runs on port 10000
    print(f"[EXPERIMENT] Found Lab Pi: {lab_pi.lab_pi_id} at {lab_pi_url}")

    # Device-level override takes precedence over the experiment's own default
    exp_name = booking.experiment.name if booking.experiment else 'Unknown'
    board_type = lab_pi.board_type or (booking.experiment.board_type if booking.experiment else 'arduino')
    sop_file = lab_pi.sop_file or (booking.experiment.sop_file if booking.experiment else None)

    # Tell the Lab Pi a session is starting so it accepts the commands the
    # Master is about to relay to it (flash/factory-reset/relay all require
    # current_session_key to be set on the Lab Pi side).
    lab_pi_notified = False
    try:
        response = requests.post(
            f"{lab_pi_url}/api/lab-pi/session-start",
            json={
                'session_key': session_key,
                'booking_id': booking.id,
                'user_email': current_user.email,
                'session_end_time': int(booking.end_time.timestamp() * 1000),  # JS milliseconds
                'experiment_name': exp_name,
                'board_type': board_type,
                'sop_file': sop_file
            },
            headers={'X-Lab-Pi-Id': lab_pi.lab_pi_id, 'X-Master-Api-Key': MASTER_API_KEY},
            timeout=5
        )
        print(f"[EXPERIMENT] Lab Pi notification response: {response.status_code}")
        response.raise_for_status()
        lab_pi_notified = True
        # current_session_key/session_start_time are already set — by the
        # atomic claim above for a fresh assignment, or already correct from
        # a prior call for a rejoin — no need to write them again here.

        log_entry = SystemLog(
            level='INFO',
            category='EXPERIMENT',
            message=f'Session started: {current_user.email} - Experiment: {exp_name} - Lab Pi: {lab_pi.lab_pi_id}',
            device_id=lab_pi.id,
            user_id=current_user.id
        )
        db.session.add(log_entry)
        db.session.commit()
    except Exception as e:
        print(f"[EXPERIMENT] Failed to notify Lab Pi: {e}")

    if not lab_pi_notified:
        if fresh_claim:
            # This claim was never confirmed by the Lab Pi — release it so a
            # transient network blip doesn't permanently strand the Lab Pi as
            # "busy" with a session that never actually started on it.
            LabPi.query.filter_by(id=lab_pi.id, current_session_key=session_key).update(
                {'current_session_key': None}, synchronize_session=False
            )
            db.session.commit()
        return render_template('expired_session.html', message="Could not reach the Lab Pi for this experiment. Please try again shortly or contact support.")

    # Every proxy/relay route (toggle_relay, flash, factory_reset, ports, the
    # SocketIO relay) reads lab_pi_url straight from here — this is the one
    # place a session gets bound to the specific Lab Pi handling it.
    active_sessions[session_key] = {
        'start_time': time.time(),
        'duration': session.duration,
        'expires_at': session.end_time.timestamp(),
        'lab_pi_id': lab_pi.lab_pi_id,
        'lab_pi_url': lab_pi_url
    }

    duration = session.duration
    session_end_time = int(session.end_time.timestamp() * 1000)

    print(f"[Experiment] Session end time: {session_end_time}, booking end_time: {session.end_time}, duration: {duration}")

    ui_config = get_lab_pi_ui_config(lab_pi_url)

    # Always render the Master's own page — never redirect the browser to
    # the Lab Pi's address. Its JS talks back to Master routes/sockets only,
    # which proxy through to lab_pi_url server-side.
    return render_template('index.html',
        session_duration=duration,
        session_end_time=session_end_time,
        session_key=session_key,
        lab_pi_id=lab_pi.lab_pi_id,
        board_type=board_type,
        experiment_name=exp_name,
        ui_config=ui_config,
        booking_page_url=url_for('my_bookings'),
    )

@app.route('/add_session', methods=['POST'])
@login_required
def add_session():
    data = request.get_json()
    session_key = data.get('session_key')
    duration = data.get('duration', 5)
    
    if session_key:
        active_sessions[session_key] = {
            'start_time': time.time(),
            'duration': duration,
            'expires_at': time.time() + (duration * 60)
        }
    
    return jsonify({'status': 'added'})

@app.route('/remove_session', methods=['POST'])
@login_required
def remove_session():
    data = request.get_json()
    session_key = data.get('session_key')
    if session_key in active_sessions:
        lab_pi_url = active_sessions[session_key].get('lab_pi_url')
        del active_sessions[session_key]
        end_lab_pi_session(session_key, lab_pi_url)
    return jsonify({'status': 'removed'})

@app.route('/toggle_relay', methods=['POST'])
@login_required
def toggle_relay():
    data = request.get_json()
    state = data.get('state')
    session_key = data.get('session_key')

    # Check for expired sessions first and clean them up
    check_expired_sessions()

    if session_key not in active_sessions:
        return jsonify({'status': 'error', 'message': 'Invalid or expired session'}), 400

    lab_pi_url = active_sessions[session_key].get('lab_pi_url')
    if not lab_pi_url:
        return jsonify({'status': 'error', 'message': 'No Lab Pi assigned to this session'}), 400

    # Forward relay control to the session's own Lab Pi (which owns the
    # actual GPIO) — never a hardcoded address, since different sessions can
    # be running on different Lab Pis at the same time.
    try:
        response = requests.post(f'{lab_pi_url}/toggle_relay',
                               json={'state': state, 'session_key': session_key}, timeout=5)
        result = response.json()
        return jsonify(result)
    except Exception as e:
        print(f"Error calling lab-pi relay: {e}")
        return jsonify({'status': 'error', 'message': f'Failed to control relay: {str(e)}'})

# Debug endpoint to test relay without session
@app.route('/test_relay', methods=['POST'])
def test_relay():
    """Test endpoint to toggle relay - calls lab-pi API"""
    data = request.get_json()
    state = data.get('state')
    
    # Forward to lab-pi
    try:
        response = requests.post('http://localhost:10000/toggle_relay', 
                               json={'state': state, 'session_key': 'test'}, timeout=5)
        result = response.json()
        return jsonify(result)
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

def _validate_session_and_get_lab_pi(session_key):
    """Shared by /chart and /camera: is this session still live, and if so
    which Lab Pi backs it? Populates active_sessions from the DB (with its
    lab_pi_url resolved) if this is a fresh reconnect that skipped
    /experiment's normal in-memory bookkeeping."""
    if not session_key:
        return None

    session_data = active_sessions.get(session_key)
    if session_data:
        expires_at = session_data.get('expires_at')
        if expires_at and datetime.now().timestamp() > expires_at:
            active_sessions.pop(session_key, None)
            end_lab_pi_session(session_key, session_data.get('lab_pi_url'))
            return None
        return session_data.get('lab_pi_url')

    booking = Booking.query.filter_by(session_key=session_key).first()
    if not booking:
        return None
    now = datetime.now()
    if not (booking.start_time <= now <= booking.end_time):
        return None

    lab_pi_url = get_session_lab_pi_url(session_key)
    active_sessions[session_key] = {
        'start_time': time.time(),
        'duration': (booking.end_time - booking.start_time).total_seconds() // 60,
        'expires_at': booking.end_time.timestamp(),
        'lab_pi_url': lab_pi_url,
    }
    return lab_pi_url


@app.route('/chart')
@login_required
def chart():
    session_key = request.args.get('key')
    if not _validate_session_and_get_lab_pi(session_key):
        return redirect(url_for('index'))
    return render_template('chart.html')

@app.route('/oscilloscope')
@login_required
def oscilloscope():
    session_key = request.args.get('key')
    if not _validate_session_and_get_lab_pi(session_key):
        return redirect(url_for('index'))
    return render_template('oscilloscope.html')

@app.route('/camera')
@login_required
def camera():
    session_key = request.args.get('key')
    if not _validate_session_and_get_lab_pi(session_key):
        return redirect(url_for('index'))
    return render_template('camera.html')

@app.route('/session/<session_key>/camera-stream')
@login_required
def camera_stream(session_key):
    """MJPEG proxy: the browser hits this Master route, Master streams it
    from the session's Lab Pi's ustreamer (port 8080) and pipes the bytes
    straight through. The browser's <img> tag never points at a Lab Pi
    address — see MASTER_UI_MIGRATION_PLAN.md Phase 3, "camera (MJPEG) is
    the easier of the two" relays. (Audio/WebRTC is not relayed yet — that's
    the genuinely hard one, still pending its own design pass.)"""
    booking = Booking.query.filter_by(session_key=session_key).first()
    if not booking or booking.user_id != current_user.id:
        return jsonify({'error': 'Not your session'}), 403

    lab_pi_url = get_session_lab_pi_url(session_key)
    if not lab_pi_url:
        return jsonify({'error': 'No Lab Pi assigned to this session'}), 400

    camera_url = lab_pi_url.replace(':10000', ':8080') + '/?action=stream&resolution=1920x1080&quality=100'
    try:
        upstream = requests.get(camera_url, stream=True, timeout=10)
    except Exception as e:
        return jsonify({'error': f'Camera stream unavailable: {e}'}), 502

    def relay_chunks():
        try:
            for chunk in upstream.iter_content(chunk_size=4096):
                if chunk:
                    yield chunk
        finally:
            upstream.close()

    return Response(relay_chunks(), content_type=upstream.headers.get('Content-Type', 'multipart/x-mixed-replace'))

@app.route('/session/<session_key>/audio-offer', methods=['POST'])
@login_required
def audio_offer(session_key):
    """WebRTC signaling endpoint for the browser's audio peer connection —
    see audio_relay.py for the two-peer-connection relay this negotiates
    (Master <-> Lab Pi mic, Master <-> this browser). The browser's SDP
    offer never goes anywhere near the Lab Pi's own address."""
    booking = Booking.query.filter_by(session_key=session_key).first()
    if not booking or booking.user_id != current_user.id:
        return jsonify({'error': 'Not your session'}), 403

    lab_pi_url = get_session_lab_pi_url(session_key)
    if not lab_pi_url:
        return jsonify({'error': 'No Lab Pi assigned to this session'}), 400

    data = request.get_json(force=True) or {}
    sdp = data.get('sdp')
    type_ = data.get('type', 'offer')
    if not sdp:
        return jsonify({'error': 'Missing SDP'}), 400

    try:
        answer_sdp, answer_type = audio_relay.handle_offer(session_key, lab_pi_url, sdp, type_)
    except Exception as e:
        print(f"[AudioRelay] Offer handling failed for session {session_key}: {e}")
        return jsonify({'error': str(e)}), 502

    return jsonify({'sdp': answer_sdp, 'type': answer_type})

@app.route('/ports')
@login_required
def ports_rest():
    """One-shot port list for a session's Lab Pi — the SocketIO relay's
    'ports_list' event covers the live-updating case; this covers a plain
    page load or a client that hasn't opened a socket yet."""
    session_key = request.args.get('key')
    lab_pi_url = get_session_lab_pi_url(session_key)
    if not lab_pi_url:
        return jsonify({'ports': []})
    try:
        response = requests.get(f'{lab_pi_url}/ports', timeout=5)
        return jsonify(response.json())
    except Exception as e:
        print(f"Error fetching ports from Lab Pi: {e}")
        return jsonify({'ports': []})

# ---------- BOOKING SYSTEM ----------

# API endpoint to get available time slots for a given experiment and date
@app.route('/api/available-slots/<int:exp_id>')
@login_required
def get_available_slots(exp_id):
    """Return available time slots for the given experiment and date"""
    experiment = Experiment.query.get(exp_id)
    if not experiment:
        return jsonify({'error': 'Experiment not found'}), 404
    
    date_str = request.args.get('date')
    if not date_str:
        return jsonify({'error': 'Date parameter required'}), 400
    
    try:
        selected_date = datetime.strptime(date_str, '%Y-%m-%d').date()
    except ValueError:
        return jsonify({'error': 'Invalid date format'}), 400
    
    # Get all bookings for this experiment on the selected date
    start_of_day = datetime.combine(selected_date, datetime.min.time())
    end_of_day = start_of_day + timedelta(days=1)

    bookings = Booking.query.filter(
        Booking.experiment_id == exp_id,
        Booking.status.notin_(['CANCELLED', 'EXPIRED']),
        Booking.start_time >= start_of_day,
        Booking.start_time < end_of_day
    ).all()

    # Several Lab Pis can serve the same experiment concurrently, so a time
    # range isn't "booked" (unavailable to the frontend, same field name/shape
    # it's always used) until overlapping bookings reach that count — a plain
    # per-booking interval list would grey out a slot the first time it's used
    # even with three more Lab Pis free. Sweep the day's booking start/end
    # events, track how many bookings overlap at each point, and only emit an
    # interval for the ranges where that count is >= capacity.
    capacity = LabPi.query.filter_by(experiment_id=exp_id, status='ONLINE').count()
    booked_intervals = []
    if capacity == 0:
        # No hardware online at all — the whole day is unavailable.
        booked_intervals = [{'start': '00:00', 'end': '24:00'}]
    elif bookings:
        events = []
        for booking in bookings:
            end_dt = booking.end_time if booking.end_time.date() == selected_date else end_of_day
            events.append((max(booking.start_time, start_of_day), 1))
            events.append((end_dt, -1))
        events.sort(key=lambda e: (e[0], -e[1]))  # process starts before ends at the same instant

        overlap = 0
        full_start = None
        for t, delta in events:
            was_full = overlap >= capacity
            overlap += delta
            is_full = overlap >= capacity
            if is_full and not was_full:
                full_start = t
            elif was_full and not is_full:
                booked_intervals.append({
                    'start': full_start.strftime('%H:%M'),
                    'end': t.strftime('%H:%M') if t.date() == selected_date else '24:00',
                })
                full_start = None
        if full_start is not None:
            booked_intervals.append({'start': full_start.strftime('%H:%M'), 'end': '24:00'})

    return jsonify({
        'date': date_str,
        'booked_intervals': booked_intervals,
        'experiment_id': exp_id,
        'capacity': capacity,
    })

@app.route('/book/<int:exp_id>', methods=['GET', 'POST'])
@login_required
def book_experiment(exp_id):
    experiment = Experiment.query.get(exp_id)
    if not experiment or not experiment.active:
        flash('Experiment not available', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        print("DEBUG: Booking form submitted")
        print(f"DEBUG: Form data: {request.form}")
        
        slot_date = request.form.get('slotDate')
        selected_slot = request.form.get('selectedSlot')  # New format: HH:00
        duration_str = request.form.get('duration')
        
        # Validate required fields
        if not slot_date or not selected_slot or not duration_str:
            flash('Please fill in all required fields', 'danger')
            return redirect(url_for('book_experiment', exp_id=exp_id))
        
        try:
            duration = int(duration_str)
        except (ValueError, TypeError):
            flash('Invalid duration format', 'danger')
            return redirect(url_for('book_experiment', exp_id=exp_id))
        
        if not selected_slot:
            flash('Please select a time slot', 'danger')
            return redirect(url_for('book_experiment', exp_id=exp_id))
        
        # Validate slot format (should be HH:00)
        try:
            hour = int(selected_slot.split(':')[0])
            if hour < 0 or hour > 23:
                raise ValueError("Invalid hour")
        except (ValueError, IndexError):
            flash('Invalid time slot format', 'danger')
            return redirect(url_for('book_experiment', exp_id=exp_id))
        
        if duration > experiment.max_duration:
            flash(f'Maximum duration for this experiment is {experiment.max_duration} minutes', 'danger')
            return redirect(url_for('book_experiment', exp_id=exp_id))
        
        # Parse date and time - use naive datetime (local time) for simplicity
        try:
            start_time = datetime.strptime(f"{slot_date} {selected_slot}", "%Y-%m-%d %H:%M")
            end_time = start_time + timedelta(minutes=duration)
            print(f"DEBUG: Parsed start time: {start_time}, end time: {end_time}")
        except ValueError as e:
            print(f"DEBUG: Date parsing error: {e}")
            flash('Invalid date or time format', 'danger')
            return redirect(url_for('book_experiment', exp_id=exp_id))
        
        # Capacity = how many Lab Pis are online for this experiment right now
        # — several can serve the same experiment concurrently, so a slot is
        # only full once overlapping bookings reach that count, not at 1.
        capacity = LabPi.query.filter_by(experiment_id=exp_id, status='ONLINE').count()
        overlapping_bookings = Booking.query.filter(
            Booking.experiment_id == exp_id,
            Booking.status.notin_(['CANCELLED', 'EXPIRED']),
            ((Booking.start_time < end_time) & (Booking.end_time > start_time))
        ).count()

        print(f"DEBUG: Overlapping bookings: {overlapping_bookings}, capacity: {capacity}")

        if capacity == 0:
            flash('No lab hardware is currently online for this experiment. Please try again later.', 'danger')
            return redirect(url_for('book_experiment', exp_id=exp_id))
        if overlapping_bookings >= capacity:
            flash('This slot is already fully booked. Please select another time.', 'danger')
            return redirect(url_for('book_experiment', exp_id=exp_id))
        
        # Create booking
        try:
            session_key = generate_session_key()
            booking = Booking(
                user_id=current_user.id,
                experiment_id=exp_id,
                start_time=start_time,
                end_time=end_time,
                status='UPCOMING',
                session_key=session_key
            )
            db.session.add(booking)
            db.session.commit()
            
            print(f"DEBUG: Booking created successfully: {booking}")
            print(f"DEBUG: Session key: {session_key}")
        except Exception as e:
            print(f"DEBUG: Error creating booking: {e}")
            db.session.rollback()
            flash('Error creating booking. Please try again.', 'danger')
            return redirect(url_for('book_experiment', exp_id=exp_id))
        
        # Send confirmation email with calendar invite - wrapped in try-except to ensure booking succeeds
        try:
            subject = 'Virtual Lab Booking Confirmed - ' + experiment.name
            
            # Generate access link - simplified
            access_link = f"http://10.114.62.73:5000/experiment?key={session_key}"
            
            # Generate ICS calendar
            ics_content = generate_ics_calendar(
                experiment.name,
                start_time,
                end_time,
                booking.id,
                session_key,
                access_link
            )
            
            template = f'''
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #2c3e50;">Virtual Lab Booking Confirmed!</h2>
                
                <p>Dear {current_user.full_name or current_user.email.split('@')[0]},</p>
                
                <p>Your virtual lab booking has been confirmed!</p>
                
                <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
                    <tr>
                        <td style="padding: 10px; border: 1px solid #ddd;"><strong>Experiment</strong></td>
                        <td style="padding: 10px; border: 1px solid #ddd;">{experiment.name}</td>
                    </tr>
                    <tr>
                        <td style="padding: 10px; border: 1px solid #ddd;"><strong>Date</strong></td>
                        <td style="padding: 10px; border: 1px solid #ddd;">{slot_date}</td>
                    </tr>
                    <tr>
                        <td style="padding: 10px; border: 1px solid #ddd;"><strong>Time</strong></td>
                        <td style="padding: 10px; border: 1px solid #ddd;">{selected_slot}</td>
                    </tr>
                    <tr>
                        <td style="padding: 10px; border: 1px solid #ddd;"><strong>Duration</strong></td>
                        <td style="padding: 10px; border: 1px solid #ddd;">{duration} minutes</td>
                    </tr>
                    <tr>
                        <td style="padding: 10px; border: 1px solid #ddd;"><strong>Booking ID</strong></td>
                        <td style="padding: 10px; border: 1px solid #ddd;">{booking.id}</td>
                    </tr>
                    <tr>
                        <td style="padding: 10px; border: 1px solid #ddd;"><strong>Access Link</strong></td>
                        <td style="padding: 10px; border: 1px solid #ddd;">
                            <a href="{access_link}" style="color: #3498db;">{access_link}</a>
                        </td>
                    </tr>
                </table>
                
                <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0;">
                    <p style="margin: 0;"><strong>Please make sure to:</strong></p>
                    <ul style="margin: 10px 0 0 0;">
                        <li>Join the session on time</li>
                        <li>Have your system setup ready</li>
                        
                    </ul>
                </div>
                
                <p style="color: #7f8c8d; font-size: 14px;">A calendar invite has been attached to help you remember this session.</p>
                
                <p style="color: #7f8c8d; font-size: 14px;">Best regards,<br>Virtual Lab Team</p>
            </div>
            '''
            
            # Send email with ICS attachment
            send_email(
                current_user.email,
                subject,
                template,
                attachment=ics_content,
                attachment_filename=f'booking_{booking.id}.ics'
            )

            # Notify admin of the new booking
            admin_subject = f'New Booking - {experiment.name}'
            admin_template = f'''
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #2c3e50;">New Virtual Lab Booking</h2>
                <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
                    <tr>
                        <td style="padding: 10px; border: 1px solid #ddd;"><strong>User</strong></td>
                        <td style="padding: 10px; border: 1px solid #ddd;">{current_user.full_name or current_user.email} ({current_user.email})</td>
                    </tr>
                    <tr>
                        <td style="padding: 10px; border: 1px solid #ddd;"><strong>Experiment</strong></td>
                        <td style="padding: 10px; border: 1px solid #ddd;">{experiment.name}</td>
                    </tr>
                    <tr>
                        <td style="padding: 10px; border: 1px solid #ddd;"><strong>Date</strong></td>
                        <td style="padding: 10px; border: 1px solid #ddd;">{slot_date}</td>
                    </tr>
                    <tr>
                        <td style="padding: 10px; border: 1px solid #ddd;"><strong>Time</strong></td>
                        <td style="padding: 10px; border: 1px solid #ddd;">{selected_slot}</td>
                    </tr>
                    <tr>
                        <td style="padding: 10px; border: 1px solid #ddd;"><strong>Duration</strong></td>
                        <td style="padding: 10px; border: 1px solid #ddd;">{duration} minutes</td>
                    </tr>
                    <tr>
                        <td style="padding: 10px; border: 1px solid #ddd;"><strong>Booking ID</strong></td>
                        <td style="padding: 10px; border: 1px solid #ddd;">{booking.id}</td>
                    </tr>
                </table>
            </div>
            '''
            send_email(app.config['MAIL_USERNAME'], admin_subject, admin_template)

            flash('Booking confirmed! Check your email for details.', 'success')
        except Exception as e:
            print(f"[EMAIL ERROR] Booking confirmation email failed: {e}")
            # Continue without failing the booking
            flash('Booking confirmed!', 'success')
        
        return redirect(url_for('my_bookings'))
    
    return render_template('book.html', experiment=experiment)

@app.route('/my_bookings')
@login_required
def my_bookings():
    bookings = Booking.query.filter_by(user_id=current_user.id).order_by(Booking.start_time.desc()).all()
    
    # Update booking statuses
    now = datetime.now()
    for booking in bookings:
        if booking.status == 'UPCOMING':
            if now < booking.start_time:
                booking.status = 'UPCOMING'
            elif booking.start_time <= now <= booking.end_time:
                booking.status = 'ACTIVE'
            elif now > booking.end_time:
                booking.status = 'EXPIRED'
        elif booking.status == 'ACTIVE':
            if now > booking.end_time:
                booking.status = 'EXPIRED'
        elif booking.status == 'IN_PROGRESS':
            # Calculate duration from start and end time
            duration = (booking.end_time - booking.start_time).total_seconds() // 60
            if now > booking.end_time:
                booking.status = 'COMPLETED'
                booking.completed_at = datetime.now()
            elif booking.started_at and now > booking.started_at + timedelta(minutes=duration):
                booking.status = 'COMPLETED'
                booking.completed_at = datetime.now()
    
    db.session.commit()
    
    # Separate bookings by status
    upcoming_statuses = ['UPCOMING', 'ACTIVE', 'IN_PROGRESS']
    cancelled_statuses = ['CANCELLED', 'EXPIRED']
    
    upcoming_bookings = [b for b in bookings if b.status in upcoming_statuses]
    completed_bookings = [b for b in bookings if b.status == 'COMPLETED']
    cancelled_bookings = [b for b in bookings if b.status in cancelled_statuses]
    
    return render_template('my_bookings.html', 
                         upcoming_bookings=upcoming_bookings,
                         completed_bookings=completed_bookings,
                         cancelled_bookings=cancelled_bookings)

@app.route('/my-bookings-data')
@login_required
def my_bookings_data():
    """API endpoint to get booking data for AJAX refresh"""
    bookings = Booking.query.filter_by(user_id=current_user.id).order_by(Booking.start_time.desc()).all()
    
    # Update booking statuses
    now = datetime.now()
    for booking in bookings:
        if booking.status == 'UPCOMING':
            if now < booking.start_time:
                booking.status = 'UPCOMING'
            elif booking.start_time <= now <= booking.end_time:
                booking.status = 'ACTIVE'
            elif now > booking.end_time:
                booking.status = 'EXPIRED'
        elif booking.status == 'ACTIVE':
            if now > booking.end_time:
                booking.status = 'EXPIRED'
    
    db.session.commit()
    return render_template('my_bookings.html', bookings=bookings)

@app.route('/cancel_booking/<int:booking_id>')
@login_required
def cancel_booking(booking_id):
    booking = Booking.query.get(booking_id)
    if not booking or booking.user_id != current_user.id:
        flash('Booking not found', 'danger')
        return redirect(url_for('my_bookings'))
    
    if booking.status != 'UPCOMING' and booking.status != 'ACTIVE':
        flash('Only upcoming or active bookings can be cancelled', 'danger')
        return redirect(url_for('my_bookings'))
    
    booking.status = 'CANCELLED'
    db.session.commit()
    flash('Booking cancelled successfully', 'success')
    return redirect(url_for('my_bookings'))

@app.route('/start_booking/<int:booking_id>')
@login_required
def start_booking(booking_id):
    booking = Booking.query.get(booking_id)
    if not booking or booking.user_id != current_user.id:
        flash('Booking not found', 'danger')
        return redirect(url_for('my_bookings'))
    
    now = datetime.now()
    if not (booking.start_time <= now <= booking.end_time):
        flash('Booking window has passed', 'danger')
        return redirect(url_for('my_bookings'))
    
    # Check if user already has an active session
    active_session = Session.query.filter_by(
        user_id=current_user.id,
        status='ACTIVE'
    ).first()
    
    if active_session:
        flash('You already have an active session. Please end your current session before starting a new one.', 'danger')
        return redirect(url_for('my_bookings'))
    
    # Create new session
    session = Session(
        booking_id=booking.id,
        user_id=current_user.id,
        session_key=booking.session_key,
        duration=(booking.end_time - booking.start_time).total_seconds() // 60,
        end_time=booking.end_time,
        ip_address=request.remote_addr
    )
    db.session.add(session)
    
    booking.status = 'IN_PROGRESS'
    booking.started_at = now
    db.session.commit()
    
    # Add to active sessions
    active_sessions[booking.session_key] = {
        'start_time': time.time(),
        'duration': session.duration,
        'expires_at': session.end_time.timestamp()
    }
    
    return redirect(url_for('experiment', key=booking.session_key))

# ---------- FLASH AND FIRMWARE ----------
# Both routes below used to run avrdude/esptool/openocd locally on the
# Master via `subprocess.Popen(cmd, shell=True, ...)` with `port` (straight
# from the request) interpolated into that shell string — a command
# injection hole, and architecturally wrong besides, since the Master has no
# boards attached. They now proxy to the session's own Lab Pi, whose /flash
# and /factory_reset already build an argv list instead of a shell string
# (see lab-pi/app.py's _flash_commands). Flashing progress arrives back over
# the SocketIO relay as 'flashing_status' events exactly as before — the Lab
# Pi emits them, lab_pi_relay forwards them into this session's room.
@app.route('/flash', methods=['POST'])
@login_required
def flash_firmware():
    session_key = request.form.get('session_key')
    lab_pi_url = get_session_lab_pi_url(session_key)
    if not lab_pi_url:
        return jsonify({'status': 'No Lab Pi assigned to this session'}), 400

    fw = request.files.get('firmware')
    if not fw:
        return jsonify({'status': 'No firmware uploaded'}), 400

    try:
        response = requests.post(
            f'{lab_pi_url}/flash',
            data={'board': request.form.get('board', 'generic'), 'port': request.form.get('port', '')},
            files={'firmware': (secure_filename(fw.filename), fw.stream, fw.mimetype)},
            timeout=15,
        )
        return jsonify(response.json()), response.status_code
    except Exception as e:
        print(f"Error proxying flash to Lab Pi: {e}")
        return jsonify({'status': f'Failed to reach Lab Pi: {e}'}), 502

@app.route('/factory_reset', methods=['POST'])
@login_required
def factory_reset():
    try:
        data = request.get_json(force=True)
    except Exception:
        data = request.form.to_dict()

    lab_pi_url = get_session_lab_pi_url(data.get('session_key'))
    if not lab_pi_url:
        return jsonify({'error': 'No Lab Pi assigned to this session'}), 400

    try:
        response = requests.post(
            f'{lab_pi_url}/factory_reset',
            json={'board': data.get('board', 'generic'), 'port': data.get('port', '')},
            timeout=15,
        )
        return jsonify(response.json()), response.status_code
    except Exception as e:
        print(f"Error proxying factory reset to Lab Pi: {e}")
        return jsonify({'error': f'Failed to reach Lab Pi: {e}'}), 502

@app.route('/sop/<path:filename>')
@login_required
def serve_sop(filename):
    safe_path = os.path.join(SOP_DIR, filename)
    if not os.path.isfile(safe_path):
        abort(404)
    return send_from_directory(SOP_DIR, filename, as_attachment=True)

# ============================================================================
# LAB PI API ROUTES (Master Pi - handles Lab Pi registration and heartbeat)
# ============================================================================

@app.route('/api/booking/by-key/<session_key>', methods=['GET'])
def get_booking_by_key(session_key):
    """
    Get booking details by session key. Used by Lab Pi to validate session.
    """
    booking = Booking.query.filter_by(session_key=session_key).first()
    if not booking:
        return jsonify({'error': 'Booking not found'}), 404
    
    # Check if booking is active
    now = datetime.now()
    if not (booking.start_time <= now <= booking.end_time):
        return jsonify({'error': 'Booking expired'}), 400
    
    if booking.status not in ['CONFIRMED', 'IN_PROGRESS']:
        return jsonify({'error': 'Booking not active'}), 400
    
    return jsonify({
        'booking_id': booking.id,
        'session_key': booking.session_key,
        'experiment_name': booking.experiment.name if booking.experiment else 'Unknown',
        'duration': int((booking.end_time - booking.start_time).total_seconds() // 60),
        'start_time': booking.start_time.isoformat(),
        'end_time': booking.end_time.isoformat(),
        'status': booking.status
    })

@app.route('/api/lab-pi/register', methods=['POST'])
@csrf.exempt
def lab_pi_register():
    """
    Register a Lab Pi with the Master Pi.
    Called by Lab Pi on startup.
    """
    if not _verify_lab_pi_request():
        return jsonify({'error': 'unauthorized'}), 401
    data = request.get_json()
    
    # Validate required fields
    required_fields = ['lab_pi_id']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'Missing required field: {field}'}), 400
    
    lab_pi_id = data.get('lab_pi_id')
    # Accept 'name' or 'lab_pi_name' for backwards compatibility
    name = data.get('name') or data.get('lab_pi_name', 'Unknown Lab Pi')
    mac_address = data.get('mac_address')
    # Only set mac_address if it's a valid non-empty value
    if mac_address is None or mac_address.strip() == '':
        mac_address = None
    else:
        mac_address = mac_address.strip()
    ip_address = data.get('ip_address') or None
    hostname = data.get('hostname') or None
    experiment_id = data.get('experiment_id')
    
    # New fields
    device_type = data.get('device_type') or 'Raspberry Pi'
    firmware_version = data.get('firmware_version') or '1.0'
    hardware_version = data.get('hardware_version')
    location = data.get('location')
    
    # Check if Lab Pi already exists
    existing = LabPi.query.filter_by(lab_pi_id=lab_pi_id).first()
    
    if existing:
        # Update existing Lab Pi
        existing.name = name
        existing.mac_address = mac_address or existing.mac_address  # Keep existing if empty
        existing.ip_address = ip_address or existing.ip_address
        existing.hostname = hostname or existing.hostname
        existing.experiment_id = experiment_id
        existing.device_type = device_type
        existing.firmware_version = firmware_version
        existing.hardware_version = hardware_version or existing.hardware_version
        existing.location = location or existing.location
        existing.status = 'ONLINE'
        existing.last_heartbeat = datetime.utcnow()
        db.session.commit()
        
        # Log the reconnection
        log_entry = SystemLog(
            level='INFO',
            category='SYSTEM',
            message=f'Lab Pi {lab_pi_id} ({name}) reconnected - IP: {ip_address}',
            device_id=existing.id
        )
        db.session.add(log_entry)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'id': existing.id,
            'message': 'Lab Pi updated successfully'
        })
    
    # Create new Lab Pi
    lab_pi = LabPi(
        lab_pi_id=lab_pi_id,
        name=name,
        mac_address=mac_address,
        ip_address=ip_address,
        hostname=hostname,
        experiment_id=experiment_id,
        device_type=device_type,
        firmware_version=firmware_version,
        hardware_version=hardware_version,
        location=location,
        status='ONLINE',
        registered_at=datetime.utcnow(),
        last_heartbeat=datetime.utcnow()
    )
    db.session.add(lab_pi)
    
    # Log new registration
    exp = Experiment.query.get(experiment_id) if experiment_id else None
    exp_name = exp.name if exp else 'Unknown'
    log_entry = SystemLog(
        level='INFO',
        category='SYSTEM',
        message=f'New Lab Pi registered: {lab_pi_id} ({name}) - Experiment: {exp_name} - IP: {ip_address}',
        device_id=None
    )
    db.session.add(log_entry)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'id': lab_pi.id,
        'message': 'Lab Pi registered successfully'
    }), 201


@app.route('/api/lab-pi/heartbeat', methods=['POST'])
@csrf.exempt
def lab_pi_heartbeat():
    """
    Receive heartbeat from Lab Pi.
    Called by Lab Pi every 30 seconds.
    """
    if not _verify_lab_pi_request():
        return jsonify({'error': 'unauthorized'}), 401
    data = request.get_json()
    lab_pi_id = request.headers.get('X-Lab-Pi-Id')
    
    if not lab_pi_id:
        return jsonify({'error': 'Missing X-Lab-Pi-Id header'}), 400
    
    # Find Lab Pi
    lab_pi = LabPi.query.filter_by(lab_pi_id=lab_pi_id).first()
    if not lab_pi:
        return jsonify({'error': 'Lab Pi not registered'}), 404
    
    # Update Lab Pi status - only set to ONLINE if not in maintenance mode
    if lab_pi.status != 'MAINTENANCE':
        lab_pi.status = 'ONLINE'
    lab_pi.last_heartbeat = datetime.utcnow()
    lab_pi.session_active = data.get('session_active', False)
    lab_pi.current_session_key = data.get('session_key')
    lab_pi.relay_state = data.get('relay_state', False)
    lab_pi.hardware_ready = data.get('hardware_ready', True)
    lab_pi.uptime = data.get('uptime')
    lab_pi.cpu_usage = data.get('cpu_usage')
    lab_pi.ram_usage = data.get('ram_usage')
    lab_pi.temperature = data.get('temperature')
    
    # Battery (DFRobot UPS)
    lab_pi.battery_soc = data.get('battery_soc')
    lab_pi.battery_voltage = data.get('battery_voltage')
    lab_pi.battery_ac_status = data.get('battery_ac_status')
    lab_pi.battery_charging = data.get('battery_charging') or data.get('battery_status')
    
    # Log heartbeat
    heartbeat_log = LabPiHeartbeat(
        lab_pi_id=lab_pi.id,
        timestamp=datetime.utcnow(),
        status='ONLINE',
        session_active=lab_pi.session_active,
        session_key=lab_pi.current_session_key,
        relay_state=lab_pi.relay_state,
        hardware_ready=lab_pi.hardware_ready,
        uptime=lab_pi.uptime
    )
    db.session.add(heartbeat_log)
    db.session.commit()
    
    # Check if there's a new session for this Lab Pi
    response_data = {'success': True}
    
    # Find active booking for this Lab Pi's experiment
    # Check 'ACTIVE', 'IN_PROGRESS', and 'UPCOMING' (if within time window) statuses
    if lab_pi.experiment_id:
        now = datetime.utcnow()
        
        # First, update any UPCOMING bookings that are now within the time window
        upcoming_bookings = Booking.query.filter(
            Booking.experiment_id == lab_pi.experiment_id,
            Booking.status == 'UPCOMING',
            Booking.start_time <= now,
            Booking.end_time > now
        ).all()
        for booking in upcoming_bookings:
            booking.status = 'ACTIVE'
        if upcoming_bookings:
            db.session.commit()
        
        # Now look for active bookings
        active_booking = Booking.query.filter(
            Booking.experiment_id == lab_pi.experiment_id,
            Booking.status.in_(['ACTIVE', 'IN_PROGRESS']),
            Booking.start_time <= now,
            Booking.end_time > now
        ).first()
        
        if active_booking and active_booking.session_key != lab_pi.current_session_key:
            # New session assigned!
            session = Session.query.filter_by(session_key=active_booking.session_key).first()
            response_data['new_session'] = True
            response_data['session'] = {
                'session_key': active_booking.session_key,
                'booking_id': active_booking.id,
                'start_time': active_booking.start_time.isoformat() if active_booking.start_time else None,
                'end_time': active_booking.end_time.isoformat() if active_booking.end_time else None,
                'user_email': active_booking.user.email if active_booking.user else None,
                'board_type': lab_pi.board_type
            }
    
    # Always include current board_type in response for real-time sync
    response_data['board_type'] = lab_pi.board_type
    response_data['sop_file'] = lab_pi.sop_file
    
    return jsonify(response_data)


@app.route('/api/lab-pi/session-end', methods=['POST'])
@csrf.exempt
def lab_pi_session_end():
    """
    Report session end from Lab Pi.
    Called by Lab Pi when session completes or is terminated.
    """
    data = request.get_json()
    lab_pi_id = request.headers.get('X-Lab-Pi-Id')
    
    if not lab_pi_id:
        return jsonify({'error': 'Missing X-Lab-Pi-Id header'}), 400
    
    lab_pi = LabPi.query.filter_by(lab_pi_id=lab_pi_id).first()
    if not lab_pi:
        return jsonify({'error': 'Lab Pi not registered'}), 404
    
    session_key = data.get('session_key')
    reason = data.get('reason', 'completed')

    # The Lab Pi already knows its session is over — drop the Master's
    # relay connection for it too so it doesn't sit there holding a socket
    # to a Lab Pi that no longer has anything to say.
    active_sessions.pop(session_key, None)
    lab_pi_relay.disconnect(session_key)
    audio_relay.disconnect(session_key)

    # Update Lab Pi state
    lab_pi.current_session_key = None
    lab_pi.session_start_time = None
    lab_pi.relay_state = False
    db.session.commit()
    
    # Gather session info for report email before updating
    report_user_email = None
    report_experiment_name = None
    report_booking_id = None
    report_start_time = None
    report_end_time = datetime.utcnow()
    report_duration = None
    report_experiment_id = None
    
    # Update session in database if exists
    session = Session.query.filter_by(session_key=session_key).first()
    if session:
        # Mark as COMPLETED when user finished normally, EXPIRED only when time ran out
        session.status = 'COMPLETED' if reason == 'completed' else ('EXPIRED' if reason == 'expired' else 'TERMINATED')
        session.end_time = datetime.utcnow()
        
        # Collect info for report email
        user = User.query.get(session.user_id)
        if user:
            report_user_email = user.email
        report_start_time = session.start_time
        report_end_time = session.end_time
        report_duration = session.duration
        # Get experiment_id from booking
        booking = Booking.query.filter_by(session_key=session_key).first()
        if booking:
            report_experiment_id = booking.experiment_id
        
        db.session.commit()
        
        # Log session end
        log_entry = SystemLog(
            level='INFO',
            category='EXPERIMENT',
            message=f'Session ended on Lab Pi {lab_pi_id}: Session {session_key} - Reason: {reason}',
            device_id=lab_pi.id,
            user_id=session.user_id if session else None
        )
        db.session.add(log_entry)
        db.session.commit()
    
    # Update booking
    booking = Booking.query.filter_by(session_key=session_key).first()
    if booking:
        booking.status = 'COMPLETED' if reason == 'completed' else 'EXPIRED'
        booking.completed_at = datetime.utcnow()
        report_booking_id = booking.id
        if booking.experiment:
            report_experiment_name = booking.experiment.name
        db.session.commit()
    
    # Send session report email (non-blocking, wrapped in try-except)
    if report_user_email and lab_pi.ip_address:
        try:
            # Fetch session data from Lab Pi
            csv_data = fetch_session_data_from_lab_pi(lab_pi.ip_address, session_key)
            
            # Send report email in background thread to avoid blocking
            def send_report():
                with app.app_context():
                    try:
                        send_session_report_email(
                            user_email=report_user_email,
                            session_key=session_key,
                            experiment_name=report_experiment_name or 'Unknown',
                            booking_id=report_booking_id or 'N/A',
                            start_time=report_start_time,
                            end_time=report_end_time,
                            duration=report_duration,
                            csv_data=csv_data,
                            experiment_id=report_experiment_id
                        )
                    finally:
                        pass  # csv_data will be GC'd when thread completes
            
            report_thread = threading.Thread(target=send_report, daemon=True)
            report_thread.start()
            
        except Exception as e:
            print(f"[SESSION REPORT] Failed to initiate session report: {e}")
    
    return jsonify({'success': True})


@app.route('/api/lab-pi/<lab_pi_id>/status', methods=['GET'])
def lab_pi_get_status(lab_pi_id):
    """
    Get status of a specific Lab Pi.
    """
    lab_pi = LabPi.query.filter_by(lab_pi_id=lab_pi_id).first()
    if not lab_pi:
        return jsonify({'error': 'Lab Pi not found'}), 404
    
    return jsonify({
        'lab_pi_id': lab_pi.lab_pi_id,
        'name': lab_pi.name,
        'status': lab_pi.status,
        'ip_address': lab_pi.ip_address,
        'hostname': lab_pi.hostname,
        'experiment_id': lab_pi.experiment_id,
        'experiment_name': lab_pi.experiment.name if lab_pi.experiment else None,
        'last_heartbeat': lab_pi.last_heartbeat.isoformat() if lab_pi.last_heartbeat else None,
        'session_active': lab_pi.current_session_key is not None,
        'session_key': lab_pi.current_session_key,
        'relay_state': lab_pi.relay_state,
        'hardware_ready': lab_pi.hardware_ready,
        'uptime': lab_pi.uptime
    })


@app.route('/api/lab-pi/<lab_pi_id>/board-config', methods=['GET'])
def lab_pi_get_board_config(lab_pi_id):
    """
    Get board configuration for a specific Lab Pi.
    Used by lab-pi to fetch latest board_type without needing session start.
    """
    lab_pi = LabPi.query.filter_by(lab_pi_id=lab_pi_id).first()
    if not lab_pi:
        return jsonify({'error': 'Lab Pi not found'}), 404
    
    return jsonify({
        'lab_pi_id': lab_pi.lab_pi_id,
        'board_type': lab_pi.board_type or 'arduino',
        'sop_file': lab_pi.sop_file
    })


@app.route('/api/lab-pi/<lab_pi_id>/active-session', methods=['GET'])
def lab_pi_active_session(lab_pi_id):
    """
    Simple polling endpoint for Lab Pi to check for active sessions.
    Lab Pi should poll this every 5 seconds.
    
    Returns:
    - status: "running" if there's an active booking, "stopped" otherwise
    - session_key: the session key if running
    - end_time: ISO format end time
    - user_email: email of the user who booked
    """
    lab_pi = LabPi.query.filter_by(lab_pi_id=lab_pi_id).first()
    if not lab_pi:
        return jsonify({'error': 'Lab Pi not found'}), 404
    
    # Use local time to match booking times stored in local timezone
    now = datetime.now()
    
    # Find active booking for this Lab Pi's experiment
    # Check 'ACTIVE', 'IN_PROGRESS', and 'UPCOMING' (if within time window) statuses
    if lab_pi.experiment_id:
        # First, update any UPCOMING bookings that are now within the time window
        upcoming_bookings = Booking.query.filter(
            Booking.experiment_id == lab_pi.experiment_id,
            Booking.status == 'UPCOMING',
            Booking.start_time <= now,
            Booking.end_time > now
        ).all()
        for booking in upcoming_bookings:
            booking.status = 'ACTIVE'
        if upcoming_bookings:
            db.session.commit()
        
        # Now look for active bookings
        active_booking = Booking.query.filter(
            Booking.experiment_id == lab_pi.experiment_id,
            Booking.status.in_(['ACTIVE', 'IN_PROGRESS']),
            Booking.start_time <= now,
            Booking.end_time > now
        ).first()
        
        if active_booking:
            return jsonify({
                'status': 'running',
                'session_key': active_booking.session_key,
                'end_time': active_booking.end_time.isoformat() + 'Z',
                'user_email': active_booking.user.email if active_booking.user else None
            })
    
    return jsonify({'status': 'stopped'})


@app.route('/api/lab-pi/list', methods=['GET'])
def lab_pi_list():
    """
    Get list of all registered Lab Pis.
    """
    lab_pis = LabPi.query.all()
    return jsonify([{
        'lab_pi_id': lp.lab_pi_id,
        'name': lp.name,
        'status': lp.status,
        'ip_address': lp.ip_address,
        'experiment_id': lp.experiment_id,
        'experiment_name': lp.experiment.name if lp.experiment else None,
        'last_heartbeat': lp.last_heartbeat.isoformat() if lp.last_heartbeat else None,
        'session_active': lp.current_session_key is not None,
        # System metrics
        'cpu_usage': lp.cpu_usage,
        'ram_usage': lp.ram_usage,
        'temperature': lp.temperature,
        # Battery metrics
        'battery_soc': lp.battery_soc,
        'battery_voltage': lp.battery_voltage,
        'battery_ac_status': lp.battery_ac_status,
        'battery_charging': lp.battery_charging
    } for lp in lab_pis])


# Admin Lab Pi Action Routes
@app.route('/admin/lab-pi/edit/<int:lab_pi_id>', methods=['GET', 'POST'])
@login_required
def admin_lab_pi_edit(lab_pi_id):
    if not current_user.is_admin:
        abort(403)
    
    lab_pi = LabPi.query.get_or_404(lab_pi_id)
    experiments = Experiment.query.all()

    # How many *other* Lab Pis already serve each experiment — informational
    # only. Several Lab Pis are allowed to serve the same experiment
    # concurrently (that's how multiple students get booked into one
    # experiment at once), so this no longer blocks selection, just tells the
    # admin who else already handles it.
    mapped_experiments = LabPi.query.filter(
        LabPi.id != lab_pi_id,
        LabPi.experiment_id.isnot(None)
    ).with_entities(LabPi.experiment_id).all()
    mapped_experiment_counts = Counter(exp_id for (exp_id,) in mapped_experiments)

    if request.method == 'POST':
        # Update Lab Pi fields
        lab_pi.name = request.form.get('name', lab_pi.name)
        lab_pi.mac_address = request.form.get('mac_address') or None
        lab_pi.ip_address = request.form.get('ip_address') or None
        lab_pi.hostname = request.form.get('hostname') or None
        lab_pi.status = request.form.get('status', lab_pi.status)
        lab_pi.hardware_ready = 'hardware_ready' in request.form

        # Update experiment assignment
        experiment_id = request.form.get('experiment_id')
        lab_pi.experiment_id = int(experiment_id) if experiment_id else None
        
        # Update board_type (auto-sync from experiment if not manually set)
        board_type = request.form.get('board_type')
        if board_type:
            lab_pi.board_type = board_type
        elif experiment_id:
            # Auto-sync from experiment (but experiments no longer have board_type)
            experiment = Experiment.query.get(int(experiment_id))
        
        db.session.commit()

        # Real-time synchronization: Push update to Lab Pi immediately if online
        if lab_pi.status == 'ONLINE' and lab_pi.ip_address:
            try:
                requests.post(
                    f"http://{lab_pi.ip_address}:10000/api/lab-pi/update-config",
                    json={
                        'board_type': lab_pi.board_type,
                        'sop_file': lab_pi.sop_file,
                        'experiment_id': lab_pi.experiment_id
                    },
                    headers={'X-Master-Api-Key': MASTER_API_KEY},
                    timeout=2
                )
            except Exception as e:
                print(f"[SYNC] Failed to push real-time update to Lab Pi {lab_pi.lab_pi_id}: {e}")

        # Update custom SOP file - handle file upload
        sop_file_upload = request.files.get('sop_file_upload')
        if sop_file_upload and sop_file_upload.filename:
            # Upload to lab-pi
            try:
                lab_pi_url = f"http://{lab_pi.ip_address}:10000" if lab_pi.ip_address else "http://10.114.62.74:10000"
                files = {'file': (sop_file_upload.filename, sop_file_upload.read(), 'application/pdf')}
                response = requests.post(f"{lab_pi_url}/upload-sop", files=files, timeout=10)
                if response.status_code == 200:
                    lab_pi.sop_file = sop_file_upload.filename
                    print(f"[SOP UPLOAD] Uploaded {sop_file_upload.filename} to lab-pi")
                else:
                    print(f"[SOP UPLOAD] Failed: {response.status_code}")
            except Exception as e:
                print(f"[SOP UPLOAD] Error: {e}")
        else:
            # Check hidden input for existing filename
            lab_pi.sop_file = request.form.get('sop_file') or None
        
        flash(f'Lab Pi "{lab_pi.name}" updated successfully!', 'success')
        return redirect(url_for('manage_devices'))
    
    return render_template('admin/edit_device.html', device=lab_pi, experiments=experiments,
                          mapped_experiment_counts=mapped_experiment_counts, is_lab_pi=True)


@app.route('/admin/lab-pi/view/<int:lab_pi_id>', methods=['GET'])
@login_required
def admin_lab_pi_view(lab_pi_id):
    if not current_user.is_admin:
        abort(403)
    lab_pi = LabPi.query.get_or_404(lab_pi_id)
    return render_template('admin/view_device.html', device=lab_pi, is_lab_pi=True)


# ---------- Lab Pi UI/layout settings (edited here, pushed to the Lab Pi's
# Tier-A /api/admin/* API — no admin ever needs to visit the Lab Pi's own IP) ----------

def _require_online_lab_pi(lab_pi_id):
    """Shared guard for every ui-settings route below: 404 if the Lab Pi
    doesn't exist, flash+None if it has no IP or isn't online (nothing to
    reach), otherwise the LabPi row."""
    lab_pi = LabPi.query.get_or_404(lab_pi_id)
    if not lab_pi.ip_address or lab_pi.status != 'ONLINE':
        flash(f'Lab Pi "{lab_pi.name}" is not online — cannot reach it to edit its UI settings.', 'danger')
        return None
    return lab_pi


@app.route('/admin/lab-pi/<int:lab_pi_id>/ui-settings', methods=['GET', 'POST'])
@login_required
def admin_lab_pi_ui_settings(lab_pi_id):
    if not current_user.is_admin:
        abort(403)
    lab_pi = _require_online_lab_pi(lab_pi_id)
    if lab_pi is None:
        return redirect(url_for('admin_lab_pi_edit', lab_pi_id=lab_pi_id))

    if request.method == 'POST':
        body = _ui_config_body_from_form(request.form)
        ok, result = _lab_pi_admin_api(lab_pi, 'POST', '/api/admin/ui-config', body)
        if ok:
            flash('UI settings saved and pushed to the Lab Pi.', 'success')
        else:
            flash(result, 'danger')
        return redirect(url_for('admin_lab_pi_ui_settings', lab_pi_id=lab_pi_id))

    ok, cfg = _lab_pi_admin_api(lab_pi, 'GET', '/api/admin/ui-config')
    if not ok:
        flash(cfg, 'danger')
        return redirect(url_for('admin_lab_pi_edit', lab_pi_id=lab_pi_id))

    # Other Lab Pis serving the same experiment — offered as "copy to" targets
    # further down the page so settings don't have to be retyped by hand on
    # every physical board handling this experiment.
    sibling_lab_pis = []
    if lab_pi.experiment_id:
        sibling_lab_pis = LabPi.query.filter(
            LabPi.experiment_id == lab_pi.experiment_id, LabPi.id != lab_pi.id
        ).all()

    return render_template('admin/lab_pi_ui_settings.html', device=lab_pi, cfg=cfg,
                          control_keys=[(c['key'], c['label']) for c in cfg.get('control_keys', [])],
                          available_ports=cfg.get('available_ports', []),
                          sibling_lab_pis=sibling_lab_pis)


@app.route('/admin/lab-pi/<int:lab_pi_id>/ui-settings/controls/add', methods=['POST'])
@login_required
def admin_lab_pi_ui_control_add(lab_pi_id):
    if not current_user.is_admin:
        abort(403)
    lab_pi = _require_online_lab_pi(lab_pi_id)
    if lab_pi is not None:
        ok, result = _lab_pi_admin_api(lab_pi, 'POST', '/api/admin/controls', dict(request.form))
        flash('Control added.' if ok else result, 'success' if ok else 'danger')
    return redirect(url_for('admin_lab_pi_ui_settings', lab_pi_id=lab_pi_id))


@app.route('/admin/lab-pi/<int:lab_pi_id>/ui-settings/controls/<control_id>/edit', methods=['POST'])
@login_required
def admin_lab_pi_ui_control_edit(lab_pi_id, control_id):
    if not current_user.is_admin:
        abort(403)
    lab_pi = _require_online_lab_pi(lab_pi_id)
    if lab_pi is not None:
        ok, result = _lab_pi_admin_api(lab_pi, 'PUT', f'/api/admin/controls/{control_id}', dict(request.form))
        flash('Control updated.' if ok else result, 'success' if ok else 'danger')
    return redirect(url_for('admin_lab_pi_ui_settings', lab_pi_id=lab_pi_id))


@app.route('/admin/lab-pi/<int:lab_pi_id>/ui-settings/controls/<control_id>/delete', methods=['POST'])
@login_required
def admin_lab_pi_ui_control_delete(lab_pi_id, control_id):
    if not current_user.is_admin:
        abort(403)
    lab_pi = _require_online_lab_pi(lab_pi_id)
    if lab_pi is not None:
        ok, result = _lab_pi_admin_api(lab_pi, 'DELETE', f'/api/admin/controls/{control_id}')
        flash('Control removed.' if ok else result, 'success' if ok else 'danger')
    return redirect(url_for('admin_lab_pi_ui_settings', lab_pi_id=lab_pi_id))


@app.route('/admin/lab-pi/<int:lab_pi_id>/ui-settings/ports/add', methods=['POST'])
@login_required
def admin_lab_pi_ui_port_add(lab_pi_id):
    if not current_user.is_admin:
        abort(403)
    lab_pi = _require_online_lab_pi(lab_pi_id)
    if lab_pi is not None:
        ok, result = _lab_pi_admin_api(lab_pi, 'POST', '/api/admin/ports', dict(request.form))
        flash('Serial port added.' if ok else result, 'success' if ok else 'danger')
    return redirect(url_for('admin_lab_pi_ui_settings', lab_pi_id=lab_pi_id))


@app.route('/admin/lab-pi/<int:lab_pi_id>/ui-settings/ports/<port_id>/edit', methods=['POST'])
@login_required
def admin_lab_pi_ui_port_edit(lab_pi_id, port_id):
    if not current_user.is_admin:
        abort(403)
    lab_pi = _require_online_lab_pi(lab_pi_id)
    if lab_pi is not None:
        ok, result = _lab_pi_admin_api(lab_pi, 'PUT', f'/api/admin/ports/{port_id}', dict(request.form))
        flash('Serial port updated.' if ok else result, 'success' if ok else 'danger')
    return redirect(url_for('admin_lab_pi_ui_settings', lab_pi_id=lab_pi_id))


@app.route('/admin/lab-pi/<int:lab_pi_id>/ui-settings/ports/<port_id>/delete', methods=['POST'])
@login_required
def admin_lab_pi_ui_port_delete(lab_pi_id, port_id):
    if not current_user.is_admin:
        abort(403)
    lab_pi = _require_online_lab_pi(lab_pi_id)
    if lab_pi is not None:
        ok, result = _lab_pi_admin_api(lab_pi, 'DELETE', f'/api/admin/ports/{port_id}')
        flash('Serial port removed.' if ok else result, 'success' if ok else 'danger')
    return redirect(url_for('admin_lab_pi_ui_settings', lab_pi_id=lab_pi_id))


@app.route('/admin/lab-pi/<int:lab_pi_id>/ui-settings/copy-to', methods=['POST'])
@login_required
def admin_lab_pi_ui_copy_to(lab_pi_id):
    """Copy this Lab Pi's control toggles, defaults, experiment name, and
    required dynamic controls onto another Lab Pi serving the same
    experiment — for when several physical boards run the same experiment
    and shouldn't need retyping the same settings on each one by hand.
    Serial port profiles are never touched here: device paths (and the ids
    that reference them) are specific to each physical Pi's attached
    hardware, so copying them verbatim would silently point at the wrong
    port on the target (see _remap_port_id_by_label)."""
    if not current_user.is_admin:
        abort(403)
    source = _require_online_lab_pi(lab_pi_id)
    if source is None:
        return redirect(url_for('admin_lab_pi_ui_settings', lab_pi_id=lab_pi_id))

    target_id = request.form.get('target_lab_pi_id', type=int)
    target = LabPi.query.get(target_id) if target_id else None
    if target is None or target.experiment_id != source.experiment_id:
        flash('Pick a valid Lab Pi that serves the same experiment.', 'danger')
        return redirect(url_for('admin_lab_pi_ui_settings', lab_pi_id=lab_pi_id))
    if not target.ip_address or target.status != 'ONLINE':
        flash(f'Lab Pi "{target.name}" is not online — cannot copy to it right now.', 'danger')
        return redirect(url_for('admin_lab_pi_ui_settings', lab_pi_id=lab_pi_id))

    # The Copy button lives inside the same form as every settings checkbox
    # (form="mainSettingsForm" in the template), so this request carries
    # whatever's currently on screen — save it to the source Lab Pi first,
    # then copy that just-saved state onward. Without this, Copy would read
    # back whatever was last actually saved to disk, silently ignoring any
    # edit made since the last "Save settings" click.
    ok, result = _lab_pi_admin_api(source, 'POST', '/api/admin/ui-config', _ui_config_body_from_form(request.form))
    if not ok:
        flash(f'Could not save current settings to "{source.name}" before copying: {result}', 'danger')
        return redirect(url_for('admin_lab_pi_ui_settings', lab_pi_id=lab_pi_id))

    ok, source_cfg = _lab_pi_admin_api(source, 'GET', '/api/admin/ui-config')
    if not ok:
        flash(source_cfg, 'danger')
        return redirect(url_for('admin_lab_pi_ui_settings', lab_pi_id=lab_pi_id))
    ok, target_cfg = _lab_pi_admin_api(target, 'GET', '/api/admin/ui-config')
    if not ok:
        flash(target_cfg, 'danger')
        return redirect(url_for('admin_lab_pi_ui_settings', lab_pi_id=lab_pi_id))

    source_ports = source_cfg.get('serial_ports', [])
    target_ports = target_cfg.get('serial_ports', [])
    warnings = []

    default_port_id, warn = _remap_port_id_by_label(
        source_cfg.get('defaults', {}).get('serial_plotter_default_port_id'), source_ports, target_ports)
    if warn:
        warnings.append(f'Default plotter port: {warn}')

    body = {
        'controls': source_cfg.get('controls', {}),
        'defaults': {**source_cfg.get('defaults', {}), 'serial_plotter_default_port_id': default_port_id},
        'experiment_name': source_cfg.get('experiment_name', ''),
    }
    ok, result = _lab_pi_admin_api(target, 'POST', '/api/admin/ui-config', body)
    if not ok:
        flash(f'Copy failed: {result}', 'danger')
        return redirect(url_for('admin_lab_pi_ui_settings', lab_pi_id=lab_pi_id))

    # Required dynamic controls: update ones that already exist on the target
    # (matched by label+type, since ids are per-Pi — see _remap_port_id_by_label),
    # add ones that don't. Never deletes a control the target has that the
    # source doesn't, so a copy can't destroy target-only setup.
    added, updated = 0, 0
    target_existing = target_cfg.get('required_controls', [])
    for control in source_cfg.get('required_controls', []):
        portId, warn = _remap_port_id_by_label(control.get('portId'), source_ports, target_ports)
        if warn:
            warnings.append(f'Required control "{control.get("label")}": {warn}')
        payload = _control_to_rc_form({**control, 'portId': portId})
        existing = next(
            (c for c in target_existing
             if c.get('label') == control.get('label') and c.get('type') == control.get('type')),
            None
        )
        if existing:
            ok, result = _lab_pi_admin_api(target, 'PUT', f'/api/admin/controls/{existing["id"]}', payload)
            if ok:
                updated += 1
            else:
                warnings.append(f'Required control "{control.get("label")}": {result}')
        else:
            ok, result = _lab_pi_admin_api(target, 'POST', '/api/admin/controls', payload)
            if ok:
                added += 1
            else:
                warnings.append(f'Required control "{control.get("label")}": {result}')

    flash(
        f'Copied to "{target.name}": controls, defaults, and experiment name applied; '
        f'{added} required control(s) added, {updated} updated. Serial port profiles were '
        f'not touched — those stay per-Lab-Pi since each board\'s device paths differ.',
        'success',
    )
    for w in warnings:
        flash(w, 'warning')
    return redirect(url_for('admin_lab_pi_ui_settings', lab_pi_id=lab_pi_id))


@app.route('/admin/lab-pi/maintenance/<int:lab_pi_id>', methods=['POST'])
@login_required
def admin_lab_pi_maintenance(lab_pi_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 401
    lab_pi = LabPi.query.get_or_404(lab_pi_id)
    lab_pi.status = 'MAINTENANCE' if lab_pi.status != 'MAINTENANCE' else 'ONLINE'
    db.session.commit()
    return jsonify({'success': True, 'status': lab_pi.status})


@app.route('/admin/lab-pi/restart/<int:lab_pi_id>', methods=['POST'])
@login_required
def admin_lab_pi_restart(lab_pi_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 401
    lab_pi = LabPi.query.get_or_404(lab_pi_id)
    try:
        import requests
        resp = requests.post(f'http://{lab_pi.ip_address}:5001/api/command', json={'command': 'restart'}, timeout=5)
        if resp.status_code == 200:
            return jsonify({'success': True, 'message': 'Restart command sent'})
        return jsonify({'error': 'Failed to send command'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/admin/lab-pi/reboot/<int:lab_pi_id>', methods=['POST'])
@login_required
def admin_lab_pi_reboot(lab_pi_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 401
    lab_pi = LabPi.query.get_or_404(lab_pi_id)
    try:
        import requests
        resp = requests.post(f'http://{lab_pi.ip_address}:5001/api/command', json={'command': 'reboot'}, timeout=5)
        if resp.status_code == 200:
            return jsonify({'success': True, 'message': 'Reboot command sent'})
        return jsonify({'error': 'Failed to send command'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/admin/lab-pi/delete/<int:lab_pi_id>', methods=['POST'])
@login_required
def admin_lab_pi_delete(lab_pi_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 401
    
    # Check if Lab Pi exists
    result = db.session.execute(db.text('SELECT id, lab_pi_id FROM lab_pi WHERE id = :id'), {'id': lab_pi_id})
    lab_pi_row = result.fetchone()
    if not lab_pi_row:
        return jsonify({'error': 'Lab Pi not found'}), 404
    
    # Delete using raw SQL - completely bypass ORM
    db.session.execute(db.text('DELETE FROM lab_pi_heartbeat WHERE lab_pi_id = :id'), {'id': lab_pi_id})
    db.session.execute(db.text('DELETE FROM lab_pi WHERE id = :id'), {'id': lab_pi_id})
    db.session.commit()
    return jsonify({'success': True})


@app.route('/api/lab-pi/<lab_pi_id>/command', methods=['POST'])
@login_required
def lab_pi_send_command(lab_pi_id):
    """
    Send command to a Lab Pi (e.g., start session, end session).
    """
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    lab_pi = LabPi.query.filter_by(lab_pi_id=lab_pi_id).first()
    if not lab_pi:
        return jsonify({'error': 'Lab Pi not found'}), 404
    
    data = request.get_json()
    command = data.get('command')
    
    if command == 'start_session':
        # Start a session on this Lab Pi
        session_key = data.get('session_key')
        booking_id = data.get('booking_id')
        
        lab_pi.current_session_key = session_key
        lab_pi.session_start_time = datetime.utcnow()
        lab_pi.relay_state = True
        db.session.commit()
        
        # Call lab-pi to start session and turn on relay
        if lab_pi.ip_address:
            try:
                # Start session on lab-pi
                requests.post(
                    f"http://{lab_pi.ip_address}:10000/api/lab-pi/session-start",
                    json={
                        'session_key': session_key,
                        'booking_id': booking_id,
                        'experiment_name': experiment.name if experiment else 'Unknown',
                        'board_type': experiment.board_type if experiment else 'arduino',
                        'sop_file': experiment.sop_file if experiment else None
                    },
                    headers={'X-Master-Api-Key': MASTER_API_KEY},
                    timeout=5
                )
                # Turn on relay
                requests.post(
                    f"http://{lab_pi.ip_address}:10000/toggle_relay",
                    json={'state': 'on', 'bypass': True},
                    timeout=5
                )
            except Exception as e:
                print(f"Error calling lab-pi: {e}")
        
        return jsonify({
            'success': True,
            'message': f'Session {session_key} started on Lab Pi {lab_pi_id}'
        })
    
    elif command == 'end_session':
        # End current session - save session key before clearing
        session_key = lab_pi.current_session_key
        lab_pi.current_session_key = None
        lab_pi.session_start_time = None
        lab_pi.relay_state = False
        db.session.commit()
        
        # Fetch CSV data from lab-pi BEFORE calling session-end (which cleans up lab-pi data)
        csv_data = None
        if session_key and lab_pi.ip_address:
            try:
                csv_data = fetch_session_data_from_lab_pi(lab_pi.ip_address, session_key)
            except Exception as e:
                print(f"[SESSION DATA] Failed to fetch data before session-end: {e}")
        
        # Call lab-pi to end session and turn off relay
        if lab_pi.ip_address:
            try:
                # Turn off relay
                requests.post(
                    f"http://{lab_pi.ip_address}:10000/toggle_relay",
                    json={'state': 'off', 'bypass': True},
                    timeout=5
                )
                # End session on lab-pi (this also cleans up lab-pi sensor data)
                if session_key:
                    requests.post(
                        f"http://{lab_pi.ip_address}:10000/api/lab-pi/session-end",
                        json={'session_key': session_key},
                        headers={'X-Master-Api-Key': MASTER_API_KEY},
                        timeout=5
                    )
            except Exception as e:
                print(f"Error calling lab-pi: {e}")
        
        # Send session report email for admin-terminated session
        if session_key:
            try:
                session = Session.query.filter_by(session_key=session_key).first()
                if session:
                    session.status = 'TERMINATED'
                    session.end_time = datetime.utcnow()
                    db.session.commit()
                    
                    # Get user and booking info
                    user = User.query.get(session.user_id)
                    booking = Booking.query.filter_by(session_key=session_key).first()
                    experiment_name = booking.experiment.name if booking and booking.experiment else 'Unknown'
                    
                    # Update booking status
                    if booking:
                        booking.status = 'EXPIRED'
                        booking.completed_at = datetime.utcnow()
                        db.session.commit()
                    
                    # Send report email with CSV data (already fetched above)
                    if user and user.email:
                        send_session_report_email(
                            user_email=user.email,
                            session_key=session_key,
                            experiment_name=experiment_name,
                            booking_id=booking.id if booking else 'N/A',
                            start_time=session.start_time,
                            end_time=session.end_time,
                            duration=session.duration,
                            csv_data=csv_data,
                            experiment_id=booking.experiment_id if booking else None
                        )
                    
                    # Explicitly clear csv_data from memory after email is sent
                    del csv_data
            except Exception as e:
                print(f"[SESSION REPORT] Failed to send report for admin-terminated session {session_key}: {e}")
        
        return jsonify({
            'success': True,
            'message': f'Session ended on Lab Pi {lab_pi_id}'
        })
    
    elif command == 'power_on':
        lab_pi.relay_state = True
        db.session.commit()
        
        # Call lab-pi to turn on relay
        if lab_pi.ip_address:
            try:
                response = requests.post(
                    f"http://{lab_pi.ip_address}:10000/toggle_relay",
                    json={'state': 'on', 'bypass': True},
                    timeout=5
                )
                if response.status_code == 200:
                    return jsonify({'success': True, 'message': 'Hardware power ON (relay activated on Lab Pi)'})
            except Exception as e:
                print(f"Error calling lab-pi toggle_relay: {e}")
                return jsonify({'success': False, 'error': f'Failed to control relay: {str(e)}'})
        return jsonify({'success': True, 'message': 'Hardware power ON'})
    
    elif command == 'power_off':
        lab_pi.relay_state = False
        db.session.commit()
        
        # Call lab-pi to turn off relay
        if lab_pi.ip_address:
            try:
                response = requests.post(
                    f"http://{lab_pi.ip_address}:10000/toggle_relay",
                    json={'state': 'off', 'bypass': True},
                    timeout=5
                )
                if response.status_code == 200:
                    return jsonify({'success': True, 'message': 'Hardware power OFF (relay deactivated on Lab Pi)'})
            except Exception as e:
                print(f"Error calling lab-pi toggle_relay: {e}")
                return jsonify({'success': False, 'error': f'Failed to control relay: {str(e)}'})
        return jsonify({'success': True, 'message': 'Hardware power OFF'})
    
    return jsonify({'error': 'Unknown command'}), 400


# ---------- AUDIO STREAMING ----------
# Audio will be streamed from Lab Pi to Master Pi, and then broadcast to connected clients
# The actual audio handling is done via SocketIO in the Audio server
# This endpoint receives audio from Lab Pi and broadcasts via SocketIO

@app.route('/api/audio/stream', methods=['POST'])
@csrf.exempt
def receive_audio_stream():
    """
    Receive audio stream from Lab Pi and broadcast to connected clients via SocketIO
    """
    try:
        data = request.json
        lab_pi_id = data.get('lab_pi_id')
        audio_b64 = data.get('audio')
        sample_rate = data.get('sample_rate', 16000)
        channels = data.get('channels', 1)
        
        if not lab_pi_id or not audio_b64:
            return jsonify({'error': 'Missing lab_pi_id or audio'}), 400
        
        # Broadcast to all connected clients
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


# ---------- SOCKET HANDLERS ----------
# Every handler below is a thin relay: it never touches hardware directly
# (the Master has none — see MASTER_UI_MIGRATION_PLAN.md), it just forwards
# the browser's event, unchanged, to whichever Lab Pi is running that
# browser's session, over lab_pi_relay's per-session client connection.

def _session_for_sid():
    with sid_session_lock:
        return sid_session_map.get(request.sid)


@socketio.on('connect')
def on_connect():
    # The page passes its session_key as a query param on the socket.io
    # connection itself (see templates/index.html) — sockets don't inherit
    # the page URL's querystring for free.
    session_key = request.args.get('key')
    print(f"[DEBUG] Client connected: {request.sid}, session_key={session_key}")
    if not session_key:
        emit('feedback', 'Server: socket connected (no session_key — nothing will work until one is set)')
        return

    lab_pi_url = get_session_lab_pi_url(session_key)
    if not lab_pi_url:
        emit('feedback', f'Server: no active Lab Pi found for session {session_key}')
        return

    join_room(session_key)
    with sid_session_lock:
        sid_session_map[request.sid] = session_key

    emit('feedback', 'Server: socket connected')
    # Warm the relay connection immediately and ask the Lab Pi for its
    # current port list, rather than waiting for the page to ask.
    lab_pi_relay.forward(session_key, lab_pi_url, 'list_ports', {})


@socketio.on('disconnect')
def on_disconnect():
    session_key = _session_for_sid()
    if not session_key:
        return
    with sid_session_lock:
        sid_session_map.pop(request.sid, None)
    leave_room(session_key)
    # Only drop the Lab Pi connection once no browser tab for this session
    # is listening anymore — a second tab (or a reconnect) shouldn't kill it.
    room_members = socketio.server.manager.get_participants('/', session_key)
    if not any(True for _ in room_members):
        lab_pi_relay.disconnect(session_key)


def _relay_from_browser(event):
    """Forward `event` (with its data payload) from the connecting browser's
    socket straight through to that session's Lab Pi."""
    def handler(data=None):
        session_key = _session_for_sid()
        if not session_key:
            emit('feedback', '[relay] No active session on this connection')
            return
        lab_pi_url = get_session_lab_pi_url(session_key)
        if not lab_pi_url:
            emit('feedback', '[relay] No Lab Pi is currently assigned to this session')
            return
        lab_pi_relay.forward(session_key, lab_pi_url, event, data)
    return handler


for _relayed_event in (
    'list_ports', 'connect_serial', 'disconnect_serial', 'send_command',
    'reset_serial', 'waveform_config', 'update_osc_settings', 'osc_auto_level',
):
    socketio.on_event(_relayed_event, _relay_from_browser(_relayed_event))


# ---------- MAIN ----------
# Runs unconditionally at import time (not just under `python app.py`) so a
# production server (gunicorn importing `app:app`) still starts the session
# monitor and Lab Pi heartbeat monitor — these used to live inside the
# `if __name__ == '__main__'` guard below, which gunicorn never executes.
print("========================================")
print("Virtual Lab Server Starting...")
print("========================================")

start_session_monitor()
start_lab_pi_heartbeat_monitor()
server_ready = True
print("Server ready - GPIO operations can now proceed")

if __name__ == '__main__':
    import socket
    def check_port(port, name):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(('127.0.0.1', port))
        sock.close()
        if result == 0:
            print(f"✓ {name} is running on port {port}")
            return True
        else:
            print(f"✗ {name} is NOT running on port {port}")
            return False

    audio_running = check_port(9000, "Audio server")
    if not audio_running:
        print("\n⚠️  Audio service not detected!")
        print("   To enable audio, run:")
        print("   sudo systemctl enable audio_stream.service")
        print("   sudo systemctl start audio_stream.service")

    print("\nStarting Flask server on port 5000 (dev mode — use gunicorn in production)...")
    print("========================================")

    try:
        socketio.run(app, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)
    finally:
        print("Main server stopped")