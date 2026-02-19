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
import json
import math
import asyncio
import string
import secrets
from datetime import datetime, timedelta
from flask import Flask, send_from_directory, request, jsonify, render_template, abort, flash, redirect, url_for
from flask_socketio import SocketIO, emit
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename

# Import GPIO and Serial modules with fallback
try:
    import lgpio
    RELAY_PIN = 26
except Exception as e:
    print(f"lgpio import failed: {e}")
    lgpio = None
    RELAY_PIN = None

try:
    import serial
    from serial.tools import list_ports
except Exception as e:
    serial = None
    list_ports = None

import eventlet
eventlet.monkey_patch()

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
from models import db, bcrypt, User, Experiment, Booking, Session, Device, OTAUpdate, PasswordResetToken, DeviceMetric, SystemLog, LabPi, LabPiHeartbeat

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
UPLOAD_DIR = os.path.join(BASE_DIR, 'uploads')
DEFAULT_FW_DIR = os.path.join(BASE_DIR, 'default_fw')
SOP_DIR = os.path.join(BASE_DIR, 'static')
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(DEFAULT_FW_DIR, exist_ok=True)
os.makedirs(SOP_DIR, exist_ok=True)

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = 'devkey'  # In production, use environment variable
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'vlab.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your-app-password'
app.config['MAIL_DEFAULT_SENDER'] = 'your-email@gmail.com'

socketio = SocketIO(app, async_mode='eventlet')
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

with app.app_context():
    db.create_all()
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

# Background task for checking expired sessions
def run_session_monitor():
    """Background task to monitor and clean up expired sessions"""
    while True:
        try:
            with app.app_context():
                # Check and cleanup expired sessions
                check_expired_sessions()
                
                # Also check database sessions that might have expired
                now = datetime.now()
                expired_db_sessions = Session.query.filter(
                    Session.status == 'ACTIVE',
                    Session.end_time < now
                ).all()
                
                for session in expired_db_sessions:
                    session.status = 'EXPIRED'
                    # Turn off relay for this session
                    relay_off()
                    print(f"DB Session {session.session_key} expired, relay turned off")
                
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


serial_lock = threading.Lock()
ser = None
ser_stop = threading.Event()
data_generator_thread = None

# ---------- RELAY CONTROL ----------
gpio_handle = None

def init_gpio():
    global gpio_handle
    if lgpio is None or RELAY_PIN is None:
        return False
    try:
        if gpio_handle is None:
            gpio_handle = lgpio.gpiochip_open(0)
            try:
                lgpio.gpio_claim_output(gpio_handle, RELAY_PIN)
            except Exception as e:
                # If GPIO is already claimed, try to release and re-claim
                if "GPIO busy" in str(e):
                    print("GPIO already in use, trying to release and re-claim...")
                    try:
                        lgpio.gpio_free(gpio_handle, RELAY_PIN)
                        lgpio.gpio_claim_output(gpio_handle, RELAY_PIN)
                    except Exception as e2:
                        print(f"Failed to re-claim GPIO: {e2}")
                        gpio_handle = None
                        return False
                else:
                    raise e
        return True
    except Exception as e:
        print(f"Error initializing GPIO: {e}")
        gpio_handle = None
        return False

def relay_on():
    if not init_gpio():
        return False
    try:
        lgpio.gpio_write(gpio_handle, RELAY_PIN, 0)
        print("Relay ON")
        return True
    except Exception as e:
        print(f"Error turning relay ON: {e}")
        return False

def relay_off():
    if not init_gpio():
        return False
    try:
        lgpio.gpio_write(gpio_handle, RELAY_PIN, 1)
        print("Relay OFF")
        return True
    except Exception as e:
        print(f"Error turning relay OFF: {e}")
        return False

# ---------- UTIL FUNCTIONS ----------
# ---------- UTIL FUNCTIONS ----------
def check_expired_sessions():
    """Check for expired sessions and turn off relay if needed"""
    now = datetime.now()
    expired_keys = []
    
    for session_key, session_data in active_sessions.items():
        expires_at = session_data.get('expires_at')
        if expires_at and now.timestamp() > expires_at:
            expired_keys.append(session_key)
            # Turn off relay when session expires
            relay_off()
            print(f"Session {session_key} expired, relay turned off")
    
    # Remove expired sessions
    for key in expired_keys:
        if key in active_sessions:
            del active_sessions[key]
    
    return expired_keys

def list_serial_ports():
    if list_ports is None:
        return []
    return [p.device for p in list_ports.comports()]

def generate_session_key():
    return ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))

def send_email(to, subject, template):
    try:
        msg = Message(subject, recipients=[to])
        msg.html = template
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Email sending failed: {e}")
        return False

# ---------- USER AUTHENTICATION ----------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
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

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        email = request.form['email']
        full_name = request.form['full_name']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if User.query.filter_by(email=email.lower()).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('signup'))
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('signup'))
        
        if not User.validate_password(password):
            flash('Password must be at least 8 characters long and include uppercase, lowercase, number, and special character', 'danger')
            return redirect(url_for('signup'))
        
        user = User(
            email=email.lower(),
            full_name=full_name,
            active=True
        )
        user.password = password
        db.session.add(user)
        db.session.commit()
        
        flash('Your account has been created! You can now log in', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'success')
    return redirect(url_for('index'))

@app.route('/forgot_password', methods=['GET', 'POST'])
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
    sessions = Session.query.all()
    
    return render_template('admin/dashboard.html', 
                         users=users, 
                         experiments=experiments, 
                         bookings=bookings, 
                         devices=devices,
                         sessions=sessions)

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

@app.route('/admin/devices/delete/<int:device_id>')
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
    
    return render_template('admin/edit_device.html', device=device)

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
    
    # Devices by status
    online_devices = Device.query.filter_by(status='ONLINE').count()
    offline_devices = Device.query.filter_by(status='OFFLINE').count()
    maintenance_devices = Device.query.filter_by(status='MAINTENANCE').count()
    
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
        
        # Device status counts for each day
        day_online = Device.query.filter(
            Device.last_seen >= start_of_day,
            Device.last_seen <= end_of_day,
            Device.status == 'ONLINE'
        ).count()
        
        day_offline = Device.query.filter(
            Device.last_seen >= start_of_day,
            Device.last_seen <= end_of_day,
            Device.status == 'OFFLINE'
        ).count()
        
        day_maintenance = Device.query.filter(
            Device.last_seen >= start_of_day,
            Device.last_seen <= end_of_day,
            Device.status == 'MAINTENANCE'
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
                            log_file = "/home/abhi/virtual_lab/ups_log.csv"
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
            max_duration=int(request.form['max_duration']),
            price=float(request.form['price'])
        )
        db.session.add(experiment)
        db.session.commit()
        flash('Experiment added successfully', 'success')
        return redirect(url_for('manage_experiments'))
    
    experiments = Experiment.query.all()
    return render_template('admin/experiments.html', experiments=experiments)

@app.route('/admin/experiments/delete/<int:exp_id>')
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

@app.route('/admin/users')
@login_required
def manage_users():
    if not current_user.is_admin:
        abort(403)
    
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/users/delete/<int:user_id>')
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        abort(403)
    
    user = User.query.get(user_id)
    if user and not user.is_admin:  # Prevent deleting admin
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully', 'success')
    else:
        flash('User not found or cannot be deleted', 'danger')
    
    return redirect(url_for('manage_users'))

@app.route('/admin/bookings')
@login_required
def manage_bookings():
    if not current_user.is_admin:
        abort(403)
    
    bookings = Booking.query.all()
    return render_template('admin/bookings.html', bookings=bookings)

@app.route('/admin/bookings/delete/<int:booking_id>')
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
    
    sessions = Session.query.all()
    return render_template('admin/sessions.html', sessions=sessions)

@app.route('/admin/sessions/delete/<int:session_id>')
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
@app.route('/')
def index():
    experiments = Experiment.query.filter_by(active=True).all()
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
                if booking.started_at and now > booking.started_at + timedelta(minutes=duration):
                    booking.status = 'COMPLETED'
                    booking.completed_at = datetime.now()
        
        # Update session statuses
        active_sessions_db = Session.query.filter_by(status='ACTIVE').all()
        for session in active_sessions_db:
            if now > session.end_time:
                session.status = 'EXPIRED'
        
        db.session.commit()
    
    return render_template('homepage.html', experiments=experiments, bookings=bookings)

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
        return render_template('expired_session.html')
    
    # Check if there's a session entry, create if not
    session = Session.query.filter_by(session_key=session_key).first()
    if not session:
        session = Session(
            booking_id=booking.id,
            user_id=current_user.id,
            session_key=booking.session_key,
            duration=(booking.end_time - booking.start_time).total_seconds() // 60,
            end_time=booking.end_time,
            ip_address=request.remote_addr,
            status='ACTIVE'
        )
        db.session.add(session)
        booking.status = 'IN_PROGRESS'
        db.session.commit()
    
    # Find Lab Pi for this experiment
    lab_pi = LabPi.query.filter_by(
        experiment_id=booking.experiment_id,
        status='ONLINE'
    ).first()
    
    # Notify Lab Pi to start session if found
    lab_pi_url = None
    if lab_pi:
        lab_pi_url = f"http://localhost:5001"  # Always use localhost for same-machine communication
        # Send command to Lab Pi to start session
        try:
            response = requests.post(
                f"{lab_pi_url}/api/lab-pi/session-start",
                json={
                    'session_key': session_key,
                    'booking_id': booking.id,
                    'user_email': current_user.email
                },
                headers={'X-Lab-Pi-Id': lab_pi.lab_pi_id},
                timeout=5
            )
            print(f"Lab Pi notification response: {response.status_code}")
            # Update Lab Pi state
            lab_pi.current_session_key = session_key
            lab_pi.session_start_time = datetime.utcnow()
            db.session.commit()
            
            # Log session start
            exp_name = booking.experiment.name if booking.experiment else 'Unknown'
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
            print(f"Failed to notify Lab Pi: {e}")
    
    # Add to active sessions
    active_sessions[session_key] = {
        'start_time': time.time(),
        'duration': session.duration,
        'expires_at': session.end_time.timestamp(),
        'lab_pi_id': lab_pi.lab_pi_id if lab_pi else None,
        'lab_pi_url': lab_pi_url
    }
    
    duration = session.duration
    session_end_time = int(session.end_time.timestamp() * 1000)
    
    # Pass Lab Pi info to template
    return render_template('index.html', 
        session_duration=duration, 
        session_end_time=session_end_time,
        lab_pi_url=lab_pi_url,
        lab_pi_id=lab_pi.lab_pi_id if lab_pi else None
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
        del active_sessions[session_key]
        relay_off()
    return jsonify({'status': 'removed'})

@app.route('/toggle_relay', methods=['POST'])
@login_required
def toggle_relay():
    data = request.get_json()
    state = data.get('state')
    session_key = data.get('session_key')
    
    # Check for expired sessions first and clean them up
    check_expired_sessions()
    
    # Check if session is valid
    if session_key not in active_sessions:
        relay_off()  # Ensure relay is off for invalid/expired session
        return jsonify({'status': 'error', 'message': 'Invalid session'}), 400
    
    if state == 'on':
        success = relay_on()
        return jsonify({'status': 'on' if success else 'error'})
    elif state == 'off':
        success = relay_off()
        return jsonify({'status': 'off' if success else 'error'})
    else:
        return jsonify({'status': 'error', 'message': 'Invalid state'}), 400

@app.route('/chart')
@login_required
def chart():
    session_key = request.args.get('key')
    if not session_key:
        return render_template('expired_session.html')
    
    # Check if session is valid (either in active_sessions or in database)
    session_valid = False
    
    # First check active sessions dictionary
    if session_key in active_sessions:
        session_valid = True
    else:
        # Check database for active session
        booking = Booking.query.filter_by(session_key=session_key).first()
        if booking:
            # Check if booking is active
            now = datetime.now()
            if booking.start_time <= now <= booking.end_time:
                session_valid = True
                # Add to active sessions if not already present
                active_sessions[session_key] = {
                    'start_time': time.time(),
                    'duration': (booking.end_time - booking.start_time).total_seconds() // 60,
                    'expires_at': booking.end_time.timestamp()
                }
    
    if not session_valid:
        return render_template('expired_session.html')
    
    return render_template('chart.html')

@app.route('/camera')
@login_required
def camera():
    session_key = request.args.get('key')
    if not session_key:
        return render_template('expired_session.html')
    
    # Check if session is valid (either in active_sessions or in database)
    session_valid = False
    
    # First check active sessions dictionary
    if session_key in active_sessions:
        session_valid = True
    else:
        # Check database for active session
        booking = Booking.query.filter_by(session_key=session_key).first()
        if booking:
            # Check if booking is active
            now = datetime.now()
            if booking.start_time <= now <= booking.end_time:
                session_valid = True
                # Add to active sessions if not already present
                active_sessions[session_key] = {
                    'start_time': time.time(),
                    'duration': (booking.end_time - booking.start_time).total_seconds() // 60,
                    'expires_at': booking.end_time.timestamp()
                }
    
    if not session_valid:
        return render_template('expired_session.html')
    
    return render_template('camera.html')

@app.route('/ports')
@login_required
def ports_rest():
    return jsonify({'ports': list_serial_ports()})

# ---------- BOOKING SYSTEM ----------
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
        
        slot_date = request.form['slotDate']
        slot_time = request.form['slotTime']
        duration = int(request.form['duration'])
        
        if duration > experiment.max_duration:
            flash(f'Maximum duration for this experiment is {experiment.max_duration} minutes', 'danger')
            return redirect(url_for('book_experiment', exp_id=exp_id))
        
        # Parse date and time - use naive datetime (local time) for simplicity
        try:
            start_time = datetime.strptime(f"{slot_date} {slot_time}", "%Y-%m-%d %H:%M")
            end_time = start_time + timedelta(minutes=duration)
            print(f"DEBUG: Parsed start time: {start_time}, end time: {end_time}")
        except ValueError as e:
            print(f"DEBUG: Date parsing error: {e}")
            flash('Invalid date or time format', 'danger')
            return redirect(url_for('book_experiment', exp_id=exp_id))
        
        # Check if slot is available
        overlapping_bookings = Booking.query.filter(
            Booking.experiment_id == exp_id,
            Booking.status.notin_(['CANCELLED', 'EXPIRED']),
            ((Booking.start_time < end_time) & (Booking.end_time > start_time))
        ).count()
        
        print(f"DEBUG: Overlapping bookings: {overlapping_bookings}")
        
        if overlapping_bookings > 0:
            flash('This slot is already booked. Please select another time.', 'danger')
            return redirect(url_for('book_experiment', exp_id=exp_id))
        
        # Create booking
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
        
        # Send confirmation email
        subject = 'Booking Confirmed'
        template = f'''
            <h1>Booking Confirmed!</h1>
            <p>Your booking for {experiment.name} has been confirmed.</p>
            <p><strong>Date:</strong> {slot_date}</p>
            <p><strong>Time:</strong> {slot_time}</p>
            <p><strong>Duration:</strong> {duration} minutes</p>
            <p><strong>Session Key:</strong> {session_key}</p>
            <p>You will receive a reminder email 30 minutes before your session starts.</p>
        '''
        send_email(current_user.email, subject, template)
        
        flash('Booking confirmed! Check your email for details.', 'success')
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
                if booking.started_at and now > booking.started_at + timedelta(minutes=duration):
                    booking.status = 'COMPLETED'
                    booking.completed_at = datetime.now()
    
    db.session.commit()
    return render_template('my_bookings.html', bookings=bookings)

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
@app.route('/flash', methods=['POST'])
@login_required
def flash_firmware():
    board = request.form.get('board', 'generic')
    port = request.form.get('port', '') or ''
    available_ports = list_serial_ports()
    
    # Validate port - don't use default if no ports available
    if not available_ports:
        return jsonify({'status': 'No serial ports found. Please connect the ESP32 device.'}), 400
    
    # Validate provided port exists in available ports
    if port and port not in available_ports:
        return jsonify({'status': f'Port {port} not found. Available ports: {available_ports}'}), 400
    
    # Use first available port if none specified
    port = port or available_ports[0]
    
    fw = request.files.get('firmware')
    if not fw:
        return jsonify({'status': 'No firmware uploaded'}), 400
    fname = secure_filename(fw.filename)
    dest = os.path.join(UPLOAD_DIR, fname)
    fw.save(dest)

    # Determine firmware file type based on extension
    file_ext = os.path.splitext(fname)[1].lower()

    # Improved flashing commands with proper options for reliability
    # Key fixes: add baud rate, flash_size detect, and --after hard_reset
    # Updated for esptool v5.x syntax (write-flash instead of write_flash)
    commands = {
        'esp32': f"python3 -m esptool --chip esp32 --port {port} --baud 921600 write-flash 0x10000 {dest}",
        'esp8266': f"python3 -m esptool --chip esp8266 --port {port} --baud 921600 write-flash 0x00000 {dest}",
        'arduino': f"avrdude -v -p atmega328p -c arduino -P {port} -b115200 -D -U flash:w:{dest}:{ 'i' if file_ext == '.hex' else 'r' }",
        'attiny': f"avrdude -v -p attiny85 -c usbasp -P {port} -U flash:w:{dest}:{ 'i' if file_ext == '.hex' else 'r' }",
        'stm32': f"openocd -f interface/stlink.cfg -f target/stm32f4x.cfg -c \"program {dest} 0x08000000 verify reset exit\"",
        'nucleo_f446re': f"openocd -f interface/stlink.cfg -f target/stm32f4x.cfg -c \"program {dest} 0x08000000 verify reset exit\"",
        'black_pill': f"openocd -f interface/stlink.cfg -f target/stm32f4x.cfg -c \"program {dest} 0x08000000 verify reset exit\"",
        'msp430': f"echo 'mspdebug not available. Please install mspdebug to flash MSP430 boards'",
        'tiva': f"openocd -f board/ti_ek-tm4c123gxl.cfg -c \"program {dest} verify reset exit\"",
        'tms320f28377s': f"python3 dsp/flash_tool.py {dest}",
        'generic': f"echo 'No flashing command configured for {board}. Uploaded to {dest}'"
    }

    cmd = commands.get(board, commands['generic'])
    socketio.start_background_task(run_flash_command, cmd, fname)
    return jsonify({'status': f'Flashing started for {board}', 'command': cmd, 'port': port})

def run_flash_command(cmd, filename=None, timeout=180):
    """Run flash command with timeout and better error handling"""
    import select
    import fcntl
    import os
    import signal
    
    try:
        socketio.emit('flashing_status', f"Starting: {cmd}")
        
        # Check if command contains 'echo' (which is always available)
        if 'echo' in cmd:
            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        else:
            # Check if command starts with a known available tool
            tool = cmd.split()[0]
            if tool not in ['avrdude', 'esptool', 'openocd', 'python3']:
                socketio.emit('flashing_status', f'❌ Error: Tool {tool} not installed')
                return
            
            # Extract port from command for cleanup (supports --port, -P, and openocd interfaces)
            port_match = re.search(r'(?:--port|-P)\s+(\S+)', cmd)
            if port_match:
                port = port_match.group(1)
                # Kill any existing processes using this port
                try:
                    result = subprocess.run(f'lsof -t {port}', shell=True, capture_output=True, text=True)
                    if result.stdout.strip():
                        pids = result.stdout.strip().split('\n')
                        for pid in pids:
                            try:
                                os.kill(int(pid), signal.SIGKILL)
                                socketio.emit('flashing_status', f'Cleaned up process {pid} using {port}')
                            except:
                                pass
                        time.sleep(1)  # Wait for port to be released
                except:
                    pass
            
            # Also check for OpenOCD processes (used for STM32, Tiva, etc.)
            if 'openocd' in cmd:
                try:
                    result = subprocess.run('pkill -9 -f openocd', shell=True, capture_output=True, text=True)
                    time.sleep(0.5)
                except:
                    pass
            
            # Use subprocess with non-blocking output reading
            p = subprocess.Popen(
                cmd, 
                shell=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.STDOUT, 
                text=True,
                bufsize=1
            )
            
            # Set non-blocking mode for stdout
            fd = p.stdout.fileno()
            fl = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
            
            start_time = time.time()
            output_lines = []
            
            while True:
                # Check if process has finished
                ret = p.poll()
                
                # Try to read any available output
                try:
                    line = p.stdout.readline()
                    if line:
                        socketio.emit('flashing_status', line.strip())
                        output_lines.append(line)
                except:
                    pass
                
                # If process finished and no more output, exit loop
                if ret is not None:
                    # Wait a bit for any remaining output
                    time.sleep(0.5)
                    try:
                        line = p.stdout.readline()
                        while line:
                            socketio.emit('flashing_status', line.strip())
                            output_lines.append(line)
                            line = p.stdout.readline()
                    except:
                        pass
                    break
                
                # Check for timeout
                if time.time() - start_time > timeout:
                    p.kill()
                    p.wait()
                    socketio.emit('flashing_status', f'❌ Error: Flashing timed out after {timeout} seconds')
                    return
                
                # Small sleep to prevent CPU spinning
                time.sleep(0.1)
            
            rc = p.returncode
        
        msg = '✅ Flashing completed successfully' if rc == 0 else f'⚠️ Flashing ended with return code {rc}'
        socketio.emit('flashing_status', f'{msg} (file: {filename})')
    except Exception as e:
        socketio.emit('flashing_status', f'Error while flashing: {e}')

@app.route('/factory_reset', methods=['POST'])
@login_required
def factory_reset():
    try:
        data = request.get_json(force=True)
    except:
        data = request.form.to_dict()
    board = (data.get('board') or 'generic').lower()

    default_map = {
        'esp32': 'esp32_default.bin',
        'esp8266': 'esp32_default.bin',
        'arduino': 'arduino_default.hex',
        'attiny': 'attiny_default.hex',
        'stm32': 'stm32_default.bin',
        'nucleo_f446re': 'stm32_default.bin',
        'black_pill': 'stm32_default.bin',
        'msp430': 'generic_default.bin',
        'tiva': 'tiva_default.out',
        'tms320f28377s': 'tms320f28377s_default.out',
        'generic': 'generic_default.bin'
    }

    fname = default_map.get(board, default_map['generic'])
    fpath = os.path.join(DEFAULT_FW_DIR, fname)
    if not os.path.isfile(fpath):
        return jsonify({'error': f'Default firmware not found for board {board}: expected {fpath}'}), 404

    # Validate port - get from request or use first available
    port = data.get('port') or ''
    available_ports = list_serial_ports()
    
    if not available_ports:
        return jsonify({'error': 'No serial ports found. Please connect the device.'}), 400
    
    # Validate provided port exists
    if port and port not in available_ports:
        return jsonify({'error': f'Port {port} not found. Available: {available_ports}'}), 400
    
    port = port or available_ports[0]
    
    # Determine firmware file type based on extension
    file_ext = os.path.splitext(fname)[1].lower()

    # Improved commands with proper options (esptool v5.x syntax)
    commands = {
        'esp32': f"python3 -m esptool --chip esp32 --port {port} --baud 921600 write-flash 0x10000 {fpath}",
        'esp8266': f"python3 -m esptool --chip esp8266 --port {port} --baud 921600 write-flash 0x00000 {fpath}",
        'arduino': f"avrdude -v -p atmega328p -c arduino -P {port} -b115200 -D -U flash:w:{fpath}:{ 'i' if file_ext == '.hex' else 'r' }",
        'attiny': f"avrdude -v -p attiny85 -c usbasp -P {port} -U flash:w:{fpath}:{ 'i' if file_ext == '.hex' else 'r' }",
        'stm32': f"openocd -f interface/stlink.cfg -f target/stm32f4x.cfg -c \"program {fpath} 0x08000000 verify reset exit\"",
        'nucleo_f446re': f"openocd -f interface/stlink.cfg -f target/stm32f4x.cfg -c \"program {fpath} 0x08000000 verify reset exit\"",
        'black_pill': f"openocd -f interface/stlink.cfg -f target/stm32f4x.cfg -c \"program {fpath} 0x08000000 verify reset exit\"",
        'msp430': f"echo 'mspdebug not available. Please install mspdebug to flash MSP430 boards'",
        'tiva': f"openocd -f board/ti_ek-tm4c123gxl.cfg -c \"program {fpath} verify reset exit\"",
        'tms320f28377s': f"python3 dsp/flash_tool.py {fpath}",
        'generic': f"echo 'No flashing command configured for {board}. Default firmware at {fpath}'"
    }
    cmd = commands.get(board, commands['generic'])
    socketio.start_background_task(run_flash_command, cmd, fname)
    return jsonify({'status': f'Factory reset started for {board}', 'command': cmd, 'port': port})

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

@app.route('/api/lab-pi/register', methods=['POST'])
def lab_pi_register():
    """
    Register a Lab Pi with the Master Pi.
    Called by Lab Pi on startup.
    """
    data = request.get_json()
    
    # Validate required fields
    required_fields = ['lab_pi_id', 'name']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'Missing required field: {field}'}), 400
    
    lab_pi_id = data.get('lab_pi_id')
    name = data.get('name')
    mac_address = data.get('mac_address') or None  # Treat empty string as NULL
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
def lab_pi_heartbeat():
    """
    Receive heartbeat from Lab Pi.
    Called by Lab Pi every 30 seconds.
    """
    data = request.get_json()
    lab_pi_id = request.headers.get('X-Lab-Pi-Id')
    
    if not lab_pi_id:
        return jsonify({'error': 'Missing X-Lab-Pi-Id header'}), 400
    
    # Find Lab Pi
    lab_pi = LabPi.query.filter_by(lab_pi_id=lab_pi_id).first()
    if not lab_pi:
        return jsonify({'error': 'Lab Pi not registered'}), 404
    
    # Update Lab Pi status
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
    lab_pi.battery_charging = data.get('battery_charging')
    
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
    if lab_pi.experiment_id:
        active_booking = Booking.query.filter(
            Booking.experiment_id == lab_pi.experiment_id,
            Booking.status == 'ACTIVE'
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
                'user_email': active_booking.user.email if active_booking.user else None
            }
    
    return jsonify(response_data)


@app.route('/api/lab-pi/session-end', methods=['POST'])
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
    
    # Update Lab Pi state
    lab_pi.current_session_key = None
    lab_pi.session_start_time = None
    lab_pi.relay_state = False
    db.session.commit()
    
    # Update session in database if exists
    session = Session.query.filter_by(session_key=session_key).first()
    if session:
        session.status = 'EXPIRED' if reason == 'expired' else 'TERMINATED'
        session.end_time = datetime.utcnow()
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
        db.session.commit()
    
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
        'session_active': lp.current_session_key is not None
    } for lp in lab_pis])


# Admin Lab Pi Action Routes
@app.route('/admin/lab-pi/edit/<int:lab_pi_id>', methods=['GET', 'POST'])
@login_required
def admin_lab_pi_edit(lab_pi_id):
    if not current_user.is_admin:
        abort(403)
    
    lab_pi = LabPi.query.get_or_404(lab_pi_id)
    experiments = Experiment.query.all()
    
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
        
        db.session.commit()
        flash(f'Lab Pi "{lab_pi.name}" updated successfully!', 'success')
        return redirect(url_for('manage_devices'))
    
    return render_template('admin/edit_device.html', device=lab_pi, experiments=experiments, is_lab_pi=True)


@app.route('/admin/lab-pi/view/<int:lab_pi_id>', methods=['GET'])
@login_required
def admin_lab_pi_view(lab_pi_id):
    if not current_user.is_admin:
        abort(403)
    lab_pi = LabPi.query.get_or_404(lab_pi_id)
    return render_template('admin/view_device.html', device=lab_pi, is_lab_pi=True)


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
def lab_pi_send_command(lab_pi_id):
    """
    Send command to a Lab Pi (e.g., start session, end session).
    """
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
        
        return jsonify({
            'success': True,
            'message': f'Session {session_key} started on Lab Pi {lab_pi_id}'
        })
    
    elif command == 'end_session':
        # End current session
        lab_pi.current_session_key = None
        lab_pi.session_start_time = None
        lab_pi.relay_state = False
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Session ended on Lab Pi {lab_pi_id}'
        })
    
    elif command == 'power_on':
        lab_pi.relay_state = True
        db.session.commit()
        return jsonify({'success': True, 'message': 'Hardware power ON'})
    
    elif command == 'power_off':
        lab_pi.relay_state = False
        db.session.commit()
        return jsonify({'success': True, 'message': 'Hardware power OFF'})
    
    return jsonify({'error': 'Unknown command'}), 400


# ---------- AUDIO STREAMING ----------
# Audio will be streamed from Lab Pi to Master Pi, and then broadcast to connected clients
# The actual audio handling is done via SocketIO in the Audio server
# This endpoint receives audio from Lab Pi and broadcasts via SocketIO

@app.route('/api/audio/stream', methods=['POST'])
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
        })
        
        return jsonify({'success': True})
        
    except Exception as e:
        print(f"Error receiving audio: {e}")
        return jsonify({'error': str(e)}), 500


# ---------- MOCK GENERATOR ----------
def mock_data_generator():
    print("Mock data generator STARTED.")
    try:
        while True:
            sensor1 = 25.0 + random.uniform(-5.0, 5.0)
            sensor2 = 60.0 + random.uniform(-10.0, 10.0)
            sensor3 = 0.5 + random.uniform(-0.2, 0.2)
            sensor4 = 3.3 + random.uniform(-0.5, 0.5)
            payload = {
                'sensor1': round(sensor1, 2),
                'sensor2': round(sensor2, 2),
                'sensor3': round(sensor3, 3),
                'sensor4': round(sensor4, 2)
            }
            socketio.emit('sensor_data', payload)
            eventlet.sleep(0.1)
    except eventlet.greenlet.GreenletExit:
        print("Mock data generator KILLED.")
    except Exception as e:
        print("Mock data generator error:", e)

# ---------- SERIAL READER ----------
def serial_reader_worker(serial_obj):
    try:
        while not ser_stop.is_set():
            line = serial_obj.readline()
            if not line:
                continue
            try:
                text = line.decode(errors='replace').strip()
            except:
                text = str(line)
            socketio.emit('feedback', text)

            if any(sep in text for sep in [':', '=', '@', '>', '#', '^', '!', '$', '*', '%', '~', '\\', '|', '+', '-', ';', ',']) and any(c.isdigit() for c in text):
                trimmed = re.sub(r'^\d{1,2}:\d{2}:\d{2}\s*', '', text.strip())
                pairGroups = re.split(r'[,;]', trimmed)
                data = {}
                for group in pairGroups:
                    if not group.strip():
                        continue
                    normalized = re.sub(r'[:=>@#>^!$*~\\|+%\s&]+', ' ', group).strip()
                    tokens = re.split(r'\s+', normalized)
                    for i in range(0, len(tokens), 2):
                        if i + 1 < len(tokens):
                            k = tokens[i].strip().lower()
                            rawv = tokens[i + 1].strip()
                            try:
                                num = float(re.sub(r'[^\d\.\-+eE]', '', rawv))
                                if not math.isnan(num):
                                    data[k] = num
                            except:
                                pass
                if data:
                    socketio.start_background_task(send_sensor_data_to_clients, data)
    except Exception as e:
        socketio.emit('feedback', f'[serial worker stopped] {e}')

# ---------- SOCKET HANDLERS ----------
@socketio.on('connect')
def on_connect():
    print("[DEBUG] Client connected:", request.sid)
    emit('ports_list', list_serial_ports())
    emit('feedback', 'Server: socket connected')

@socketio.on('list_ports')
def handle_list_ports():
    emit('ports_list', list_serial_ports())

@socketio.on('connect_serial')
def handle_connect_serial(data):
    global ser, ser_stop, data_generator_thread
    port = data.get('port')
    baud = int(data.get('baud', 115200))
    if not port:
        emit('serial_status', {'status': 'error', 'message': 'No port selected'})
        return
    if serial is None:
        emit('serial_status', {'status': 'error', 'message': 'pyserial not available on server'})
        return
    with serial_lock:
        try:
            if ser and ser.is_open:
                ser.close()
            if data_generator_thread:
                data_generator_thread.kill()
                data_generator_thread = None

            ser = serial.Serial(port, baud, timeout=1)
            ser_stop.clear()
            eventlet.spawn(serial_reader_worker, ser)
            emit('serial_status', {'status': 'connected', 'port': port, 'baud': baud})
        except Exception as e:
            emit('serial_status', {'status': 'error', 'message': str(e)})

@socketio.on('disconnect_serial')
def handle_disconnect_serial():
    global ser, ser_stop, data_generator_thread
    with serial_lock:
        try:
            ser_stop.set()
            if ser and ser.is_open:
                ser.close()
            if data_generator_thread is None:
                data_generator_thread = eventlet.spawn(mock_data_generator)
            emit('serial_status', {'status': 'disconnected'})
        except Exception as e:
            emit('serial_status', {'status': 'error', 'message': str(e)})

@socketio.on('send_command')
def handle_send_command(data):
    global ser
    cmd = data.get('cmd', '')
    out = cmd + ("\n" if not cmd.endswith("\n") else "")
    try:
        with serial_lock:
            if ser and ser.is_open:
                ser.write(out.encode())
                emit('feedback', f'SENT> {cmd}')
            else:
                emit('feedback', f'[no-serial] {cmd}')
    except Exception as e:
        emit('feedback', f'[send error] {e}')

@socketio.on('waveform_config')
def handle_waveform_config(cfg):
    shape = cfg.get('shape'); freq = cfg.get('freq'); amp = cfg.get('amp')
    msg = f'WAVE {shape} FREQ {freq} AMP {amp}'
    emit('feedback', f'[waveform] {msg}')
    with serial_lock:
        try:
            if ser and ser.is_open:
                ser.write((msg + "\n").encode())
        except Exception as e:
            emit('feedback', f'[waveform send error] {e}')

def send_sensor_data_to_clients(data):
    try:
        with app.app_context():
            socketio.emit('sensor_data', data, namespace='/')
            print("[DEBUG] Emitted to clients:", data)
    except Exception as e:
        print("[ERROR] Failed to emit sensor_data:", e)

# ---------- MAIN ----------
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

    print("========================================")
    print("Virtual Lab Server Starting...")
    print("========================================")

    audio_running = check_port(9000, "Audio server")
    if not audio_running:
        print("\n⚠️  Audio service not detected!")
        print("   To enable audio, run:")
        print("   sudo systemctl enable audio_stream.service")
        print("   sudo systemctl start audio_stream.service")

    print("\nStarting Flask server on port 5000...")
    print("========================================")
    
    # Start the session monitor background task
    start_session_monitor()
    
    # Start the Lab Pi heartbeat monitor
    start_lab_pi_heartbeat_monitor()
    
    try:
        socketio.run(app, host='0.0.0.0', port=5000)
    finally:
        print("Main server stopped")