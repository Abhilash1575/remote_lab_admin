from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import UserMixin
import re

db = SQLAlchemy()
bcrypt = Bcrypt()

# Password policy constants
MIN_PASSWORD_LENGTH = 8
REQUIRE_UPPERCASE = True
REQUIRE_LOWERCASE = True
REQUIRE_NUMBER = True
REQUIRE_SPECIAL = True
PASSWORD_EXPIRY_DAYS = 90

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    password_changed_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login_at = db.Column(db.DateTime)
    last_login_ip = db.Column(db.String(45))
    is_admin = db.Column(db.Boolean, default=False)
    active = db.Column(db.Boolean, default=True)
    
    # Relationships
    bookings = db.relationship('Booking', backref='user', lazy=True)
    sessions = db.relationship('Session', backref='user', lazy=True)
    
    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')
    
    @password.setter
    def password(self, password):
        # Validate password against policy
        if not self.validate_password(password):
            raise ValueError('Password does not meet security requirements')
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        self.password_changed_at = datetime.utcnow()
    
    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)
    
    @staticmethod
    def validate_password(password):
        # Check minimum length
        if len(password) < MIN_PASSWORD_LENGTH:
            return False
        
        # Check character requirements
        if REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
            return False
        
        if REQUIRE_LOWERCASE and not any(c.islower() for c in password):
            return False
        
        if REQUIRE_NUMBER and not any(c.isdigit() for c in password):
            return False
        
        if REQUIRE_SPECIAL and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False
        
        return True
    
    def is_password_expired(self):
        if self.password_changed_at is None:
            return True
        return datetime.utcnow() - self.password_changed_at > timedelta(days=PASSWORD_EXPIRY_DAYS)
    
    def __repr__(self):
        return f'<User {self.email}>'

class Experiment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    max_duration = db.Column(db.Integer, nullable=False, default=60)  # in minutes
    price = db.Column(db.Float, default=0.0)
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    bookings = db.relationship('Booking', backref='experiment', lazy=True)
    
    def __repr__(self):
        return f'<Experiment {self.name}>'

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    experiment_id = db.Column(db.Integer, db.ForeignKey('experiment.id'), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default='UPCOMING')  # UPCOMING, ACTIVE, IN_PROGRESS, COMPLETED, EXPIRED, CANCELLED
    session_key = db.Column(db.String(20), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    
    # Relationships
    session = db.relationship('Session', backref='booking', uselist=False)
    
    def __repr__(self):
        return f'<Booking {self.session_key}>'

class Session(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    booking_id = db.Column(db.Integer, db.ForeignKey('booking.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    session_key = db.Column(db.String(20), unique=True, nullable=False)
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=False)
    duration = db.Column(db.Integer, nullable=False)  # in minutes
    ip_address = db.Column(db.String(45))
    mac_address = db.Column(db.String(17))
    status = db.Column(db.String(20), default='ACTIVE')  # ACTIVE, EXPIRED, TERMINATED
    
    def __repr__(self):
        return f'<Session {self.session_key}>'

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mac_address = db.Column(db.String(17), unique=True, nullable=False)
    ip_address = db.Column(db.String(45))
    device_name = db.Column(db.String(100), nullable=False)
    device_type = db.Column(db.String(50), nullable=False)
    location = db.Column(db.String(100))
    status = db.Column(db.String(20), default='ONLINE')  # ONLINE, OFFLINE, MAINTENANCE
    last_seen = db.Column(db.DateTime)
    registered_at = db.Column(db.DateTime)  # When device first came online
    firmware_version = db.Column(db.String(20))
    hardware_version = db.Column(db.String(20))
    
    # Monitoring fields
    cpu_usage = db.Column(db.Float)  # Percentage
    ram_usage = db.Column(db.Float)  # Percentage
    temperature = db.Column(db.Float)  # Celsius
    battery_level = db.Column(db.Float)  # Percentage
    battery_voltage = db.Column(db.Float)  # Volts
    ac_status = db.Column(db.Boolean)  # True if AC power is connected
    charging_status = db.Column(db.Boolean)  # True if battery is charging
    maintenance_mode = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f'<Device {self.device_name}>'

class DeviceMetric(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    cpu_usage = db.Column(db.Float)
    ram_usage = db.Column(db.Float)
    temperature = db.Column(db.Float)
    battery_level = db.Column(db.Float)
    battery_voltage = db.Column(db.Float)
    ac_status = db.Column(db.Boolean)
    charging_status = db.Column(db.Boolean)
    
    # Relationships
    device = db.relationship('Device', backref='metrics', lazy=True)
    
    def __repr__(self):
        return f'<DeviceMetric device_id={self.device_id} timestamp={self.timestamp}>'

class SystemLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    level = db.Column(db.String(10), default='INFO')  # DEBUG, INFO, WARNING, ERROR, CRITICAL
    category = db.Column(db.String(50), default='SYSTEM')  # SYSTEM, EXPERIMENT, ERROR, SSH
    message = db.Column(db.Text, nullable=False)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # Relationships
    device = db.relationship('Device', backref='logs', lazy=True)
    user = db.relationship('User', backref='logs', lazy=True)
    
    def __repr__(self):
        return f'<SystemLog {self.level}: {self.message}>'

class OTAUpdate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'), nullable=False)
    firmware_version = db.Column(db.String(20), nullable=False)
    firmware_path = db.Column(db.String(255), nullable=False)
    update_status = db.Column(db.String(20), default='PENDING')  # PENDING, DOWNLOADING, INSTALLING, COMPLETED, FAILED
    error_message = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    
    def __repr__(self):
        return f'<OTAUpdate {self.firmware_version}>'

class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    
    def __init__(self, user_id, token, expires_in=3600):
        self.user_id = user_id
        self.token = token
        self.expires_at = datetime.utcnow() + timedelta(seconds=expires_in)
    
    def is_expired(self):
        return datetime.utcnow() > self.expires_at
    
    def __repr__(self):
        return f'<PasswordResetToken {self.token}>'


class LabPi(db.Model):
    """
    Lab Pi - Represents a Raspberry Pi that handles experiment hardware.
    Each Lab Pi is registered with the Master Pi and sends heartbeats.
    """
    id = db.Column(db.Integer, primary_key=True)
    
    # Unique identifier (set in Lab Pi config)
    lab_pi_id = db.Column(db.String(50), unique=True, nullable=False)
    
    # Display name
    name = db.Column(db.String(100), nullable=False)
    
    # Network identification
    mac_address = db.Column(db.String(17), unique=True)
    ip_address = db.Column(db.String(45))
    hostname = db.Column(db.String(100))
    
    # Experiment this Lab Pi handles
    experiment_id = db.Column(db.Integer, db.ForeignKey('experiment.id'))
    experiment = db.relationship('Experiment', backref='lab_pis')
    
    # Status
    status = db.Column(db.String(20), default='OFFLINE')  # ONLINE, OFFLINE, MAINTENANCE, ERROR
    
    # Registration
    registered_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_heartbeat = db.Column(db.DateTime)
    heartbeat_interval = db.Column(db.Integer, default=30)  # seconds
    
    # Current session (if any)
    current_session_key = db.Column(db.String(20))
    session_start_time = db.Column(db.DateTime)
    
    # Hardware state
    relay_state = db.Column(db.Boolean, default=False)
    hardware_ready = db.Column(db.Boolean, default=True)
    hardware_status = db.Column(db.String(100))
    
    # System metrics
    cpu_usage = db.Column(db.Float)
    ram_usage = db.Column(db.Float)
    temperature = db.Column(db.Float)
    uptime = db.Column(db.Float)  # seconds
    
    # Battery (DFRobot UPS)
    battery_soc = db.Column(db.Float)  # State of Charge %
    battery_voltage = db.Column(db.Float)  # Voltage
    battery_ac_status = db.Column(db.String(50))  # AC_CONNECTED / AC_DISCONNECTED
    battery_charging = db.Column(db.String(50))  # CHARGING / NOT_CHARGING
    
    # Configuration
    api_key = db.Column(db.String(64))
    auto_register = db.Column(db.Boolean, default=True)
    
    def __repr__(self):
        return f'<LabPi {self.lab_pi_id} - {self.name}>'


class LabPiHeartbeat(db.Model):
    """
    Heartbeat log from Lab Pi - for monitoring and analytics
    """
    id = db.Column(db.Integer, primary_key=True)
    lab_pi_id = db.Column(db.Integer, db.ForeignKey('lab_pi.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Status at heartbeat time
    status = db.Column(db.String(20))  # ONLINE, OFFLINE
    session_active = db.Column(db.Boolean, default=False)
    session_key = db.Column(db.String(20))
    relay_state = db.Column(db.Boolean)
    hardware_ready = db.Column(db.Boolean)
    
    # System metrics
    uptime = db.Column(db.Float)
    
    # Relationship
    lab_pi = db.relationship('LabPi', backref='heartbeats')
    
    def __repr__(self):
        return f'<LabPiHeartbeat {self.lab_pi_id} at {self.timestamp}>'