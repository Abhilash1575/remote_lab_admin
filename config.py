#!/usr/bin/env python3
"""
Virtual Lab Configuration
=========================
Central configuration for Master Pi (Admin/Booking) and Lab Pi (Experiment Node)

Usage:
    For Master Pi: Copy this file and set PI_TYPE = "master"
    For Lab Pi: Copy this file and set PI_TYPE = "lab"
"""

import os

# ============================================================================
# PI TYPE CONFIGURATION - CHANGE THIS FOR EACH PI
# ============================================================================
# Options: "master" or "lab"
PI_TYPE = os.environ.get('VLAB_PI_TYPE', 'master')  # Default is master for testing

# ============================================================================
# MASTER PI CONFIGURATION (Admin + Booking + Database)
# ============================================================================
MASTER_CONFIG = {
    # Server settings
    'HOST': os.environ.get('MASTER_HOST', '0.0.0.0'),
    'PORT': int(os.environ.get('MASTER_PORT', 5000)),
    'DEBUG': os.environ.get('MASTER_DEBUG', 'False').lower() == 'true',
    
    # Database
    'DATABASE_URI': os.environ.get('MASTER_DB_URI', 'sqlite:///vlab.db'),
    
    # Security
    'SECRET_KEY': os.environ.get('SECRET_KEY', 'devkey'),
    
    # Heartbeat settings (for Lab Pi monitoring)
    'HEARTBEAT_INTERVAL': 30,  # seconds
    'HEARTBEAT_TIMEOUT': 120,  # seconds (Lab Pi offline if no heartbeat)
    
    # Mail settings
    'MAIL_SERVER': os.environ.get('MAIL_SERVER', 'smtp.gmail.com'),
    'MAIL_PORT': int(os.environ.get('MAIL_PORT', 587)),
    'MAIL_USE_TLS': True,
    'MAIL_USERNAME': os.environ.get('MAIL_USERNAME', 'your-email@gmail.com'),
    'MAIL_PASSWORD': os.environ.get('MAIL_PASSWORD', 'your-app-password'),
    'MAIL_DEFAULT_SENDER': os.environ.get('MAIL_DEFAULT_SENDER', 'your-email@gmail.com'),
}

# ============================================================================
# LAB PI CONFIGURATION (Experiment Node)
# ============================================================================
LAB_CONFIG = {
    # Server settings
    'HOST': os.environ.get('LAB_HOST', '0.0.0.0'),
    'PORT': int(os.environ.get('LAB_PORT', 5001)),
    'DEBUG': os.environ.get('LAB_DEBUG', 'False').lower() == 'true',
    
    # Master Pi connection settings
    'MASTER_URL': os.environ.get('MASTER_URL', 'http://localhost:5000'),
    'MASTER_API_KEY': os.environ.get('MASTER_API_KEY', ''),  # Set for security
    
    # This Lab Pi's unique identifier
    'LAB_PI_ID': os.environ.get('VLAB_PI_ID', 'lab-default'),  # e.g., "lab-001", "lab-002" - default for testing
    'LAB_PI_NAME': os.environ.get('VLAB_PI_NAME', 'Lab Pi'),  # e.g., "Experiment 1 - LED Blinky"
    'LAB_PI_MAC': os.environ.get('VLAB_PI_MAC', ''),  # MAC address for identification
    
    # Experiment this Lab Pi handles
    'EXPERIMENT_ID': int(os.environ.get('EXPERIMENT_ID', 1)),  # Which experiment this PI runs
    
    # Heartbeat settings
    'HEARTBEAT_INTERVAL': 30,  # seconds - how often to send heartbeat to master
    'HEARTBEAT_RETRY': 5,  # Number of retries before marking master unreachable
    
    # Hardware settings
    'RELAY_PIN': int(os.environ.get('RELAY_PIN', 26)),
    
    # Upload settings
    'UPLOAD_DIR': os.environ.get('UPLOAD_DIR', 'uploads'),
    'DEFAULT_FW_DIR': os.environ.get('DEFAULT_FW_DIR', 'default_fw'),
}

# ============================================================================
# GET ACTIVE CONFIGURATION BASED ON PI TYPE
# ============================================================================
def get_config():
    """Return configuration based on PI_TYPE"""
    if PI_TYPE == 'lab':
        return LAB_CONFIG
    return MASTER_CONFIG

# ============================================================================
# DIRECTORY PATHS
# ============================================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, LAB_CONFIG['UPLOAD_DIR'])
DEFAULT_FW_DIR = os.path.join(BASE_DIR, LAB_CONFIG['DEFAULT_FW_DIR'])
SOP_DIR = os.path.join(BASE_DIR, 'static')

# Create directories
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(DEFAULT_FW_DIR, exist_ok=True)
os.makedirs(SOP_DIR, exist_ok=True)

# ============================================================================
# EXPORT CONFIGURATION AS FLASK COMPATIBLE DICT
# ============================================================================
def get_flask_config():
    """Return Flask-compatible configuration dict"""
    config = get_config()
    flask_config = {
        'SECRET_KEY': config.get('SECRET_KEY', MASTER_CONFIG['SECRET_KEY']),
        'SQLALCHEMY_DATABASE_URI': config.get('DATABASE_URI', MASTER_CONFIG['DATABASE_URI']),
        'SQLALCHEMY_TRACK_MODIFICATIONS': False,
        'MAIL_SERVER': config.get('MAIL_SERVER', MASTER_CONFIG['MAIL_SERVER']),
        'MAIL_PORT': config.get('MAIL_PORT', MASTER_CONFIG['MAIL_PORT']),
        'MAIL_USE_TLS': config.get('MAIL_USE_TLS', True),
        'MAIL_USERNAME': config.get('MAIL_USERNAME', MASTER_CONFIG['MAIL_USERNAME']),
        'MAIL_PASSWORD': config.get('MAIL_PASSWORD', MASTER_CONFIG['MAIL_PASSWORD']),
        'MAIL_DEFAULT_SENDER': config.get('MAIL_DEFAULT_SENDER', MASTER_CONFIG['MAIL_DEFAULT_SENDER']),
    }
    return flask_config
