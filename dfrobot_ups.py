#!/usr/bin/env python3
"""
DFRobot UPS (FIT0992) Monitoring Module
Monitors battery status, voltage, SOC, and AC power status
Compatible with Raspberry Pi OS
"""

import time
import csv
import os
import json
import logging
from datetime import datetime
from smbus2 import SMBus
import gpiod

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# =========================
# CONFIG
# =========================

BUS = 1
ADDR = 0x36

# GPIO pin for AC adapter detection
# The DFRobot UPS uses GPIO 6 by default, can be changed
AC_GPIO = 6

# Logging configuration - Use dynamic paths for portability
LOG_INTERVAL = 30  # seconds
HOME_DIR = os.path.expanduser("~")  # Get home directory dynamically
PROJECT_NAME = "admin-pi"  # Admin-pi specific
LOG_FILE = f"{HOME_DIR}/{PROJECT_NAME}/ups_log.csv"
BATTERY_STATUS_FILE = f"{HOME_DIR}/{PROJECT_NAME}/battery_status.json"

# Ensure log directory exists
os.makedirs(f"{HOME_DIR}/{PROJECT_NAME}", exist_ok=True)

# Battery thresholds
WARNING_SOC = 20
CRITICAL_SOC = 15
SHUTDOWN_SOC = 5

# =========================
# INITIALIZATION
# =========================

# Initialize I2C bus
try:
    bus = SMBus(BUS)
    i2c_available = True
    logger.info(f"I2C bus {BUS} initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize I2C bus: {e}")
    bus = None
    i2c_available = False

# Initialize GPIO for AC detection
gpio_available = False
chip = None
line = None
try:
    chip = gpiod.Chip("gpiochip0")
    line = chip.get_line(AC_GPIO)
    line.request(consumer="ups-monitor", type=gpiod.LINE_REQ_DIR_IN)
    gpio_available = True
    logger.info(f"GPIO pin {AC_GPIO} initialized for AC detection")
except (FileNotFoundError, OSError) as e:
    logger.warning(f"GPIO chip not available: {e}. AC monitoring disabled.")
    chip = None
    line = None

shutdown_triggered = False

# =========================
# I2C FUNCTIONS
# =========================

def swap16(x):
    """Swap bytes of a 16-bit integer"""
    return ((x & 0xFF) << 8) | (x >> 8)


def read_soc():
    """
    Read battery State of Charge (SOC) from UPS
    Returns: float - battery percentage (0-100)
    """
    if not i2c_available:
        return None
    try:
        # Register 0x04 contains SOC
        raw = bus.read_word_data(ADDR, 0x04)
        soc = swap16(raw) / 256.0
        
        # Get voltage for diagnostic and fallback calculation
        voltage = None
        try:
            raw_v = bus.read_word_data(ADDR, 0x02)
            voltage = swap16(raw_v) * 1.25 / 1000 / 16.0
        except:
            pass
        
        # If SOC is very low (<15%) and voltage is above 3.5V, use voltage-based estimation
        # This handles cases where fuel gauge lost calibration or has wrong parameters
        if soc < 15 and voltage is not None and voltage > 3.5:
            # Estimate SOC based on voltage (LiPo 3.0V-4.2V range)
            estimated_soc = ((voltage - 3.0) / 1.2) * 100
            estimated_soc = max(0, min(100, estimated_soc))  # Clamp to 0-100
            logger.warning(f"Fuel gauge shows {soc:.1f}% but voltage is {voltage:.3f}V - using voltage-based estimate: {estimated_soc:.1f}%")
            return round(estimated_soc, 2)
        
        return round(soc, 2)
    except Exception as e:
        logger.error(f"Error reading SOC: {e}")
        return None


def read_voltage():
    """
    Read battery voltage from UPS
    Returns: float - voltage in Volts
    """
    if not i2c_available:
        return None
    try:
        # Register 0x02 contains voltage
        raw = bus.read_word_data(ADDR, 0x02)
        # Convert to voltage (see DFRobot FIT0992 datasheet)
        vcell = swap16(raw) * 1.25 / 1000
        return round(vcell / 16.0, 3)
    except Exception as e:
        logger.error(f"Error reading voltage: {e}")
        return None


def read_current():
    """
    Read battery current from UPS
    Returns: float - current in Amps (positive = charging, negative = discharging)
    """
    if not i2c_available:
        return None
    try:
        # Register 0x10 contains current (need to check datasheet)
        raw = bus.read_word_data(ADDR, 0x10)
        current = swap16(raw)
        # Convert to current (signed 16-bit)
        if current > 32768:
            current -= 65536
        return round(current / 1000.0, 3)
    except Exception as e:
        logger.error(f"Error reading current: {e}")
        return None


def read_power():
    """
    Read battery power from UPS
    Returns: float - power in Watts
    """
    if not i2c_available:
        return None
    try:
        # Register 0x12 contains power
        raw = bus.read_word_data(ADDR, 0x12)
        power = swap16(raw) / 1000.0
        return round(power, 2)
    except Exception as e:
        logger.error(f"Error reading power: {e}")
        return None


# =========================
# GPIO FUNCTIONS
# =========================

def ac_status():
    """
    Check if AC adapter is connected
    Returns: str - "AC_CONNECTED" or "ON_BATTERY"
    """
    if not gpio_available:
        return "AC_CONNECTED"  # Default when GPIO unavailable
    
    try:
        value = line.get_value()
        return "AC_CONNECTED" if value else "ON_BATTERY"
    except Exception as e:
        logger.error(f"Error reading GPIO: {e}")
        return "UNKNOWN"


def charging_status(ac, voltage):
    """
    Determine charging status based on AC connection and voltage
    Returns: str - "CHARGING", "FULL", or "DISCHARGING"
    """
    if ac == "ON_BATTERY":
        return "DISCHARGING"
    if voltage is None:
        return "UNKNOWN"
    if voltage >= 4.15:
        return "FULL"
    return "CHARGING"


# =========================
# LOGGING FUNCTIONS
# =========================

def init_log():
    """Initialize CSV log file with headers"""
    if not os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp", "SOC", "Voltage", "Current", "Power", "AC", "Charging"])
            logger.info(f"Initialized log file: {LOG_FILE}")
        except Exception as e:
            logger.error(f"Failed to create log file: {e}")


def log_data(soc, voltage, current, power, ac, chg):
    """Log battery data to CSV and JSON files"""
    
    # Create JSON status file for web interface
    battery_data = {
        "soc": soc,
        "voltage": voltage,
        "current": current,
        "power": power,
        "ac_status": ac,
        "charging_status": chg,
        "timestamp": datetime.now().isoformat()
    }
    
    try:
        with open(BATTERY_STATUS_FILE, "w") as f:
            json.dump(battery_data, f, indent=2)
    except Exception as e:
        logger.error(f"Failed to write battery status JSON: {e}")
    
    # Append to CSV log
    try:
        with open(LOG_FILE, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                soc if soc is not None else "N/A",
                voltage if voltage is not None else "N/A",
                current if current is not None else "N/A",
                power if power is not None else "N/A",
                ac,
                chg
            ])
    except Exception as e:
        logger.error(f"Failed to write to log file: {e}")


# =========================
# BATTERY MONITORING
# =========================

def battery_check(soc, voltage=None):
    """
    Check battery level and trigger actions based on thresholds
    """
    global shutdown_triggered
    
    if shutdown_triggered:
        return
    
    if soc is None:
        return
    
    # If SOC is very low but we have voltage reading, check if it's a false reading
    if soc <= SHUTDOWN_SOC and voltage is not None and voltage > 3.5:
        # Voltage is above 3.8V, likely a fuel gauge issue - don't shutdown
        logger.warning(f"⚠️ SOC shows {soc}% but voltage is {voltage:.3f}V - possible fuel gauge error, skipping shutdown")
        return
    
    if soc <= SHUTDOWN_SOC:
        logger.critical(f"🛑 Battery at {soc}% ({voltage:.3f}V if available) → Initiating shutdown")
        shutdown_triggered = True
        time.sleep(5)
        # Execute shutdown
        os.system("sudo shutdown -h now")
    
    elif soc <= CRITICAL_SOC:
        logger.warning(f"🔔 CRITICAL battery at {soc}%")
    
    elif soc <= WARNING_SOC:
        logger.warning(f"🔔 WARNING battery at {soc}%")


def get_ups_status():
    """
    Get current UPS status as a dictionary
    Useful for web interface API
    
    Returns: dict with keys: soc, voltage, current, power, ac_status, charging_status, timestamp
    """
    soc = read_soc()
    voltage = read_voltage()
    current = read_current()
    power = read_power()
    ac = ac_status()
    chg = charging_status(ac, voltage)
    
    return {
        "soc": soc,
        "voltage": voltage,
        "current": current,
        "power": power,
        "ac_status": ac,
        "charging_status": chg,
        "timestamp": datetime.now().isoformat()
    }


# =========================
# MAIN LOOP
# =========================

def main():
    """Main monitoring loop"""
    
    logger.info("🔋 DFRobot UPS Monitor Started")
    logger.info(f"AC GPIO Pin: {AC_GPIO}")
    logger.info(f"I2C Address: {hex(ADDR)}")
    logger.info(f"Log Interval: {LOG_INTERVAL} seconds")
    
    # Initialize log file
    init_log()
    
    last_log = 0
    
    while True:
        try:
            # Read battery metrics
            soc = read_soc()
            voltage = read_voltage()
            current = read_current()
            power = read_power()
            
            # Check AC status
            ac = ac_status()
            chg = charging_status(ac, voltage)
            
            # Check battery thresholds
            battery_check(soc, voltage)
            
            # Log status
            logger.info(
                f"🔋 SOC: {soc:.2f}% | ⚡ {voltage:.3f}V | "
                f"I: {current:.3f}A | P: {power:.2f}W | 🔌 {ac} | {chg}"
            )
            
            now = time.time()
            
            # Log to file at intervals
            if now - last_log > LOG_INTERVAL:
                log_data(soc, voltage, current, power, ac, chg)
                last_log = now
        
        except Exception as e:
            logger.error(f"UPS error: {e}")
        
        time.sleep(5)


if __name__ == "__main__":
    main()
