#!/usr/bin/env python3
import time
from smbus2 import SMBus
import csv
import os
from datetime import datetime, timedelta

# ===============================
# Hardware: DFRobot FIT0992
# ===============================

BUS = 1
ADDR = 0x36        # MAX17048

# Try to import GPIO module - try lgpio first (used in main app), then gpiozero
GPIO_AVAILABLE = False
LGPIO_AVAILABLE = False
AC_GPIO = 6  # GPIO6 = AC present
lgpio_handle = None

try:
    import lgpio
    LGPIO_AVAILABLE = True
    lgpio_handle = lgpio.gpiochip_open(0)
    try:
        lgpio.gpio_claim_input(lgpio_handle, AC_GPIO)
        GPIO_AVAILABLE = True
        print("✅ LGPIO initialized successfully")
    except Exception as e:
        # Try alternative claim method
        try:
            lgpio_handle = lgpio.gpiochip_open(0)
            lgpio.gpio_claim_input(lgpio_handle, AC_GPIO, lgpio.SET_BIAS_DISABLE)
            GPIO_AVAILABLE = True
            print("✅ LGPIO initialized successfully (with bias)")
        except Exception as e2:
            print(f"⚠️ LGPIO GPIO claim failed: {e2}")
except ImportError:
    print("⚠️ lgpio not available")
except Exception as e:
    print(f"⚠️ LGPIO initialization failed: {e}")

# Fallback to gpiozero if lgpio fails
if not GPIO_AVAILABLE:
    try:
        from gpiozero import Button
        ac_button = Button(AC_GPIO, pull_up=False)
        GPIO_AVAILABLE = True
        print("✅ GPIO initialized successfully using gpiozero")
    except ImportError:
        print("⚠️ gpiozero not available")
    except Exception as e:
        print(f"⚠️ GPIO initialization failed: {e}")

bus = SMBus(BUS)

# Logging configuration - Use relative to script location
import os
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_NAME = os.path.basename(SCRIPT_DIR)  # "admin-pi" or "lab-pi"
LOG_FILE = f"/home/{os.environ.get('USER', 'abhi')}/{PROJECT_NAME}/ups_log.csv"
BATTERY_STATUS_FILE = f"/home/{os.environ.get('USER', 'abhi')}/{PROJECT_NAME}/battery_status.json"
LOG_INTERVAL = 30  # seconds
LOG_RETENTION = 6 * 3600  # 6 hours in seconds

# Battery thresholds
WARNING_SOC = 20
CRITICAL_SOC = 15
SHUTDOWN_SOC = 10

# Shutdown flag to prevent multiple triggers
shutdown_triggered = False

def swap16(x):
    return ((x & 0xFF) << 8) | (x >> 8)

def read_soc():
    raw = bus.read_word_data(ADDR, 0x04)
    soc = swap16(raw) / 256.0
    # Validate - SOC should be between 0 and 100
    if soc < 0 or soc > 100:
        raise ValueError(f"Invalid SOC value: {soc}")
    return max(0.0, min(100.0, soc))

def read_voltage():
    """
    FIT0992 board uses resistor scaling.
    Datasheet VCELL formula must be divided by 16.
    """
    raw = bus.read_word_data(ADDR, 0x02)
    vcell = swap16(raw) * 1.25 / 1000.0
    voltage = round(vcell / 16.0, 3)
    # Validate - voltage should be between 3.0V and 4.2V for a LiPo battery
    if voltage < 3.0 or voltage > 4.5:
        raise ValueError(f"Invalid voltage value: {voltage}")
    return voltage

def ac_status():
    if not GPIO_AVAILABLE:
        return "UNKNOWN"  # No GPIO available
    
    try:
        # Use lgpio if available
        if LGPIO_AVAILABLE and lgpio_handle:
            try:
                value = lgpio.gpio_read(lgpio_handle, AC_GPIO)
                # lgpio.gpio_read returns an integer or tuple
                # If level is 1, AC is connected (pin pulled high)
                if isinstance(value, tuple):
                    level = value[0]
                else:
                    level = value
                return "AC_CONNECTED" if level == 1 else "ON_BATTERY"
            except lgpio.error as e:
                # GPIO might be busy, try to re-claim and read
                if "not allocated" in str(e) or "busy" in str(e):
                    try:
                        lgpio.gpio_free(lgpio_handle, AC_GPIO)
                        lgpio.gpio_claim_input(lgpio_handle, AC_GPIO)
                        value = lgpio.gpio_read(lgpio_handle, AC_GPIO)
                        if isinstance(value, tuple):
                            level = value[0]
                        else:
                            level = value
                        return "AC_CONNECTED" if level == 1 else "ON_BATTERY"
                    except:
                        return "UNKNOWN"
                raise
        
        # Fallback to gpiozero
        from gpiozero import Button
        ac_button = Button(AC_GPIO, pull_up=False)
        return "AC_CONNECTED" if ac_button.is_pressed else "ON_BATTERY"
    except Exception as e:
        print(f"⚠️ GPIO read error: {e}")
        return "UNKNOWN"

def charging_status(ac, voltage):
    """
    FIT0992 has no charge-status pin.
    We infer charging based on AC + voltage level.
    """
    if ac == "ON_BATTERY":
        return "DISCHARGING"
    if voltage >= 4.15:
        return "FULL"
    return "CHARGING"

def init_csv_log():
    """Initialize CSV log file with headers if it doesn't exist"""
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w', newline='') as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(["Timestamp", "SOC (%)", "Voltage (V)", "AC Status", "Charging Status"])

def log_data(soc, voltage, ac, chg):
    """Log data to CSV file with retention control"""
    import json
    global LOG_RETENTION
    
    # Write battery status to JSON file for Lab Pi to read
    try:
        battery_data = {
            'soc': round(soc, 2) if soc else 0,
            'voltage': round(voltage, 3) if voltage else 0,
            'ac_status': ac,
            'charging_status': chg,
            'timestamp': datetime.now().isoformat()
        }
        with open(BATTERY_STATUS_FILE, 'w') as f:
            json.dump(battery_data, f)
    except Exception as e:
        print(f"Failed to write battery status: {e}")
    
    # Check if log file needs to be rotated (older than 6 hours)
    if os.path.exists(LOG_FILE):
        file_mod_time = os.path.getmtime(LOG_FILE)
        current_time = time.time()
        if current_time - file_mod_time > LOG_RETENTION:
            print("🔄 Rotating log file (older than 6 hours)")
            os.remove(LOG_FILE)
            init_csv_log()
    
    # Log current data
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, 'a', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow([timestamp, round(soc, 2), voltage, ac, chg])
    print("📝 Logged data to CSV")

def battery_reminder(soc):
    """Check battery SOC and trigger reminders or shutdown"""
    global shutdown_triggered
    
    if shutdown_triggered:
        return
    
    if soc <= SHUTDOWN_SOC:
        print("🛑 SOC ≤ 10% - Initiating graceful shutdown")
        shutdown_triggered = True
        # Give time for logs to flush
        time.sleep(5)
        os.system("sudo shutdown -h now")
    elif soc <= CRITICAL_SOC:
        print("🔔 CRITICAL: SOC ≤ 15% - Shutdown imminent")
    elif soc <= WARNING_SOC:
        print("🔔 WARNING: SOC ≤ 20%")

def main():
    print("DFRobot FIT0992 UPS Monitor started", flush=True)
    
    # Initialize CSV log
    init_csv_log()
    
    # Check if log file is older than 6 hours on startup
    if os.path.exists(LOG_FILE):
        file_mod_time = os.path.getmtime(LOG_FILE)
        current_time = time.time()
        if current_time - file_mod_time > LOG_RETENTION:
            print("🔄 Rotating log file (older than 6 hours)")
            os.remove(LOG_FILE)
            init_csv_log()
    
    last_ac = None
    last_log_time = 0
    
    while True:
        try:
            # Retry I2C reads up to 3 times
            soc = None
            voltage = None
            i2c_success = False
            for attempt in range(3):
                try:
                    soc = read_soc()
                    voltage = read_voltage()
                    i2c_success = True
                    break  # Success, exit retry loop
                except IOError as e:
                    if attempt < 2:
                        print(f"⚠️ I2C read error, retrying... ({attempt+1}/3)")
                        time.sleep(1)
                    else:
                        print(f"⚠️ I2C read failed after 3 attempts")
            
            # Only check battery status if I2C read was successful
            # Don't shutdown if I2C fails - just skip the check
            if i2c_success and soc is not None and soc > 0:
                battery_reminder(soc)
            elif not i2c_success:
                print("⚠️ Skipping battery check - I2C communication issue")
            
            # Get AC status (works even if I2C fails)
            ac = ac_status()
            
            # Only get charging status if we have valid voltage
            if voltage is not None and voltage > 0:
                chg = charging_status(ac, voltage)
            else:
                chg = "UNKNOWN"
            
            if ac != last_ac:
                print(f"🔌 POWER STATUS → {ac}", flush=True)
                last_ac = ac
            
            # Log data every LOG_INTERVAL seconds
            current_time = time.time()
            if current_time - last_log_time >= LOG_INTERVAL:
                log_data(soc if soc else 0, voltage if voltage else 0, ac, chg)
                last_log_time = current_time
            
            # Print status - handle None values
            soc_display = soc if soc is not None else 0
            voltage_display = voltage if voltage is not None else 0
            print(
                f"🔋 SOC: {soc_display:.2f}% | "
                f"⚡ Voltage: {voltage_display:.3f} V | "
                f"🔄 {ac} | "
                f"🔋 {chg}",
                flush=True
            )
        
        except Exception as e:
            # Don't print error for I2C retries
            if "retrying" not in str(e):
                print(f"❌ UPS read error: {e}", flush=True)
        
        time.sleep(5)

if __name__ == "__main__":
    main()
