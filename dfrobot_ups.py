#!/usr/bin/env python3

import time
import csv
import os
import json
from datetime import datetime
from smbus2 import SMBus
import gpiod

# =========================
# CONFIG
# =========================

BUS = 1
ADDR = 0x36

AC_GPIO = 6
LOG_INTERVAL = 30
LOG_FILE = "/home/abhi/admin-pi/ups_log.csv"
BATTERY_STATUS_FILE = "/home/abhi/admin-pi/battery_status.json"

WARNING_SOC = 20
CRITICAL_SOC = 15
SHUTDOWN_SOC = 10

# =========================
# INIT
# =========================

bus = SMBus(BUS)

# Check if GPIO chip exists
gpio_available = False
try:
    chip = gpiod.Chip("gpiochip0")
    line = chip.get_line(AC_GPIO)
    line.request(consumer="ups-monitor", type=gpiod.LINE_REQ_DIR_IN)
    gpio_available = True
except (FileNotFoundError, OSError):
    print("⚠️ GPIO chip not available, AC monitoring disabled")
    chip = None
    line = None

shutdown_triggered = False

# =========================
# FUNCTIONS
# =========================

def swap16(x):
    return ((x & 0xFF) << 8) | (x >> 8)


def read_soc():
    raw = bus.read_word_data(ADDR, 0x04)
    return swap16(raw) / 256.0


def read_voltage():
    raw = bus.read_word_data(ADDR, 0x02)
    vcell = swap16(raw) * 1.25 / 1000
    return round(vcell / 16.0, 3)


def ac_status():
    if not gpio_available:
        return "AC_CONNECTED"  # Default when GPIO unavailable
    value = line.get_value()
    return "AC_CONNECTED" if value else "ON_BATTERY"


def charging_status(ac, voltage):
    if ac == "ON_BATTERY":
        return "DISCHARGING"
    if voltage >= 4.15:
        return "FULL"
    return "CHARGING"


def init_log():
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "SOC", "Voltage", "AC", "Charging"])


def log_data(soc, voltage, ac, chg):

    battery_data = {
        "soc": round(soc, 2),
        "voltage": voltage,
        "ac_status": ac,
        "charging_status": chg,
        "timestamp": datetime.now().isoformat()
    }

    with open(BATTERY_STATUS_FILE, "w") as f:
        json.dump(battery_data, f)

    with open(LOG_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            round(soc, 2),
            voltage,
            ac,
            chg
        ])


def battery_check(soc):
    global shutdown_triggered

    if shutdown_triggered:
        return

    if soc <= SHUTDOWN_SOC:
        print("🛑 Battery ≤10% → Shutdown")
        shutdown_triggered = True
        time.sleep(5)
        os.system("sudo shutdown -h now")

    elif soc <= CRITICAL_SOC:
        print("🔔 CRITICAL battery ≤15%")

    elif soc <= WARNING_SOC:
        print("🔔 WARNING battery ≤20%")


# =========================
# MAIN LOOP
# =========================

def main():

    print("🔋 UPS Monitor Started")

    init_log()

    last_log = 0

    while True:

        try:

            soc = read_soc()
            voltage = read_voltage()

            ac = ac_status()
            chg = charging_status(ac, voltage)

            battery_check(soc)

            print(
                f"🔋 SOC: {soc:.2f}% | "
                f"⚡ {voltage:.3f}V | "
                f"🔌 {ac} | "
                f"{chg}"
            )

            now = time.time()

            if now - last_log > LOG_INTERVAL:
                log_data(soc, voltage, ac, chg)
                last_log = now

        except Exception as e:
            print("UPS error:", e)

        time.sleep(5)


if __name__ == "__main__":
    main()