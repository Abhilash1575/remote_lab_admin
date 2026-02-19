#!/bin/bash

# Virtual Lab - Admin Pi APT-based Additional Installer
# This script is called by install.sh for additional setup
# It sets up services, DFRobot UPS, and other extras

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "========================================"
echo "Admin Pi - APT Additional Setup"
echo "========================================"
echo ""

# Get the project directory (parent of install/)
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"

# ============================================================================
# Step 1: Install additional hardware-specific packages
# ============================================================================
echo -e "${YELLOW}Step 1: Installing hardware-specific packages...${NC}"
sudo apt install -y \
    avrdude \
    openocd \
    esptool \
    alsa-utils \
    libportaudio2 \
    ffmpeg \
    ustreamer

# ============================================================================
# Step 2: Create required directories
# ============================================================================
echo -e "${YELLOW}Step 2: Creating required directories...${NC}"
mkdir -p uploads
mkdir -p default_fw
mkdir -p static/sop

# ============================================================================
# Step 3: Setup systemd services
# ============================================================================
echo -e "${YELLOW}Step 3: Setting up systemd services...${NC}"

# Admin Pi main service
sudo tee /etc/systemd/system/vlab-admin.service > /dev/null << 'EOF'
[Unit]
Description=Virtual Lab - Admin Pi (Master)
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$HOME/vlab
EnvironmentFile=$HOME/vlab/.env
ExecStart=$HOME/vlab/venv/bin/python $HOME/vlab/app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Audio streaming service (optional)
sudo tee /etc/systemd/system/vlab-audio.service > /dev/null << 'EOF'
[Unit]
Description=Virtual Lab - Audio Stream Service
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$HOME/vlab
ExecStart=$HOME/vlab/venv/bin/python $HOME/vlab/Audio/server.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# MJPG-Streamer service (optional, for camera)
sudo tee /etc/systemd/system/vlab-camera.service > /dev/null << 'EOF'
[Unit]
Description=Virtual Lab - Camera Stream Service
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$HOME/vlab
ExecStart=/usr/local/bin/mjpg_streamer -i "input_uvc.so -r 640x480 -f 15" -o "output_http.so -w $HOME/vlab/static"
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable vlab-admin.service

echo -e "${GREEN}✅ Admin Pi service installed${NC}"

# ============================================================================
# Step 4: Configure permissions
# ============================================================================
echo -e "${YELLOW}Step 4: Configuring permissions...${NC}"
sudo usermod -a -G dialout $USER 2>/dev/null || true
sudo usermod -a -G gpio $USER 2>/dev/null || true

# ============================================================================
# Step 5: Install DFRobot UPS support (Raspberry Pi only)
# ============================================================================
echo -e "${YELLOW}Step 5: Installing DFRobot UPS support...${NC}"

# Check if we're running on Raspberry Pi
if [ "$(uname -m)" = "armv7l" ] || [ "$(uname -m)" = "aarch64" ]; then
    if [ -f "/proc/device-tree/model" ] && grep -q "Raspberry" "/proc/device-tree/model"; then
        echo -e "${GREEN}✅ Detected Raspberry Pi - Installing DFRobot UPS support${NC}"
        
        # Copy UPS script
        if [ -f "$PROJECT_DIR/install/rpi_dfrobot_ups_all_in_one.sh" ]; then
            REAL_USER=$(whoami) bash "$PROJECT_DIR/install/rpi_dfrobot_ups_all_in_one.sh"
        else
            echo -e "${YELLOW}⚠️ DFRobot UPS script not found${NC}"
        fi
    else
        echo -e "${YELLOW}⚠️ Not a Raspberry Pi - Skipping DFRobot UPS installation${NC}"
    fi
else
    echo -e "${YELLOW}⚠️ Not ARM architecture - Skipping DFRobot UPS installation${NC}"
fi

# ============================================================================
# Step 6: Fix ALSA config for venv
# ============================================================================
echo -e "${YELLOW}Step 6: Fixing ALSA config for venv...${NC}"
sudo mkdir -p /tmp/vendor/share/alsa
sudo cp -r /usr/share/alsa/* /tmp/vendor/share/alsa/ 2>/dev/null || true

echo ""
echo "========================================"
echo "✅ Admin Pi APT additional setup complete!"
echo "========================================"
