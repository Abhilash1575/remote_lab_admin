#!/bin/bash
# ============================================================================
# Virtual Lab - Admin Pi (Master) Setup Script
# ============================================================================
# This script automates the complete setup of the Admin Pi server,
# including system dependencies, compilation of ustreamer, Python venv,
# configuration, and systemd services.
# ============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}====================================================${NC}"
echo -e "${BLUE}        Virtual Lab - Admin Pi Setup Script         ${NC}"
echo -e "${BLUE}====================================================${NC}"

# Get directory paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Ensure we have sudo rights
echo -e "${YELLOW}Authenticating sudo rights...${NC}"
sudo -v

# 1. Update and install system dependencies
echo -e "${YELLOW}Step 1: Installing system packages...${NC}"
sudo apt update
sudo apt install -y \
    python3-pip \
    python3-venv \
    python3-dev \
    git \
    curl \
    wget \
    avrdude \
    openocd \
    alsa-utils \
    libportaudio2 \
    ffmpeg \
    i2c-tools \
    python3-smbus \
    swig \
    liblgpio-dev \
    libbsd-dev \
    libjpeg-dev \
    libevent-dev \
    portaudio19-dev

# 2. Clean conflicting Python packages and install standard library tools
echo -e "${YELLOW}Step 2: Cleaning up and installing global python libraries...${NC}"
sudo apt remove -y esptool python3-esptool 2>/dev/null || true
pip3 install --break-system-packages esptool lgpio smbus2 RPi.GPIO

# 3. Clone, compile, and install ustreamer
echo -e "${YELLOW}Step 3: Compiling and installing ustreamer...${NC}"
cd /tmp
sudo rm -rf ustreamer || true
git clone --depth 1 https://github.com/pikvm/ustreamer.git
cd ustreamer
make -j$(nproc)
sudo make install
cd "$PROJECT_DIR"

# 4. Set up python virtual environment
echo -e "${YELLOW}Step 4: Setting up virtual environment (venv) and requirements...${NC}"
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# 5. Setup configuration (.env)
echo -e "${YELLOW}Step 5: Configuring environment...${NC}"
LOCAL_IP=$(hostname -I | awk '{print $1}')
if [ -z "$LOCAL_IP" ]; then
    LOCAL_IP="127.0.0.1"
fi

ENV_FILE="$PROJECT_DIR/.env"
if [ ! -f "$ENV_FILE" ]; then
    echo "Creating new .env file..."
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    API_KEY=$(python3 -c "import secrets; print(secrets.token_hex(16))")
    
    cat > "$ENV_FILE" << EOF
# Admin Pi Configuration
VLAB_PI_TYPE=master
VLAB_PI_ID=admin-001
VLAB_PI_NAME="Admin Pi"

# Server settings
MASTER_HOST=0.0.0.0
MASTER_PORT=5000
MASTER_DEBUG=False

# Database
MASTER_DB_URI=sqlite:///vlab.db

# Security
SECRET_KEY=$SECRET_KEY

# Master URL (for Lab Pis to connect)
MASTER_URL=http://$LOCAL_IP:5000
MASTER_API_KEY=$API_KEY

# Mail settings (configure for your email)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password

# Google OAuth (from Google Cloud Console -> Credentials)
GOOGLE_CLIENT_ID=your-oauth-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-oauth-client-secret
EOF
    echo "Configuration written to .env with URL http://$LOCAL_IP:5000"
else
    echo ".env file already exists, skipping creation to preserve keys."
fi

# 6. Create systemd services
echo -e "${YELLOW}Step 6: Writing and enabling systemd services...${NC}"

# Admin service
sudo tee /etc/systemd/system/vlab-admin.service > /dev/null << EOF
[Unit]
Description=Virtual Lab - Admin Pi (Master)
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$PROJECT_DIR
EnvironmentFile=$PROJECT_DIR/.env
ExecStart=$PROJECT_DIR/venv/bin/gunicorn --worker-class gthread --threads 8 --workers 1 --timeout 120 --bind 0.0.0.0:5000 app:app
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Audio service
sudo tee /etc/systemd/system/vlab-audio.service > /dev/null << EOF
[Unit]
Description=Virtual Lab - Audio Stream Service
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$PROJECT_DIR
ExecStart=$PROJECT_DIR/venv/bin/python $PROJECT_DIR/Audio/server.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Camera service
sudo tee /etc/systemd/system/vlab-camera.service > /dev/null << EOF
[Unit]
Description=Virtual Lab - Camera Stream Service
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$PROJECT_DIR
ExecStart=/usr/local/bin/ustreamer --host 0.0.0.0 --port 8080 --device /dev/video0 --format jpeg --resolution 640x480 --desired-fps 15
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Reload and restart services
sudo systemctl daemon-reload

echo "Enabling services..."
sudo systemctl enable vlab-admin.service
sudo systemctl enable vlab-audio.service
sudo systemctl enable vlab-camera.service

echo "Starting services..."
sudo systemctl restart vlab-admin.service
sudo systemctl restart vlab-audio.service
sudo systemctl restart vlab-camera.service

echo -e "${GREEN}====================================================${NC}"
echo -e "${GREEN}🎉 Setup Complete!${NC}"
echo -e "${GREEN}====================================================${NC}"
echo "Your Admin Pi is now fully configured and running."
echo "Admin Web UI: http://$LOCAL_IP:5000"
echo "Audio stream: http://$LOCAL_IP:9000"
echo "Camera stream: http://$LOCAL_IP:8080"
echo -e "${GREEN}====================================================${NC}"
