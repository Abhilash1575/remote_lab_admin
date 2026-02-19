#!/bin/bash

# ============================================================================
# Virtual Lab - Admin Pi (Master) Installation Script
# ============================================================================
# This script sets up the Master Pi (Admin + Booking + Database)
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/Abhilash1575/remote_lab_admin/main/install.sh | bash
#
# Or with parameters:
#   MASTER_URL=http://192.168.1.100:5000 MASTER_API_KEY=secret ./install.sh
# ============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Virtual Lab - Admin Pi Setup${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo -e "${YELLOW}⚠️  Running as root is not recommended. Run as regular user with sudo.${NC}"
fi

# ============================================================================
# Step 1: Get Configuration (optional)
# ============================================================================
echo -e "${YELLOW}Step 1: Configuration${NC}"
echo ""

# Master URL (for Lab Pis to connect to)
if [ -z "$MASTER_URL" ]; then
    read -p "Enter this Pi's URL (e.g., http://192.168.1.100:5000): " MASTER_URL
fi

# Admin API Key (for Lab Pi authentication)
if [ -z "$MASTER_API_KEY" ]; then
    read -p "Enter Admin API Key (optional, press Enter to skip): " MASTER_API_KEY
fi

echo ""
echo -e "${GREEN}Configuration Summary:${NC}"
echo "  Master URL: $MASTER_URL"
echo ""

# ============================================================================
# Step 2: Update System
# ============================================================================
echo -e "${YELLOW}Step 2: Updating system packages...${NC}"
sudo apt update && sudo apt upgrade -y

# ============================================================================
# Step 3: Install Dependencies
# ============================================================================
echo -e "${YELLOW}Step 3: Installing system dependencies...${NC}"
sudo apt install -y \
    python3-pip \
    python3-venv \
    python3-dev \
    git \
    curl \
    wget \
    avrdude \
    openocd \
    esptool \
    alsa-utils \
    libportaudio2 \
    ffmpeg

# ============================================================================
# Step 4: Clone Repository
# ============================================================================
echo -e "${YELLOW}Step 4: Setting up project...${NC}"

PROJECT_DIR="$HOME/vlab"
if [ -d "$PROJECT_DIR" ]; then
    echo "Project directory already exists. Pulling latest changes..."
    cd "$PROJECT_DIR"
    git pull
else
    echo "Cloning repository..."
    REPO_URL=${REPO_URL:-"https://github.com/Abhilash1575/remote_lab_admin.git"}
    git clone "$REPO_URL" "$PROJECT_DIR"
    cd "$PROJECT_DIR"
fi

# ============================================================================
# Step 5: Create Configuration
# ============================================================================
echo -e "${YELLOW}Step 5: Creating Admin Pi configuration...${NC}"

# Create .env file for Admin Pi
cat > "$PROJECT_DIR/.env" << EOF
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
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")

# Master URL (for Lab Pis to connect)
MASTER_URL=$MASTER_URL
MASTER_API_KEY=$MASTER_API_KEY

# Mail settings (configure for your email)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
EOF

echo "Configuration saved to $PROJECT_DIR/.env"

# ============================================================================
# Step 6: Setup Python Environment
# ============================================================================
echo -e "${YELLOW}Step 6: Setting up Python environment...${NC}"

cd "$PROJECT_DIR"

if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# ============================================================================
# Step 7: Detect OS and Run OS-specific Installation
# ============================================================================
echo -e "${YELLOW}Step 7: Running OS-specific installation...${NC}"

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    OS="unknown"
fi

echo "Detected OS: $OS"

# Run OS-specific installation
case "$OS" in
    debian|ubuntu|raspbian|linuxmint|pop)
        echo "Running APT-based installation..."
        if [ -f "$PROJECT_DIR/install/install-apt.sh" ]; then
            bash "$PROJECT_DIR/install/install-apt.sh"
        else
            echo -e "${YELLOW}install-apt.sh not found, skipping OS-specific setup${NC}"
        fi
        ;;
    *)
        echo -e "${YELLOW}Unknown OS: $OS - skipping OS-specific setup${NC}"
        ;;
esac

# ============================================================================
# Step 8: Create Systemd Service
# ============================================================================
echo -e "${YELLOW}Step 8: Creating systemd service...${NC}"

sudo tee /etc/systemd/system/vlab-admin.service > /dev/null << EOF
[Unit]
Description=Virtual Lab - Admin Pi (Master)
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$PROJECT_DIR
EnvironmentFile=$PROJECT_DIR/.env
ExecStart=$PROJECT_DIR/venv/bin/python $PROJECT_DIR/app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable vlab-admin.service

# ============================================================================
# Step 9: Final Summary
# ============================================================================
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Installation Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Admin Pi has been configured with:"
echo "  - URL: $MASTER_URL"
echo ""
echo "To start the Admin Pi service:"
echo "  sudo systemctl start vlab-admin"
echo ""
echo "To check status:"
echo "  sudo systemctl status vlab-admin"
echo ""
echo "To view logs:"
echo "  journalctl -u vlab-admin -f"
echo ""
