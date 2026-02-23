#!/bin/bash

# ============================================================================
# Lab Pi Services Setup Script
# ============================================================================
# This script installs and enables the audio and video streaming services
# for the Lab Pi node.
# ============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Lab Pi Services Setup${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

PROJECT_DIR="/home/abhi/admin-pi"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}⚠️  This script must be run as root (use sudo)${NC}"
    exit 1
fi

# ============================================================================
# Step 1: Install system dependencies
# ============================================================================
echo -e "${YELLOW}Step 1: Installing system dependencies...${NC}"

# Install ustreamer (MJPG streamer alternative)
if ! command -v ustreamer &> /dev/null; then
    echo "Installing ustreamer..."
    cd /tmp
    git clone https://github.com/pikvm/ustreamer.git
    cd ustreamer
    make
    make install
    cd $PROJECT_DIR
else
    echo "ustreamer already installed"
fi

# Install audio dependencies
echo "Installing audio dependencies..."
apt install -y alsa-utils libportaudio2 ffmpeg

# Install Python audio dependencies
echo "Installing Python audio packages..."
pip3 install aiohttp aiortc av

echo -e "${GREEN}Dependencies installed successfully${NC}"
echo ""

# ============================================================================
# Step 2: Copy service files
# ============================================================================
echo -e "${YELLOW}Step 2: Setting up service files...${NC}"

# Copy audio service
cp $PROJECT_DIR/Audio/services/audio_stream.service /etc/systemd/system/
echo "Copied audio_stream.service"

# Copy MJPG streamer service
cp $PROJECT_DIR/Audio/services/mjpg-streamer.service /etc/systemd/system/
echo "Copied mjpg-streamer.service"

# Reload systemd
systemctl daemon-reload

echo -e "${GREEN}Service files installed${NC}"
echo ""

# ============================================================================
# Step 3: Enable services
# ============================================================================
echo -e "${YELLOW}Step 3: Enabling services...${NC}"

# Enable and start audio service
systemctl enable audio_stream.service
systemctl start audio_stream.service
echo "Audio service enabled and started"

# Enable and start MJPG streamer service
systemctl enable mjpg-streamer.service
systemctl start mjpg-streamer.service
echo "MJPG streamer service enabled and started"

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Lab Pi Services Setup Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Services installed:"
echo "  - Audio Stream (port 9000)"
echo "  - MJPG/ustreamer Video Stream (port 8080)"
echo ""
echo "To check service status:"
echo "  systemctl status audio_stream.service"
echo "  systemctl status mjpg-streamer.service"
echo ""
