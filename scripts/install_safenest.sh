#!/bin/bash

################################################################################
# SafeNest Automated Installation Script
#
# This script automates the complete installation and setup of SafeNest
# on a Raspberry Pi running Raspberry Pi OS (Debian-based).
#
# What it does:
# 1. Install system dependencies (Mosquitto, Python, etc.)
# 2. Install Python dependencies
# 3. Generate TLS certificates
# 4. Configure Mosquitto broker
# 5. Create user accounts
# 6. Setup firewall rules
# 7. Create systemd service files
# 8. Setup log directories
#
# Usage: sudo bash install_safenest.sh
#
# Note: This script must be run as root (sudo)
################################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Project directory (assumes script is in SafeNest/scripts/)
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_DIR="/opt/safenest"

echo -e "${GREEN}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║         SafeNest Installation Script v1.0                 ║"
echo "║    Secure Smart Home Framework for Raspberry Pi           ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}ERROR: This script must be run as root (sudo)${NC}"
    echo "Usage: sudo bash install_safenest.sh"
    exit 1
fi

# Confirm installation
echo -e "${YELLOW}This will install SafeNest and its dependencies.${NC}"
echo "Installation directory: $INSTALL_DIR"
echo ""
read -p "Continue? (yes/no): " -r
if [[ ! $REPLY =~ ^[Yy](es)?$ ]]; then
    echo "Installation cancelled."
    exit 0
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 1/10: Updating system packages"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
apt-get update
apt-get upgrade -y

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 2/10: Installing system dependencies"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
apt-get install -y \
    mosquitto \
    mosquitto-clients \
    python3 \
    python3-pip \
    python3-paho-mqtt \
    openssl \
    iptables \
    iptables-persistent \
    git

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 3/10: Installing Python dependencies"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
# Use system package instead of pip due to PEP 668
echo "Using python3-paho-mqtt from system packages (already installed)"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 4/10: Copying project files to $INSTALL_DIR"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
mkdir -p "$INSTALL_DIR"
cp -r "$PROJECT_DIR"/* "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR"/scripts/*.sh
chmod +x "$INSTALL_DIR"/src/*.py
chmod +x "$INSTALL_DIR"/tests/*.py

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 5/10: Generating TLS certificates"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cd "$INSTALL_DIR/certs"
bash generate_certs.sh

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 6/10: Configuring Mosquitto MQTT broker"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Backup existing config if present
if [ -f /etc/mosquitto/mosquitto.conf ]; then
    cp /etc/mosquitto/mosquitto.conf /etc/mosquitto/mosquitto.conf.backup
fi

cp "$INSTALL_DIR/config/mosquitto.conf" /etc/mosquitto/mosquitto.conf
cp "$INSTALL_DIR/config/aclfile.conf" /etc/mosquitto/aclfile.conf

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 7/10: Creating MQTT user accounts"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cd "$INSTALL_DIR/scripts"
bash setup_mosquitto_users.sh

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 8/10: Setting up firewall rules"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
bash setup_iptables.sh

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 9/10: Creating log directories"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
mkdir -p /var/log/mosquitto
chown mosquitto:mosquitto /var/log/mosquitto

touch /var/log/safenest_controller.log
touch /var/log/safenest_security.log
touch /var/log/safenest_logwatcher.log

chmod 644 /var/log/safenest_*.log

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 10/10: Creating systemd service files"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# SafeNest Controller Service
cat > /etc/systemd/system/safenest-controller.service <<EOF
[Unit]
Description=SafeNest Controller Service
After=network.target mosquitto.service
Requires=mosquitto.service

[Service]
Type=simple
User=pi
WorkingDirectory=$INSTALL_DIR/src
ExecStart=/usr/bin/python3 $INSTALL_DIR/src/safenest_controller.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# SafeNest Anomaly Detector Service
cat > /etc/systemd/system/safenest-detector.service <<EOF
[Unit]
Description=SafeNest Anomaly Detection Engine
After=network.target mosquitto.service
Requires=mosquitto.service

[Service]
Type=simple
User=pi
WorkingDirectory=$INSTALL_DIR/src
ExecStart=/usr/bin/python3 $INSTALL_DIR/src/safenest_detector.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# SafeNest Log Watcher Service
cat > /etc/systemd/system/safenest-logwatcher.service <<EOF
[Unit]
Description=SafeNest Log Watcher and Auto-Blocker
After=network.target mosquitto.service

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR/src
ExecStart=/usr/bin/python3 $INSTALL_DIR/src/safenest_logwatcher.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
systemctl daemon-reload

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Restarting Mosquitto broker"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
systemctl restart mosquitto
systemctl enable mosquitto

echo ""
echo -e "${GREEN}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║              Installation Complete!                       ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo ""
echo "Next steps:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "1. Start SafeNest services:"
echo "   sudo systemctl start safenest-controller"
echo "   sudo systemctl start safenest-detector"
echo "   sudo systemctl start safenest-logwatcher"
echo ""
echo "2. Enable auto-start on boot:"
echo "   sudo systemctl enable safenest-controller"
echo "   sudo systemctl enable safenest-detector"
echo "   sudo systemctl enable safenest-logwatcher"
echo ""
echo "3. Check service status:"
echo "   sudo systemctl status safenest-controller"
echo "   sudo systemctl status safenest-detector"
echo "   sudo systemctl status safenest-logwatcher"
echo ""
echo "4. Monitor logs:"
echo "   sudo tail -f /var/log/safenest_controller.log"
echo "   sudo tail -f /var/log/safenest_security.log"
echo ""
echo "5. Test the system:"
echo "   cd $INSTALL_DIR/tests"
echo "   python3 simulate_normal.py --duration 30"
echo ""
echo -e "${YELLOW}IMPORTANT SECURITY NOTES:${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "• Change default passwords in: $INSTALL_DIR/scripts/setup_mosquitto_users.sh"
echo "• Update passwords in Python scripts accordingly"
echo "• Copy CA certificate to clients: /etc/mosquitto/certs/ca.crt"
echo "• Review firewall rules: sudo iptables -L -n -v"
echo ""
echo "Documentation: $INSTALL_DIR/README.md"
echo "Node-RED Setup: $INSTALL_DIR/docs/node_red_setup.md"
echo ""
echo -e "${GREEN}SafeNest is ready to secure your smart home!${NC}"
echo ""
