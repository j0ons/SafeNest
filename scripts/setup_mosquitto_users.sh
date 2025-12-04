#!/bin/bash

################################################################################
# Mosquitto User Setup Script for SafeNest
#
# This script creates username/password combinations for all MQTT clients.
# Passwords are hashed using mosquitto_passwd utility.
#
# Usage: sudo bash setup_mosquitto_users.sh
################################################################################

set -e

PASSWD_FILE="/etc/mosquitto/passwd"

echo "[SafeNest] Setting up Mosquitto user authentication..."

# Create or clear password file
sudo rm -f "$PASSWD_FILE"
sudo touch "$PASSWD_FILE"

# Function to add user with password
add_user() {
    local username=$1
    local password=$2
    echo "Adding user: $username"
    sudo mosquitto_passwd -b "$PASSWD_FILE" "$username" "$password"
}

# === CREATE USERS ===
# NOTE: Change these passwords in production!

add_user "security_user" "SecurePass123!"
add_user "panel_user" "PanelPass123!"
add_user "intercom_user" "IntercomPass123!"
add_user "motion_user" "MotionPass123!"
add_user "light1_user" "Light1Pass123!"
add_user "light2_user" "Light2Pass123!"
add_user "nodered_user" "NodeRedPass123!"
add_user "controller_user" "ControllerPass123!"

# Set proper permissions
sudo chmod 600 "$PASSWD_FILE"
sudo chown mosquitto:mosquitto "$PASSWD_FILE"

echo ""
echo "✓ Users created successfully in $PASSWD_FILE"
echo ""
echo "Created users:"
echo "  - security_user    (Anomaly detection engine)"
echo "  - controller_user  (Main SafeNest controller)"
echo "  - panel_user       (Home control panel)"
echo "  - intercom_user    (Intercom device)"
echo "  - motion_user      (Motion sensor)"
echo "  - light1_user      (Smart light 1)"
echo "  - light2_user      (Smart light 2)"
echo "  - nodered_user     (Node-RED dashboard)"
echo ""
echo "WARNING: Change default passwords before production deployment!"
echo ""
echo "Next steps:"
echo "  1. Update client configurations with credentials"
echo "  2. Restart Mosquitto: sudo systemctl restart mosquitto"
