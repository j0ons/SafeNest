#!/bin/bash

################################################################################
# SafeNest Firewall Setup Script
#
# Configures iptables firewall rules for the SafeNest Raspberry Pi gateway.
# Implements a secure default-deny policy with specific allows for required services.
#
# Features:
# - Default DROP policy on INPUT chain
# - Allow established/related connections
# - Allow localhost traffic
# - Allow SSH (optional, can be disabled)
# - Allow MQTT over TLS (8883)
# - Allow Node-RED dashboard (1880)
# - Rate limiting for connection attempts (DoS mitigation)
# - Logging of dropped packets
#
# Usage: sudo bash setup_iptables.sh
#
# To make persistent across reboots:
#   sudo apt-get install iptables-persistent
#   sudo netfilter-persistent save
################################################################################

set -e

echo "=================================="
echo "SafeNest Firewall Setup"
echo "=================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run as root (sudo)"
    exit 1
fi

echo "[1/6] Flushing existing rules..."
# Flush all existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

echo "[2/6] Setting default policies..."
# Default policies: DROP incoming, ACCEPT outgoing
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

echo "[3/6] Allowing loopback and established connections..."
# Allow loopback traffic (localhost)
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established and related connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

echo "[4/6] Configuring service access rules..."

# === SSH Access (Optional - comment out to disable) ===
# Allow SSH from local network only for security
iptables -A INPUT -p tcp -s 192.168.1.0/24 --dport 22 -m conntrack --ctstate NEW -j ACCEPT

# For added security, rate limit SSH connections to prevent brute force
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set --name SSH
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP

# === MQTT over TLS ===
# Allow MQTT TLS connections (port 8883)
iptables -A INPUT -p tcp --dport 8883 -m conntrack --ctstate NEW -j ACCEPT

# Rate limit MQTT connections to prevent DoS
iptables -A INPUT -p tcp --dport 8883 -m conntrack --ctstate NEW -m recent --set --name MQTT
iptables -A INPUT -p tcp --dport 8883 -m conntrack --ctstate NEW -m recent --update --seconds 10 --hitcount 20 --name MQTT -j DROP

# === Node-RED Dashboard ===
# Allow Node-RED web interface (local network only)
iptables -A INPUT -p tcp -s 192.168.1.0/24 --dport 1880 -m conntrack --ctstate NEW -j ACCEPT

# === OPTIONAL: MQTT WebSocket (if enabled in mosquitto.conf) ===
# Uncomment if you enabled WebSocket listener on port 9001
# iptables -A INPUT -p tcp -s 192.168.1.0/24 --dport 9001 -m conntrack --ctstate NEW -j ACCEPT

echo "[5/6] Configuring protection rules..."

# === Protection Against Common Attacks ===

# Drop invalid packets
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# Drop NULL packets (reconnaissance)
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

# Drop XMAS packets (reconnaissance)
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP

# Drop SYN flood protection
iptables -N syn_flood
iptables -A INPUT -p tcp --syn -j syn_flood
iptables -A syn_flood -m limit --limit 1/s --limit-burst 3 -j RETURN
iptables -A syn_flood -j DROP

# Limit ICMP (ping) to prevent ping flood
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 2 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

echo "[6/6] Configuring logging..."

# === Logging (Optional - can generate lots of logs) ===
# Log dropped packets for monitoring (limit to prevent log flooding)
iptables -N LOGGING
iptables -A INPUT -j LOGGING
iptables -A LOGGING -m limit --limit 5/min -j LOG --log-prefix "IPTables-Dropped: " --log-level 4
iptables -A LOGGING -j DROP

echo ""
echo "✓ Firewall rules applied successfully!"
echo ""
echo "Active Rules Summary:"
echo "---------------------"
iptables -L -n -v --line-numbers
echo ""
echo "To make these rules persistent across reboots:"
echo "  1. Install iptables-persistent: sudo apt-get install iptables-persistent"
echo "  2. Save current rules: sudo netfilter-persistent save"
echo ""
echo "To view rules later: sudo iptables -L -n -v"
echo "To flush rules: sudo iptables -F"
echo ""

# Optional: Save rules immediately if iptables-persistent is installed
if command -v netfilter-persistent &> /dev/null; then
    echo "Saving rules with netfilter-persistent..."
    netfilter-persistent save
    echo "✓ Rules saved!"
else
    echo "Note: Install iptables-persistent to auto-load rules on boot"
    echo "  sudo apt-get install iptables-persistent"
fi

echo ""
echo "=================================="
echo "Firewall setup complete!"
echo "=================================="
