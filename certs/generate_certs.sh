#!/bin/bash

################################################################################
# TLS Certificate Generation Script for SafeNest MQTT Broker
#
# This script generates self-signed TLS certificates for Mosquitto broker.
# For production, replace with properly signed certificates from a CA.
#
# Usage: sudo bash generate_certs.sh
################################################################################

set -e  # Exit on error

CERT_DIR="/etc/mosquitto/certs"
DAYS_VALID=3650  # 10 years

echo "[SafeNest] Generating TLS certificates for MQTT broker..."

# Create certificate directory if it doesn't exist
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

# Generate CA (Certificate Authority) key and certificate
echo "[1/4] Generating CA private key..."
openssl genrsa -out ca.key 4096

echo "[2/4] Generating CA certificate..."
openssl req -new -x509 -days "$DAYS_VALID" -key ca.key -out ca.crt \
    -subj "/C=US/ST=State/L=City/O=SafeNest/OU=Security/CN=SafeNest-CA"

# Generate server key and certificate signing request (CSR)
echo "[3/4] Generating server private key..."
openssl genrsa -out server.key 4096

echo "[4/4] Generating server certificate..."
openssl req -new -key server.key -out server.csr \
    -subj "/C=US/ST=State/L=City/O=SafeNest/OU=Gateway/CN=192.168.1.10"

# Sign the server certificate with CA
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out server.crt -days "$DAYS_VALID"

# Set proper permissions (readable by mosquitto user)
chmod 644 ca.crt server.crt
chmod 600 ca.key server.key
chown -R mosquitto:mosquitto "$CERT_DIR" 2>/dev/null || echo "Warning: Could not set mosquitto ownership"

# Clean up CSR file
rm -f server.csr

echo ""
echo "✓ Certificates generated successfully in $CERT_DIR"
echo ""
echo "Generated files:"
echo "  - ca.crt       (CA certificate - distribute to clients)"
echo "  - ca.key       (CA private key - KEEP SECURE)"
echo "  - server.crt   (Server certificate)"
echo "  - server.key   (Server private key - KEEP SECURE)"
echo ""
echo "Next steps:"
echo "  1. Copy ca.crt to all MQTT clients for TLS verification"
echo "  2. Update mosquitto.conf to reference these certificates"
echo "  3. Restart Mosquitto: sudo systemctl restart mosquitto"
