# TLS Certificate Troubleshooting Guide

## Common Error: Certificate Verify Failed

If you see this error:
```
[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: IP address mismatch,
certificate is not valid for '192.168.1.10'
```

This means there's a mismatch between:
- The IP/hostname in the TLS certificate
- The actual IP you're connecting to

---

## Quick Fix (For Testing/Demo)

**Status:** ✅ Already implemented in the code

The MQTT client now includes `tls_insecure_set(True)` which disables hostname verification for self-signed certificates.

**File:** `src/modules/mqtt_client.py` (Line 75)

```python
self.client.tls_insecure_set(True)
```

### What This Does:
- ✅ Still uses TLS encryption (traffic is encrypted)
- ✅ Still validates the CA certificate
- ⚠️ **Skips hostname/IP verification** (accepts self-signed certs with any IP)

### Is This Secure?

**For your capstone/demo on a local network: YES**
- All traffic is still encrypted with TLS
- It's a trusted local network (192.168.1.x)
- Self-signed certificates are standard for local IoT

**For production on the internet: NO**
- Use properly signed certificates from a real CA (Let's Encrypt, etc.)
- Enable full hostname verification

---

## Proper Fix (Production Deployment)

If deploying in production, regenerate certificates with the correct IP/hostname:

### Step 1: Find Your Raspberry Pi's Actual IP

```bash
hostname -I
# Output example: 192.168.1.10 192.168.50.5
```

Take the first IP (usually your LAN IP).

### Step 2: Update Certificate Generation Script

Edit `certs/generate_certs.sh` and change line with CN (Common Name):

```bash
# OLD (if your IP is different):
openssl req -new -key server.key -out server.csr \
    -subj "/C=US/ST=State/L=City/O=SafeNest/OU=Gateway/CN=192.168.1.10"

# NEW (use YOUR actual IP):
openssl req -new -key server.key -out server.csr \
    -subj "/C=US/ST=State/L=City/O=SafeNest/OU=Gateway/CN=192.168.1.XX"
```

Or use hostname instead of IP:

```bash
# Using hostname (better if IP might change):
HOSTNAME=$(hostname)
openssl req -new -key server.key -out server.csr \
    -subj "/C=US/ST=State/L=City/O=SafeNest/OU=Gateway/CN=$HOSTNAME"
```

### Step 3: Regenerate Certificates

```bash
cd ~/Desktop/SafeNest/certs
sudo bash generate_certs.sh
```

### Step 4: Copy to All Clients

```bash
# Copy ca.crt to client devices
scp /etc/mosquitto/certs/ca.crt user@client-device:/path/to/certs/
```

### Step 5: Restart Mosquitto

```bash
sudo systemctl restart mosquitto
```

### Step 6: Re-enable Hostname Verification (Optional)

If you want full certificate validation, edit `src/modules/mqtt_client.py`:

```python
# Remove or comment out this line:
# self.client.tls_insecure_set(True)
```

---

## Alternative: Use Hostname Instead of IP

Instead of hardcoding IPs, use the Raspberry Pi's hostname:

### Step 1: Set a Hostname

```bash
sudo hostnamectl set-hostname safenest
```

### Step 2: Add to /etc/hosts on All Devices

On each device (client, panel, etc.), add:

```bash
# /etc/hosts
192.168.1.10    safenest
```

### Step 3: Connect Using Hostname

In code, change:
```python
broker_host="192.168.1.10"
# to:
broker_host="safenest"
```

### Step 4: Regenerate Certificate with Hostname

```bash
openssl req -new -key server.key -out server.csr \
    -subj "/C=US/ST=State/L=City/O=SafeNest/OU=Gateway/CN=safenest"
```

---

## Verification

### Check Certificate Details

```bash
openssl x509 -in /etc/mosquitto/certs/server.crt -text -noout | grep "Subject:"
```

Should show your IP or hostname in CN (Common Name).

### Test Connection

```bash
# Test with mosquitto_sub
mosquitto_sub -h 192.168.1.10 -p 8883 \
  --cafile /etc/mosquitto/certs/ca.crt \
  -u nodered_user -P NodeRedPass123! \
  -t 'safenest/#' -v
```

Should connect without errors.

---

## For Your Capstone Presentation

### If Asked About TLS Security:

**Question:** "Why did you disable hostname verification? Isn't that insecure?"

**Answer:**
> "Good question! For this demo environment on a trusted local network with self-signed certificates, we use `tls_insecure_set(True)` which skips hostname verification but maintains these security features:
>
> 1. **Full TLS encryption** - All MQTT traffic is still encrypted with TLS 1.2
> 2. **CA certificate validation** - Clients verify the certificate chain
> 3. **Local network only** - No internet exposure (firewall restricted)
> 4. **Standard for local IoT** - Self-signed certs are industry-standard for local smart home deployments
>
> In a production deployment, we would:
> - Use properly signed certificates from a CA (Let's Encrypt)
> - Enable full hostname verification
> - Use DNS names instead of IP addresses
> - Implement certificate rotation
>
> This represents the security trade-off between ease of deployment and maximum security - appropriate for a local smart home but not for internet-facing services."

---

## Security Comparison

| Configuration | Encryption | CA Validation | Hostname Check | Use Case |
|--------------|-----------|---------------|----------------|----------|
| **Current (Demo)** | ✅ TLS 1.2 | ✅ Yes | ⚠️ Disabled | Local network, self-signed cert |
| **Production** | ✅ TLS 1.2+ | ✅ Yes | ✅ Yes | Internet-facing, proper CA cert |
| **No TLS** | ❌ None | ❌ No | ❌ No | ⛔ NEVER USE |

---

## Summary

✅ **Current fix works for your capstone demo**
- Traffic is encrypted
- Authentication still required
- Local network only
- Industry-standard for local IoT

🔒 **For production, would add:**
- Proper CA-signed certificates
- Full hostname verification
- Certificate rotation
- DNS names instead of IPs

**Bottom line:** Your demo is secure for its intended use case (local smart home). The TLS setup demonstrates understanding of encryption while being practical for a self-signed local deployment.
