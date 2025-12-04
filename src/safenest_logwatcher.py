#!/usr/bin/env python3

"""
SafeNest Log Watcher and Auto-Blocker

Host-based IDS that monitors log files for security events and automatically
blocks malicious IP addresses using iptables (fail2ban-style behavior).

Monitors:
- /var/log/mosquitto/mosquitto.log (MQTT broker logs)
- /var/log/safenest_security.log (Security detection logs)

Actions:
- Parse logs for authentication failures, connection floods, repeated alerts
- Extract source IP addresses from suspicious activity
- Automatically block IPs using iptables after threshold exceeded
- Publish critical alerts to MQTT
- Maintain block list with automatic unblocking after timeout

Usage:
    sudo python3 safenest_logwatcher.py

Note: Requires root/sudo privileges for iptables commands

Author: SafeNest Security Team
Version: 1.0.0
"""

import sys
import signal
import time
import re
import json
import subprocess
from pathlib import Path
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, Set, Optional

# Add modules directory to path
sys.path.insert(0, str(Path(__file__).parent))

from modules.logging_utils import get_logger


class LogWatcher:
    """
    Monitor log files for security events and auto-block malicious IPs.

    Implements fail2ban-style behavior for SafeNest security logs.
    """

    # === CONFIGURATION ===
    LOG_FILES = [
        "/var/log/mosquitto/mosquitto.log",
        "/var/log/safenest_security.log"
    ]

    # Thresholds for auto-blocking
    AUTH_FAILURE_THRESHOLD = 3  # Failed auth attempts before block
    ALERT_THRESHOLD = 5  # Security alerts before block
    TIME_WINDOW = 300  # 5 minutes

    # Block duration
    BLOCK_DURATION = 3600  # 1 hour in seconds

    # Regex patterns to extract IPs and detect events
    IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

    AUTH_FAILURE_PATTERNS = [
        re.compile(r'authentication failed', re.IGNORECASE),
        re.compile(r'bad username or password', re.IGNORECASE),
        re.compile(r'not authorized', re.IGNORECASE),
        re.compile(r'connection refused', re.IGNORECASE),
    ]

    DOS_PATTERNS = [
        re.compile(r'DOS_ATTACK_DETECTED', re.IGNORECASE),
        re.compile(r'message flooding', re.IGNORECASE),
        re.compile(r'rate limit exceeded', re.IGNORECASE),
    ]

    UNAUTHORIZED_PATTERNS = [
        re.compile(r'UNAUTHORIZED_', re.IGNORECASE),
        re.compile(r'ACL denied', re.IGNORECASE),
    ]

    def __init__(self):
        """Initialize log watcher."""
        self.logger = get_logger(
            "safenest_logwatcher",
            log_file="/var/log/safenest_logwatcher.log",
            console=True
        )

        self.logger.info("Initializing SafeNest Log Watcher...")

        # Track events per IP
        self.ip_events: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))

        # Track blocked IPs with block time
        self.blocked_ips: Dict[str, float] = {}  # IP -> block_timestamp

        # Track file positions for tailing
        self.file_positions: Dict[str, int] = {}

        # Whitelist (never block these IPs)
        self.ip_whitelist: Set[str] = {
            "127.0.0.1",
            "192.168.1.10",  # SafeNest gateway itself
            "192.168.1.20",  # Zigbee hub/coordinator (Zigbee2MQTT, deCONZ, etc.)
            "::1"
        }

        self.running = False

    def start(self):
        """Start log monitoring service."""
        self.logger.info("Starting SafeNest Log Watcher...")

        # Initialize file positions
        for log_file in self.LOG_FILES:
            if Path(log_file).exists():
                # Start at end of file (only watch new entries)
                with open(log_file, 'r') as f:
                    f.seek(0, 2)  # Seek to end
                    self.file_positions[log_file] = f.tell()
                self.logger.info(f"Monitoring log file: {log_file}")
            else:
                self.logger.warning(f"Log file not found: {log_file}")
                self.file_positions[log_file] = 0

        self.running = True
        self.logger.info("Log Watcher is now running")

        return True

    def _read_new_lines(self, log_file: str) -> list:
        """Read new lines from log file since last position."""
        if not Path(log_file).exists():
            return []

        new_lines = []

        try:
            with open(log_file, 'r') as f:
                # Seek to last known position
                f.seek(self.file_positions[log_file])

                # Read new lines
                new_lines = f.readlines()

                # Update position
                self.file_positions[log_file] = f.tell()

        except Exception as e:
            self.logger.error(f"Error reading {log_file}: {e}")

        return new_lines

    def _extract_ip(self, line: str) -> Optional[str]:
        """Extract IP address from log line."""
        match = self.IP_PATTERN.search(line)
        if match:
            ip = match.group(0)
            # Filter out invalid IPs (e.g., version numbers like 1.2.3.4)
            octets = ip.split('.')
            if all(0 <= int(octet) <= 255 for octet in octets):
                return ip
        return None

    def _analyze_line(self, line: str, log_file: str):
        """Analyze log line for security events."""
        # Extract IP if present
        ip = self._extract_ip(line)

        if not ip or ip in self.ip_whitelist:
            return

        current_time = time.time()
        event_detected = False
        event_type = None

        # Check for authentication failures
        for pattern in self.AUTH_FAILURE_PATTERNS:
            if pattern.search(line):
                event_type = "AUTH_FAILURE"
                event_detected = True
                break

        # Check for DoS attacks
        if not event_detected:
            for pattern in self.DOS_PATTERNS:
                if pattern.search(line):
                    event_type = "DOS_ATTACK"
                    event_detected = True
                    break

        # Check for unauthorized access
        if not event_detected:
            for pattern in self.UNAUTHORIZED_PATTERNS:
                if pattern.search(line):
                    event_type = "UNAUTHORIZED_ACCESS"
                    event_detected = True
                    break

        if event_detected:
            # Record event
            self.ip_events[ip].append({
                "time": current_time,
                "type": event_type,
                "log_file": log_file,
                "line": line.strip()
            })

            self.logger.info(
                f"Security event detected from {ip}",
                event_type=event_type,
                ip=ip
            )

            # Check if IP should be blocked
            self._check_and_block_ip(ip)

    def _check_and_block_ip(self, ip: str):
        """Check if IP should be blocked based on event threshold."""
        if ip in self.blocked_ips:
            # Already blocked
            return

        current_time = time.time()
        cutoff_time = current_time - self.TIME_WINDOW

        # Count recent events
        recent_events = [
            event for event in self.ip_events[ip]
            if event["time"] > cutoff_time
        ]

        # Count by event type
        auth_failures = sum(1 for e in recent_events if e["type"] == "AUTH_FAILURE")
        dos_events = sum(1 for e in recent_events if e["type"] == "DOS_ATTACK")
        unauth_events = sum(1 for e in recent_events if e["type"] == "UNAUTHORIZED_ACCESS")

        should_block = False
        reason = None

        if auth_failures >= self.AUTH_FAILURE_THRESHOLD:
            should_block = True
            reason = f"{auth_failures} authentication failures"

        elif dos_events >= 1:  # Single DoS event is enough
            should_block = True
            reason = "DoS attack detected"

        elif unauth_events >= self.ALERT_THRESHOLD:
            should_block = True
            reason = f"{unauth_events} unauthorized access attempts"

        if should_block:
            self._block_ip(ip, reason)

    def _block_ip(self, ip: str, reason: str):
        """Block IP address using iptables."""
        self.logger.security_event(
            "IP_BLOCKED",
            "CRITICAL",
            {
                "ip": ip,
                "reason": reason,
                "block_duration": self.BLOCK_DURATION
            }
        )

        try:
            # Add iptables rule to drop packets from this IP
            cmd = [
                "iptables",
                "-I", "INPUT",  # Insert at top of chain
                "-s", ip,
                "-j", "DROP"
            ]

            result = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True
            )

            # Record block
            self.blocked_ips[ip] = time.time()

            self.logger.critical(
                f"IP {ip} blocked via iptables",
                ip=ip,
                reason=reason
            )

            # Publish critical alert (if MQTT available)
            self._publish_critical_alert(ip, reason)

        except subprocess.CalledProcessError as e:
            self.logger.error(
                f"Failed to block IP {ip}: {e.stderr}",
                ip=ip
            )
        except Exception as e:
            self.logger.error(f"Error blocking IP: {e}", ip=ip)

    def _unblock_ip(self, ip: str):
        """Remove IP block from iptables."""
        self.logger.info(f"Unblocking IP: {ip}")

        try:
            # Remove iptables rule
            cmd = [
                "iptables",
                "-D", "INPUT",
                "-s", ip,
                "-j", "DROP"
            ]

            subprocess.run(cmd, check=True, capture_output=True)

            # Remove from blocked list
            del self.blocked_ips[ip]

            self.logger.info(f"IP {ip} unblocked", ip=ip)

        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to unblock IP {ip}: {e.stderr}")
        except Exception as e:
            self.logger.error(f"Error unblocking IP: {e}")

    def _check_block_expiry(self):
        """Check if any blocks have expired and remove them."""
        current_time = time.time()

        for ip, block_time in list(self.blocked_ips.items()):
            if current_time - block_time >= self.BLOCK_DURATION:
                self._unblock_ip(ip)

    def _publish_critical_alert(self, ip: str, reason: str):
        """Publish critical alert to MQTT (optional, requires MQTT client)."""
        try:
            # Import here to avoid dependency if MQTT is not available
            from modules.mqtt_client import SecureMQTTClient

            client = SecureMQTTClient(
                client_id="logwatcher_alert",
                username=None,
                password=None,
                ca_cert_path=None
            )

            if client.connect(retry=False):
                alert = {
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "source": "log_watcher",
                    "severity": "CRITICAL",
                    "message": f"IP {ip} has been blocked",
                    "ip": ip,
                    "reason": reason,
                    "block_duration_seconds": self.BLOCK_DURATION
                }

                client.publish("safenest/alerts/critical", json.dumps(alert))
                client.disconnect()

        except Exception as e:
            # Don't fail if MQTT is not available
            self.logger.debug(f"Could not publish MQTT alert: {e}")

    def _monitor_logs(self):
        """Monitor all log files for new entries."""
        for log_file in self.LOG_FILES:
            new_lines = self._read_new_lines(log_file)

            for line in new_lines:
                self._analyze_line(line, log_file)

    def run(self):
        """Main monitoring loop."""
        try:
            self.logger.info("Monitoring log files for security events...")

            check_interval = 2  # Check logs every 2 seconds
            expiry_check_interval = 60  # Check block expiry every minute
            last_expiry_check = time.time()

            while self.running:
                # Monitor logs
                self._monitor_logs()

                # Check for expired blocks
                if time.time() - last_expiry_check >= expiry_check_interval:
                    self._check_block_expiry()
                    last_expiry_check = time.time()

                time.sleep(check_interval)

        except KeyboardInterrupt:
            self.logger.info("Keyboard interrupt received")
        except Exception as e:
            self.logger.error(f"Error in main loop: {e}")
        finally:
            self.stop()

    def stop(self):
        """Stop log watcher service."""
        self.logger.info("Stopping Log Watcher...")
        self.running = False

        # Optionally unblock all IPs on shutdown (uncomment if desired)
        # for ip in list(self.blocked_ips.keys()):
        #     self._unblock_ip(ip)

        self.logger.info("Log Watcher stopped")


def signal_handler(signum, frame):
    """Handle system signals for graceful shutdown."""
    print("\nShutdown signal received...")
    sys.exit(0)


def main():
    """Main entry point."""
    # Check if running as root (required for iptables)
    if subprocess.run(["id", "-u"], capture_output=True, text=True).stdout.strip() != "0":
        print("ERROR: This script must be run as root (sudo) to use iptables", file=sys.stderr)
        print("Usage: sudo python3 safenest_logwatcher.py", file=sys.stderr)
        sys.exit(1)

    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Create and start log watcher
    watcher = LogWatcher()

    if watcher.start():
        watcher.run()
    else:
        print("Failed to start Log Watcher", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
