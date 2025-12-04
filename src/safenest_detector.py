#!/usr/bin/env python3

"""
SafeNest Anomaly Detection Engine

IDS-like security monitoring service for the SafeNest smart home system.
Monitors all MQTT traffic for suspicious patterns and potential attacks.

Detection Capabilities:
- Rate-based DoS detection (message flooding)
- Unauthorized topic usage (ACL violations)
- Suspicious motion sensor behavior
- Unknown/unauthorized clients
- Abnormal message patterns

Usage:
    sudo python3 safenest_detector.py

Author: SafeNest Security Team
Version: 1.0.0
"""

import sys
import signal
import time
import json
from pathlib import Path
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, Deque, Set

# Add modules directory to path
sys.path.insert(0, str(Path(__file__).parent))

from modules.mqtt_client import SecureMQTTClient
from modules.logging_utils import get_logger


class AnomalyDetector:
    """
    Intrusion Detection System for SafeNest MQTT network.

    Monitors all MQTT traffic and detects:
    - DoS attacks (message flooding)
    - Unauthorized topic access
    - Suspicious patterns in sensor data
    """

    # === DETECTION THRESHOLDS ===
    DOS_THRESHOLD = 50  # Messages per time window
    DOS_TIME_WINDOW = 5  # Seconds
    MOTION_BURST_THRESHOLD = 10  # Motion events per time window
    MOTION_BURST_WINDOW = 10  # Seconds

    # === ALLOWED TOPIC MAPPINGS ===
    # Define which clients (by username) can publish to which topics
    TOPIC_WHITELIST = {
        "motion_user": ["safenest/motion/state"],
        "intercom_user": ["safenest/intercom/event"],
        "light1_user": ["safenest/light1/state"],
        "light2_user": ["safenest/light2/state"],
        "panel_user": ["safenest/light1/set", "safenest/light2/set"],
        "controller_user": ["safenest/#"],  # Controller can publish anywhere
        "security_user": ["safenest/alerts/#"],  # Security can publish alerts
    }

    def __init__(self):
        """Initialize anomaly detection engine."""
        self.logger = get_logger(
            "safenest_detector",
            log_file="/var/log/safenest_security.log",
            console=True
        )

        self.logger.info("Initializing SafeNest Anomaly Detection Engine...")

        # Initialize MQTT client with full read access
        self.mqtt_client = SecureMQTTClient(
            client_id="safenest_detector",
            broker_host="192.168.1.10",
            broker_port=1883,
            username=None,
            password=None,
            ca_cert_path=None,
            log_file="/var/log/safenest_security.log"
        )

        # === DETECTION STATE ===
        # Track message rates per topic
        self.topic_message_times: Dict[str, Deque[float]] = defaultdict(
            lambda: deque(maxlen=1000)
        )

        # Track message rates per client (based on topic patterns)
        self.client_message_times: Dict[str, Deque[float]] = defaultdict(
            lambda: deque(maxlen=1000)
        )

        # Track motion events specifically
        self.motion_events: Deque[float] = deque(maxlen=100)

        # Track known/expected clients
        self.known_topics: Set[str] = {
            "safenest/motion/state",
            "safenest/intercom/event",
            "safenest/light1/state",
            "safenest/light1/set",
            "safenest/light2/state",
            "safenest/light2/set",
            "safenest/alerts/info",
            "safenest/alerts/warn",
            "safenest/alerts/critical",
            "safenest/system/command",
            "safenest/system/status",
        }

        # Blocked topics/clients (temporary blacklist)
        self.blocked_topics: Set[str] = set()
        self.blocked_clients: Set[str] = set()

        self.running = False

    def start(self):
        """Start the anomaly detection service."""
        self.logger.info("Starting SafeNest Anomaly Detection Engine...")

        # Connect to MQTT broker
        if not self.mqtt_client.connect(retry=True, retry_interval=5, max_retries=-1):
            self.logger.critical("Failed to connect to MQTT broker. Exiting.")
            return False

        # Subscribe to ALL topics for monitoring
        self.mqtt_client.subscribe("#", self._on_any_message)

        self.running = True
        self.logger.info("Anomaly Detection Engine is now running")

        # Publish startup alert
        self._publish_alert("info", "Anomaly Detection Engine started")

        return True

    def _on_any_message(self, topic: str, payload: str):
        """
        Monitor all MQTT messages for anomalies.

        This is the main detection entry point - every message goes through here.
        """
        current_time = time.time()

        # Record message for rate tracking
        self.topic_message_times[topic].append(current_time)

        # Infer client from topic (simple heuristic for demo)
        client_id = self._infer_client_from_topic(topic)
        if client_id:
            self.client_message_times[client_id].append(current_time)

        # === DETECTION CHECKS ===

        # 1. Check for DoS (message flooding)
        self._check_dos_attack(topic, client_id)

        # 2. Check for unauthorized topic usage
        self._check_unauthorized_topic(topic, payload)

        # 3. Check for suspicious motion patterns
        if topic == "safenest/motion/state":
            self._check_motion_anomaly(payload, current_time)

        # 4. Check for unknown topics
        if topic not in self.known_topics and not topic.startswith("safenest/alerts"):
            self._check_unknown_topic(topic)

    def _infer_client_from_topic(self, topic: str) -> str:
        """
        Infer client ID from topic pattern.

        In production, you'd get this from MQTT broker logs or client certificates.
        For this demo, we use topic patterns.
        """
        if "motion" in topic:
            return "motion_user"
        elif "intercom" in topic:
            return "intercom_user"
        elif "light1" in topic:
            return "light1_user"
        elif "light2" in topic:
            return "light2_user"
        elif "system" in topic or "alerts" in topic:
            return "controller_user"
        else:
            return "unknown"

    def _check_dos_attack(self, topic: str, client_id: str):
        """
        Detect DoS attacks based on message rate.

        Triggers if more than DOS_THRESHOLD messages in DOS_TIME_WINDOW seconds.
        """
        current_time = time.time()
        cutoff_time = current_time - self.DOS_TIME_WINDOW

        # Count recent messages for this topic
        topic_recent_messages = [
            t for t in self.topic_message_times[topic]
            if t > cutoff_time
        ]

        if len(topic_recent_messages) > self.DOS_THRESHOLD:
            self.logger.security_event(
                "DOS_ATTACK_DETECTED",
                "CRITICAL",
                {
                    "topic": topic,
                    "message_count": len(topic_recent_messages),
                    "time_window": self.DOS_TIME_WINDOW,
                    "threshold": self.DOS_THRESHOLD,
                    "suspected_client": client_id
                }
            )

            self._publish_alert(
                "critical",
                f"DoS attack detected on topic: {topic}",
                {
                    "topic": topic,
                    "message_count": len(topic_recent_messages),
                    "client": client_id
                }
            )

            # Add to blocked topics temporarily
            self.blocked_topics.add(topic)

    def _check_unauthorized_topic(self, topic: str, payload: str):
        """
        Check if message is published to an unauthorized topic.

        Uses TOPIC_WHITELIST to validate access.
        """
        # Infer client from topic
        client_id = self._infer_client_from_topic(topic)

        if client_id == "unknown":
            # Unknown client publishing
            self.logger.security_event(
                "UNAUTHORIZED_CLIENT",
                "WARN",
                {
                    "topic": topic,
                    "payload_preview": payload[:100]
                }
            )

            self._publish_alert(
                "warn",
                f"Unknown client publishing to: {topic}",
                {"topic": topic}
            )

        else:
            # Check if client is allowed to publish to this topic
            allowed_topics = self.TOPIC_WHITELIST.get(client_id, [])

            # Check if topic matches any allowed pattern
            is_allowed = False
            for allowed_pattern in allowed_topics:
                if self._topic_matches(topic, allowed_pattern):
                    is_allowed = True
                    break

            if not is_allowed:
                self.logger.security_event(
                    "UNAUTHORIZED_TOPIC_ACCESS",
                    "WARN",
                    {
                        "client": client_id,
                        "topic": topic,
                        "allowed_topics": allowed_topics
                    }
                )

                self._publish_alert(
                    "warn",
                    f"Client {client_id} accessing unauthorized topic: {topic}",
                    {
                        "client": client_id,
                        "topic": topic
                    }
                )

    def _topic_matches(self, topic: str, pattern: str) -> bool:
        """Check if topic matches pattern (supporting MQTT wildcards)."""
        if pattern == "#":
            return True

        if "#" in pattern:
            prefix = pattern.replace("/#", "")
            return topic.startswith(prefix)

        if "+" in pattern:
            # Simple single-level wildcard matching
            pattern_parts = pattern.split("/")
            topic_parts = topic.split("/")

            if len(pattern_parts) != len(topic_parts):
                return False

            for p, t in zip(pattern_parts, topic_parts):
                if p != "+" and p != t:
                    return False
            return True

        return topic == pattern

    def _check_motion_anomaly(self, payload: str, current_time: float):
        """
        Detect suspicious motion sensor behavior.

        Triggers if motion events are too frequent (possible sensor malfunction or attack).
        """
        if payload == "motion_detected":
            self.motion_events.append(current_time)

            # Check for burst of motion events
            cutoff_time = current_time - self.MOTION_BURST_WINDOW
            recent_motion = [t for t in self.motion_events if t > cutoff_time]

            if len(recent_motion) > self.MOTION_BURST_THRESHOLD:
                self.logger.security_event(
                    "MOTION_SENSOR_ANOMALY",
                    "WARN",
                    {
                        "event_count": len(recent_motion),
                        "time_window": self.MOTION_BURST_WINDOW,
                        "threshold": self.MOTION_BURST_THRESHOLD
                    }
                )

                self._publish_alert(
                    "warn",
                    "Suspicious motion sensor activity detected",
                    {
                        "event_count": len(recent_motion),
                        "possible_cause": "sensor malfunction or tampering"
                    }
                )

    def _check_unknown_topic(self, topic: str):
        """Detect messages on unknown/unexpected topics."""
        # Only alert once per unknown topic
        if topic not in self.blocked_topics:
            self.logger.security_event(
                "UNKNOWN_TOPIC",
                "WARN",
                {"topic": topic}
            )

            self._publish_alert(
                "warn",
                f"Message on unknown topic: {topic}",
                {"topic": topic}
            )

            # Mark as seen to avoid repeated alerts
            self.blocked_topics.add(topic)

    def _publish_alert(self, severity: str, message: str, details: dict = None):
        """Publish security alert to MQTT."""
        topic = f"safenest/alerts/{severity}"

        alert_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "source": "anomaly_detector",
            "message": message
        }

        if details:
            alert_data.update(details)

        payload = json.dumps(alert_data)
        self.mqtt_client.publish(topic, payload)

    def run(self):
        """Main run loop."""
        try:
            self.logger.info("Anomaly detector monitoring all MQTT traffic...")

            # Periodic cleanup of old data
            last_cleanup = time.time()
            cleanup_interval = 60  # Clean up every minute

            while self.running:
                # Clean up old message timestamps
                if time.time() - last_cleanup >= cleanup_interval:
                    self._cleanup_old_data()
                    last_cleanup = time.time()

                time.sleep(1)

        except KeyboardInterrupt:
            self.logger.info("Keyboard interrupt received")
        except Exception as e:
            self.logger.error(f"Error in main loop: {e}")
        finally:
            self.stop()

    def _cleanup_old_data(self):
        """Clean up old message timestamps to prevent memory bloat."""
        current_time = time.time()
        cutoff_time = current_time - (self.DOS_TIME_WINDOW * 2)

        # Clean topic message times
        for topic in list(self.topic_message_times.keys()):
            times = self.topic_message_times[topic]
            # Deque automatically maintains maxlen, but we can clear if empty
            if times and times[-1] < cutoff_time:
                del self.topic_message_times[topic]

        # Clean client message times
        for client in list(self.client_message_times.keys()):
            times = self.client_message_times[client]
            if times and times[-1] < cutoff_time:
                del self.client_message_times[client]

    def stop(self):
        """Stop the anomaly detection service."""
        self.logger.info("Stopping Anomaly Detection Engine...")
        self.running = False

        # Publish shutdown alert
        self._publish_alert("info", "Anomaly Detection Engine shutting down")

        # Disconnect from MQTT
        self.mqtt_client.disconnect()
        self.logger.info("Anomaly Detection Engine stopped")


def signal_handler(signum, frame):
    """Handle system signals for graceful shutdown."""
    print("\nShutdown signal received...")
    sys.exit(0)


def main():
    """Main entry point."""
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Create and start detector
    detector = AnomalyDetector()

    if detector.start():
        detector.run()
    else:
        print("Failed to start Anomaly Detection Engine", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
