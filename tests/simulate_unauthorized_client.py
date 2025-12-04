#!/usr/bin/env python3

"""
SafeNest Unauthorized Client Simulator

Simulates unauthorized access attempts to test ACL enforcement and
intrusion detection capabilities.

Attack Scenarios:
1. Wrong credentials: Attempt to connect with invalid username/password
2. Topic ACL violation: Publish to topics the client is not authorized for
3. Unknown client: Connect with unrecognized client ID
4. Privilege escalation: Try to access admin/system topics

Expected Detection:
- Mosquitto ACL should block unauthorized topic access
- Failed authentication should be logged
- Anomaly detector should flag unauthorized topic usage
- Log watcher should detect repeated auth failures and block IP

WARNING: This is a security testing tool. Only use in authorized testing environments.

Usage:
    python3 simulate_unauthorized_client.py [--scenario SCENARIO]

Scenarios:
    auth_failure: Attempt connection with wrong credentials
    acl_violation: Publish to unauthorized topics
    topic_scan: Attempt to access multiple restricted topics
"""

import sys
import time
import argparse
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from modules.mqtt_client import SecureMQTTClient
from modules.logging_utils import get_logger


class UnauthorizedClientSimulator:
    """Simulates unauthorized access attempts."""

    def __init__(self):
        """Initialize simulator."""
        self.logger = get_logger("simulator_unauthorized", console=True)

    def test_auth_failure(self, attempts: int = 5):
        """
        Test authentication failure detection.

        Attempts to connect with wrong credentials multiple times.
        """
        self.logger.warning("Testing authentication failure detection...")

        for i in range(attempts):
            self.logger.info(f"Auth attempt {i + 1}/{attempts}")

            try:
                client = SecureMQTTClient(
                    client_id=f"unauthorized_client_{i}",
                    broker_host="192.168.1.10",
                    broker_port=1883,
                    username=None,
                    password=None,
                    ca_cert_path=None
                )

                # Try to connect (should fail)
                connected = client.connect(retry=False)

                if connected:
                    self.logger.error("UNEXPECTED: Connection succeeded with wrong credentials!")
                    client.disconnect()
                else:
                    self.logger.info("Connection rejected (expected)")

            except Exception as e:
                self.logger.info(f"Connection failed: {e} (expected)")

            # Wait between attempts
            time.sleep(2)

        self.logger.warning(
            f"Auth failure test complete: {attempts} attempts made. "
            "Check logs for detection."
        )

    def test_acl_violation(self):
        """
        Test ACL violation detection.

        Connect with valid credentials but attempt to publish to unauthorized topics.
        """
        self.logger.warning("Testing ACL violation detection...")

        try:
            # Connect as motion sensor (limited permissions)
            client = SecureMQTTClient(
                client_id="acl_violator",
                broker_host="192.168.1.10",
                broker_port=1883,
                username=None,
                password=None,
                ca_cert_path=None
            )

            if not client.connect(retry=False):
                self.logger.error("Failed to connect")
                return

            self.logger.info("Connected as motion_user")

            # Attempt to publish to unauthorized topics
            unauthorized_topics = [
                "safenest/light1/set",  # Motion sensor shouldn't control lights
                "safenest/system/command",  # Motion sensor shouldn't access system
                "safenest/alerts/critical",  # Motion sensor shouldn't publish alerts
                "safenest/intercom/event",  # Motion sensor shouldn't publish intercom events
            ]

            for topic in unauthorized_topics:
                self.logger.warning(f"Attempting unauthorized publish to: {topic}")

                success = client.publish(topic, "unauthorized_payload", qos=1)

                if success:
                    self.logger.error(
                        f"WARNING: Publish to {topic} succeeded (ACL may be misconfigured!)"
                    )
                else:
                    self.logger.info(f"Publish blocked (expected)")

                time.sleep(1)

            # Also try to subscribe to unauthorized topics
            self.logger.warning("Attempting unauthorized subscriptions...")

            def dummy_callback(topic, payload):
                self.logger.error(f"UNEXPECTED: Received message from {topic}")

            unauthorized_subs = [
                "safenest/alerts/#",
                "safenest/system/#",
            ]

            for topic in unauthorized_subs:
                self.logger.warning(f"Attempting unauthorized subscribe to: {topic}")
                client.subscribe(topic, dummy_callback)
                time.sleep(1)

            # Wait a bit to see if subscriptions work
            time.sleep(5)

            client.disconnect()

        except Exception as e:
            self.logger.error(f"Error during ACL test: {e}")

        self.logger.warning("ACL violation test complete. Check logs for detections.")

    def test_topic_scan(self):
        """
        Test topic scanning detection.

        Attempt to discover and access multiple topics (reconnaissance behavior).
        """
        self.logger.warning("Testing topic scanning detection...")

        try:
            client = SecureMQTTClient(
                client_id="topic_scanner",
                broker_host="192.168.1.10",
                broker_port=1883,
                username=None,
                password=None,
                ca_cert_path=None
            )

            if not client.connect(retry=False):
                self.logger.error("Failed to connect")
                return

            self.logger.info("Connected as light1_user")

            # Attempt to scan various topics
            scan_topics = [
                "safenest/admin/config",
                "safenest/system/users",
                "safenest/backup/data",
                "safenest/security/keys",
                "safenest/camera/feed",
                "safenest/motion/state",
                "safenest/intercom/event",
                "safenest/light2/state",
                "$SYS/broker/clients/connected",  # System topic
            ]

            for topic in scan_topics:
                self.logger.info(f"Scanning topic: {topic}")
                client.publish(topic, "scan", qos=0)
                time.sleep(0.5)

            client.disconnect()

        except Exception as e:
            self.logger.error(f"Error during topic scan: {e}")

        self.logger.warning("Topic scan test complete. Check logs for detections.")

    def test_unknown_client(self):
        """
        Test unknown client detection.

        Connect with credentials not in the user list.
        """
        self.logger.warning("Testing unknown client detection...")

        try:
            client = SecureMQTTClient(
                client_id="unknown_device_12345",
                broker_host="192.168.1.10",
                broker_port=1883,
                username=None,
                password=None,
                ca_cert_path=None
            )

            connected = client.connect(retry=False)

            if connected:
                self.logger.error("UNEXPECTED: Unknown client connected!")
                time.sleep(5)
                client.disconnect()
            else:
                self.logger.info("Connection rejected (expected)")

        except Exception as e:
            self.logger.info(f"Connection failed: {e} (expected)")

        self.logger.warning("Unknown client test complete.")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Simulate unauthorized access attempts on SafeNest"
    )
    parser.add_argument(
        "--scenario",
        choices=["auth_failure", "acl_violation", "topic_scan", "unknown_client", "all"],
        default="all",
        help="Attack scenario to simulate (default: all)"
    )
    parser.add_argument(
        "--auth-attempts",
        type=int,
        default=5,
        help="Number of failed auth attempts (default: 5)"
    )

    args = parser.parse_args()

    print("="*60)
    print("WARNING: UNAUTHORIZED ACCESS SIMULATION")
    print("="*60)
    print("This will trigger security alerts and may result in IP blocking.")
    print("Only use in authorized testing environments.")
    print("="*60)
    print()

    response = input("Continue? (yes/no): ")
    if response.lower() not in ["yes", "y"]:
        print("Aborted.")
        return

    simulator = UnauthorizedClientSimulator()

    if args.scenario == "all":
        simulator.test_auth_failure(attempts=args.auth_attempts)
        time.sleep(3)
        simulator.test_acl_violation()
        time.sleep(3)
        simulator.test_topic_scan()
        time.sleep(3)
        simulator.test_unknown_client()
    elif args.scenario == "auth_failure":
        simulator.test_auth_failure(attempts=args.auth_attempts)
    elif args.scenario == "acl_violation":
        simulator.test_acl_violation()
    elif args.scenario == "topic_scan":
        simulator.test_topic_scan()
    elif args.scenario == "unknown_client":
        simulator.test_unknown_client()

    print()
    print("="*60)
    print("Simulation complete!")
    print("Check the following for detection results:")
    print("  - /var/log/safenest_security.log")
    print("  - /var/log/mosquitto/mosquitto.log")
    print("  - MQTT topic: safenest/alerts/#")
    print("="*60)


if __name__ == "__main__":
    main()
