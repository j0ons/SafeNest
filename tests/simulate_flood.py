#!/usr/bin/env python3

"""
SafeNest DoS/Flood Attack Simulator

Simulates a Denial-of-Service (DoS) attack by flooding MQTT topics with messages.
This is a testing tool to verify that the anomaly detection engine properly
detects and responds to message flooding attacks.

WARNING: This is a security testing tool. Only use in authorized testing environments.

Attack Patterns:
- Message flooding: Rapidly publish many messages to a single topic
- Multiple topic flooding: Flood multiple topics simultaneously
- Burst attacks: Short bursts of high-volume messages

Expected Detection:
- SafeNest anomaly detector should detect flooding within 5 seconds
- Alerts should be published to safenest/alerts/critical
- Log watcher may block the source IP if patterns are severe

Usage:
    python3 simulate_flood.py [--rate MESSAGES_PER_SEC] [--duration SECONDS]

Arguments:
    --rate: Messages per second (default: 20)
    --duration: Attack duration in seconds (default: 10)
    --topic: Topic to flood (default: safenest/motion/state)
"""

import sys
import time
import argparse
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from modules.mqtt_client import SecureMQTTClient
from modules.logging_utils import get_logger


class FloodSimulator:
    """Simulates DoS/flooding attacks on MQTT broker."""

    def __init__(self, topic: str = "safenest/motion/state"):
        """Initialize flood simulator."""
        self.logger = get_logger("simulator_flood", console=True)
        self.topic = topic

        # Initialize MQTT client
        try:
            self.client = SecureMQTTClient(
                client_id="flood_attacker",
                broker_host="192.168.1.10",
                broker_port=1883,
                username=None,
                password=None,
                ca_cert_path=None
            )

            if not self.client.connect(retry=False):
                self.logger.error("Failed to connect to broker")
                sys.exit(1)

            self.logger.info("Connected to MQTT broker")

        except Exception as e:
            self.logger.error(f"Error connecting: {e}")
            sys.exit(1)

    def flood_attack(self, rate: int = 20, duration: int = 10):
        """
        Execute flooding attack.

        Args:
            rate: Messages per second
            duration: Attack duration in seconds
        """
        self.logger.warning(f"Starting flood attack on topic: {self.topic}")
        self.logger.warning(f"Rate: {rate} msg/sec | Duration: {duration} seconds")

        interval = 1.0 / rate
        start_time = time.time()
        message_count = 0

        try:
            while time.time() - start_time < duration:
                # Send flood message
                payload = "motion_detected"  # Constant payload
                self.client.publish(self.topic, payload, qos=0)  # QoS 0 for speed

                message_count += 1

                # Show progress every 50 messages
                if message_count % 50 == 0:
                    elapsed = time.time() - start_time
                    actual_rate = message_count / elapsed
                    self.logger.info(
                        f"Sent {message_count} messages "
                        f"({actual_rate:.1f} msg/sec)"
                    )

                # Rate limiting
                time.sleep(interval)

        except KeyboardInterrupt:
            self.logger.info("Attack interrupted by user")
        except Exception as e:
            self.logger.error(f"Error during attack: {e}")
        finally:
            elapsed = time.time() - start_time
            self.logger.warning(
                f"Attack complete: {message_count} messages sent "
                f"in {elapsed:.1f} seconds ({message_count/elapsed:.1f} msg/sec)"
            )
            self.cleanup()

    def burst_attack(self, burst_size: int = 100, num_bursts: int = 3, interval: int = 5):
        """
        Execute burst attack (short intense bursts).

        Args:
            burst_size: Messages per burst
            num_bursts: Number of bursts
            interval: Seconds between bursts
        """
        self.logger.warning(f"Starting burst attack on topic: {self.topic}")
        self.logger.warning(
            f"{num_bursts} bursts of {burst_size} messages "
            f"with {interval}s intervals"
        )

        try:
            for burst_num in range(num_bursts):
                self.logger.info(f"Burst {burst_num + 1}/{num_bursts}")

                # Send burst as fast as possible
                for i in range(burst_size):
                    self.client.publish(self.topic, "motion_detected", qos=0)

                    if (i + 1) % 25 == 0:
                        self.logger.info(f"  {i + 1}/{burst_size} messages sent")

                if burst_num < num_bursts - 1:
                    self.logger.info(f"Waiting {interval} seconds before next burst...")
                    time.sleep(interval)

        except KeyboardInterrupt:
            self.logger.info("Attack interrupted by user")
        except Exception as e:
            self.logger.error(f"Error during attack: {e}")
        finally:
            self.logger.warning("Burst attack complete")
            self.cleanup()

    def cleanup(self):
        """Disconnect client."""
        self.logger.info("Disconnecting from broker")
        self.client.disconnect()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Simulate DoS/flooding attack on SafeNest MQTT broker"
    )
    parser.add_argument(
        "--rate",
        type=int,
        default=20,
        help="Messages per second for flood attack (default: 20)"
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=10,
        help="Attack duration in seconds (default: 10)"
    )
    parser.add_argument(
        "--topic",
        type=str,
        default="safenest/motion/state",
        help="Topic to flood (default: safenest/motion/state)"
    )
    parser.add_argument(
        "--mode",
        choices=["flood", "burst"],
        default="flood",
        help="Attack mode: flood (continuous) or burst (intermittent)"
    )
    parser.add_argument(
        "--burst-size",
        type=int,
        default=100,
        help="Messages per burst in burst mode (default: 100)"
    )
    parser.add_argument(
        "--num-bursts",
        type=int,
        default=3,
        help="Number of bursts in burst mode (default: 3)"
    )

    args = parser.parse_args()

    print("="*60)
    print("WARNING: DoS ATTACK SIMULATION")
    print("="*60)
    print("This will trigger security alerts and may result in IP blocking.")
    print("Only use in authorized testing environments.")
    print("="*60)
    print()

    response = input("Continue? (yes/no): ")
    if response.lower() not in ["yes", "y"]:
        print("Aborted.")
        return

    simulator = FloodSimulator(topic=args.topic)

    if args.mode == "flood":
        simulator.flood_attack(rate=args.rate, duration=args.duration)
    else:
        simulator.burst_attack(
            burst_size=args.burst_size,
            num_bursts=args.num_bursts,
            interval=5
        )


if __name__ == "__main__":
    main()
