#!/usr/bin/env python3

"""
SafeNest Normal Behavior Simulator

Simulates normal device behavior for testing the SafeNest system.
Creates realistic patterns of:
- Motion sensor events (occasional motion detection)
- Light state changes (normal on/off cycles)
- Intercom events (doorbell, door open)
- System status updates

This script is useful for:
- Testing the system under normal load
- Verifying device communication
- Generating baseline traffic for anomaly detection calibration

Usage:
    python3 simulate_normal.py [--duration SECONDS]

Arguments:
    --duration: How long to run simulation (default: 60 seconds)
"""

import sys
import time
import random
import argparse
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from modules.mqtt_client import SecureMQTTClient
from modules.logging_utils import get_logger


class NormalBehaviorSimulator:
    """Simulates normal smart home device behavior."""

    def __init__(self):
        """Initialize simulator."""
        self.logger = get_logger("simulator_normal", console=True)

        # Initialize MQTT clients for different devices
        self.clients = {}

        self._init_clients()

    def _init_clients(self):
        """Initialize MQTT clients for each simulated device."""
        devices = [
            ("motion_sensor", "motion_user", "MotionPass123!"),
            ("light1", "light1_user", "Light1Pass123!"),
            ("light2", "light2_user", "Light2Pass123!"),
            ("intercom", "intercom_user", "IntercomPass123!"),
        ]

        for client_id, username, password in devices:
            try:
                client = SecureMQTTClient(
                    client_id=f"sim_{client_id}",
                    broker_host="192.168.1.10",
                    broker_port=1883,
                    username=None,
                    password=None,
                    ca_cert_path=None
                )

                if client.connect(retry=False):
                    self.clients[client_id] = client
                    self.logger.info(f"Connected {client_id}")
                else:
                    self.logger.error(f"Failed to connect {client_id}")

            except Exception as e:
                self.logger.error(f"Error initializing {client_id}: {e}")

    def simulate_motion_sensor(self):
        """Simulate motion sensor events."""
        if "motion_sensor" not in self.clients:
            return

        # Random motion detection (20% chance)
        if random.random() < 0.2:
            self.clients["motion_sensor"].publish(
                "safenest/motion/state",
                "motion_detected"
            )
            self.logger.info("Motion detected")

            # Motion clears after 2-5 seconds
            time.sleep(random.uniform(2, 5))

            self.clients["motion_sensor"].publish(
                "safenest/motion/state",
                "idle"
            )
            self.logger.info("Motion cleared")
        else:
            # No motion
            self.clients["motion_sensor"].publish(
                "safenest/motion/state",
                "idle"
            )

    def simulate_light_state(self, light_id: str):
        """Simulate light state updates."""
        if light_id not in self.clients:
            return

        # Lights report their current state periodically
        # Randomly choose ON or OFF (simulate normal usage)
        state = random.choice(["ON", "OFF"])

        self.clients[light_id].publish(
            f"safenest/{light_id}/state",
            state
        )

        self.logger.info(f"{light_id}: {state}")

    def simulate_intercom(self):
        """Simulate intercom events."""
        if "intercom" not in self.clients:
            return

        # Occasional doorbell or door opening (5% chance)
        if random.random() < 0.05:
            event = random.choice(["call_button_pressed", "door_opened"])

            self.clients["intercom"].publish(
                "safenest/intercom/event",
                event
            )

            self.logger.info(f"Intercom: {event}")

    def run(self, duration: int = 60):
        """
        Run normal behavior simulation.

        Args:
            duration: Simulation duration in seconds
        """
        self.logger.info(f"Starting normal behavior simulation for {duration} seconds...")

        start_time = time.time()
        iteration = 0

        try:
            while time.time() - start_time < duration:
                iteration += 1
                self.logger.info(f"--- Iteration {iteration} ---")

                # Simulate each device
                self.simulate_motion_sensor()
                self.simulate_light_state("light1")
                self.simulate_light_state("light2")
                self.simulate_intercom()

                # Wait 5-10 seconds between iterations (realistic interval)
                wait_time = random.uniform(5, 10)
                self.logger.info(f"Waiting {wait_time:.1f} seconds...")
                time.sleep(wait_time)

        except KeyboardInterrupt:
            self.logger.info("Simulation interrupted by user")
        finally:
            self.cleanup()

        self.logger.info("Simulation complete")

    def cleanup(self):
        """Disconnect all clients."""
        for name, client in self.clients.items():
            self.logger.info(f"Disconnecting {name}")
            client.disconnect()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Simulate normal SafeNest device behavior"
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=60,
        help="Simulation duration in seconds (default: 60)"
    )

    args = parser.parse_args()

    simulator = NormalBehaviorSimulator()
    simulator.run(duration=args.duration)


if __name__ == "__main__":
    main()
