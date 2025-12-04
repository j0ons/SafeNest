#!/usr/bin/env python3
"""
SafeNest Controller

Central controller for the SafeNest smart home security demo.

Responsibilities:
- Subscribe to device state topics (lights, motion sensor, intercom)
- Maintain simple in-memory state for each device
- Apply security logic (e.g., motion while armed -> alert)
- Publish alerts to safenest/alerts/*
- Expose clean log messages for demo
"""

import json
import logging
import signal
import sys
import threading
import time
from typing import Dict

from modules.mqtt_client import SecureMQTTClient
from modules.device_controller import DeviceController
from modules.logging_utils import get_logger


# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

MQTT_HOST = "192.168.1.10"
MQTT_PORT = 1883
MQTT_USERNAME = None
MQTT_PASSWORD = None

TOPIC_MOTION_STATE = "safenest/motion/state"
TOPIC_LIGHT1_STATE = "safenest/light1/state"
TOPIC_LIGHT2_STATE = "safenest/light2/state"
TOPIC_INTERCOM_EVENT = "safenest/intercom/event"
TOPIC_COMMANDS = "safenest/system/command"
TOPIC_ALERTS = "safenest/alerts/info"
TOPIC_STATUS = "safenest/system/status"

LOG_COMPONENT = "safenest_controller"


# -----------------------------------------------------------------------------
# Controller
# -----------------------------------------------------------------------------

class SafeNestController:
    def __init__(self) -> None:
        self.logger = get_logger(
            LOG_COMPONENT,
            log_file=None,
            console=True,
        )

        self.logger.info("Initializing SafeNest Controller...")

        # Track simple device states in memory (string states)
        self.devices: Dict[str, str] = {}

        # MQTT client for controller
        self.mqtt_client = SecureMQTTClient(
            client_id="safenest_controller",
            broker_host=MQTT_HOST,
            broker_port=MQTT_PORT,
            username=MQTT_USERNAME,
            password=MQTT_PASSWORD,
            ca_cert_path=None,
        )

        # Device controller abstraction (reuses same MQTT client)
        self.device_controller = DeviceController(mqtt_client=self.mqtt_client)

        self._running = False
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # MQTT subscription setup
    # ------------------------------------------------------------------

    def _subscribe_to_state_topics(self) -> None:
        """Subscribe to the topics where devices publish their state."""
        self.mqtt_client.subscribe(
            topic=TOPIC_MOTION_STATE,
            qos=1,
            callback=self._on_motion_state,
        )
        self.mqtt_client.subscribe(
            topic=TOPIC_LIGHT1_STATE,
            qos=1,
            callback=self._on_light1_state,
        )
        self.mqtt_client.subscribe(
            topic=TOPIC_LIGHT2_STATE,
            qos=1,
            callback=self._on_light2_state,
        )
        self.mqtt_client.subscribe(
            topic=TOPIC_INTERCOM_EVENT,
            qos=1,
            callback=self._on_intercom_event,
        )

    def _subscribe_to_commands(self) -> None:
        """Subscribe to system command topic (arm/disarm, etc.)."""
        self.mqtt_client.subscribe(
            topic=TOPIC_COMMANDS,
            qos=1,
            callback=self._on_system_command,
        )

    # ------------------------------------------------------------------
    # Helper methods
    # ------------------------------------------------------------------

    def _update_device_state(
        self,
        device_id: str,
        new_state: str,
    ) -> None:
        with self._lock:
            self.devices[device_id] = new_state

        self.logger.debug(
            "Updated state",
            device_id=device_id,
            new_state=new_state,
        )

    def _publish_info_alert(self, message: str) -> None:
        """Publish a simple info alert as JSON-safe payload."""
        payload = json.dumps(
            {
                "severity": "info",
                "source": LOG_COMPONENT,
                "message": message,
                "timestamp": time.time(),
            }
        )
        self.mqtt_client.publish(
            topic=TOPIC_ALERTS,
            payload=payload,
            qos=1,
            retain=False,
        )
        self.logger.info("Publishing info alert", alert_message=message)

    def _publish_status(self, status: str) -> None:
        payload = json.dumps(
            {
                "component": LOG_COMPONENT,
                "status": status,
                "timestamp": time.time(),
            }
        )
        self.mqtt_client.publish(
            topic=TOPIC_STATUS,
            payload=payload,
            qos=0,
            retain=True,
        )

    # ------------------------------------------------------------------
    # MQTT callbacks
    # ------------------------------------------------------------------

    def _on_motion_state(self, topic: str, payload: str) -> None:
        self.logger.info("Motion topic update", payload=payload)
        self._update_device_state(
            device_id="motion_sensor",
            new_state=payload,
        )

        # Example security logic: motion while system armed -> alert
        # (For now, system is always "disarmed" in demo; logic can be extended.)

    def _on_light1_state(self, topic: str, payload: str) -> None:
        self.logger.info("Light1 state update", payload=payload)
        self._update_device_state(
            device_id="light1",
            new_state=payload,
        )

    def _on_light2_state(self, topic: str, payload: str) -> None:
        self.logger.info("Light2 state update", payload=payload)
        self._update_device_state(
            device_id="light2",
            new_state=payload,
        )

    def _on_intercom_event(self, topic: str, payload: str) -> None:
        self.logger.info("Intercom event", payload=payload)
        self._update_device_state(
            device_id="intercom",
            new_state=payload,
        )

        if payload == "ringing":
            self._publish_info_alert("Intercom: doorbell pressed (demo event)")

    def _on_system_command(self, topic: str, payload: str) -> None:
        self.logger.info("System command received", payload=payload)
        # In full version, handle "ARM", "DISARM", etc.
        # For demo we just log it and publish a simple alert.
        self._publish_info_alert(f"System command received: {payload}")

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def start(self) -> None:
        self.logger.info("Starting SafeNest Controller Service...")

        # Connect MQTT
        self.mqtt_client.connect()

        # Subscribe to device topics and commands
        self._subscribe_to_state_topics()
        self._subscribe_to_commands()

        self._running = True
        self._publish_status("running")
        self._publish_info_alert("SafeNest Controller started successfully")
        self.logger.info("SafeNest Controller is now running")

        try:
            while self._running:
                time.sleep(1.0)
        except KeyboardInterrupt:
            self.logger.info("Keyboard interrupt received, stopping...")
        finally:
            self.stop()

    def stop(self) -> None:
        if not self._running:
            return

        self._running = False
        self.logger.info("Stopping SafeNest Controller...")
        self._publish_info_alert("SafeNest Controller shutting down")
        self._publish_status("stopped")

        try:
            self.mqtt_client.disconnect()
        except Exception as exc:  # noqa: BLE001
            self.logger.error(f"Error during MQTT disconnect: {exc}")


# -----------------------------------------------------------------------------
# Entry point
# -----------------------------------------------------------------------------

def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    controller = SafeNestController()

    def handle_signal(signum, frame):  # noqa: ANN001, D401
        """Handle SIGTERM/SIGINT for clean shutdown."""
        controller.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    controller.start()


if __name__ == "__main__":
    main()
