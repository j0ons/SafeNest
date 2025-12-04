"""
SafeNest Device Controller Module

Provides high-level device control abstractions for lights, sensors,
and other smart home devices in the SafeNest ecosystem.
"""

from typing import Callable, Optional, Dict, Any
from enum import Enum
from modules.mqtt_client import SecureMQTTClient
from modules.logging_utils import get_logger


class DeviceState(Enum):
    """Standard device states."""
    ON = "ON"
    OFF = "OFF"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"


class MotionState(Enum):
    """Motion sensor states."""
    IDLE = "idle"
    MOTION_DETECTED = "motion_detected"
    UNKNOWN = "unknown"


class DeviceController:
    """
    High-level controller for SafeNest smart home devices.

    Provides methods to control lights, read sensors, and manage device states
    with automatic state tracking and error handling.
    """

    def __init__(self, mqtt_client: SecureMQTTClient):
        """
        Initialize device controller.

        Args:
            mqtt_client: Initialized SecureMQTTClient instance
        """
        self.mqtt = mqtt_client
        self.logger = get_logger(
            "device_controller",
            log_file=None
        )

        # Device state cache
        self.device_states: Dict[str, Any] = {
            "light1": DeviceState.UNKNOWN,
            "light2": DeviceState.UNKNOWN,
            "motion": MotionState.UNKNOWN,
            "intercom": "idle"
        }

        # Subscribe to device state topics to track states
        self._subscribe_to_states()

    def _subscribe_to_states(self):
        """Subscribe to all device state topics for tracking."""
        self.mqtt.subscribe("safenest/light1/state", self._on_light1_state)
        self.mqtt.subscribe("safenest/light2/state", self._on_light2_state)
        self.mqtt.subscribe("safenest/motion/state", self._on_motion_state)
        self.mqtt.subscribe("safenest/intercom/event", self._on_intercom_event)

    def _on_light1_state(self, topic: str, payload: str):
        """Callback for light 1 state updates."""
        try:
            self.device_states["light1"] = DeviceState(payload)
            self.logger.info("Light 1 state updated", state=payload)
        except ValueError:
            self.logger.warning("Invalid light 1 state received", state=payload)
            self.device_states["light1"] = DeviceState.UNKNOWN

    def _on_light2_state(self, topic: str, payload: str):
        """Callback for light 2 state updates."""
        try:
            self.device_states["light2"] = DeviceState(payload)
            self.logger.info("Light 2 state updated", state=payload)
        except ValueError:
            self.logger.warning("Invalid light 2 state received", state=payload)
            self.device_states["light2"] = DeviceState.UNKNOWN

    def _on_motion_state(self, topic: str, payload: str):
        """Callback for motion sensor state updates."""
        try:
            self.device_states["motion"] = MotionState(payload)
            self.logger.info("Motion sensor state updated", state=payload)

            # Trigger action on motion detection
            if payload == MotionState.MOTION_DETECTED.value:
                self._on_motion_detected()

        except ValueError:
            self.logger.warning("Invalid motion state received", state=payload)
            self.device_states["motion"] = MotionState.UNKNOWN

    def _on_intercom_event(self, topic: str, payload: str):
        """Callback for intercom events."""
        self.device_states["intercom"] = payload
        self.logger.info("Intercom event received", event=payload)

        # Trigger actions based on intercom events
        if payload == "call_button_pressed":
            self._on_intercom_call()
        elif payload == "door_opened":
            self._on_door_opened()

    def _on_motion_detected(self):
        """Handle motion detection event."""
        self.logger.info("Motion detected - triggering security protocol")
        # Could trigger lights, send alerts, etc.
        # For now, just log the event

    def _on_intercom_call(self):
        """Handle intercom call button press."""
        self.logger.info("Intercom call button pressed")
        # Could trigger notification, unlock door, etc.

    def _on_door_opened(self):
        """Handle door opened event."""
        self.logger.info("Door opened event detected")
        # Could trigger security check, log entry, etc.

    # === LIGHT CONTROL METHODS ===

    def set_light(self, light_id: str, state: DeviceState):
        """
        Set light state (ON or OFF).

        Args:
            light_id: Light identifier ("light1" or "light2")
            state: Desired state (DeviceState.ON or DeviceState.OFF)

        Returns:
            bool: True if command sent successfully
        """
        if light_id not in ["light1", "light2"]:
            self.logger.error(f"Invalid light ID: {light_id}")
            return False

        if state not in [DeviceState.ON, DeviceState.OFF]:
            self.logger.error(f"Invalid state for light: {state}")
            return False

        topic = f"safenest/{light_id}/set"
        payload = state.value

        self.logger.info(f"Setting {light_id} to {state.value}")
        return self.mqtt.publish(topic, payload)

    def turn_on_light(self, light_id: str) -> bool:
        """Turn on a light."""
        return self.set_light(light_id, DeviceState.ON)

    def turn_off_light(self, light_id: str) -> bool:
        """Turn off a light."""
        return self.set_light(light_id, DeviceState.OFF)

    def turn_on_all_lights(self):
        """Turn on all lights."""
        self.logger.info("Turning on all lights")
        self.turn_on_light("light1")
        self.turn_on_light("light2")

    def turn_off_all_lights(self):
        """Turn off all lights."""
        self.logger.info("Turning off all lights")
        self.turn_off_light("light1")
        self.turn_off_light("light2")

    def get_light_state(self, light_id: str) -> DeviceState:
        """
        Get current state of a light.

        Args:
            light_id: Light identifier

        Returns:
            Current DeviceState
        """
        return self.device_states.get(light_id, DeviceState.UNKNOWN)

    # === SENSOR READING METHODS ===

    def get_motion_state(self) -> MotionState:
        """Get current motion sensor state."""
        return self.device_states.get("motion", MotionState.UNKNOWN)

    def get_intercom_state(self) -> str:
        """Get current intercom state."""
        return self.device_states.get("intercom", "unknown")

    # === ALERT PUBLISHING ===

    def publish_alert(self, severity: str, message: str, details: Optional[Dict] = None):
        """
        Publish security alert to appropriate topic.

        Args:
            severity: Alert severity ("info", "warn", "critical")
            message: Alert message
            details: Additional details dictionary
        """
        topic = f"safenest/alerts/{severity}"

        # Create structured alert payload
        alert_data = {
            "message": message,
            "severity": severity
        }
        if details:
            alert_data.update(details)

        import json
        payload = json.dumps(alert_data)

        self.logger.info(f"Publishing {severity} alert", alert_message=message)
        self.mqtt.publish(topic, payload)

    # === STATUS METHODS ===

    def get_all_device_states(self) -> Dict[str, Any]:
        """Get current states of all devices."""
        return self.device_states.copy()

    def print_status(self):
        """Print current status of all devices to console."""
        print("\n" + "="*50)
        print("SafeNest Device Status")
        print("="*50)
        print(f"Light 1:        {self.device_states['light1'].value}")
        print(f"Light 2:        {self.device_states['light2'].value}")
        print(f"Motion Sensor:  {self.device_states['motion'].value}")
        print(f"Intercom:       {self.device_states['intercom']}")
        print("="*50 + "\n")
