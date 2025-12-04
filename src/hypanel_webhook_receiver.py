#!/usr/bin/env python3

"""
SafeNest Hypanel Webhook Receiver

This service receives HTTP webhooks from the Hypanel Akubela smart home panel
when device events occur (motion detected, lights changed, door events, etc.)
and publishes them to the SafeNest MQTT broker.

Integration Flow:
1. Hypanel automation triggers (e.g., motion detected)
2. Hypanel sends HTTP request to this service
3. Service publishes event to MQTT
4. SafeNest components react to MQTT messages

Setup on Hypanel:
- Create automations for each device event
- Set action to "Send HTTP command"
- URL format: http://RASPBERRY_PI_IP:9000/device/{device_type}?state={state}

Examples:
- Motion detected: http://192.168.1.10:9000/device/motion?state=detected
- Light 1 ON: http://192.168.1.10:9000/device/light1?state=ON
- Intercom pressed: http://192.168.1.10:9000/device/intercom?event=call_button_pressed

Usage:
    python3 hypanel_webhook_receiver.py

The service runs on port 9000 by default.

Author: SafeNest Security Team
Version: 1.0.0
"""

import sys
import json
import signal
from pathlib import Path
from flask import Flask, request, jsonify
import os
from datetime import datetime
from threading import Thread

# Add modules directory to path
sys.path.insert(0, str(Path(__file__).parent))

from modules.mqtt_client import SecureMQTTClient
from modules.logging_utils import get_logger

# Flask app for receiving webhooks
app = Flask(__name__)

# Global logger and MQTT client
logger = None
mqtt_client = None

# Configuration
WEBHOOK_PORT = int(os.environ.get("WEBHOOK_PORT", "9000"))
RASPBERRY_PI_IP = "192.168.1.10"  # Your Raspberry Pi IP
MQTT_BROKER_HOST = "localhost"
MQTT_BROKER_PORT = 1883


class HypanelWebhookReceiver:
    """
    Receives webhooks from Hypanel and publishes to MQTT.
    """

    def __init__(self):
        """Initialize the webhook receiver."""
        global logger, mqtt_client

        self.logger = get_logger(
            "hypanel_webhook",
            log_file=None,
            console=True
        )
        logger = self.logger

        self.logger.info("Initializing Hypanel Webhook Receiver...")

        # Initialize MQTT client (non-TLS for local connection)
        self.mqtt_client = SecureMQTTClient(
            client_id="hypanel_bridge",
            broker_host=MQTT_BROKER_HOST,
            broker_port=MQTT_BROKER_PORT,
            username=None,
            password=None,
            ca_cert_path=None,
            log_file=None
        )
        mqtt_client = self.mqtt_client

        # Device state tracking
        self.device_states = {
            "light1": "UNKNOWN",
            "light2": "UNKNOWN",
            "motion": "idle",
            "intercom": "idle"
        }

    def start(self):
        """Start the webhook receiver service."""
        self.logger.info("Starting Hypanel Webhook Receiver...")

        # Connect to MQTT broker
        if not self.mqtt_client.connect(retry=True, retry_interval=5, max_retries=-1):
            self.logger.critical("Failed to connect to MQTT broker. Exiting.")
            return False

        self.logger.info("Connected to MQTT broker successfully")
        self.logger.info(f"Webhook receiver ready on port {WEBHOOK_PORT}")
        self.logger.info(f"Configure Hypanel to send webhooks to: http://{RASPBERRY_PI_IP}:{WEBHOOK_PORT}/device/<device_name>")

        return True


# Global receiver instance
receiver = None


def handle_device_event(device_type: str, state: str, event_data: dict = None):
    """
    Handle device event from Hypanel and publish to MQTT.

    Args:
        device_type: Type of device (motion, light1, light2, intercom)
        state: Device state (detected/idle, ON/OFF, etc.)
        event_data: Additional event data from webhook
    """
    global logger, mqtt_client, receiver

    if not mqtt_client:
        logger.error("MQTT client not initialized")
        return False

    # Map device types to MQTT topics
    topic_mapping = {
        "motion": "safenest/motion/state",
        "light1": "safenest/light1/state",
        "light2": "safenest/light2/state",
        "intercom": "safenest/intercom/event"
    }

    # Normalize device state
    normalized_state = state.strip().lower()

    # Map common state variations
    state_mapping = {
        # Motion sensor states
        "detected": "motion_detected",
        "motion_detected": "motion_detected",
        "motion": "motion_detected",
        "active": "motion_detected",
        "idle": "idle",
        "clear": "idle",
        "no_motion": "idle",

        # Light states
        "on": "ON",
        "true": "ON",
        "1": "ON",
        "off": "OFF",
        "false": "OFF",
        "0": "OFF",

        # Intercom events
        "call": "call_button_pressed",
        "call_button_pressed": "call_button_pressed",
        "doorbell": "call_button_pressed",
        "pressed": "call_button_pressed",
        "door_opened": "door_opened",
        "opened": "door_opened",
        "open": "door_opened"
    }

    # Get normalized state
    mqtt_state = state_mapping.get(normalized_state, state)

    # Get MQTT topic for this device
    mqtt_topic = topic_mapping.get(device_type.lower())

    if not mqtt_topic:
        logger.warning(f"Unknown device type: {device_type}")
        return False

    # Update internal state tracking
    if device_type in receiver.device_states:
        receiver.device_states[device_type] = mqtt_state

    # Publish to MQTT
    logger.info(f"Publishing: {mqtt_topic} = {mqtt_state}")
    mqtt_client.publish(mqtt_topic, mqtt_state)

    # Log event details
    logger.info(
        f"Device event received",
        device=device_type,
        state=mqtt_state,
        source="hypanel",
        timestamp=datetime.utcnow().isoformat()
    )

    return True


@app.route('/', methods=['GET'])
def index():
    """Root endpoint - show service status."""
    global receiver

    status = {
        "service": "SafeNest Hypanel Webhook Receiver",
        "status": "running",
        "mqtt_connected": mqtt_client and mqtt_client.client and mqtt_client.client.is_connected(),
        "device_states": receiver.device_states if receiver else {},
        "webhook_url_format": f"http://{RASPBERRY_PI_IP}:{WEBHOOK_PORT}/device/<device_name>?state=<state>",
        "examples": [
            f"http://{RASPBERRY_PI_IP}:{WEBHOOK_PORT}/device/motion?state=detected",
            f"http://{RASPBERRY_PI_IP}:{WEBHOOK_PORT}/device/light1?state=ON",
            f"http://{RASPBERRY_PI_IP}:{WEBHOOK_PORT}/device/intercom?event=call_button_pressed"
        ]
    }

    return jsonify(status), 200


@app.route('/device/<device_type>', methods=['GET', 'POST'])
def webhook_device(device_type):
    """
    Receive device event webhook from Hypanel.

    URL Parameters:
        device_type: Type of device (motion, light1, light2, intercom)

    Query Parameters:
        state: Device state (detected, idle, ON, OFF, etc.)
        event: Event name (for intercom: call_button_pressed, door_opened)

    Examples:
        GET /device/motion?state=detected
        GET /device/light1?state=ON
        GET /device/intercom?event=call_button_pressed
        POST /device/motion (with JSON body)
    """
    global logger

    try:
        # Get state from query parameters or JSON body
        if request.method == 'GET':
            state = request.args.get('state') or request.args.get('event') or 'unknown'
            event_data = dict(request.args)
        else:  # POST
            if request.is_json:
                data = request.get_json()
                state = data.get('state') or data.get('event') or 'unknown'
                event_data = data
            else:
                state = request.form.get('state') or request.form.get('event') or 'unknown'
                event_data = dict(request.form)

        # Log received webhook
        logger.info(f"Webhook received: {device_type} -> {state}")

        # Handle the device event
        success = handle_device_event(device_type, state, event_data)

        if success:
            return jsonify({
                "status": "success",
                "device": device_type,
                "state": state,
                "message": "Event published to MQTT"
            }), 200
        else:
            return jsonify({
                "status": "error",
                "device": device_type,
                "message": "Failed to publish event"
            }), 500

    except Exception as e:
        logger.error(f"Error handling webhook: {e}")
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({"status": "healthy"}), 200


def signal_handler(signum, frame):
    """Handle system signals for graceful shutdown."""
    print("\nShutdown signal received...")
    sys.exit(0)


def main():
    """Main entry point."""
    global receiver

    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Create receiver instance
    receiver = HypanelWebhookReceiver()

    if not receiver.start():
        print("Failed to start Hypanel Webhook Receiver", file=sys.stderr)
        sys.exit(1)

    # Print setup instructions
    print("\n" + "="*70)
    print("SafeNest Hypanel Webhook Receiver - RUNNING")
    print("="*70)
    print(f"\nWebhook endpoint: http://{RASPBERRY_PI_IP}:{WEBHOOK_PORT}/device/<device_name>")
    print("\nSetup Instructions for Hypanel:")
    print("-" * 70)
    print("1. Go to Hypanel web interface → Automation/Scenes")
    print("2. Create automations for each device event:")
    print("")
    print("   MOTION SENSOR:")
    print(f"   - Trigger: Motion detected")
    print(f"   - Action: Send HTTP → http://{RASPBERRY_PI_IP}:{WEBHOOK_PORT}/device/motion?state=detected")
    print("")
    print("   LIGHT 1:")
    print(f"   - Trigger: Light 1 turns ON")
    print(f"   - Action: Send HTTP → http://{RASPBERRY_PI_IP}:{WEBHOOK_PORT}/device/light1?state=ON")
    print(f"   - Trigger: Light 1 turns OFF")
    print(f"   - Action: Send HTTP → http://{RASPBERRY_PI_IP}:{WEBHOOK_PORT}/device/light1?state=OFF")
    print("")
    print("   INTERCOM:")
    print(f"   - Trigger: Doorbell pressed")
    print(f"   - Action: Send HTTP → http://{RASPBERRY_PI_IP}:{WEBHOOK_PORT}/device/intercom?event=call_button_pressed")
    print("")
    print("-" * 70)
    print(f"\nTest webhook: curl http://{RASPBERRY_PI_IP}:{WEBHOOK_PORT}/device/motion?state=detected")
    print("="*70 + "\n")

    # Start Flask web server
    ports_to_try = [WEBHOOK_PORT, WEBHOOK_PORT + 1, WEBHOOK_PORT + 2]
    for port in ports_to_try:
        try:
            print(f"Binding webhook server to http://0.0.0.0:{port}")
            logger.info(f"Webhook server binding", port=port)
            app.run(host='0.0.0.0', port=port, debug=False)
            break
        except (OSError, SystemExit):
            logger.warning("Webhook port unavailable", port=port)
            continue


if __name__ == "__main__":
    main()
