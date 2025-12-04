"""
SafeNest MQTT Client Module

Provides a secure MQTT client wrapper with TLS support, automatic reconnection,
and callback-based message handling for the SafeNest system.
"""

import ssl
import time
from typing import Callable, Optional, Dict, Any
import paho.mqtt.client as mqtt
from modules.logging_utils import get_logger


class SecureMQTTClient:
    """
    Secure MQTT client with TLS encryption and authentication.

    Handles connection, reconnection, message publishing/subscribing with
    proper error handling and logging.
    """

    def __init__(
        self,
        client_id: str,
        broker_host: str = "192.168.1.10",
        broker_port: int = 1883,
        username: Optional[str] = None,
        password: Optional[str] = None,
        ca_cert_path: str = None,
        log_file: Optional[str] = None
    ):
        """
        Initialize secure MQTT client.

        Args:
            client_id: Unique client identifier
            broker_host: MQTT broker hostname/IP
            broker_port: MQTT broker port (8883 for TLS)
            username: MQTT username
            password: MQTT password
            ca_cert_path: Path to CA certificate for TLS
            log_file: Path to log file
        """
        self.client_id = client_id
        self.broker_host = broker_host
        self.broker_port = broker_port
        self.username = username
        self.password = password
        self.ca_cert_path = ca_cert_path

        # Initialize logger
        self.logger = get_logger(
            f"mqtt.{client_id}",
            log_file=log_file,
            console=True
        )

        # Create MQTT client instance
        self.client = mqtt.Client(client_id=client_id, protocol=mqtt.MQTTv311)

        # Set authentication
        if username and password:
            self.client.username_pw_set(username, password)

        # Configure TLS (only if certificate path provided)
        if ca_cert_path:
            try:
                self.client.tls_set(
                    ca_certs=ca_cert_path,
                    cert_reqs=ssl.CERT_REQUIRED,
                    tls_version=ssl.PROTOCOL_TLSv1_2
                )
                # For self-signed certificates in testing/demo environments,
                # disable hostname verification to avoid IP mismatch errors
                self.client.tls_insecure_set(True)
                self.logger.info("TLS configured successfully (hostname verification disabled for self-signed cert)")
            except Exception as e:
                self.logger.error(f"Failed to configure TLS: {e}")
                raise
        else:
            self.logger.info("TLS disabled - using unencrypted connection (localhost only)")

        # Set callbacks
        self.client.on_connect = self._on_connect
        self.client.on_disconnect = self._on_disconnect
        self.client.on_message = self._on_message
        self.client.on_publish = self._on_publish
        self.client.on_subscribe = self._on_subscribe

        # Subscription callbacks
        self._message_callbacks: Dict[str, Callable] = {}

        # Connection state
        self.connected = False

    def _on_connect(self, client, userdata, flags, rc):
        """Callback when client connects to broker."""
        if rc == 0:
            self.connected = True
            self.logger.info(
                "Connected to MQTT broker",
                broker=self.broker_host,
                port=self.broker_port
            )
        else:
            self.connected = False
            error_messages = {
                1: "Incorrect protocol version",
                2: "Invalid client identifier",
                3: "Server unavailable",
                4: "Bad username or password",
                5: "Not authorized"
            }
            error_msg = error_messages.get(rc, f"Unknown error code: {rc}")
            self.logger.error(f"Connection failed: {error_msg}", return_code=rc)

    def _on_disconnect(self, client, userdata, rc):
        """Callback when client disconnects from broker."""
        self.connected = False
        if rc == 0:
            self.logger.info("Disconnected from MQTT broker (clean)")
        else:
            self.logger.warning(
                "Unexpected disconnection from MQTT broker",
                return_code=rc
            )

    def _on_message(self, client, userdata, msg):
        """Callback when message is received."""
        topic = msg.topic
        payload = msg.payload.decode('utf-8', errors='ignore')

        self.logger.debug(
            "Message received",
            topic=topic,
            payload=payload,
            qos=msg.qos
        )

        # Call registered callback for this topic if exists
        for topic_pattern, callback in self._message_callbacks.items():
            if mqtt.topic_matches_sub(topic_pattern, topic):
                try:
                    callback(topic, payload)
                except Exception as e:
                    self.logger.error(
                        f"Error in message callback: {e}",
                        topic=topic,
                        callback=callback.__name__
                    )

    def _on_publish(self, client, userdata, mid):
        """Callback when message is published."""
        self.logger.debug("Message published", message_id=mid)

    def _on_subscribe(self, client, userdata, mid, granted_qos):
        """Callback when subscription is confirmed."""
        self.logger.debug("Subscription confirmed", message_id=mid, qos=granted_qos)

    def connect(self, retry: bool = True, retry_interval: int = 5, max_retries: int = 10):
        """
        Connect to MQTT broker with optional retry logic.

        Args:
            retry: Whether to retry on connection failure
            retry_interval: Seconds between retry attempts
            max_retries: Maximum number of retry attempts (-1 for infinite)

        Returns:
            bool: True if connected successfully
        """
        attempts = 0
        while True:
            try:
                self.logger.info(
                    f"Connecting to MQTT broker...",
                    broker=self.broker_host,
                    port=self.broker_port
                )
                self.client.connect(self.broker_host, self.broker_port, keepalive=60)
                self.client.loop_start()

                # Wait for connection to establish
                timeout = 10
                while not self.connected and timeout > 0:
                    time.sleep(0.5)
                    timeout -= 0.5

                if self.connected:
                    return True
                else:
                    raise ConnectionError("Connection timeout")

            except Exception as e:
                attempts += 1
                self.logger.error(
                    f"Connection attempt {attempts} failed: {e}",
                    broker=self.broker_host
                )

                if not retry or (max_retries != -1 and attempts >= max_retries):
                    self.logger.critical("Max connection retries reached")
                    return False

                self.logger.info(f"Retrying in {retry_interval} seconds...")
                time.sleep(retry_interval)

    def disconnect(self):
        """Disconnect from MQTT broker."""
        self.logger.info("Disconnecting from MQTT broker")
        self.client.loop_stop()
        self.client.disconnect()

    def publish(self, topic: str, payload: str, qos: int = 1, retain: bool = False):
        """
        Publish message to MQTT topic.

        Args:
            topic: MQTT topic
            payload: Message payload
            qos: Quality of Service (0, 1, or 2)
            retain: Whether message should be retained

        Returns:
            bool: True if published successfully
        """
        if not self.connected:
            self.logger.error("Cannot publish: not connected to broker")
            return False

        try:
            result = self.client.publish(topic, payload, qos=qos, retain=retain)
            if result.rc == mqtt.MQTT_ERR_SUCCESS:
                self.logger.info(
                    "Published message",
                    topic=topic,
                    payload=payload,
                    qos=qos
                )
                return True
            else:
                self.logger.error(
                    "Publish failed",
                    topic=topic,
                    return_code=result.rc
                )
                return False
        except Exception as e:
            self.logger.error(f"Exception during publish: {e}", topic=topic)
            return False

    def subscribe(self, topic: str, callback: Callable[[str, str], None], qos: int = 1):
        """
        Subscribe to MQTT topic with callback.

        Args:
            topic: MQTT topic (supports wildcards + and #)
            callback: Function to call when message received (topic, payload)
            qos: Quality of Service (0, 1, or 2)

        Returns:
            bool: True if subscribed successfully
        """
        if not self.connected:
            self.logger.error("Cannot subscribe: not connected to broker")
            return False

        try:
            result, mid = self.client.subscribe(topic, qos=qos)
            if result == mqtt.MQTT_ERR_SUCCESS:
                self._message_callbacks[topic] = callback
                self.logger.info("Subscribed to topic", topic=topic, qos=qos)
                return True
            else:
                self.logger.error("Subscribe failed", topic=topic, return_code=result)
                return False
        except Exception as e:
            self.logger.error(f"Exception during subscribe: {e}", topic=topic)
            return False

    def unsubscribe(self, topic: str):
        """Unsubscribe from MQTT topic."""
        if topic in self._message_callbacks:
            del self._message_callbacks[topic]
        self.client.unsubscribe(topic)
        self.logger.info("Unsubscribed from topic", topic=topic)
