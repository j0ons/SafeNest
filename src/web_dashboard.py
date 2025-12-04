#!/usr/bin/env python3

"""
SafeNest Simple Web Dashboard

A lightweight web dashboard for monitoring SafeNest security system.
Uses Flask and MQTT to display real-time device states and alerts.

No Node-RED required - runs standalone on Raspberry Pi.

Usage:
    python3 web_dashboard.py

Access at: http://192.168.1.10:5000
"""

import sys
import json
import os
from pathlib import Path
from flask import Flask, render_template_string
from threading import Thread

# Add modules directory to path
sys.path.insert(0, str(Path(__file__).parent))

from modules.mqtt_client import SecureMQTTClient
from modules.logging_utils import get_logger

app = Flask(__name__)

# Store latest device states
device_states = {
    "light1": "UNKNOWN",
    "light2": "UNKNOWN",
    "motion": "idle",
    "intercom": "idle",
    "alerts": [],
    "system_armed": False
}

logger = get_logger("web_dashboard", console=True)

# Track MQTT connectivity
mqtt_client = None
mqtt_connected = False

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>SafeNest Dashboard</title>
    <meta http-equiv="refresh" content="2">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }

        :root {
            --bg-dark: #0b0921;
            --bg-darker: #07061A;
            --purple-3: #7c3aed;
            --purple-4: #a78bfa;
            --accent-cyan: #22d3ee;
            --accent-pink: #fb7185;
            --text: #E5E7EB;
            --card: rgba(17, 24, 39, 0.65);
            --glass: rgba(31, 41, 55, 0.5);
            --neon-shadow: 0 0 20px rgba(167,139,250,0.35), 0 0 40px rgba(124,58,237,0.25);
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', sans-serif;
            background:
                radial-gradient(1200px 600px at 10% 0%, rgba(124,58,237,0.25), transparent 60%),
                radial-gradient(800px 400px at 90% 20%, rgba(34,211,238,0.15), transparent 60%),
                radial-gradient(600px 300px at 30% 80%, rgba(251,113,133,0.18), transparent 60%),
                linear-gradient(135deg, var(--bg-darker) 0%, var(--bg-dark) 100%);
            padding: 24px; min-height: 100vh; color: var(--text);
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        .header {
            background: var(--glass);
            padding: 24px 32px;
            border-radius: 18px;
            margin-bottom: 24px;
            box-shadow: var(--neon-shadow);
            border: 1px solid rgba(167,139,250,0.25);
            backdrop-filter: saturate(140%) blur(10px);
        }

        .header h1 { color: var(--purple-4); margin-bottom: 6px; font-weight: 800; text-shadow: 0 0 12px rgba(167,139,250,0.35); }

        .header p { color: #cbd5e1; font-size: 14px; }

        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 24px; margin-bottom: 24px; }

        .card { background: var(--card); padding: 24px; border-radius: 18px; box-shadow: var(--neon-shadow); border: 1px solid rgba(124,58,237,0.25); }

        .card h2 { font-size: 18px; color: var(--purple-4); margin-bottom: 15px; border-bottom: 2px solid var(--purple-3); padding-bottom: 10px; }

        .device-status { display: flex; justify-content: space-between; align-items: center; padding: 12px; margin: 8px 0; background: rgba(67,56,202,0.20); border-radius: 10px; border: 1px solid rgba(67,56,202,0.35); }

        .device-name { font-weight: 700; color: var(--text); }

        .status-badge { padding: 8px 16px; border-radius: 20px; font-size: 12px; font-weight: 800; text-transform: uppercase; border: 1px solid rgba(167,139,250,0.3); box-shadow: var(--neon-shadow); }

        .status-on { background: linear-gradient(135deg, #34d399 0%, #10b981 100%); color: #062e25; }

        .status-off { background: linear-gradient(135deg, #a78bfa 0%, #7c3aed 100%); color: #1a093b; }

        .status-motion { background: linear-gradient(135deg, #fb7185 0%, #f59e0b 100%); color: #3a0a0a; animation: pulse 1s infinite; }

        .status-idle { background: linear-gradient(135deg, #64748b 0%, #475569 100%); color: #0a1117; }

        .status-armed { background: linear-gradient(135deg, #fb7185 0%, #ef4444 100%); color: #3d0d0d; font-weight: 800; }

        .status-disarmed { background: linear-gradient(135deg, #a78bfa 0%, #7c3aed 100%); color: #1a093b; }

        .alert-item { padding: 14px; margin: 10px 0; border-radius: 10px; border-left: 4px solid; }

        .alert-critical { background: rgba(239,68,68,0.2); border-color: #ef4444; color: #fecaca; }

        .alert-warn { background: rgba(245,158,11,0.18); border-color: #f59e0b; color: #fde68a; }

        .alert-info { background: rgba(59,130,246,0.18); border-color: #3b82f6; color: #bfdbfe; }

        .alert-time { font-size: 12px; color: #cbd5e1; margin-bottom: 5px; }

        .alert-message { font-weight: 700; }

        .no-alerts { text-align: center; padding: 40px; color: #9ca3af; }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }

        .footer { text-align: center; color: var(--text); margin-top: 20px; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🏠 SafeNest Security Dashboard</h1>
            <p>Real-time monitoring | Last updated: {{ current_time }}</p>
        </div>

        <div class="grid">
            <!-- Lights Card -->
            <div class="card">
                <h2>💡 Lights</h2>
                <div class="device-status">
                    <span class="device-name">Light 1</span>
                    <span class="status-badge {% if states.light1 == 'ON' %}status-on{% else %}status-off{% endif %}">
                        {{ states.light1 }}
                    </span>
                </div>
                <div class="device-status">
                    <span class="device-name">Light 2</span>
                    <span class="status-badge {% if states.light2 == 'ON' %}status-on{% else %}status-off{% endif %}">
                        {{ states.light2 }}
                    </span>
                </div>
            </div>

            <!-- Sensors Card -->
            <div class="card">
                <h2>📡 Sensors</h2>
                <div class="device-status">
                    <span class="device-name">Motion Sensor</span>
                    <span class="status-badge {% if states.motion == 'motion_detected' %}status-motion{% else %}status-idle{% endif %}">
                        {{ states.motion }}
                    </span>
                </div>
                <div class="device-status">
                    <span class="device-name">Intercom</span>
                    <span class="status-badge status-idle">
                        {{ states.intercom }}
                    </span>
                </div>
            </div>

            <!-- System Status Card -->
            <div class="card">
                <h2>⚙️ System Status</h2>
                <div class="device-status">
                    <span class="device-name">Security System</span>
                    <span class="status-badge {% if states.system_armed %}status-armed{% else %}status-disarmed{% endif %}">
                        {% if states.system_armed %}ARMED{% else %}DISARMED{% endif %}
                    </span>
                </div>
                <div class="device-status">
                    <span class="device-name">Total Alerts</span>
                    <span class="status-badge" style="background: #667eea; color: white;">
                        {{ states.alerts|length }}
                    </span>
                </div>
            </div>
        </div>

        <!-- Alerts Section -->
        <div class="card">
            <h2>🚨 Security Alerts</h2>
            {% if states.alerts %}
                {% for alert in states.alerts[:10] %}
                <div class="alert-item alert-{{ alert.severity }}">
                    <div class="alert-time">{{ alert.time }}</div>
                    <div class="alert-message">{{ alert.message }}</div>
                </div>
                {% endfor %}
            {% else %}
                <div class="no-alerts">
                    <p>✅ No security alerts</p>
                    <p style="font-size: 12px; margin-top: 10px;">System operating normally</p>
                </div>
            {% endif %}
        </div>

        <div class="footer">
            SafeNest v1.0 | Capstone Project | Auto-refresh every 2 seconds
        </div>
    </div>
</body>
</html>
"""


def mqtt_listener():
    """Background thread to listen to MQTT and update states."""
    global mqtt_client, mqtt_connected
    mqtt_client = SecureMQTTClient(
        client_id="web_dashboard",
        broker_host="localhost",
        broker_port=1883,
        username=None,
        password=None,
        ca_cert_path=None
    )

    def on_light1(topic, payload):
        device_states["light1"] = payload

    def on_light2(topic, payload):
        device_states["light2"] = payload

    def on_motion(topic, payload):
        device_states["motion"] = payload

    def on_intercom(topic, payload):
        device_states["intercom"] = payload

    def on_alert(topic, payload):
        try:
            alert_data = json.loads(payload)
            severity = topic.split('/')[-1]  # info, warn, critical

            alert = {
                "time": alert_data.get("timestamp", "Unknown"),
                "message": alert_data.get("message", payload),
                "severity": severity
            }

            # Add to front of list, keep last 50
            device_states["alerts"].insert(0, alert)
            device_states["alerts"] = device_states["alerts"][:50]

        except:
            pass

    if mqtt_client.connect(retry=True):
        mqtt_connected = True
        mqtt_client.subscribe("safenest/light1/state", on_light1)
        mqtt_client.subscribe("safenest/light2/state", on_light2)
        mqtt_client.subscribe("safenest/motion/state", on_motion)
        mqtt_client.subscribe("safenest/intercom/event", on_intercom)
        mqtt_client.subscribe("safenest/alerts/#", on_alert)

        logger.info("MQTT listener started")

        # Keep thread alive
        import time
        while True:
            time.sleep(1)
    

@app.route('/')
def dashboard():
    """Render dashboard."""
    from datetime import datetime
    return render_template_string(
        HTML_TEMPLATE,
        states=device_states,
        current_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )


@app.route('/health')
def health():
    """Health endpoint to verify server and MQTT connectivity."""
    return {
        "status": "ok",
        "mqtt_connected": bool(mqtt_client and mqtt_connected)
    }, 200


def main():
    """Main entry point."""
    logger.info("Starting SafeNest Web Dashboard...")

    # Start MQTT listener in background
    mqtt_thread = Thread(target=mqtt_listener, daemon=True)
    mqtt_thread.start()

    ports_to_try = [int(os.environ.get("DASHBOARD_PORT", "5000")), 5001, 5002]
    for port in ports_to_try:
        try:
            logger.info(f"Dashboard starting on http://0.0.0.0:{port}")
            app.run(host='0.0.0.0', port=port, debug=False)
            break
        except (OSError, SystemExit):
            logger.warning("Port unavailable", port=port)
            continue


if __name__ == "__main__":
    main()
