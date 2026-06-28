#!/usr/bin/env python3
"""
ai-ot-soc/devices/plc_simulator.py

Simulates a PLC (Programmable Logic Controller) that issues motor
start/stop commands over MQTT.

Normal behavior  : motor commands only between 06:00 and 22:00
Attack scenario  : motor START command issued at 02:00 (unauthorized hours)
MITRE ATT&CK ICS : T0855 — Unauthorized Command Message
"""

import json
import logging
import os
import random
import time
from datetime import datetime, timezone

import paho.mqtt.client as mqtt
import sys
sys.path.insert(0, os.path.dirname(__file__))
import config

# ── Setup ──────────────────────────────────────────────────────────────────────
DEVICE_ID  = "plc-controller-001"
LOG_FILE   = os.path.join(os.path.dirname(__file__), config.LOG_DIR, "plc.log")
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
)
log = logging.getLogger(__name__)

# ── PLC state ──────────────────────────────────────────────────────────────────
motor_state   = "STOPPED"
rpm           = 0
publish_count = 0

NORMAL_COMMANDS = ["START", "STOP", "SET_SPEED", "EMERGENCY_STOP", "STATUS"]
MOTOR_SPEEDS    = [0, 750, 1200, 1500, 1800, 3000]   # RPM values

# ── Helpers ────────────────────────────────────────────────────────────────────

def is_authorized_hour():
    """Normal production hours: 06:00–22:00 local time."""
    hour = datetime.now().hour
    return 6 <= hour < 22

def normal_plc_event():
    """Issue a realistic PLC command within normal operating parameters."""
    global motor_state, rpm
    command = random.choice(NORMAL_COMMANDS)
    if command == "START":
        motor_state = "RUNNING"
        rpm = random.choice([1200, 1500, 1800])
    elif command in ("STOP", "EMERGENCY_STOP"):
        motor_state = "STOPPED"
        rpm = 0
    elif command == "SET_SPEED" and motor_state == "RUNNING":
        rpm = random.choice(MOTOR_SPEEDS[1:])
    return {
        "command":      command,
        "motor_state":  motor_state,
        "rpm":          rpm,
        "anomaly_type": "normal",
        "authorized":   True,
    }

def unauthorized_plc_event():
    """
    Motor START outside authorized hours.
    MITRE ATT&CK for ICS: T0855 — Unauthorized Command Message
    """
    global motor_state, rpm
    motor_state = "RUNNING"
    rpm = random.choice([1500, 3000])
    log.warning(f"[ATTACK] T0855 — Unauthorized command at {datetime.now().strftime('%H:%M')}")
    return {
        "command":      "START",
        "motor_state":  motor_state,
        "rpm":          rpm,
        "anomaly_type": "unauthorized_command",
        "authorized":   False,
        "mitre":        "T0855",
    }

def build_payload(event: dict) -> dict:
    global publish_count
    publish_count += 1
    return {
        "device_id":   DEVICE_ID,
        "device_type": "plc_controller",
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "sequence":    publish_count,
        **event,
    }

# ── MQTT callbacks ─────────────────────────────────────────────────────────────

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        log.info(f"[MQTT] Connected to {config.BROKER_HOST}:{config.BROKER_PORT}")
        client.publish(
            config.TOPIC_STATUS.format(device_id=DEVICE_ID),
            json.dumps({"device_id": DEVICE_ID, "status": "online",
                        "timestamp": datetime.now(timezone.utc).isoformat()}),
            retain=True
        )
    else:
        log.error(f"[MQTT] Connection failed rc={rc}")

def on_disconnect(client, userdata, rc):
    if rc != 0:
        log.warning(f"[MQTT] Unexpected disconnect rc={rc}")

# ── Main ───────────────────────────────────────────────────────────────────────

def run():
    client = mqtt.Client(client_id=DEVICE_ID, clean_session=True)
    client.on_connect    = on_connect
    client.on_disconnect = on_disconnect
    try:
        client.connect(config.BROKER_HOST, config.BROKER_PORT, keepalive=60)
    except ConnectionRefusedError:
        log.error("[MQTT] Cannot connect. Is Mosquitto running?  sudo systemctl start mosquitto")
        return

    client.loop_start()
    log.info(f"[PLC] {DEVICE_ID} starting — publishing to '{config.TOPIC_PLC}'")

    try:
        while True:
            # Inject unauthorized command at low probability (or always if outside hours for demo)
            if random.random() < config.PROB_PLC_UNAUTHORIZED or not is_authorized_hour():
                event = unauthorized_plc_event()
            else:
                event = normal_plc_event()

            payload = build_payload(event)
            client.publish(config.TOPIC_PLC, json.dumps(payload), qos=1)
            log.info(f"[PLC] cmd={payload['command']} motor={payload['motor_state']} "
                     f"rpm={payload['rpm']} type={payload['anomaly_type']}")
            time.sleep(config.PLC_INTERVAL)

    except KeyboardInterrupt:
        log.info("[PLC] Shutting down...")
        client.publish(
            config.TOPIC_STATUS.format(device_id=DEVICE_ID),
            json.dumps({"device_id": DEVICE_ID, "status": "offline",
                        "timestamp": datetime.now(timezone.utc).isoformat()}),
            retain=True
        )
        client.loop_stop()
        client.disconnect()

if __name__ == "__main__":
    run()
