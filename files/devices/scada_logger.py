#!/usr/bin/env python3
"""
ai-ot-soc/devices/scada_logger.py

Simulates a SCADA (Supervisory Control and Data Acquisition) system
generating operator action logs and security events.

Normal behavior  : operator logins, setpoint changes, alarm acknowledgments
Attack scenarios :
  - Repeated failed logins        → brute force / credential stuffing
  - Login from unknown workstation → lateral movement
  - Setpoint change outside hours  → unauthorized configuration change
MITRE ATT&CK ICS : T0859 — Valid Accounts
                   T0821 — Modify Controller Tasking
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
DEVICE_ID = "scada-system-001"
LOG_FILE  = os.path.join(os.path.dirname(__file__), config.LOG_DIR, "scada.log")
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
)
log = logging.getLogger(__name__)

# ── SCADA state ────────────────────────────────────────────────────────────────
publish_count  = 0
failed_logins  = {}   # tracks {username: fail_count} for burst detection

KNOWN_OPERATORS    = ["op.johnson", "op.patel", "op.chen", "supervisor.kim"]
KNOWN_WORKSTATIONS = ["HMI-STATION-01", "HMI-STATION-02", "ENGINEERING-WS"]
UNKNOWN_WORKSTATIONS = ["192.168.99.55", "UNKNOWN-HOST", "LAPTOP-ATTACKER"]

NORMAL_ACTIONS = [
    "LOGIN_SUCCESS", "LOGOUT", "ACK_ALARM",
    "VIEW_TREND", "SETPOINT_CHANGE", "PRINT_REPORT"
]

# ── Event generators ───────────────────────────────────────────────────────────

def normal_event():
    """Routine operator activity during business hours."""
    operator  = random.choice(KNOWN_OPERATORS)
    workstation = random.choice(KNOWN_WORKSTATIONS)
    action    = random.choice(NORMAL_ACTIONS)

    details = {}
    if action == "SETPOINT_CHANGE":
        details = {"parameter": "temp_setpoint", "old_value": 75, "new_value": random.randint(70, 85)}
    elif action == "ACK_ALARM":
        details = {"alarm_id": f"ALM-{random.randint(1000,9999)}", "alarm_type": "HIGH_TEMP"}

    return {
        "action":       action,
        "operator":     operator,
        "workstation":  workstation,
        "login_result": "SUCCESS" if "LOGIN" in action else None,
        "anomaly_type": "normal",
        "mitre":        None,
        **details,
    }

def failed_login_burst():
    """
    Repeated failed logins — brute force or credential stuffing.
    MITRE ATT&CK for ICS: T0859 — Valid Accounts (credential attack precursor)
    """
    username = random.choice(["admin", "operator", "root", random.choice(KNOWN_OPERATORS)])
    failed_logins[username] = failed_logins.get(username, 0) + 1
    burst_count = failed_logins[username]

    log.warning(f"[ATTACK] T0859 — Failed login #{burst_count} for '{username}'")
    return {
        "action":        "LOGIN_FAILURE",
        "operator":      username,
        "workstation":   random.choice(UNKNOWN_WORKSTATIONS),
        "login_result":  "FAILURE",
        "fail_count":    burst_count,
        "anomaly_type":  "failed_login_burst",
        "mitre":         "T0859",
    }

def unauthorized_setpoint():
    """
    Configuration change outside authorized hours — possible insider threat
    or attacker with valid credentials.
    MITRE ATT&CK for ICS: T0821 — Modify Controller Tasking
    """
    log.warning(f"[ATTACK] T0821 — Setpoint changed outside hours at {datetime.now().strftime('%H:%M')}")
    return {
        "action":       "SETPOINT_CHANGE",
        "operator":     random.choice(KNOWN_OPERATORS),
        "workstation":  random.choice(UNKNOWN_WORKSTATIONS),
        "parameter":    "pump_speed_setpoint",
        "old_value":    1200,
        "new_value":    3000,   # max RPM — potentially dangerous
        "login_result": None,
        "anomaly_type": "unauthorized_setpoint",
        "mitre":        "T0821",
    }

def lateral_movement_login():
    """
    Successful login from an unrecognized workstation.
    MITRE ATT&CK for ICS: T0859 — Valid Accounts (attacker using stolen creds)
    """
    operator = random.choice(KNOWN_OPERATORS)
    ws = random.choice(UNKNOWN_WORKSTATIONS)
    log.warning(f"[ATTACK] T0859 — '{operator}' logged in from unknown workstation: {ws}")
    return {
        "action":       "LOGIN_SUCCESS",
        "operator":     operator,
        "workstation":  ws,
        "login_result": "SUCCESS",
        "anomaly_type": "unknown_workstation_login",
        "mitre":        "T0859",
    }

def build_payload(event: dict) -> dict:
    global publish_count
    publish_count += 1
    return {
        "device_id":   DEVICE_ID,
        "device_type": "scada_system",
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

# ── Main ───────────────────────────────────────────────────────────────────────

def run():
    client = mqtt.Client(client_id=DEVICE_ID, clean_session=True)
    client.on_connect = on_connect
    try:
        client.connect(config.BROKER_HOST, config.BROKER_PORT, keepalive=60)
    except ConnectionRefusedError:
        log.error("[MQTT] Cannot connect. Is Mosquitto running?  sudo systemctl start mosquitto")
        return

    client.loop_start()
    log.info(f"[SCADA] {DEVICE_ID} starting — publishing to '{config.TOPIC_SCADA}'")

    try:
        while True:
            roll = random.random()

            if roll < config.PROB_LOGIN_FAIL:
                # Inject burst: 3–6 rapid failed logins to make pattern visible
                for _ in range(random.randint(3, 6)):
                    event   = failed_login_burst()
                    payload = build_payload(event)
                    client.publish(config.TOPIC_SCADA, json.dumps(payload), qos=1)
                    log.info(f"[SCADA] {payload['action']} user={payload['operator']} "
                             f"ws={payload['workstation']} type={payload['anomaly_type']}")
                    time.sleep(0.5)   # rapid-fire logins look like brute force

            elif roll < config.PROB_LOGIN_FAIL + 0.03:
                event = unauthorized_setpoint()
                payload = build_payload(event)
                client.publish(config.TOPIC_SCADA, json.dumps(payload), qos=1)
                log.info(f"[SCADA] {payload['action']} type={payload['anomaly_type']}")

            elif roll < config.PROB_LOGIN_FAIL + 0.03 + 0.03:
                event = lateral_movement_login()
                payload = build_payload(event)
                client.publish(config.TOPIC_SCADA, json.dumps(payload), qos=1)
                log.info(f"[SCADA] {payload['action']} user={payload['operator']} "
                         f"ws={payload['workstation']} type={payload['anomaly_type']}")

            else:
                event   = normal_event()
                payload = build_payload(event)
                client.publish(config.TOPIC_SCADA, json.dumps(payload), qos=1)
                log.info(f"[SCADA] {payload['action']} user={payload['operator']} "
                         f"ws={payload['workstation']} type={payload['anomaly_type']}")

            time.sleep(config.SCADA_INTERVAL)

    except KeyboardInterrupt:
        log.info("[SCADA] Shutting down...")
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
