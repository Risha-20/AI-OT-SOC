#!/usr/bin/env python3
"""
ai-ot-soc/devices/temp_sensor.py

Simulates an industrial temperature sensor on a production line.

Normal behavior  : temperature drifts slowly between 60–90°C
Attack scenario  : sensor reports 999°C (spoofed/injected value)
MITRE ATT&CK ICS : T0856 — Spoof Reporting Message
                   T0832 — Manipulation of View
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
DEVICE_ID = "temp-sensor-001"
LOG_FILE  = os.path.join(os.path.dirname(__file__), config.LOG_DIR, "temp_sensor.log")
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
)
log = logging.getLogger(__name__)

# ── Sensor state ───────────────────────────────────────────────────────────────
last_temp     = 72.0    # °C — realistic industrial process temperature
TEMP_MIN      = 60.0
TEMP_MAX      = 90.0
TEMP_ALARM    = 95.0    # legitimate high-temp alarm threshold
publish_count = 0

# ── Reading generators ─────────────────────────────────────────────────────────

def normal_reading():
    """Slow drift mimicking real thermal mass behavior."""
    global last_temp
    drift     = random.uniform(-1.5, 1.5)
    last_temp = max(TEMP_MIN, min(TEMP_MAX, last_temp + drift))
    return {
        "temperature_c": round(last_temp, 2),
        "status":        "OK" if last_temp < TEMP_ALARM else "HIGH_TEMP_ALARM",
        "anomaly_type":  "normal",
        "mitre":         None,
    }

def spoofed_reading():
    """
    Sensor value injected by attacker — 999°C is physically impossible.
    This would trigger emergency shutdown in a real plant (that's the goal).
    MITRE ATT&CK for ICS: T0856 — Spoof Reporting Message
    """
    log.warning("[ATTACK] T0856 — Spoofed temperature value: 999°C")
    return {
        "temperature_c": 999.0,
        "status":        "SPOOFED",
        "anomaly_type":  "sensor_spoof",
        "mitre":         "T0856",
    }

def build_payload(reading: dict) -> dict:
    global publish_count
    publish_count += 1
    return {
        "device_id":   DEVICE_ID,
        "device_type": "temperature_sensor",
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "sequence":    publish_count,
        "unit":        "celsius",
        "normal_range": f"{TEMP_MIN}–{TEMP_MAX}°C",
        **reading,
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
    log.info(f"[TEMP] {DEVICE_ID} starting — publishing to '{config.TOPIC_TEMP}'")

    try:
        while True:
            if random.random() < config.PROB_SENSOR_SPOOF:
                reading = spoofed_reading()
            else:
                reading = normal_reading()

            payload = build_payload(reading)
            client.publish(config.TOPIC_TEMP, json.dumps(payload), qos=1)
            log.info(f"[TEMP] temp={payload['temperature_c']}°C "
                     f"status={payload['status']} type={payload['anomaly_type']}")
            time.sleep(config.TEMP_INTERVAL)

    except KeyboardInterrupt:
        log.info("[TEMP] Shutting down...")
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
