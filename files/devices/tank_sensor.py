#!/usr/bin/env python3
"""
ai-ot-soc/devices/tank_sensor.py

Simulates a water tank level sensor in an industrial facility.

Normal behavior  : level changes slowly (fill/drain cycles), 20–80%
Attack scenario  : sudden jump to 95%+ or drop to 2% (unexpected level change)
MITRE ATT&CK ICS : T0831 — Manipulation of Control (forcing valve open/closed)
                   T0856 — Spoof Reporting Message
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
DEVICE_ID = "tank-level-001"
LOG_FILE  = os.path.join(os.path.dirname(__file__), config.LOG_DIR, "tank_sensor.log")
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
)
log = logging.getLogger(__name__)

# ── Tank state ─────────────────────────────────────────────────────────────────
level         = 50.0    # % full
LEVEL_MIN     = 20.0    # low-level alarm
LEVEL_MAX     = 80.0    # high-level alarm
FILL_RATE     =  0.5    # % per reading when filling
DRAIN_RATE    = -0.3    # % per reading when draining
fill_mode     = True    # alternates to simulate fill/drain cycle
publish_count = 0

# ── Reading generators ─────────────────────────────────────────────────────────

def normal_reading():
    """Slow fill/drain cycle — realistic tank behavior."""
    global level, fill_mode

    rate  = FILL_RATE if fill_mode else DRAIN_RATE
    noise = random.uniform(-0.2, 0.2)
    level = round(max(15.0, min(85.0, level + rate + noise)), 2)

    # Flip mode at limits
    if level >= 80.0:
        fill_mode = False
    elif level <= 20.0:
        fill_mode = True

    alarm = "OK"
    if level >= LEVEL_MAX:
        alarm = "HIGH_LEVEL_ALARM"
    elif level <= LEVEL_MIN:
        alarm = "LOW_LEVEL_ALARM"

    return {
        "level_pct":    level,
        "fill_mode":    fill_mode,
        "alarm_status": alarm,
        "anomaly_type": "normal",
        "mitre":        None,
    }

def spike_reading():
    """
    Sudden jump in tank level — indicates valve forced open by attacker
    or spoofed sensor value hiding a real overflow/drain event.
    MITRE ATT&CK for ICS: T0831 — Manipulation of Control
    """
    global level
    direction = random.choice(["overflow", "drain"])
    if direction == "overflow":
        level = round(random.uniform(93.0, 99.0), 2)
        log.warning(f"[ATTACK] T0831 — Abnormal HIGH tank level: {level}%")
    else:
        level = round(random.uniform(1.0, 5.0), 2)
        log.warning(f"[ATTACK] T0831 — Abnormal LOW tank level: {level}%")

    return {
        "level_pct":    level,
        "fill_mode":    fill_mode,
        "alarm_status": "CRITICAL",
        "anomaly_type": "abnormal_level",
        "direction":    direction,
        "mitre":        "T0831",
    }

def build_payload(reading: dict) -> dict:
    global publish_count
    publish_count += 1
    return {
        "device_id":   DEVICE_ID,
        "device_type": "tank_level_sensor",
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "sequence":    publish_count,
        "unit":        "percent",
        "normal_range": f"{LEVEL_MIN}–{LEVEL_MAX}%",
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
    log.info(f"[TANK] {DEVICE_ID} starting — publishing to '{config.TOPIC_TANK}'")

    try:
        while True:
            if random.random() < config.PROB_TANK_SPIKE:
                reading = spike_reading()
            else:
                reading = normal_reading()

            payload = build_payload(reading)
            client.publish(config.TOPIC_TANK, json.dumps(payload), qos=1)
            log.info(f"[TANK] level={payload['level_pct']}% "
                     f"alarm={payload['alarm_status']} type={payload['anomaly_type']}")
            time.sleep(config.TANK_INTERVAL)

    except KeyboardInterrupt:
        log.info("[TANK] Shutting down...")
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
