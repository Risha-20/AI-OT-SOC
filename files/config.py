"""
ai-ot-soc/devices/config.py
Shared configuration for all OT device simulators.
Edit this file to change broker address, topics, or anomaly rates.
"""

# ── MQTT broker ───────────────────────────────────────────────────────────────
BROKER_HOST = "localhost"
BROKER_PORT = 1883

# ── MQTT topics (all under ot/ namespace for easy Wazuh/Splunk filtering) ────
TOPIC_PLC      = "ot/plc/controller-001"
TOPIC_TEMP     = "ot/sensors/temperature-001"
TOPIC_TANK     = "ot/sensors/tank-level-001"
TOPIC_SCADA    = "ot/scada/events"
TOPIC_STATUS   = "ot/devices/{device_id}/status"   # format() before use

# ── Log directory (relative to each device script's location) ─────────────────
LOG_DIR = "../logs"

# ── Publish intervals (seconds) ───────────────────────────────────────────────
PLC_INTERVAL    = 4
TEMP_INTERVAL   = 3
TANK_INTERVAL   = 5
SCADA_INTERVAL  = 6

# ── Anomaly injection probabilities ───────────────────────────────────────────
# These intentionally inject labeled anomalies so Isolation Forest has
# both normal and attack samples for training.
PROB_SENSOR_SPOOF     = 0.05   # temperature → 999°C
PROB_PLC_UNAUTHORIZED = 0.04   # motor command outside 06:00–22:00
PROB_TANK_SPIKE       = 0.05   # water level jump
PROB_LOGIN_FAIL       = 0.06   # repeated failed SCADA logins
