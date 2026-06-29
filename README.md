# AI-Powered OT SOC

An Industrial Control System (ICS/OT) security monitoring pipeline using Python, MQTT, and Splunk.

Four simulated OT devices publish telemetry over MQTT. A detection engine maps anomalies to MITRE ATT&CK for ICS techniques and generates alerts. Alerts are ingested into Splunk for dashboard visualization and automated incident reporting.

---

## Pipeline

```
OT Devices → MQTT Broker → mqtt_collector.py → detection_engine.py → Splunk + Incident Reports
```

## Attack Scenarios

| Device | Attack | MITRE Technique |
|---|---|---|
| temp-sensor-001 | Sensor spoofed to 999°C | T0856 — Spoof Reporting Message |
| plc-controller-001 | Unauthorized motor command at 02:00 | T0855 — Unauthorized Command Message |
| tank-level-001 | Tank level jumps to 98% or drops to 1% | T0831 — Manipulation of Control |
| scada-system-001 | Rapid failed logins from unknown host | T0859 — Valid Accounts |
| scada-system-001 | Setpoint changed 1200→3000 RPM from unknown host | T0821 — Modify Controller Tasking |

## Quick Start

```bash
# Install dependencies
pip install paho-mqtt
sudo apt install mosquitto

# Run
sudo systemctl start mosquitto
python3 mqtt_collector.py        # terminal 1
python3 run_all_devices.py       # terminal 2

# After collecting events:
python3 detection_engine.py      # generates logs/ai_alerts.json
python3 report_generator.py      # generates reports/incidents/
```

## Stack

Python · paho-mqtt · Mosquitto · Splunk Enterprise · MITRE ATT&CK for ICS
