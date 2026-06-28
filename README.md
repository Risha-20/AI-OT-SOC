# AI-OT-SOC

An AI-powered Industrial (OT) Security Operations Center built using Python, MQTT, Splunk, and MITRE ATT&CK for ICS.

## Features

- Simulated PLC, SCADA, Tank, and Temperature devices
- MQTT-based telemetry collection
- AI-based anomaly detection
- MITRE ATT&CK for ICS mapping
- Splunk dashboards
- Automated incident report generation

## Technologies

- Python
- MQTT
- Splunk Enterprise
- MITRE ATT&CK ICS

## Project Workflow

Device Simulation
        ↓
MQTT Collector
        ↓
Detection Engine
        ↓
Splunk Dashboard
        ↓
Incident Reports


## Folder Structure

```
devices/
docs/
logs/
reports/
screenshots/
config.py
mqtt_collector.py
detection_engine.py
report_generator.py
run_all_devices.py
```

## Future Improvements

- Wazuh integration
- Real PLC hardware support
- Email alerting
- Threat intelligence feeds
