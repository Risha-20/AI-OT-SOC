import json
import os
from datetime import datetime

EVENTS_FILE = "logs/ot_events.json"
ALERTS_FILE = "logs/ai_alerts.json"

MITRE = {
    "sensor_spoof": {"id": "T0856", "name": "Spoof Reporting Message"},
    "abnormal_level": {"id": "T0831", "name": "Manipulation of Control"},
    "unauthorized_command": {"id": "T0855", "name": "Unauthorized Command Message"},
    "failed_login_burst": {"id": "T0859", "name": "Valid Accounts"},
    "unauthorized_setpoint": {"id": "T0821", "name": "Modify Controller Tasking"},
    "unknown_workstation_login": {"id": "T0859", "name": "Valid Accounts"}
}

RECOMMENDATIONS = {
    "sensor_spoof": "Validate the physical sensor, inspect MQTT publisher, and compare with backup readings.",
    "abnormal_level": "Check tank valve state, verify sensor calibration, and review controller logic.",
    "unauthorized_command": "Stop affected PLC process, review operator activity, and investigate command source.",
    "failed_login_burst": "Temporarily disable suspicious account, review SCADA authentication logs, and block source workstation.",
    "unauthorized_setpoint": "Restore safe setpoint, verify operator authorization, and review engineering workstation activity.",
    "unknown_workstation_login": "Investigate workstation, validate credentials, and check for lateral movement."
}

def build_alert(event):
    anomaly = event.get("anomaly_type")

    if not anomaly or anomaly == "normal":
        return None

    mitre = MITRE.get(anomaly, {"id": "T0000", "name": "Unknown"})

    return {
        "alert_time": datetime.utcnow().isoformat() + "Z",
        "device_id": event.get("device_id"),
        "device_type": event.get("device_type"),
        "severity": "HIGH" if anomaly in ["sensor_spoof", "abnormal_level", "unauthorized_command"] else "MEDIUM",
        "anomaly_type": anomaly,
        "mitre_technique": mitre["id"],
        "mitre_name": mitre["name"],
        "description": f"Detected {anomaly} from {event.get('device_id')}",
        "response_recommendation": RECOMMENDATIONS.get(anomaly, "Investigate event and validate device behavior."),
        "raw_event": event
    }

def main():
    if not os.path.exists(EVENTS_FILE):
        print("[ERROR] ot_events.json not found")
        return

    alerts = []

    with open(EVENTS_FILE, "r") as infile:
        for line in infile:
            try:
                event = json.loads(line)
                alert = build_alert(event)

                if alert:
                    alerts.append(alert)
                    print(f"[ALERT] {alert['severity']} | {alert['anomaly_type']} | {alert['device_id']} | {alert['mitre_technique']}")

            except json.JSONDecodeError:
                continue

    with open(ALERTS_FILE, "w") as outfile:
        for alert in alerts:
            outfile.write(json.dumps(alert) + "\n")

    print(f"\nDetection complete. Alerts created: {len(alerts)}")
    print(f"Output: {ALERTS_FILE}")

if __name__ == "__main__":
    main()