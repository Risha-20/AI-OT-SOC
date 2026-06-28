import json
import os

ALERTS_FILE = "logs/ai_alerts.json"
REPORT_DIR = "reports/incidents"

os.makedirs(REPORT_DIR, exist_ok=True)

with open(ALERTS_FILE, "r") as f:
    alerts = f.readlines()

for i, line in enumerate(alerts, start=1):
    alert = json.loads(line)

    filename = f"{REPORT_DIR}/incident_{i}.txt"

    with open(filename, "w") as report:
        report.write("AI-Powered OT SOC Incident Report\n")
        report.write("=" * 40 + "\n\n")
        report.write(f"Device: {alert.get('device_id')}\n")
        report.write(f"Device Type: {alert.get('device_type')}\n")
        report.write(f"Severity: {alert.get('severity')}\n")
        report.write(f"Anomaly Type: {alert.get('anomaly_type')}\n")
        report.write(f"MITRE Technique: {alert.get('mitre_technique')}\n")
        report.write(f"MITRE Name: {alert.get('mitre_name')}\n\n")
        report.write("Description:\n")
        report.write(f"{alert.get('description')}\n\n")
        report.write("Response Recommendation:\n")
        report.write(f"{alert.get('response_recommendation')}\n")

    print(f"Created {filename}")

print("Done.")