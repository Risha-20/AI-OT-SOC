#!/usr/bin/env python3
"""
ai-ot-soc/run_all_devices.py

Launches all four OT device simulators as parallel subprocesses.
Each device logs to its own file under logs/.

Usage:
    cd ai-ot-soc
    python3 run_all_devices.py

Stop with Ctrl+C — all subprocesses are cleaned up automatically.
"""

import subprocess
import sys
import os
import signal
import time

DEVICES = [
    ("PLC Controller",   "devices/plc_simulator.py"),
    ("Temp Sensor",      "devices/temp_sensor.py"),
    ("Tank Sensor",      "devices/tank_sensor.py"),
    ("SCADA Logger",     "devices/scada_logger.py"),
]

processes = []

def shutdown(sig=None, frame=None):
    print("\n[LAUNCHER] Stopping all devices...")
    for name, proc in processes:
        proc.terminate()
        print(f"  Stopped {name}")
    sys.exit(0)

signal.signal(signal.SIGINT,  shutdown)
signal.signal(signal.SIGTERM, shutdown)

print("[LAUNCHER] Starting AI-Powered OT SOC device simulators")
print("=" * 55)

for name, script in DEVICES:
    path = os.path.join(os.path.dirname(__file__), script)
    proc = subprocess.Popen(
        [sys.executable, path],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    processes.append((name, proc))
    print(f"  [{name}] started (PID {proc.pid})")

print("\n[LAUNCHER] All devices running. Press Ctrl+C to stop.")
print("[LAUNCHER] Subscribe to all topics: mosquitto_sub -h localhost -t 'ot/#' -v\n")

# Stream output from all processes
import select
fds = {p.stdout.fileno(): (name, p) for name, p in processes}

while True:
    ready, _, _ = select.select(list(fds.keys()), [], [], 1.0)
    for fd in ready:
        name, proc = fds[fd]
        line = proc.stdout.readline()
        if line:
            print(f"[{name}] {line}", end="")
    # Check if any process died unexpectedly
    for name, proc in processes:
        if proc.poll() is not None:
            print(f"[LAUNCHER] WARNING: {name} exited with code {proc.returncode}")
    time.sleep(0.1)
