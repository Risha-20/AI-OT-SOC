import paho.mqtt.client as mqtt

LOGFILE = "logs/ot_events.json"

def on_message(client, userdata, msg):
    payload = msg.payload.decode()

    with open(LOGFILE, "a") as f:
        f.write(payload + "\n")

    print(payload)

client = mqtt.Client()

client.on_message = on_message

client.connect("localhost", 1883)

client.subscribe("ot/#")

print("Collecting OT Events...")

client.loop_forever()