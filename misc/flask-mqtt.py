import json

from flask import Flask, request
from flask_mqtt import Mqtt

app = Flask(__name__)

app.config['MQTT_BROKER_URL'] = 'srv-mosquitto-clusterip'
app.config['MQTT_BROKER_PORT'] = 1883  # default port for non-tls connection
app.config['MQTT_KEEPALIVE'] = 5  # set the time interval for sending a ping to the broker to 5 seconds
app.config['MQTT_TLS_ENABLED'] = False

mqtt = Mqtt(app)


@app.route('/publish', methods=['POST'])
def publish():
    data = request.get_json()
    topic = data.pop("topic")
    result, msg_id = mqtt.publish('sensor/temperature', json.dumps(data))
    if result != 0:
        return f"Failed to queue message: Error code {result}", 400
    return f"Message queued for ID {msg_id}", 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
