import requests
import sys
import random
import time

while True:
    temp = random.randint(20, 35)
    resp = requests.post(sys.argv[1], json={"topic": "sensor/temperature", "temp-sensor-1": temp})
    print(f"Send data temperature={temp}: {resp.text}")
    time.sleep(1)
