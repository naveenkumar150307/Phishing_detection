import requests
import json

API_URL = "http://127.0.0.1:8001/verify"

payload = {"url": "https://www.airtel.in/"}

try:
    resp = requests.post(API_URL, json=payload, timeout=10)
    print("Status:", resp.status_code)
    try:
        print("Response JSON:")
        print(json.dumps(resp.json(), indent=2))
    except ValueError:
        print("Non-JSON response:")
        print(resp.text)
except requests.exceptions.RequestException as e:
    print("Request failed:", e)
