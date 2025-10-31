from mitmproxy import http
import requests

ML_BACKEND = "http://localhost:8000/check_url"

def request(flow: http.HTTPFlow) -> None:
    url = flow.request.pretty_url
    try:
        r = requests.post(ML_BACKEND, json={"url": url}, timeout=2.0)
        j = r.json()
        if j.get("is_phishing"):
            flow.response = http.HTTPResponse.make(
                403, b"<html><body><h1>Blocked by PhishGuard</h1></body></html>",
                {"Content-Type": "text/html"}
            )
    except Exception:
        flow.response = http.HTTPResponse.make(
            500, b"<html><body><h1>PhishGuard error</h1></body></html>",
            {"Content-Type": "text/html"}
        )

