import argparse
import json
import sys
import requests


def main():
    parser = argparse.ArgumentParser(description="Kago Security backend client")
    parser.add_argument("url", help="URL to verify, e.g. https://example.com")
    parser.add_argument("--host", default="http://127.0.0.1:8000", help="Backend base URL")
    args = parser.parse_args()

    try:
        resp = requests.post(f"{args.host.rstrip('/')}/verify", json={"url": args.url}, timeout=8)
        resp.raise_for_status()
        data = resp.json()
        print(json.dumps(data, indent=2))
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
