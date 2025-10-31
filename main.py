import argparse
import json
from src.pipeline import PhishingDetectionPipeline
from src.content_layer import _scrape  # reuse scraper for training ingest
from urllib.parse import urlparse
import os
import hashlib


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("url", nargs="?", help="URL to analyze")
    parser.add_argument("--dataset", help="Path to dataset directory for organization corpus", default=None)
    parser.add_argument("--org-domains", help="Comma-separated list of canonical org domains (e.g., example.org,sub.example.org)", default=None)
    parser.add_argument("--org-keywords", help="Comma-separated list of org-specific keywords/aliases", default=None)
    parser.add_argument("--json", action="store_true", help="Print full JSON output instead of the default 5-parameter summary")
    parser.add_argument("--train-legit", action="store_true", help="Ingest this URL's page content into the dataset as legitimate")
    args = parser.parse_args()
    if not args.url:
        args.url = input("Enter URL to analyze: ").strip()
    org_domains = [d.strip().lower() for d in args.org_domains.split(",")] if args.org_domains else None
    org_keywords = [k.strip().lower() for k in args.org_keywords.split(",")] if args.org_keywords else None
    pipe = PhishingDetectionPipeline(dataset_path=args.dataset, org_domains=org_domains, org_keywords=org_keywords)
    result = pipe.run(args.url)

    # Optional training ingest
    if args.train_legit and args.dataset:
        try:
            text, _links, _has_form = _scrape(args.url)
            os.makedirs(args.dataset, exist_ok=True)
            parsed = urlparse(args.url)
            slug_host = (parsed.hostname or "site").replace(":", "_")
            path_part = parsed.path or "/"
            h = hashlib.sha1((path_part + (parsed.query or "")).encode("utf-8", errors="ignore")).hexdigest()[:12]
            fname = f"legit_{slug_host}_{h}.txt"
            out_path = os.path.join(args.dataset, fname)
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(text)
        except Exception:
            pass

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        # Default: concise output using Layer 2 and final
        decision = result.get("final", {}).get("decision", "")
        layer2 = result.get("layer2", {}).get("label", "")
        action = result.get("final", {}).get("action", "")
        host = urlparse(args.url).hostname or ""
        print(f"decision: {decision}")
        print(f"host: {host}")
        print(f"layer2: {layer2}")
        print(f"action: {action}")


if __name__ == "__main__":
    main()
