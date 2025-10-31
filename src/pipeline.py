from typing import Dict, Any, List, Optional
from .ssl_dns_layer import check_ssl_dns


class PhishingDetectionPipeline:
    def __init__(self, dataset_path: Optional[str] = None, org_domains: Optional[List[str]] = None, org_keywords: Optional[List[str]] = None) -> None:
        self.org_domains = [d.lower() for d in org_domains] if org_domains else None
        self.org_keywords = [k.lower() for k in org_keywords] if org_keywords else None

    def run(self, url: str) -> Dict[str, Any]:
        l2_label, l2_conf, l2_meta = check_ssl_dns(url, org_domains=self.org_domains)
        # Final decision based solely on Layer 2 (SSL/DNS)
        if l2_label == "Malicious SSL/DNS detected":
            final = "Phishing"
            action = "Block immediately"
            score = 0.9
        elif l2_label == "Suspicious DNS or SSL anomaly":
            final = "Suspected"
            action = "Alert and log evidence"
            score = 0.5
        else:
            final = "Legitimate"
            action = "Whitelist and allow dataset expansion"
            score = 0.0
        return {
            "layer2": {"label": l2_label, "confidence": l2_conf, "meta": l2_meta},
            "final": {"decision": final, "score": score, "action": action},
        }
