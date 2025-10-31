import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Dict, Any, Tuple, List, Optional
import dns.resolver
import tldextract


def _hostname_from_url(url: str) -> str:
    parsed = urlparse(url)
    return parsed.hostname or ""


def _get_ssl_info(hostname: str, port: int = 443) -> Dict[str, Any]:
    ctx = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=6) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            return cert


def _check_cn_match(cert: Dict[str, Any], hostname: str) -> bool:
    try:
        ssl.match_hostname(cert, hostname)
        return True
    except Exception:
        return False


def _cert_expired(cert: Dict[str, Any]) -> bool:
    not_after = cert.get("notAfter")
    if not_after:
        dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        return dt < datetime.now(timezone.utc)
    return True


def _dns_records_ok(hostname: str) -> Tuple[bool, Dict[str, Any]]:
    results: Dict[str, Any] = {"A": [], "MX": [], "TXT": []}
    ok = True
    try:
        for rdata in dns.resolver.resolve(hostname, "A"):
            results["A"].append(rdata.address)
    except Exception:
        ok = False
    try:
        for rdata in dns.resolver.resolve(hostname, "MX"):
            results["MX"].append(str(rdata.exchange))
    except Exception:
        pass
    try:
        for rdata in dns.resolver.resolve(hostname, "TXT"):
            s = b"".join(rdata.strings).decode(errors="ignore") if getattr(rdata, "strings", None) else str(rdata)
            results["TXT"].append(s)
    except Exception:
        pass
    return ok, results


def _suspicious_hosting(hostname: str) -> bool:
    s = hostname.lower()
    bad = [
        "ngrok.io",
        "vercel.app",
        "github.io",
        "cloudfront.net",
        "appspot.com",
        "firebaseapp.com",
        "web.app",
        "pages.dev",
        "fly.dev",
        "railway.app",
        "render.com",
        "netlify.app",
        "glitch.me",
    ]
    return any(b in s for b in bad)


def _suspicious_subdomain(hostname: str) -> bool:
    ext = tldextract.extract(hostname)
    sub = ext.subdomain
    if not sub:
        return False
    tokens = ["secure", "login", "verify", "support", "update", "billing", "account", "security"]
    return sum(1 for t in tokens if t in sub.lower()) >= 2


def _is_within_org(hostname: str, org_domains: Optional[List[str]]) -> bool:
    if not org_domains:
        return False
    h = hostname.lower()
    for root in org_domains:
        r = root.lstrip(".").lower()
        if h == r or h.endswith("." + r):
            return True
    return False


def check_ssl_dns(url: str, org_domains: Optional[List[str]] = None) -> Tuple[str, float, Dict[str, Any]]:
    hostname = _hostname_from_url(url)
    if not hostname:
        return "Malicious SSL/DNS detected", 0.9, {"reason": "no hostname"}
    meta: Dict[str, Any] = {"hostname": hostname}
    ssl_ok = True
    try:
        cert = _get_ssl_info(hostname)
        meta["cert"] = cert
        if _cert_expired(cert):
            ssl_ok = False
            meta["cert_expired"] = True
        if not _check_cn_match(cert, hostname):
            ssl_ok = False
            meta["cn_mismatch"] = True
    except Exception as e:
        ssl_ok = False
        meta["ssl_error"] = str(e)
    dns_ok, dns_meta = _dns_records_ok(hostname)
    meta["dns"] = dns_meta
    susp_host = _suspicious_hosting(hostname)
    susp_sub = _suspicious_subdomain(hostname)
    within_org = _is_within_org(hostname, org_domains)
    meta["within_org"] = within_org
    if ssl_ok and dns_ok and not susp_host and not susp_sub and (within_org or not org_domains):
        return "SSL/DNS Verified – Safe", 0.85, meta
    if not ssl_ok or not dns_ok or susp_host or susp_sub:
        if not ssl_ok and (susp_host or susp_sub):
            return "Malicious SSL/DNS detected", 0.95, meta
        # If outside org domains, increase suspicion slightly
        if org_domains and not within_org:
            return "Suspicious DNS or SSL anomaly", 0.75, meta
        return "Suspicious DNS or SSL anomaly", 0.7, meta
    # If everything looks okay but outside org tree, keep as suspicious to be conservative
    if org_domains and not within_org:
        return "Suspicious DNS or SSL anomaly", 0.65, meta
    return "Suspicious DNS or SSL anomaly", 0.6, meta
