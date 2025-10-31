from typing import Tuple, Dict, Any, List, Optional
from urllib.parse import urlparse
import re
import requests
from bs4 import BeautifulSoup
import tldextract


def _get_domain(host: str) -> str:
    ext = tldextract.extract(host)
    return f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain


def _scrape(url: str) -> Tuple[str, List[str], bool]:
    r = requests.get(url, timeout=8, headers={"User-Agent": "Mozilla/5.0"})
    soup = BeautifulSoup(r.text, "html.parser")
    has_form = bool(soup.find("form"))
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    text = " ".join(soup.stripped_strings)
    links = []
    for a in soup.find_all("a", href=True):
        links.append(a.get("href"))
    return text[:50000], links[:500], has_form


def _keyword_score(text: str, extra_keywords: Optional[List[str]] = None) -> int:
    kw = [
        "verify your account",
        "password",
        "login",
        "bank",
        "urgent",
        "update your",
        "confirm",
        "security alert",
        "unusual activity",
        "gift",
        "win",
        "limited time",
        "reset",
        "otp",
        "credit card",
    ]
    # Do NOT add org_keywords to phishing keyword list to avoid penalizing legitimate brand mentions
    t = text.lower()
    return sum(1 for k in kw if k in t)


def _link_mismatch(page_url: str, links: List[str], text: str, org_domains: Optional[List[str]] = None, org_keywords: Optional[List[str]] = None) -> bool:
    parsed = urlparse(page_url)
    page_domain = _get_domain(parsed.hostname or "")
    brand_tokens = ["microsoft", "google", "facebook", "apple", "amazon", "paypal", "chase", "bankofamerica", "irs", "github"]
    if org_keywords:
        brand_tokens = list({*brand_tokens, *[k.lower() for k in org_keywords]})
    text_hit = any(b in text.lower() for b in brand_tokens)
    out_domains = []
    for href in links:
        if href.startswith("mailto:") or href.startswith("tel:"):
            continue
        try:
            p = urlparse(href)
            host = p.hostname
            if not host:
                continue
            d = _get_domain(host)
            out_domains.append(d)
        except Exception:
            continue
    out_domains = [d for d in out_domains if d and d != page_domain]
    # If org_domains provided, consider mismatch when links point outside org domain tree
    if org_domains:
        def within_org(d: str) -> bool:
            h = d.lower()
            for root in org_domains:
                r = root.lstrip('.').lower()
                if h == r or h.endswith('.' + r):
                    return True
            return False
        external = [d for d in out_domains if not within_org(d)]
        if text_hit and len(external) >= 1:
            return True
    else:
        if text_hit and len(out_domains) >= 1:
            return True
    return False


def _within_org(hostname: str, org_domains: Optional[List[str]]) -> bool:
    if not hostname or not org_domains:
        return False
    h = hostname.lower()
    for root in org_domains:
        r = root.lstrip('.') .lower()
        if h == r or h.endswith('.' + r):
            return True
    return False


def classify(url: str, org_domains: Optional[List[str]] = None, org_keywords: Optional[List[str]] = None) -> Tuple[str, float, Dict[str, Any]]:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.hostname:
        return "Phishing – Block access", 0.95, {"reason": "invalid url"}
    try:
        text, links, has_form = _scrape(url)
    except Exception as e:
        return "Suspected – Alert user and legitimate domain", 0.7, {"error": str(e)}
    kw_score = _keyword_score(text)
    mismatch = _link_mismatch(url, links, text, org_domains=org_domains, org_keywords=org_keywords)
    in_org = _within_org(parsed.hostname, org_domains)
    # If within org, no mismatch, and not obviously harvesting (no form or low keyword pressure), bias to Legitimate
    if in_org and not mismatch:
        if has_form and kw_score >= 3:
            return "Suspected – Alert user and legitimate domain", 0.7, {"kw": kw_score, "mismatch": mismatch, "form": has_form, "within_org": True}
        return "Legitimate – Add to training dataset for future learning", 0.85, {"kw": kw_score, "mismatch": mismatch, "form": has_form, "within_org": True}
    if mismatch and (kw_score >= 2 or has_form):
        return "Phishing – Block access", 0.92, {"kw": kw_score, "mismatch": mismatch, "form": has_form}
    if kw_score >= 3 or has_form:
        return "Suspected – Alert user and legitimate domain", 0.7, {"kw": kw_score, "mismatch": mismatch, "form": has_form}
    return "Legitimate – Add to training dataset for future learning", 0.8, {"kw": kw_score, "mismatch": mismatch, "form": has_form}
