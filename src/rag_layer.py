import re
import math
from urllib.parse import urlparse
from typing import List, Tuple, Optional, Dict
import tldextract
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import os
import difflib

try:
    from bs4 import BeautifulSoup  # type: ignore
except Exception:  # bs4 optional for dataset parsing
    BeautifulSoup = None  # type: ignore


class RAGContextChecker:
    def __init__(self, dataset_path: Optional[str] = None, org_keywords: Optional[List[str]] = None, org_domains: Optional[List[str]] = None) -> None:
        self.vectorizer = TfidfVectorizer(ngram_range=(1, 2), min_df=1, lowercase=True)
        self.corpus_texts: List[str] = []
        self.corpus_labels: List[str] = []
        self.corpus_domains: List[str] = []
        self.tfidf_matrix = None
        self.org_keywords = [k.lower() for k in org_keywords] if org_keywords else []
        self.org_domains = [d.lower().lstrip('.') for d in org_domains] if org_domains else []
        if dataset_path and os.path.isdir(dataset_path):
            self._load_dataset_corpus(dataset_path)
        else:
            self._bootstrap_corpus()

    def _bootstrap_corpus(self) -> None:
        seed = [
            ("google.com", "google search account gmail workspace login security"),
            ("accounts.google.com", "google account signin oauth secure"),
            ("facebook.com", "facebook social login security"),
            ("twitter.com", "twitter x social login"),
            ("paypal.com", "paypal payments wallet login security"),
            ("chase.com", "chase bank login secure banking"),
            ("bankofamerica.com", "bank of america online banking secure"),
            ("irs.gov", "irs government tax official"),
            ("usa.gov", "usa government official"),
            ("un.org", "united nations official organization"),
            ("github.com", "github code repository login"),
            ("microsoft.com", "microsoft account login azure office"),
            ("apple.com", "apple id login icloud"),
        ]
        # add org domains as legitimate anchors
        for d in self.org_domains:
            seed.append((d, f"{d} org legitimate brand { ' '.join(self.org_keywords) }".strip()))
        for dom, desc in seed:
            self.corpus_texts.append(desc)
            self.corpus_labels.append("legitimate")
            self.corpus_domains.append(dom)
        self.tfidf_matrix = self.vectorizer.fit_transform(self.corpus_texts)

    def _read_file_text(self, path: str) -> str:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                raw = f.read()
        except Exception:
            return ""
        # If HTML and bs4 available, extract visible text
        if ("<html" in raw.lower() or "</" in raw) and BeautifulSoup is not None:
            try:
                soup = BeautifulSoup(raw, "html.parser")
                for tag in soup(["script", "style", "noscript"]):
                    tag.decompose()
                return " ".join(soup.stripped_strings)
            except Exception:
                pass
        return re.sub(r"\s+", " ", raw)

    def _load_dataset_corpus(self, dataset_path: str) -> None:
        texts: List[str] = []
        domains: List[str] = []
        for root, _, files in os.walk(dataset_path):
            for name in files:
                if not any(name.lower().endswith(ext) for ext in [".txt", ".html", ".htm", ".md"]):
                    continue
                p = os.path.join(root, name)
                t = self._read_file_text(p)
                if not t:
                    continue
                if self.org_keywords:
                    t = t + " " + " ".join(self.org_keywords)
                texts.append(t)
                domains.append(os.path.relpath(p, dataset_path))
        if not texts:
            self._bootstrap_corpus()
            return
        self.corpus_texts = texts
        self.corpus_labels = ["legitimate"] * len(texts)
        self.corpus_domains = domains
        self.tfidf_matrix = self.vectorizer.fit_transform(self.corpus_texts)

    def _tokenize_url(self, url: str) -> str:
        parsed = urlparse(url)
        ext = tldextract.extract(parsed.netloc)
        host_tokens = [ext.subdomain.replace(".", " "), ext.domain, ext.suffix]
        path_tokens = re.sub(r"[\/._\-?=&]+", " ", parsed.path + " " + (parsed.query or "")).strip()
        s = " ".join([t for t in host_tokens if t] + [path_tokens])
        if self.org_keywords:
            s = s + " " + " ".join(self.org_keywords)
        s = re.sub(r"\d+", " ", s)
        s = re.sub(r"\s+", " ", s).strip()
        return s

    def check(self, url: str) -> Tuple[str, float, List[Tuple[str, float]], str]:
        # Org domain prior: if within declared org domains, bias to legitimate
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        if hostname and self.org_domains:
            h = hostname.lower()
            for root in self.org_domains:
                if h == root or h.endswith("." + root):
                    return "Legitimate", 0.9, [(root, 1.0)], "Hostname is within declared organization domain tree."
        # If hostname contains explicit org keywords, consider legitimate prior
        if hostname and self.org_keywords:
            low = hostname.lower()
            if any(k in low for k in self.org_keywords):
                return "Legitimate", 0.85, [(hostname, 1.0)], "Hostname contains organization keywords."

        # Simple lexical safety for clean apex hostnames
        ext = tldextract.extract(hostname)
        common_tlds = {"com", "in", "org", "net", "gov", "edu"}
        clean_root = bool(ext.domain) and (ext.suffix in common_tlds) and (not ext.subdomain)
        has_suspicious_tokens = any(t in (parsed.path or "").lower() for t in ["login", "verify", "reset", "account", "secure"])
        many_hyphens = hostname.count("-") >= 3
        numeric_heavy = sum(c.isdigit() for c in ext.domain) >= max(3, len(ext.domain) // 2)
        if clean_root and not has_suspicious_tokens and not many_hyphens and not numeric_heavy:
            return "Legitimate", 0.8, [(f"{ext.domain}.{ext.suffix}", 1.0)], "Clean apex domain without suspicious tokens."

        text = self._tokenize_url(url)
        if not text:
            return "Unknown", 0.4, [], "Insufficient context to compare."
        vec = self.vectorizer.transform([text])
        sims = cosine_similarity(vec, self.tfidf_matrix).flatten()
        pairs = list(zip(self.corpus_domains, sims))
        pairs.sort(key=lambda x: x[1], reverse=True)
        topk = pairs[:5]
        max_sim = topk[0][1] if topk else 0.0
        # Typosquatting check against org keywords (if any) and seed domains
        brand_candidates = self.org_keywords or []
        for dom in self.corpus_domains:
            d = dom.split(".")[0].lower()
            if d not in brand_candidates:
                brand_candidates.append(d)
        is_typosquat = False
        if ext.domain and brand_candidates:
            for b in brand_candidates:
                if not b or b == ext.domain.lower():
                    continue
                ratio = difflib.SequenceMatcher(None, b, ext.domain.lower()).ratio()
                if ratio >= 0.8:
                    is_typosquat = True
                    break

        if max_sim > 0.6 and not is_typosquat:
            decision = "Legitimate"
            conf = min(0.9, 0.5 + (max_sim - 0.6) * 1.0)
        elif max_sim > 0.35 and not is_typosquat:
            decision = "Unknown"
            conf = 0.6
        else:
            # Only call phishing if we see typosquatting or obvious suspicious tokens
            if is_typosquat or has_suspicious_tokens or many_hyphens or numeric_heavy:
                decision = "Phishing imitation identified"
                conf = 0.75
            else:
                decision = "Unknown"
                conf = 0.55
        reason_bits = []
        if is_typosquat:
            reason_bits.append("domain similar to trusted brand")
        if has_suspicious_tokens:
            reason_bits.append("suspicious tokens in path")
        if many_hyphens:
            reason_bits.append("many hyphens")
        if numeric_heavy:
            reason_bits.append("numeric heavy domain")
        if max_sim > 0:
            topref = topk[0][0]
            reason_bits.append(f"closest to {topref} (sim={max_sim:.2f})")
        reasoning = "; ".join(reason_bits) if reason_bits else "based on semantic similarity and lexical patterns"
        return decision, conf, topk, reasoning

    def assess_with_evidence(self, retrieved_context: str, input_url: str) -> Dict[str, str]:
        """
        Evidence-only assessment that follows strict rules:
        - Only use retrieved_context text and input_url.
        - If evidence doesn't clearly mention the domain, return Unknown – insufficient evidence.
        - If evidence flags domain as phishing/suspicious, return Phishing.
        - If evidence verifies domain as official/trusted, return Legitimate.
        - If partial/weak match, return Suspected.
        Output keys: decision, confidence (High|Medium|Low), reason.
        """
        ctx = (retrieved_context or "").strip()
        if not ctx:
            return {
                "decision": "Unknown",
                "confidence": "Low",
                "reason": "Unknown – insufficient evidence",
            }
        ctx_low = ctx.lower()
        parsed = urlparse(input_url)
        host = (parsed.hostname or "").lower()
        ext = tldextract.extract(host)
        root = (ext.domain + "." + ext.suffix) if ext.domain and ext.suffix else host

        # Helper to check if context mentions host/root
        mentions_host = host and (host in ctx_low)
        mentions_root = root and (root in ctx_low)
        mentions = mentions_host or mentions_root

        # If no mention at all -> Unknown
        if not mentions:
            return {
                "decision": "Unknown",
                "confidence": "Low",
                "reason": "Unknown – insufficient evidence",
            }

        negative_markers = [
            "phishing",
            "malware",
            "scam",
            "typosquat",
            "fake",
            "spoof",
            "deceptive",
            "suspicious",
            "blacklist",
            "blocklist",
            "reported",
        ]
        positive_markers = [
            "official",
            "verified",
            "trusted",
            "legitimate",
            "authentic",
        ]

        neg_hit = any(m in ctx_low for m in negative_markers)
        pos_hit = any(m in ctx_low for m in positive_markers)

        # Typosquat/lookalike heuristic: if evidence mentions a well-known brand close to our domain label
        suspected = False
        if ext.domain:
            brand = ext.domain.lower()
            # If evidence mentions a different brand and is similar to our brand, mark suspected
            brands_in_ctx = re.findall(r"\b([a-z][a-z0-9\-]{2,})\.(com|in|org|net|gov|edu)\b", ctx_low)
            for b, _t in brands_in_ctx:
                if b and b != brand:
                    ratio = difflib.SequenceMatcher(None, b, brand).ratio()
                    if ratio >= 0.8:
                        suspected = True
                        break

        if neg_hit:
            return {
                "decision": "Phishing",
                "confidence": "High" if mentions_host else "Medium",
                "reason": "Evidence reports phishing/suspicious activity for this domain",
            }
        if pos_hit and not neg_hit:
            return {
                "decision": "Legitimate",
                "confidence": "High" if mentions_host else "Medium",
                "reason": "Evidence indicates official/verified/trusted domain",
            }
        if suspected:
            return {
                "decision": "Suspected",
                "confidence": "Medium",
                "reason": "Evidence references similar trusted brand suggesting possible imitation",
            }
        # Mentioned but neither positive nor negative -> Unknown (insufficient specifics)
        return {
            "decision": "Unknown",
            "confidence": "Low",
            "reason": "Unknown – insufficient evidence",
        }

    def assess_fused(self, retrieved_context: str, web_content_summary: str, input_url: str) -> Dict[str, str]:
        """
        Combine two evidence sources (RAG context + web content summary) following rules:
        - Prefer Legitimate only if BOTH sources support legitimacy.
        - If either shows clear malicious patterns, classify Phishing.
        - If weak/contradictory, classify Suspected.
        - If no relevant evidence, classify Unknown.
        Do NOT use SSL/DNS in this decision.
        Returns: dict(decision, confidence, reason)
        """
        ctx = (retrieved_context or "").strip().lower()
        content = (web_content_summary or "").strip().lower()
        parsed = urlparse(input_url)
        host = (parsed.hostname or "").lower()
        ext = tldextract.extract(host)
        root = (ext.domain + "." + ext.suffix) if ext.domain and ext.suffix else host

        # Evaluate RAG evidence
        def eval_rag(text: str) -> str:
            if not text:
                return "unknown"
            neg = any(k in text for k in [
                "phishing", "malware", "scam", "typosquat", "fake", "spoof", "deceptive", "suspicious", "blacklist", "blocklist", "reported"
            ])
            pos = any(k in text for k in [
                "official", "verified", "trusted", "legitimate", "authentic"
            ])
            mentioned = (host and host in text) or (root and root in text)
            if neg and mentioned:
                return "phishing"
            if pos and mentioned and not neg:
                return "legitimate"
            if mentioned and not (pos or neg):
                return "suspected"
            return "unknown"

        rag_label = eval_rag(ctx)

        # Evaluate content evidence
        def eval_content(text: str) -> str:
            if not text:
                return "unknown"
            phishing_terms = [
                "login", "sign in", "password", "otp", "credit card", "cvv", "verify your account",
                "update your", "confirm", "security alert", "unusual activity"
            ]
            has_phish_terms = any(k in text for k in phishing_terms)
            mentions_form = any(k in text for k in ["form", "submit", "input", "enter" ])
            # Brand/domain mismatch using org keywords/domains if available
            mismatch = False
            if self.org_keywords:
                for k in self.org_keywords:
                    if k and k not in (ext.domain or "") and k in text:
                        mismatch = True
                        break
            # If org_domains provided and content mentions a different root
            if not mismatch and self.org_domains and root:
                for od in self.org_domains:
                    od = od.lstrip('.')
                    if od != root and od in text:
                        mismatch = True
                        break
            if (has_phish_terms and mentions_form) or mismatch:
                return "phishing"
            legit_terms = ["official", "welcome", "homepage", "support", "contact us"]
            if any(k in text for k in legit_terms) and not (has_phish_terms or mismatch):
                return "legitimate"
            return "suspected" if (has_phish_terms or mentions_form) else "unknown"

        content_label = eval_content(content)

        # Decision fusion
        if rag_label == "phishing" or content_label == "phishing":
            return {
                "decision": "Phishing",
                "confidence": "High" if (rag_label == "phishing" and content_label == "phishing") else "Medium",
                "reason": "RAG or page content indicates phishing patterns (brand imitation, credential prompts, or mismatch)",
            }
        if rag_label == "legitimate" and content_label == "legitimate":
            return {
                "decision": "Legitimate",
                "confidence": "High",
                "reason": "Both RAG evidence and page content align with legitimate patterns",
            }
        if rag_label == "unknown" and content_label == "unknown":
            return {
                "decision": "Unknown",
                "confidence": "Low",
                "reason": "Unknown – insufficient evidence from both RAG and content",
            }
        # Contradictory or weak signals
        return {
            "decision": "Suspected",
            "confidence": "Medium",
            "reason": "Signals are weak or contradictory between RAG and content",
        }
