from __future__ import annotations

from urllib.parse import urlparse

from .config import DOH_DOMAINS, SUSPICIOUS_TLDS
from .threat_intel import match_iocs
from .accuracy_rules import domain_is_safe


def classify_domain(domain: str | None, url: str | None = None) -> tuple[str, int, list[str]]:
    normalized = (domain or "").strip(".").lower()
    if not normalized and url:
        normalized = (urlparse(url).hostname or "").lower()
    reasons: list[str] = []
    score = 0
    matches = match_iocs(domain=normalized or None, url=url)
    if matches:
        score = max(int(match.get("confidence", 85)) for match in matches)
        reasons.extend(f"threat_intelligence:{match['type']}" for match in matches)
    if domain_is_safe(normalized) and not matches:
        return "SAFE", 95, ["safe_baseline"]
    if normalized in DOH_DOMAINS or any(normalized.endswith("." + item) for item in DOH_DOMAINS):
        score = max(score, 45)
        reasons.append("dns_over_https_endpoint")
    if any(normalized.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score = max(score, 55)
        reasons.append("suspicious_tld")
    if normalized and len(normalized.split(".")[0]) > 24:
        score = max(score, 55)
        reasons.append("domain_shape")
    if score >= 86:
        classification = "CONFIRMED THREAT"
    elif score >= 61:
        classification = "HIGH RISK"
    elif score >= 31:
        classification = "SUSPICIOUS"
    elif score:
        classification = "INFORMATIONAL"
    else:
        classification = "SAFE"
    return classification, score, reasons
