from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from rules.auth_rules import AuthFailureRule
from rules.base import CompositeRule, Rule
from rules.content_rules import FearLanguageRule, FormExfilRule
from rules.domain_rules import DomainRule
from rules.header_rules import SuspiciousHostRule
from rules.ip_rules import CloudVPSRule
from whitelist import get_config


def build_detector() -> CompositeRule:
    whitelist = get_config()
    rules: List[Rule] = [
        AuthFailureRule(),
        SuspiciousHostRule(),
        DomainRule(whitelist=whitelist),
        FearLanguageRule(),
        FormExfilRule(whitelist=whitelist),
        CloudVPSRule(),
    ]
    return CompositeRule(rules)


def _normalize_score(raw_score: int) -> int:
    max_raw = 20
    normalized = int((raw_score / max_raw) * 20)
    return max(0, min(20, normalized))


def _check_reply_to_mismatch(headers: str) -> bool:
    from_header = re.search(r"^From:\s*(.+)$", headers, re.MULTILINE | re.IGNORECASE)
    reply_to_header = re.search(r"^Reply-To:\s*(.+)$", headers, re.MULTILINE | re.IGNORECASE)
    if from_header and reply_to_header:
        from_val = from_header.group(1).strip()
        reply_val = reply_to_header.group(1).strip()
        from_domain = from_val.split("@")[-1].lower().strip(">") if "@" in from_val else ""
        reply_domain = reply_val.split("@")[-1].lower().strip(">") if "@" in reply_val else ""
        if from_domain and reply_domain and from_domain != reply_domain:
            return True
    return False


def _check_url_obfuscation(urls: List[str]) -> bool:
    for url in urls:
        parsed = re.search(r"https?://([^/]+)", url)
        if not parsed:
            continue
        domain = parsed.group(1)
        if domain.startswith("xn--"):
            return True
        if re.search(r"[a-zA-Z0-9]{20,}", domain):
            return True
        if domain.count(".") > 2:
            return True
    return False


def analyze_email(data: Dict[str, Any]) -> Dict[str, Any]:
    detector = build_detector()
    raw_score = 0
    reasons: List[str] = []
    auth_results = {
        "spf_fail": "spf=temperror" in data.get("headers", "").lower() or "spf=fail" in data.get("headers", "").lower(),
        "dkim_pass": "dkim=pass" in data.get("headers", "").lower(),
        "dkim_fail": "dkim=none" in data.get("headers", "").lower() or "dkim=fail" in data.get("headers", "").lower(),
        "dmarc_fail": "dmarc=temperror" in data.get("headers", "").lower() or "dmarc=fail" in data.get("headers", "").lower(),
    }

    if hasattr(detector, "rules"):
        for rule in detector.rules:
            try:
                triggered, score, reason = rule.check(data)
                if triggered:
                    raw_score += score
                    reasons.append(reason)
            except Exception as exc:
                import logging
                logging.getLogger(__name__).warning("Rule %s failed: %s", rule.name, exc)

    if _check_reply_to_mismatch(data.get("headers", "")):
        raw_score += 2
        reasons.append("Reply-To mismatch with From address")

    if _check_url_obfuscation(data.get("urls", [])):
        raw_score += 3
        reasons.append("URL obfuscation detected (punycode or excessive subdomains)")

    total_score = _normalize_score(raw_score)

    if total_score >= 10:
        verdict = "PHISHING"
    elif total_score >= 4:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return {
        "score": total_score,
        "verdict": verdict,
        "reasons": reasons,
        "auth_results": auth_results,
        "iocs": {
            "urls": data.get("urls", []),
            "domains": data.get("domains", []),
            "ips": data.get("ips", []),
        },
    }
