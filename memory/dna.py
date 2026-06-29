from __future__ import annotations

import hashlib
import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


def _hash(text: str) -> str:
    if not text:
        return ""
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def _extract_css_signature(html: str) -> str:
    soup = BeautifulSoup(html, "lxml")
    styles = []
    for tag in soup.find_all(style=True):
        styles.append(tag.get("style", ""))
    for link in soup.find_all("link", rel="stylesheet"):
        href = link.get("href", "")
        if href and not href.startswith("http"):
            styles.append(href)
    raw = "|".join(sorted(set(styles)))
    return _hash(raw)


def _extract_subject_pattern(subject: str) -> str:
    if not subject:
        return ""
    subject = subject.lower()
    subject = re.sub(r"\d+", "{N}", subject)
    subject = re.sub(r"[a-f0-9]{8,}", "{HEX}", subject)
    return subject


def _extract_sender_domain(from_header: str) -> str:
    match = re.search(r"@([^>]+)", from_header)
    if match:
        return match.group(1).lower().strip()
    return ""


def _extract_timezone(headers: str) -> str:
    match = re.search(r"Date:\s.*?([+-]\d{4}|[A-Z]{2,4})\s*$", headers, re.MULTILINE | re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return "unknown"


def _extract_attachment_types(attachments: List[Any]) -> List[str]:
    types = []
    for att in attachments:
        ct = getattr(att, "content_type", "")
        if ct:
            types.append(ct.split(";")[0].strip().lower())
    return sorted(set(types))


def _extract_url_patterns(urls: List[str]) -> List[str]:
    patterns = []
    for url in urls:
        parsed = re.search(r"https?://(.+?)(/|$)", url)
        if parsed:
            domain = parsed.group(1)
            if domain.startswith("xn--"):
                patterns.append("punycode")
            elif re.search(r"[a-z0-9]{15,}", domain):
                patterns.append("long-random-domain")
            elif domain.count(".") > 2:
                patterns.append("excessive-subdomains")
            else:
                patterns.append("standard-domain")
    return sorted(set(patterns))


def compute_threat_dna(
    email_data: Any,
    iocs: Dict[str, List[str]],
    analysis: Dict[str, Any],
    registrar: str = "",
    hosting_provider: str = "",
    language: str = "unknown",
) -> Dict[str, Any]:
    html = email_data.body_html if email_data else ""
    headers = "\n".join(f"{k}: {v}" for k, v in email_data.headers.items()) if email_data else ""
    subject = email_data.headers.get("Subject", "") if email_data else ""
    from_header = email_data.headers.get("From", "") if email_data else ""
    attachments = email_data.attachments if email_data else []
    urls = iocs.get("urls", [])

    html_hash = _hash(html.lower().strip())
    css_hash = _extract_css_signature(html)
    subject_pattern = _extract_subject_pattern(subject)
    sender_domain = _extract_sender_domain(from_header)
    timezone = _extract_timezone(headers)
    attachment_types = _extract_attachment_types(attachments)
    url_patterns = _extract_url_patterns(urls)

    soup = BeautifulSoup(html, "lxml")
    forms = soup.find_all("form")
    form_domains = []
    for form in forms:
        action = form.get("action", "")
        if action:
            match = re.search(r"https?://([^/]+)", action)
            if match:
                form_domains.append(match.group(1).lower())
    form_action_domain = form_domains[0] if form_domains else ""

    dna_vector = {
        "html_hash": html_hash,
        "css_hash": css_hash,
        "subject_pattern": subject_pattern,
        "sender_domain": sender_domain,
        "registrar": registrar,
        "hosting_provider": hosting_provider,
        "language": language,
        "timezone": timezone,
        "attachment_types": attachment_types,
        "form_action_domain": form_action_domain,
        "url_patterns": url_patterns,
        "verdict": analysis.get("verdict", ""),
        "score": analysis.get("score", 0),
        "reasons": analysis.get("reasons", []),
    }

    return {
        "html_hash": html_hash,
        "css_hash": css_hash,
        "subject_pattern": subject_pattern,
        "sender_domain": sender_domain,
        "registrar": registrar,
        "hosting_provider": hosting_provider,
        "language": language,
        "timezone": timezone,
        "attachment_types": attachment_types,
        "form_action_domain": form_action_domain,
        "url_patterns": url_patterns,
        "dna_vector": dna_vector,
    }
