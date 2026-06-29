from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)


class OSINTError(Exception):
    pass


class AbuseIPDBProvider:
    name = "abuseipdb"
    base_url = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: Optional[str] = None) -> None:
        self.api_key = api_key

    def check_ip(self, ip: str) -> Dict[str, Any]:
        if not self.api_key:
            return {"provider": self.name, "query": ip, "error": "API key required for AbuseIPDB"}
        try:
            headers = {"Key": self.api_key, "Accept": "application/json"}
            resp = requests.get(f"{self.base_url}/check", params={"ipAddress": ip, "maxAgeInDays": "90"}, headers=headers, timeout=30)
            resp.raise_for_status()
            data = resp.json().get("data", {})
            return {
                "provider": self.name,
                "query": ip,
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "country": data.get("countryCode", ""),
                "isp": data.get("isp", ""),
                "domain": data.get("domain", ""),
                "total_reports": data.get("totalReports", 0),
            }
        except Exception as exc:
            logger.warning("AbuseIPDB check failed for %s: %s", ip, exc)
            return {"provider": self.name, "query": ip, "error": str(exc)}


class CISAKEVProvider:
    name = "cisa-kev"
    base_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def check_domain(self, domain: str) -> Dict[str, Any]:
        return {"provider": self.name, "query": domain, "note": "CISA KEV is vulnerability-only; use for vendor/software checks"}

    def check_ip(self, ip: str) -> Dict[str, Any]:
        try:
            resp = requests.get(self.base_url, timeout=30)
            resp.raise_for_status()
            vulnerabilities = resp.json().get("vulnerabilities", [])
            matching = []
            for vuln in vulnerabilities:
                notes = vuln.get("notes", "") or ""
                required_action = vuln.get("requiredAction", "") or ""
                combined = f"{notes} {required_action}".lower()
                if ip.lower() in combined:
                    matching.append({
                        "cve_id": vuln.get("cveID", ""),
                        "vendor": vuln.get("vendorProject", ""),
                        "product": vuln.get("product", ""),
                        "due_date": vuln.get("dueDate", ""),
                    })
            return {
                "provider": self.name,
                "query": ip,
                "match_count": len(matching),
                "matches": matching[:10],
            }
        except Exception as exc:
            logger.warning("CISA KEV check failed for %s: %s", ip, exc)
            return {"provider": self.name, "query": ip, "error": str(exc)}


class RDAPProvider:
    name = "rdap"
    base_urls = {
        "ip": "https://rdap.org/ip",
        "domain": "https://rdap.org/domain",
    }

    def check_ip(self, ip: str) -> Dict[str, Any]:
        try:
            resp = requests.get(f"{self.base_urls['ip']}/{ip}", timeout=30, allow_redirects=True)
            resp.raise_for_status()
            data = resp.json()
            entities = data.get("entities", [])
            asn = ""
            org = ""
            country = ""
            for ent in entities:
                asn_val = ent.get("handle", "")
                if asn_val.startswith("AS"):
                    asn = asn_val
                vcard = ent.get("vcardArray", [])
                if len(vcard) > 1:
                    for item in vcard[1:]:
                        if item[0] in ("org", "fn"):
                            org = item[2] if len(item) > 2 else ""
                for addr in ent.get("roles", []):
                    pass
            for event in data.get("events", []):
                if event.get("eventAction") == "lastChanged":
                    pass
            remarks = data.get("remarks", [])
            for r in remarks:
                desc = r.get("description", [])
                for d in desc:
                    if d.startswith("Country"):
                        country = d.split(" ")[-1] if " " in d else ""
            return {
                "provider": self.name,
                "query": ip,
                "asn": asn,
                "org": org,
                "country": country,
                "raw": data,
            }
        except Exception as exc:
            logger.warning("RDAP check failed for %s: %s", ip, exc)
            return {"provider": self.name, "query": ip, "error": str(exc)}


class DNSOverHTTPSProvider:
    name = "doh"
    base_url = "https://dns.google/resolve"

    def check_domain(self, domain: str) -> Dict[str, Any]:
        try:
            resp = requests.get(self.base_url, params={"name": domain, "type": "A"}, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            answers = data.get("Answer", [])
            ips = [a["data"] for a in answers if a.get("type") == 1]
            return {
                "provider": self.name,
                "query": domain,
                "resolved_ips": ips,
                "status": data.get("Status", -1),
            }
        except Exception as exc:
            logger.warning("DNS over HTTPS check failed for %s: %s", domain, exc)
            return {"provider": self.name, "query": domain, "error": str(exc)}


class PhishTankProvider:
    name = "phishtank"
    base_url = "https://checkurl.phishtank.com/checkurl/"

    def check_url(self, url: str) -> Dict[str, Any]:
        try:
            resp = requests.post(self.base_url, data={"url": url, "format": "json"}, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            results = data.get("results", {})
            in_db = results.get("in_database", False)
            return {
                "provider": self.name,
                "query": url,
                "in_database": in_db,
                "verified": results.get("verified", False),
                "valid": results.get("valid", False),
            }
        except Exception as exc:
            logger.warning("PhishTank check failed for %s: %s", url, exc)
            return {"provider": self.name, "query": url, "error": str(exc)}


class AlienVaultOTXProvider:
    name = "alienvault-otx"
    base_url = "https://otx.alienvault.com/api/v1"

    def __init__(self, api_key: Optional[str] = None) -> None:
        self.api_key = api_key
        self.headers = {"X-OTX-API-KEY": api_key} if api_key else {}

    def check_indicator(self, indicator: str, ioc_type: str = "domain") -> Dict[str, Any]:
        if not self.api_key:
            return {"provider": self.name, "query": indicator, "error": "API key required for AlienVault OTX"}
        type_map = {"domain": "domain", "url": "url", "ip": "IPv4", "email": "email"}
        otx_type = type_map.get(ioc_type, "domain")
        try:
            resp = requests.get(
                f"{self.base_url}/indicators/{otx_type}/{indicator}/general",
                headers=self.headers,
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
            pulse_info = data.get("pulse_info", {})
            return {
                "provider": self.name,
                "query": indicator,
                "pulse_count": pulse_info.get("count", 0),
                "reputation": data.get("reputation", 0),
                "is_valid": pulse_info.get("is_valid", False),
            }
        except Exception as exc:
            logger.warning("AlienVault OTX check failed for %s: %s", indicator, exc)
            return {"provider": self.name, "query": indicator, "error": str(exc)}


def get_osint_provider(name: str, api_key: Optional[str] = None) -> Any:
    name_lower = name.lower()
    if name_lower == "abuseipdb":
        return AbuseIPDBProvider(api_key=api_key)
    if name_lower == "cisa-kev":
        return CISAKEVProvider()
    if name_lower == "rdap":
        return RDAPProvider()
    if name_lower == "doh":
        return DNSOverHTTPSProvider()
    if name_lower == "phishtank":
        return PhishTankProvider()
    if name_lower == "alienvault-otx":
        return AlienVaultOTXProvider(api_key=api_key)
    raise ValueError(f"Unsupported OSINT provider: {name}")
