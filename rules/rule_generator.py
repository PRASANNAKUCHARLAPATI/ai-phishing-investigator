from __future__ import annotations

import json
import logging
import re
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class RuleGenerator:
    def __init__(self, analysis: Dict[str, Any], iocs: Dict[str, List[str]], email_data: Any):
        self.analysis = analysis
        self.iocs = iocs
        self.email_data = email_data
        self.rules: List[Dict[str, Any]] = []

    def generate_sigma(self) -> str:
        score = self.analysis.get("score", 0)
        verdict = self.analysis.get("verdict", "")
        reasons = self.analysis.get("reasons", [])
        urls = self.iocs.get("urls", [])
        domains = self.iocs.get("domains", [])
        ips = self.iocs.get("ips", [])

        title = f"Phishing Detection - {verdict} Score {score}"
        description = f"Detected phishing indicators: {'; '.join(reasons)}"

        selection = []
        logsource = {"product": "email-gateway", "service": "email"}

        condition_parts = []

        if any("SPF" in r for r in reasons):
            selection.append({"campaign|contains": ["spf=fail", "spf=temperror"]})
            condition_parts.append("1 of them")
        if any("DKIM" in r for r in reasons):
            selection.append({"campaign|contains": ["dkim=fail", "dkim=none", "dkim=temperror"]})
            condition_parts.append("1 of them")
        if any("DMARC" in r for r in reasons):
            selection.append({"campaign|contains": ["dmarc=fail", "dmarc=temperror"]})
            condition_parts.append("1 of them")
        if any("hostname" in r.lower() for r in reasons):
            selection.append({"headers|contains": ["ubuntu", "centos", "debian", "postfix"]})
            condition_parts.append("1 of them")
        if any("reply-to" in r.lower() for r in reasons):
            selection.append({"Reply-To|contains": ["gmail", "yahoo", "hotmail", "outlook"]})
            condition_parts.append("1 of them")
        if any("root" in r.lower() for r in reasons):
            selection.append({"headers|contains": ["root@"]})
            condition_parts.append("1 of them")
        if any("VPS" in r or "cloud" in r.lower() for r in reasons):
            selection.append({"headers|contains": ["digitalocean", "hetzner", "aws", "gcp", "azure"]})
            condition_parts.append("1 of them")
        if any("form" in r.lower() or "exfiltration" in r.lower() for r in reasons):
            selection.append({"body|contains": ["<form", "password", "credentials"]})
            condition_parts.append("1 of them")
        if urls:
            selection.append({"url|contains": urls[0]})
            condition_parts.append("1 of them")
        if domains:
            selection.append({"email|endswith": [f"@{d}" for d in domains[:3]]})
            condition_parts.append("1 of them")

        if not condition_parts:
            condition = "1 of selection"
        else:
            condition = " and ".join(condition_parts)

        rule = {
            "title": title,
            "id": "phishx-auto-" + re.sub(r"[^a-z0-9]", "-", title.lower())[:30],
            "status": "experimental",
            "description": description,
            "author": "phishx",
            "date": "2026-06-28",
            "modified": "2026-06-28",
            "references": ["https://attack.mitre.org/techniques/T1566/"],
            "tags": [{"name": "attack-social-engineering"}, {"name": "attack-t1566.002"}],
            "logsource": logsource,
            "selection": selection,
            "condition": condition,
        }

        sigma = [
            'title: "' + rule["title"] + '"',
            'id: "' + rule["id"] + '"',
            'status: ' + rule["status"],
            'description: "' + rule["description"] + '"',
            'author: "' + rule["author"] + '"',
            'date: "' + rule["date"] + '"',
            'references:',
            '  - "' + rule["references"][0] + '"',
            'tags:',
            '  - name: "attack-social-engineering"',
            '  - name: "attack-t1566.002"',
            'logsource:',
            '  product: email-gateway',
            '  service: email',
            'detection:',
            '  selection:',
        ]
        for sel in rule["selection"]:
            for k, v in sel.items():
                if isinstance(v, list):
                    items = ", ".join(f'"{item}"' for item in v)
                    sigma.append(f'    {k}: [{items}]')
                else:
                    sigma.append(f'    {k}: "{v}"')
        sigma.append('  condition: ' + rule["condition"])
        return "\n".join(sigma)

    def generate_yara(self) -> str:
        reasons = self.analysis.get("reasons", [])
        html = self.email_data.body_html if self.email_data else ""
        verdict = self.analysis.get("verdict", "")

        strings = []
        conditions = []

        if any("SPF" in r for r in reasons):
            strings.append('$spf_fail = "spf=fail"')
            strings.append('$spf_temp = "spf=temperror"')
            conditions.append("any of ($spf_*)")
        if any("DKIM" in r for r in reasons):
            strings.append('$dkim_fail = "dkim=fail"')
            strings.append('$dkim_none = "dkim=none"')
            conditions.append("any of ($dkim_*)")
        if any("DMARC" in r for r in reasons):
            strings.append('$dmarc_fail = "dmarc=fail"')
            conditions.append("any of ($dmarc_*)")
        if any("hostname" in r.lower() for r in reasons):
            conditions.append('1 of ($linux_host_*)')
        if any("form" in r.lower() for r in reasons):
            conditions.append('$cred_form')

        if html and ("<form" in html.lower() and ("password" in html.lower() or "credentials" in html.lower())):
            strings.append('$cred_form = "<form" nocase')
        if "ubuntu" in html.lower() or "centos" in html.lower():
            strings.append('$linux_host_1 = "ubuntu" nocase')
            strings.append('$linux_host_2 = "centos" nocase')

        if not conditions:
            conditions.append("filesize < 10MB")

        rule_name = f"PhishX_Email_{verdict}_{int(time.time())}"
        condition = " and ".join(conditions) if len(conditions) > 1 else conditions[0]

        yara = f'rule {rule_name} {{\n'
        yara += '    meta:\n'
        yara += '        description = "PhishX generated YARA rule"\n'
        yara += f'        verdict = "{verdict}"\n'
        yara += '    strings:\n'
        for s in strings:
            yara += f'        {s}\n'
        yara += '    condition:\n'
        yara += f'        {condition}\n'
        yara += '}\n'
        return yara

    def generate_suricata(self) -> str:
        urls = self.iocs.get("urls", [])
        domains = self.iocs.get("domains", [])
        ips = self.iocs.get("ips", [])
        reasons = self.analysis.get("reasons", [])
        verdict = self.analysis.get("verdict", "")

        sid_base = 9000000
        rules = []

        if any("form" in r.lower() or "exfiltration" in r.lower() for r in reasons):
            for url in urls[:3]:
                parsed = re.search(r"https?://([^/]+)(/.*)?", url)
                if parsed:
                    domain = parsed.group(1)
                    path = parsed.group(2) or "/"
                    rules.append(
                        f'alert http any any -> any any (msg:"PHISHX: Credential exfiltration to {domain}"; '
                        f'http.method; content:"POST"; http.uri; content "{path}"; '
                        f'dst_ip; external; '
                        f'sid:{sid_base + 1}; rev:1; classtype:attempted-admin; priority:1;)'
                    )

        if ips:
            for ip in ips[:3]:
                rules.append(
                    f'alert ip any any -> {ip} any (msg:"PHISHX: Known phishing IP {ip}"; '
                    f'sid:{sid_base + 2}; rev:1; classtype:network-scan; priority:2;)'
                )

        return "\n\n".join(rules)

    def generate_all(self) -> Dict[str, str]:
        return {
            "sigma": self.generate_sigma(),
            "yara": self.generate_yara(),
            "suricata": self.generate_suricata(),
        }
