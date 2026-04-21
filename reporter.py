def generate_report(email_data, iocs, analysis_result, filename="report.txt"):
    """Generate a comprehensive phishing investigation report."""
    
    from whitelist import WHITELIST_DOMAINS
    
    lines = []
    lines.append("=" * 60)
    lines.append("PHISHING INVESTIGATION REPORT")
    lines.append("=" * 60)
    lines.append("")
    
    # Verdict section
    lines.append("VERDICT")
    lines.append("-" * 60)
    lines.append(f"Verdict   : {analysis_result['verdict']}")
    lines.append(f"Score     : {analysis_result['score']}")
    
    # Confidence calculation
    if analysis_result["score"] >= 10:
        confidence = "HIGH"
    elif analysis_result["score"] >= 6:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"
    lines.append(f"Confidence: {confidence}")
    lines.append("")
    
    # Reasons section
    lines.append("DETECTION REASONS")
    lines.append("-" * 60)
    for reason in analysis_result['reasons']:
        lines.append(f"  - {reason}")
    lines.append("")
    
    # IOC section
    lines.append("EXTRACTED IoCs")
    lines.append("-" * 60)
    
    # Classify URLs
    malicious_urls = []
    legit_urls = []
    for u in iocs.get("urls", []):
        if any(w in u for w in WHITELIST_DOMAINS):
            legit_urls.append(u)
        else:
            malicious_urls.append(u)
    
    lines.append("Malicious URLs:")
    if malicious_urls:
        for u in malicious_urls:
            lines.append(f"  - {u}")
    else:
        lines.append("  (none)")
    lines.append("")
    
    lines.append("Legitimate URLs (used for disguise):")
    if legit_urls:
        for u in legit_urls:
            lines.append(f"  - {u}")
    else:
        lines.append("  (none)")
    lines.append("")
    
    # Classify domains
    malicious_domains = []
    legit_domains = []
    for d in iocs.get("domains", []):
        if any(w in d for w in WHITELIST_DOMAINS):
            legit_domains.append(d)
        else:
            malicious_domains.append(d)
    
    lines.append("Malicious Domains:")
    if malicious_domains:
        for d in malicious_domains:
            lines.append(f"  - {d}")
    else:
        lines.append("  (none)")
    lines.append("")
    
    lines.append("Domain Reputation Note:")
    lines.append("  - Newly registered / lookalike domain used for brand impersonation")
    lines.append("")
    
    lines.append("Legitimate Domains (used to appear safe):")
    if legit_domains:
        for d in legit_domains:
            lines.append(f"  - {d}")
    else:
        lines.append("  (none)")
    lines.append("")
    
    lines.append("IP Addresses:")
    if iocs['ips']:
        for ip in iocs['ips']:
            lines.append(f"  - {ip}")
    else:
        lines.append("  (none)")
    lines.append("")
    
    lines.append("Email Addresses:")
    if iocs['emails']:
        for email in iocs['emails']:
            lines.append(f"  - {email}")
    else:
        lines.append("  (none)")
    lines.append("")
    
    # Email details
    lines.append("EMAIL DETAILS")
    lines.append("-" * 60)
    lines.append(f"From    : {email_data['headers'].get('From', 'N/A')}")
    lines.append(f"To      : {email_data['headers'].get('To', 'N/A')}")
    lines.append(f"Subject : {email_data['headers'].get('Subject', 'N/A')}")
    lines.append(f"Date    : {email_data['headers'].get('Date', 'N/A')}")
    lines.append("")
    
    # Email authentication summary
    lines.append("EMAIL AUTHENTICATION SUMMARY")
    lines.append("-" * 60)
    auth_results = analysis_result.get("auth_results", {})
    spf = "FAIL" if auth_results.get("spf_fail") else "PASS"
    dkim = "NOT PRESENT" if not auth_results.get("dkim_signed") else "PASS"
    dmarc = "FAIL" if auth_results.get("dmarc_fail") else "PASS"
    lines.append(f"SPF   : {spf}")
    lines.append(f"DKIM  : {dkim}")
    lines.append(f"DMARC : {dmarc}")
    lines.append("")
    
    # Attack technique analysis
    lines.append("ATTACK TECHNIQUE OBSERVED")
    lines.append("-" * 60)
    lines.append("Technique: Brand Impersonation + Infrastructure Camouflage")
    lines.append("")
    lines.append("The attacker used trusted Google CDN domains (fonts.gstatic.com, fonts.googleapis.com)")
    lines.append("to make the email appear legitimate while hosting the credential harvesting page")
    lines.append("on a newly registered malicious domain.")
    lines.append("")
    
    # MITRE ATT&CK mapping
    lines.append("MITRE ATT&CK MAPPING")
    lines.append("-" * 60)
    lines.append("T1566.002 - Phishing: Link")
    lines.append("T1583.001 - Acquire Infrastructure: Domains")
    lines.append("T1583.003 - Acquire Infrastructure: VPS")
    lines.append("")
    
    # Risk to organization
    lines.append("RISK TO ORGANIZATION")
    lines.append("-" * 60)
    lines.append("If a user clicks the malicious link, attackers may harvest credentials,")
    lines.append("leading to account takeover, internal phishing spread, and data breach.")
    lines.append("")
    
    # Recommendations
    lines.append("RECOMMENDED ACTIONS FOR SOC")
    lines.append("-" * 60)
    
    if analysis_result['verdict'] == 'PHISHING':
        lines.append("  [HIGH PRIORITY - PHISHING DETECTED]")
        lines.append("  1. Block sending IP in firewall/email gateway")
        lines.append("  2. Block all malicious domains in web proxy/email gateway")
        lines.append("  3. Block only malicious URLs in web filtering systems")
        lines.append("  4. Search SIEM logs for connections to:")
        for d in malicious_domains:
            lines.append(f"     - {d}")
        for ip in iocs['ips']:
            lines.append(f"     - Traffic from {ip}")
        lines.append("  5. Reset affected user passwords (if applicable)")
        lines.append("  6. Notify incident response team")
        lines.append("  7. Add sender to email blocklist")
        lines.append("  8. Report phishing domain to abuse contacts")
    else:
        lines.append("  [MONITOR - SUSPICIOUS EMAIL]")
        lines.append("  1. Monitor user account for suspicious activity")
        lines.append("  2. Search logs for connections to suspicious domains")
        lines.append("  3. Consider blocking suspicious domains/IPs")
        lines.append("  4. Alert user about potential phishing attempt")
    
    lines.append("")
    lines.append("=" * 60)
    lines.append(f"Report generated: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 60)
    
    report_content = "\n".join(lines)
    
    with open(filename, 'w') as f:
        f.write(report_content)
    
    return filename
