from whitelist import WHITELIST_DOMAINS

def analyze_email(data):
    score = 0
    reasons = []

    headers = data.get("headers", "")
    urls = data.get("urls", [])
    domains = data.get("domains", [])
    ips = data.get("ips", [])

    # Rule 1: SPF/DKIM/DMARC failure
    spf_fail = "spf=temperror" in headers.lower()
    if spf_fail:
        score += 2
        reasons.append("SPF failure")

    dkim_signed = "dkim=pass" in headers.lower()
    if "dkim=none" in headers.lower():
        score += 2
        reasons.append("No DKIM signature")

    dmarc_fail = "dmarc=temperror" in headers.lower()
    if dmarc_fail:
        score += 2
        reasons.append("DMARC failure")

    # Rule 2: Suspicious return path
    if "ubuntu" in headers.lower() or "root@" in headers.lower():
        score += 2
        reasons.append("Suspicious return-path (Linux host)")

    # Rule 3: Suspicious domain patterns (with whitelist)
    for d in domains:
        # Skip whitelisted domains
        if any(w in d for w in WHITELIST_DOMAINS):
            continue

        if ".me" in d or "blog" in d or "segui" in d:
            score += 3
            reasons.append(f"Suspicious domain: {d}")

    # Rule 4: IP from cloud VPS range (basic check)
    for ip in ips:
        if ip.startswith("137."):
            score += 2
            reasons.append(f"Cloud VPS IP: {ip}")

    verdict = "PHISHING" if score >= 6 else "SUSPICIOUS"

    return {
        "score": score,
        "verdict": verdict,
        "reasons": reasons,
        "auth_results": {
            "spf_fail": spf_fail,
            "dkim_signed": dkim_signed,
            "dmarc_fail": dmarc_fail
        }
    }
