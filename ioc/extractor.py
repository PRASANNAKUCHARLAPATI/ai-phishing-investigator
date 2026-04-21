import re
from urllib.parse import urlparse

def extract_iocs(text):
    urls = re.findall(r'https?://[^\s"]+', text)
    domains = []
    ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)
    emails = re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', text)

    for url in urls:
        parsed = urlparse(url)
        domains.append(parsed.netloc)

    return {
        "urls": list(set(urls)),
        "domains": list(set(domains)),
        "ips": list(set(ips)),
        "emails": list(set(emails))
    }
