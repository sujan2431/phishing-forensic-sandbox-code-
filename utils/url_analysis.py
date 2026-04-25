import re

SUSPICIOUS_TLDS = [
    ".xyz", ".ru", ".tk", ".cc", ".pw", ".top", ".win", ".gq",
    ".ml", ".cf", ".ga", ".icu", ".live", ".online", ".site",
    ".club", ".info", ".biz", ".click", ".link", ".ws"
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "short.io", "is.gd", "buff.ly", "rb.gy", "cutt.ly",
    "shorturl.at", "tiny.cc"
]

KNOWN_BRANDS = [
    "paypal", "google", "amazon", "microsoft", "apple", "netflix",
    "facebook", "instagram", "twitter", "linkedin", "dropbox",
    "chase", "wellsfargo", "bankofamerica", "citibank", "irs",
    "ups", "fedex", "dhl", "ebay", "walmart", "yahoo"
]

OFFICIAL_DOMAINS = {
    "paypal": "paypal.com",
    "google": "google.com",
    "amazon": "amazon.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "twitter": "twitter.com",
    "linkedin": "linkedin.com",
    "dropbox": "dropbox.com",
    "ebay": "ebay.com",
    "yahoo": "yahoo.com",
}

URL_REGEX = re.compile(
    r'https?://[^\s\'"<>\]\[)(\{\}]+',
    re.IGNORECASE
)

IP_REGEX = re.compile(
    r'https?://(\d{1,3}\.){3}\d{1,3}',
    re.IGNORECASE
)


def extract_domain(url: str) -> str:
    match = re.match(r'https?://([^/\?#]+)', url)
    if match:
        host = match.group(1).lower()
        # strip port
        host = re.sub(r':\d+$', '', host)
        return host
    return ""


def extract_urls(text: str) -> list:
    return list(set(URL_REGEX.findall(text)))


def analyze_urls(text: str) -> dict:
    urls = extract_urls(text)
    findings = []
    url_results = []

    for url in urls:
        domain = extract_domain(url)
        result = {
            "original": url,
            "domain": domain,
            "risk": "Low",
            "reason": "No issues detected"
        }
        url_findings = []

        # IP-based URL
        if IP_REGEX.match(url):
            url_findings.append("IP-based URL — legitimate services use domain names, not raw IPs")
            result["risk"] = "High"
            findings.append({
                "type": "url",
                "severity": "high",
                "title": "IP-Based URL Detected",
                "detail": f'The URL "{url}" uses a raw IP address instead of a domain name. Phishers use IPs to bypass blocklists and hide their infrastructure.',
                "score": 25
            })

        # URL shortener
        for shortener in URL_SHORTENERS:
            if shortener in domain:
                url_findings.append(f"URL shortener ({shortener}) — hides the real destination")
                result["risk"] = "Medium" if result["risk"] == "Low" else result["risk"]
                findings.append({
                    "type": "url",
                    "severity": "medium",
                    "title": "URL Shortener Used",
                    "detail": f'The link uses "{shortener}" to hide the real destination. Phishers use URL shorteners to disguise malicious sites.',
                    "score": 15
                })

        # Suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                url_findings.append(f"Suspicious TLD ({tld}) — commonly abused by phishers")
                result["risk"] = "High"
                findings.append({
                    "type": "url",
                    "severity": "high",
                    "title": f"Suspicious Domain Extension ({tld})",
                    "detail": f'The domain "{domain}" uses the "{tld}" extension which is commonly used by phishing sites because they are cheap or free to register.',
                    "score": 20
                })

        # Brand in URL but wrong domain
        for brand in KNOWN_BRANDS:
            official = OFFICIAL_DOMAINS.get(brand)
            if brand in domain:
                if official and not (domain == official or domain.endswith("." + official)):
                    url_findings.append(f'Fake brand domain — contains "{brand}" but is not {official}')
                    result["risk"] = "High"
                    findings.append({
                        "type": "url",
                        "severity": "high",
                        "title": f"Fake Brand URL ({brand})",
                        "detail": f'The URL contains "{brand}" in the domain "{domain}" but this is NOT the official site "{official}". This is a classic phishing technique.',
                        "score": 25
                    })

        # @ in URL (username trick)
        if "@" in url:
            url_findings.append("Contains '@' — browser ignores everything before '@' in a URL")
            result["risk"] = "High"
            findings.append({
                "type": "url",
                "severity": "high",
                "title": "URL Contains '@' Character",
                "detail": f'The URL "{url}" contains an "@" symbol. Browsers treat everything before "@" as credentials and redirect to the domain after it, a known phishing trick.',
                "score": 20
            })

        result["reason"] = "; ".join(url_findings) if url_findings else "No issues detected"
        url_results.append(result)

    # Deduplicate findings by title
    seen_titles = set()
    unique_findings = []
    for f in findings:
        if f["title"] not in seen_titles:
            seen_titles.add(f["title"])
            unique_findings.append(f)

    return {
        "url_results": url_results,
        "findings": unique_findings,
        "url_count": len(urls)
    }
