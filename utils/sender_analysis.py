import re

FREE_MAIL_DOMAINS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "aol.com", "protonmail.com", "icloud.com", "mail.com",
    "zoho.com", "yandex.com", "gmx.com", "live.com"
]

KNOWN_BRANDS = [
    "paypal", "google", "amazon", "microsoft", "apple", "netflix",
    "facebook", "instagram", "twitter", "linkedin", "dropbox",
    "chase", "wellsfargo", "bankofamerica", "citibank", "irs",
    "ups", "fedex", "dhl", "ebay", "walmart"
]


def extract_email_address(raw: str) -> str:
    """Extract email address from a string like 'Name <email@domain.com>'."""
    match = re.search(r'[\w\.\-\+]+@[\w\.\-]+\.\w+', raw)
    return match.group(0).lower() if match else raw.lower().strip()


def extract_display_name(raw: str) -> str:
    match = re.match(r'^"?([^<"]+)"?\s*<', raw.strip())
    return match.group(1).strip() if match else ""


def get_domain(email: str) -> str:
    if "@" in email:
        return email.split("@")[-1].strip(">").lower()
    return ""


def analyze_sender(headers: dict) -> list:
    findings = []

    from_raw = headers.get("from", "")
    reply_to_raw = headers.get("reply-to", "")
    return_path_raw = headers.get("return-path", "")

    from_email = extract_email_address(from_raw)
    from_domain = get_domain(from_email)
    display_name = extract_display_name(from_raw)

    # 1. Free email domain impersonating a brand
    if from_domain in FREE_MAIL_DOMAINS and display_name:
        for brand in KNOWN_BRANDS:
            if brand in display_name.lower():
                findings.append({
                    "type": "sender",
                    "severity": "high",
                    "title": "Brand Impersonation via Free Email",
                    "detail": (
                        f'Display name claims to be "{display_name}" but the actual '
                        f'sender domain is "{from_domain}", a free email provider. '
                        f'Legitimate companies never use free email addresses.'
                    ),
                    "score": 30
                })
                break

    # 2. Reply-To mismatch
    if reply_to_raw:
        reply_email = extract_email_address(reply_to_raw)
        reply_domain = get_domain(reply_email)
        if reply_domain and reply_domain != from_domain:
            findings.append({
                "type": "sender",
                "severity": "high",
                "title": "Reply-To / From Domain Mismatch",
                "detail": (
                    f'The "From" address is "{from_email}" but replies will go to '
                    f'"{reply_email}". Attackers set a different Reply-To so they '
                    f'receive your response while you think you are replying to a trusted sender.'
                ),
                "score": 25
            })

    # 3. Return-Path mismatch
    if return_path_raw:
        rp_email = extract_email_address(return_path_raw)
        rp_domain = get_domain(rp_email)
        if rp_domain and rp_domain != from_domain:
            findings.append({
                "type": "sender",
                "severity": "medium",
                "title": "Return-Path / From Domain Mismatch",
                "detail": (
                    f'The "Return-Path" domain "{rp_domain}" does not match the '
                    f'"From" domain "{from_domain}". This is a strong indicator '
                    f'of email spoofing or a compromised mail relay.'
                ),
                "score": 20
            })

    # 4. From domain impersonating known brand (not exact match)
    for brand in KNOWN_BRANDS:
        if brand in from_domain and not from_domain.startswith(brand + "."):
            findings.append({
                "type": "sender",
                "severity": "high",
                "title": "Typosquatted Sender Domain",
                "detail": (
                    f'The sender domain "{from_domain}" contains the brand name '
                    f'"{brand}" but is not the official domain. This is a classic '
                    f'typosquatting attack to trick recipients into trusting the email.'
                ),
                "score": 25
            })
            break

    return findings
