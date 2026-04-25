import re
import unicodedata

# Map of visually similar Unicode chars → ASCII equivalent
HOMOGRAPH_MAP = {
    'а': 'a',  # Cyrillic а
    'е': 'e',  # Cyrillic е
    'о': 'o',  # Cyrillic о
    'р': 'p',  # Cyrillic р
    'с': 'c',  # Cyrillic с
    'ѕ': 's',
    'ԁ': 'd',
    'ɡ': 'g',
    'ı': 'i',
    'ʼ': "'",
    '\u0131': 'i',  # dotless i
    '\u0399': 'I',  # Greek capital iota
    '\u04c0': 'I',  # Cyrillic palochka
    '\u2160': 'I',  # Roman numeral I
    'ν': 'v',       # Greek nu
    'μ': 'u',       # Greek mu
    'ω': 'w',       # Greek omega
    '0': '0',
    'l': 'l',       # lowercase L (already ASCII, used in checks)
    'I': 'I',       # uppercase i (already ASCII)
    '1': '1',
    'rn': 'm',      # two chars that look like m
}

KNOWN_BRANDS = [
    "paypal", "google", "amazon", "microsoft", "apple", "netflix",
    "facebook", "instagram", "twitter", "linkedin", "chase",
    "wellsfargo", "bankofamerica", "citibank", "ebay"
]

# Common single-char substitutions (l→1, o→0, etc.)
CONFUSABLE_PAIRS = [
    ('l', '1'), ('o', '0'), ('i', '1'), ('i', 'l'),
    ('rn', 'm'), ('vv', 'w'), ('cl', 'd'),
]

URL_REGEX = re.compile(r'https?://[^\s\'"<>\]\[)(\{\}]+', re.IGNORECASE)


def normalize_domain(domain: str) -> str:
    """Convert unicode homographs to ASCII equivalents."""
    result = ""
    for ch in domain:
        mapped = HOMOGRAPH_MAP.get(ch)
        result += mapped if mapped else ch
    return result


def has_non_ascii(s: str) -> bool:
    return any(ord(c) > 127 for c in s)


def extract_domain(url: str) -> str:
    match = re.match(r'https?://([^/\?#@]+)', url)
    if match:
        return match.group(1).lower().split(":")[0]
    return ""


def check_confusable(domain: str) -> list:
    hits = []
    for brand in KNOWN_BRANDS:
        # Check with confusable pair substitutions
        for orig, sub in CONFUSABLE_PAIRS:
            if orig in domain:
                candidate = domain.replace(orig, sub)
                if brand in candidate and brand not in domain:
                    hits.append((domain, brand, f'"{orig}" looks like "{sub}"'))
    return hits


def analyze_homographs(text: str) -> list:
    findings = []
    urls = URL_REGEX.findall(text)

    for url in urls:
        domain = extract_domain(url)

        # 1. Unicode / IDN homograph
        if has_non_ascii(domain):
            normalized = normalize_domain(domain)
            for brand in KNOWN_BRANDS:
                if brand in normalized and brand not in domain:
                    findings.append({
                        "type": "homograph",
                        "severity": "high",
                        "title": "Homograph / Unicode Domain Attack",
                        "detail": (
                            f'The domain "{domain}" uses look-alike Unicode characters '
                            f'that visually resemble "{normalized}" (a known brand). '
                            f'Your browser may display it as the real site but it is a fake.'
                        ),
                        "score": 30
                    })

        # 2. ASCII confusable substitutions (rn→m, l→1, etc.)
        confusable_hits = check_confusable(domain)
        for (dom, brand, reason) in confusable_hits:
            findings.append({
                "type": "homograph",
                "severity": "high",
                "title": "Confusable Character Substitution",
                "detail": (
                    f'The domain "{dom}" uses {reason} which makes it look like '
                    f'"{brand}" — a known brand. This is a typosquatting technique '
                    f'designed to trick you visually.'
                ),
                "score": 25
            })

    # Also scan plain text (not just URLs) for suspicious domain-like strings
    domain_like = re.findall(r'\b[\w\-\.]+\.(?:com|net|org|io)\b', text)
    for domain in domain_like:
        if has_non_ascii(domain):
            normalized = normalize_domain(domain)
            for brand in KNOWN_BRANDS:
                if brand in normalized and brand not in domain:
                    findings.append({
                        "type": "homograph",
                        "severity": "high",
                        "title": "Homograph in Email Body",
                        "detail": (
                            f'The text contains "{domain}" which uses Unicode look-alike '
                            f'characters to impersonate "{brand}". This is a visual deception attack.'
                        ),
                        "score": 25
                    })

    # Deduplicate
    seen = set()
    unique = []
    for f in findings:
        key = f["title"] + f["detail"][:40]
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique
