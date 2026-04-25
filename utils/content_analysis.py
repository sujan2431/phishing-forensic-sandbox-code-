import re

# --- Urgency / Pressure Patterns ---
URGENCY_PATTERNS = [
    (r'\burgent\b', "Urgency trigger word"),
    (r'\bimmediately\b', "Urgency trigger word"),
    (r'\bact now\b', "Pressure tactic"),
    (r'\baction required\b', "Pressure tactic"),
    (r'\bverify (your|now|immediately)\b', "Verification pressure"),
    (r'\bconfirm (your|now|immediately)\b', "Verification pressure"),
    (r'\bwithin 24 hours?\b', "Artificial deadline"),
    (r'\bwithin 48 hours?\b', "Artificial deadline"),
    (r'\bexpires? (today|soon|in)\b', "Artificial deadline"),
    (r'\blast (chance|warning|notice)\b', "Urgency trigger word"),
    (r'\btime.sensitive\b', "Urgency trigger word"),
    (r'\bdo not (ignore|delay)\b', "Pressure tactic"),
    (r'\bfailure to (respond|comply|verify)\b', "Threat of consequence"),
    (r'\brespond (immediately|asap|now)\b', "Urgency trigger word"),
]

# --- Fear / Threat Patterns ---
FEAR_PATTERNS = [
    (r'\baccount (will be|has been|is) (suspended|closed|locked|disabled|terminated)\b', "Account threat"),
    (r'\bsuspicious (activity|login|access)\b', "Fear of compromise"),
    (r'\bunauthorized (access|login|activity)\b', "Fear of compromise"),
    (r'\byour account (is|has been)\b.*\b(compromised|hacked|breached)\b', "Fear of compromise"),
    (r'\blegal action\b', "Legal threat"),
    (r'\bcriminal charges?\b', "Legal threat"),
    (r'\blaw enforcement\b', "Legal threat"),
    (r'\byou (will|may) (be|face) (fined|arrested|prosecuted)\b', "Legal threat"),
    (r'\bpassword (was|has been) (changed|reset|compromised)\b', "Security scare"),
    (r'\bdata breach\b', "Security scare"),
]

# --- Reward / Bait Patterns ---
REWARD_PATTERNS = [
    (r'\byou (have|\'ve) won\b', "Lottery / prize bait"),
    (r'\bcongratulations\b', "Prize bait"),
    (r'\bclaim (your )?(prize|reward|gift|voucher)\b', "Prize bait"),
    (r'\bfree (gift|prize|iphone|laptop|money)\b', "Free offer bait"),
    (r'\b\$[\d,]+ (reward|bonus|gift card)\b', "Money bait"),
    (r'\blottery\b', "Lottery bait"),
    (r'\binheritance\b', "Advance-fee fraud bait"),
    (r'\bbillion(s)?\b.*\bleft\b', "Advance-fee fraud bait"),
    (r'\btransfer (of )?funds?\b', "Advance-fee fraud bait"),
    (r'\bunclaimed (funds?|money|prize)\b', "Advance-fee fraud bait"),
]

# --- Generic/Impersonal Greetings ---
GENERIC_GREETINGS = [
    r'\bdear (customer|user|account (holder|owner)|member|valued (customer|member))\b',
    r'\bhello (customer|user|member)\b',
    r'\bto whom it may concern\b',
    r'\bdear (sir|ma\'?am|friend)\b',
]

# --- Suspicious Attachment Types ---
SUSPICIOUS_ATTACHMENTS = [
    r'\b[\w\-]+\.(exe|bat|cmd|vbs|js|jar|zip|rar|7z|iso|img|docm|xlsm|pptm|ps1|msi)\b'
]

# --- Grammar issues (common phishing tells) ---
GRAMMAR_PATTERNS = [
    (r'\bplease to \w+', "Grammatically incorrect phrase"),
    (r'\bkindly to \w+', "Grammatically incorrect phrase"),
    (r'\byour (account|password) is (need|require)\b', "Grammar error"),
    (r'\bwe (is|are) (writing|contacting) you\b.*\bfor (your|the) account\b', "Awkward phrasing"),
]


def analyze_content(body: str) -> list:
    findings = []
    text = body.lower()

    # 1. Urgency patterns
    urgency_hits = []
    for pattern, label in URGENCY_PATTERNS:
        if re.search(pattern, text):
            urgency_hits.append(label)

    if urgency_hits:
        unique_labels = list(dict.fromkeys(urgency_hits))
        findings.append({
            "type": "content",
            "severity": "medium",
            "title": "Urgency / Pressure Tactics Detected",
            "detail": (
                f'The email uses psychological pressure techniques: '
                f'{", ".join(unique_labels[:4])}. '
                f'Legitimate organizations rarely pressure you with urgent deadlines or threats.'
            ),
            "score": min(20, len(urgency_hits) * 5)
        })

    # 2. Fear / threat patterns
    fear_hits = []
    for pattern, label in FEAR_PATTERNS:
        if re.search(pattern, text):
            fear_hits.append(label)

    if fear_hits:
        unique_labels = list(dict.fromkeys(fear_hits))
        findings.append({
            "type": "content",
            "severity": "high",
            "title": "Fear & Threat Language Detected",
            "detail": (
                f'The email uses fear-inducing or threatening language: '
                f'{", ".join(unique_labels[:4])}. '
                f'This is a classic social engineering tactic to make you act without thinking.'
            ),
            "score": min(25, len(fear_hits) * 7)
        })

    # 3. Reward / bait patterns
    reward_hits = []
    for pattern, label in REWARD_PATTERNS:
        if re.search(pattern, text):
            reward_hits.append(label)

    if reward_hits:
        unique_labels = list(dict.fromkeys(reward_hits))
        findings.append({
            "type": "content",
            "severity": "medium",
            "title": "Reward / Bait Language Detected",
            "detail": (
                f'The email offers unexpected rewards or prizes: '
                f'{", ".join(unique_labels[:4])}. '
                f'Unsolicited prize offers are almost always scams.'
            ),
            "score": min(20, len(reward_hits) * 6)
        })

    # 4. Generic greeting
    for pattern in GENERIC_GREETINGS:
        if re.search(pattern, text):
            findings.append({
                "type": "content",
                "severity": "low",
                "title": "Generic / Impersonal Greeting",
                "detail": (
                    'The email uses a generic greeting like "Dear Customer" or "Dear User" '
                    'instead of your real name. Legitimate companies almost always address '
                    'you by name.'
                ),
                "score": 8
            })
            break

    # 5. Suspicious attachments
    attachment_hits = []
    for pattern in SUSPICIOUS_ATTACHMENTS:
        matches = re.findall(pattern, body, re.IGNORECASE)
        attachment_hits.extend(matches)

    if attachment_hits:
        exts = list(set(attachment_hits))
        findings.append({
            "type": "content",
            "severity": "high",
            "title": "Suspicious Attachment Mentioned",
            "detail": (
                f'The email references file type(s): {", ".join(exts[:5])}. '
                f'These file types are commonly used to deliver malware. Never open '
                f'attachments from untrusted senders.'
            ),
            "score": 25
        })

    # 6. Grammar issues
    grammar_hits = []
    for pattern, label in GRAMMAR_PATTERNS:
        if re.search(pattern, text):
            grammar_hits.append(label)

    if grammar_hits:
        findings.append({
            "type": "content",
            "severity": "low",
            "title": "Grammar / Language Issues",
            "detail": (
                f'Detected grammatical irregularities: {", ".join(set(grammar_hits))}. '
                f'Poor grammar is a common indicator of phishing emails, often written '
                f'by non-native speakers or automated generators.'
            ),
            "score": 7
        })

    return findings
