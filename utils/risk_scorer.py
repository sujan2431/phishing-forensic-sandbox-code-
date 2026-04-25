MAX_SCORE = 100


def calculate_risk(all_findings: list) -> dict:
    """
    Aggregate findings from all modules and compute:
    - Total score (0–100)
    - Risk level (Safe / Suspicious / High Risk)
    - Emoji indicator
    - Verdict
    - Category breakdown
    """
    raw_score = sum(f.get("score", 0) for f in all_findings)
    score = min(raw_score, MAX_SCORE)

    if score <= 30:
        level = "Safe"
        emoji = "🟢"
        verdict = "No"
        verdict_label = "Not Phishing"
        color = "#22c55e"
    elif score <= 70:
        level = "Suspicious"
        emoji = "🟡"
        verdict = "Likely"
        verdict_label = "Likely Phishing"
        color = "#eab308"
    else:
        level = "High Risk"
        emoji = "🔴"
        verdict = "Yes"
        verdict_label = "Phishing Detected"
        color = "#ef4444"

    # Severity counts
    severity_counts = {"high": 0, "medium": 0, "low": 0}
    for f in all_findings:
        sev = f.get("severity", "low")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Category breakdown
    categories = {}
    for f in all_findings:
        cat = f.get("type", "other")
        categories[cat] = categories.get(cat, 0) + 1

    # Generate conclusion text
    if score <= 30:
        conclusion = (
            "This email appears to be legitimate. No significant phishing indicators were detected. "
            "However, always exercise caution with unsolicited emails and verify requests through official channels."
        )
    elif score <= 70:
        conclusion = (
            f"This email shows {severity_counts['high']} high-risk and {severity_counts['medium']} medium-risk indicators. "
            "There are notable suspicious elements that warrant caution. Do not click any links or provide personal information "
            "until you have verified the sender through official channels."
        )
    else:
        conclusion = (
            f"This email is almost certainly a phishing attempt. {severity_counts['high']} high-risk indicators were detected "
            "including potential spoofing, malicious URLs, and social engineering tactics. "
            "Do NOT click any links, open attachments, or reply to this email. Report it and delete it immediately."
        )

    return {
        "score": score,
        "raw_score": raw_score,
        "level": level,
        "emoji": emoji,
        "color": color,
        "verdict": verdict,
        "verdict_label": verdict_label,
        "severity_counts": severity_counts,
        "categories": categories,
        "conclusion": conclusion,
        "total_findings": len(all_findings)
    }
