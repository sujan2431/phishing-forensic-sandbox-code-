import sys
import os
import argparse

# Allow imports from the local app logic
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backend.app import parse_email_headers, extract_body
from utils.sender_analysis import analyze_sender
from utils.url_analysis import analyze_urls
from utils.homograph import analyze_homographs
from utils.content_analysis import analyze_content
from utils.risk_scorer import calculate_risk

def analyze_email(raw_email):
    if len(raw_email.strip()) < 10:
        print("Error: Email content is too short to analyze.")
        sys.exit(1)

    headers = parse_email_headers(raw_email)
    body = extract_body(raw_email)
    full_text = raw_email

    sender_findings = analyze_sender(headers)
    url_data = analyze_urls(full_text)
    homograph_findings = analyze_homographs(full_text)
    content_findings = analyze_content(body)

    all_findings = (
        sender_findings +
        url_data['findings'] +
        homograph_findings +
        content_findings
    )
    risk = calculate_risk(all_findings)

    # OUTPUT FORMAT
    print("🔍 PHISHING FORENSIC REPORT\n")
    print(f"Risk Score: {risk['score']} / 100")
    print(f"Risk Level: {risk['level']} ({risk['emoji']})\n")

    print("Findings:")
    sorted_findings = sorted(all_findings, key=lambda x: x.get('score', 0), reverse=True)
    if not sorted_findings:
        print("- None detected")
    else:
        for f in sorted_findings:
            title = f.get('title', 'Unknown Issue')
            detail = f.get('detail', 'No description available')
            print(f"- ⚠ {title}: {detail}")
    
    print("\nURL Analysis:")
    if not url_data['url_results']:
        print("- No URLs detected")
    else:
        for u in url_data['url_results']:
            original = u.get('original', 'Unknown')
            domain = u.get('domain', 'Unknown')
            url_risk = u.get('risk', 'Unknown')
            print(f"- {original} → {domain} → {url_risk}")
            
    print("\nConclusion:")
    print(risk['conclusion'])

def main():
    parser = argparse.ArgumentParser(description="Phishing Forensic Analyzer")
    parser.add_argument("file", nargs="?", help="Path to email file (or read from stdin if omitted)")
    args = parser.parse_args()

    raw_email = ""
    # Read from file or stdin
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                raw_email = f.read()
        except Exception as e:
            print(f"Error reading {args.file}: {e}")
            sys.exit(1)
    elif not sys.stdin.isatty():
        raw_email = sys.stdin.read()
    else:
        print("Please provide an email to analyze via file argument or pipe.", file=sys.stderr)
        print("Example: py analyze.py email.txt", file=sys.stderr)
        sys.exit(1)

    analyze_email(raw_email)

if __name__ == "__main__":
    main()
