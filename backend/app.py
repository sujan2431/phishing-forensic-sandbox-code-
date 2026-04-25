import sys
import os
import re
import io

# Force UTF-8 output on Windows consoles that default to cp1252
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# Allow imports from the utils/ directory (sibling of backend/)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

from utils.sender_analysis import analyze_sender
from utils.url_analysis import analyze_urls
from utils.homograph import analyze_homographs
from utils.content_analysis import analyze_content
from utils.risk_scorer import calculate_risk

app = Flask(
    __name__,
    static_folder=os.path.join(os.path.dirname(__file__), '..', 'frontend'),
    static_url_path=''
)
CORS(app)

# ─────────────────────────────────────────────
# Header Parser
# ─────────────────────────────────────────────

def parse_email_headers(raw: str) -> dict:
    """
    Extract well-known email headers from raw text.
    Returns a dict with lowercase header names as keys.
    """
    headers = {}
    header_names = [
        "from", "to", "cc", "reply-to", "return-path",
        "subject", "date", "message-id", "received",
        "x-mailer", "x-originating-ip", "mime-version",
        "content-type", "dkim-signature", "authentication-results"
    ]
    for name in header_names:
        pattern = re.compile(
            r'^' + re.escape(name) + r'\s*:\s*(.+)',
            re.IGNORECASE | re.MULTILINE
        )
        match = pattern.search(raw)
        if match:
            headers[name] = match.group(1).strip()
    return headers


def extract_body(raw: str) -> str:
    """
    Separate headers from body. Body starts after the first blank line.
    If no blank line is found, treat entire text as body.
    """
    parts = re.split(r'\n\s*\n', raw, maxsplit=1)
    if len(parts) == 2:
        return parts[1]
    return raw


# ─────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────

@app.route('/')
def serve_index():
    return send_from_directory(app.static_folder, 'index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json(force=True, silent=True)
    if not data or 'email' not in data:
        return jsonify({'error': 'No email content provided.'}), 400

    raw_email = data['email'].strip()
    if len(raw_email) < 10:
        return jsonify({'error': 'Email content is too short to analyze.'}), 400

    headers = parse_email_headers(raw_email)
    body = extract_body(raw_email)
    full_text = raw_email  # analyze URLs and homographs in full text

    # Run all analysis modules
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

    # Build response
    response = {
        "risk": risk,
        "headers": headers,
        "findings": all_findings,
        "url_analysis": url_data['url_results'],
        "url_count": url_data['url_count'],
        "finding_counts": {
            "sender": len(sender_findings),
            "url": len(url_data['findings']),
            "homograph": len(homograph_findings),
            "content": len(content_findings),
        }
    }

    return jsonify(response)


# ─────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────

if __name__ == '__main__':
    print("=" * 55)
    print("  [*] Phishing Email Forensic Analyzer")
    print("  [*] Running at: http://localhost:5000")
    print("=" * 55)
    app.run(debug=True, port=5000)
