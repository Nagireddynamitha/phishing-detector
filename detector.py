import re
from urllib.parse import urlparse

# Suspicious top-level domains
suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']

# Keywords often used in phishing
sensitive_keywords = [
    'facebook', 'gmail', 'instagram', 'apple', 'amazon',
    'login', 'verify', 'secure', 'update', 'account', 'password'
]

def is_phishing_url(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    issues = []

    # 1. No HTTPS
    if parsed.scheme != 'https':
        issues.append("[WARNING] Missing HTTPS (Not secure)")

    # 2. Suspicious TLD
    if any(domain.endswith(tld) for tld in suspicious_tlds):
        issues.append("[WARNING] Suspicious TLD used")

    # 3. Sensitive keywords
    for keyword in sensitive_keywords:
        if keyword in domain or keyword in path:
            issues.append(f"[WARNING] Keyword found: {keyword}")

    # 4. Long or suspicious domain
    if len(domain) > 40 or re.search(r"[-_]{2,}", domain):
        issues.append("[WARNING] Domain looks suspicious or too long")

    # Verdict
    return issues if issues else ["[OK] Safe"]

# Test with file input (optional)
def scan_from_file(file_path):
    try:
        with open(file_path, 'r') as f:
            urls = f.read().splitlines()
            for url in urls:
                if not url.strip():
                    continue
                print(f"\n[SCAN] {url}")
                verdict = is_phishing_url(url)
                for v in verdict:
                    print(v)
    except FileNotFoundError:
        print("[ERROR] File not found.")

# Run the scanner
if __name__ == "__main__":
    print("== Phishing URL Detection ==")
    test_url = input("Enter a URL to scan: ").strip()
    print(f"\n[SCAN] {test_url}")
    verdict = is_phishing_url(test_url)
    for v in verdict:
        print(v)



