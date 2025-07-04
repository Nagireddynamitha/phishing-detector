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
        issues.append("❌ Missing HTTPS (Not secure)")

    # 2. Suspicious TLD
    if any(domain.endswith(tld) for tld in suspicious_tlds):
        issues.append("⚠️ Suspicious TLD used")

    # 3. Sensitive keywords
    for keyword in sensitive_keywords:
        if keyword in domain or keyword in path:
            issues.append(f"⚠️ Keyword found: {keyword}")

    # 4. Long or suspicious domain
    if len(domain) > 40 or re.search(r"[-_]{2,}", domain):
        issues.append("⚠️ Domain looks suspicious or too long")

    # Verdict
    return issues if issues else ["✅ Safe"]

# Test with file input (optional)
def scan_from_file(file_path):
    try:
        with open(file_path, 'r') as f:
            urls = f.read().splitlines()
            for url in urls:
                print(f"\n🔎 Scanning: {url}")
                verdict = is_phishing_url(url)
                for v in verdict:
                    print(v)
    except FileNotFoundError:
        print("File not found.")

# Test run
if __name__ == "__main__":
    print("== Phishing URL Detection ==")
    scan_from_file("phishing_urls.txt")  # You can change or remove this line

