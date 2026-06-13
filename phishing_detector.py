"""
Cybersecurity URL Threat Analysis Tool

Author: Layan Alotaibi

Description:
Analyzes URLs for common phishing indicators and produces
a threat assessment report.
"""

import re
from urllib.parse import urlparse


# v.v.v.v.v.v.v.v.v.v.v.v.v.v.v
# URL Length Check
# v.v.v.v.v.v.v.v.v.v.v.v.v.v.v
def url_length_check(url):
    """
    Long URLs are often used to hide malicious content.
    """
    return len(url) > 75


# :>:>:>:>:>:>:>:>:>:>:>:>:>:>
# IP Address Detection
# :>:>:>:>:>:>:>:>:>:>:>:>:>:>
def contains_ip_address(url):
    """
    Detect URLs that use an IP address
    instead of a domain name.
    """
    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    try:
        domain = urlparse(url).netloc.split(":")[0]
        return bool(re.match(ip_pattern, domain))
    except Exception:
        return False


# '3''3''3''3''3''3''3''3''3''3'
# URL Shortener Detection
# '3''3''3''3''3''3''3''3''3''3'
def uses_url_shortener(url):

    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "ow.ly",
        "is.gd",
        "goo.gl",
    ]

    domain = urlparse(url).netloc.lower()

    return any(service in domain for service in shorteners)


# :|:/:\:|:\:/:|:\:/:|:/:\:|:\
# Suspicious Keyword Detection
# :|:/:\:|:\:/:|:\:/:|:/:\:|:\
def has_suspicious_keywords(url):

    keywords = [
        "login",
        "signin",
        "verify",
        "account",
        "secure",
        "update",
        "password",
        "banking",
    ]

    url = url.lower()

    return any(keyword in url for keyword in keywords)


# .l.l.l.l.l.l.l.l.l.l.l.l.l.l.
# Excessive Subdomains
# .l.l.l.l.l.l.l.l.l.l.l.l.l.l.
def excessive_subdomains(url):

    domain = urlparse(url).netloc

    return domain.count(".") > 3


# ----------------------------
# '@' Symbol Detection
# ----------------------------
def contains_at_symbol(url):

    return "@" in url


# 'o''o''o''o''o''o''o''o''o''o'
# Hyphen Detection
# 'o''o''o''o''o''o''o''o''o''o'
def excessive_hyphens(url):

    domain = urlparse(url).netloc

    return domain.count("-") >= 2


# '-''-''-''-''-''-''-''-''-''-'
# HTTPS Check
# '-''-''-''-''-''-''-''-''-''-'
def uses_https(url):

    return urlparse(url).scheme.lower() == "https"

# ^._.^^._.^^._.^^._.^^._.^^._.^
# Suspicious TLD Detection
# ^._.^^._.^^._.^^._.^^._.^^._.^
def suspicious_tld(url):

    suspicious_tlds = [
        ".xyz",
        ".top",
        ".click",
        ".work",
        ".zip",
        ".country",
    ]

    domain = urlparse(url).netloc.lower()

    return any(domain.endswith(tld) for tld in suspicious_tlds)


# :):):):):):):):):):):):):):)
# Threat Scoring Engine
# :):):):):):):):):):):):):):)
def analyze_url(url):

    score = 0
    findings = []

    if url_length_check(url):
        score += 10
        findings.append("Unusually long URL")

    if contains_ip_address(url):
        score += 30
        findings.append("Uses IP address instead of domain")

    if uses_url_shortener(url):
        score += 20
        findings.append("Uses URL shortening service")

    if has_suspicious_keywords(url):
        score += 15
        findings.append("Contains phishing-related keywords")

    if excessive_subdomains(url):
        score += 15
        findings.append("Excessive number of subdomains")

    if contains_at_symbol(url):
        score += 20
        findings.append("Contains '@' symbol")

    if excessive_hyphens(url):
        score += 10
        findings.append("Multiple hyphens detected")

    if not uses_https(url):
        score += 10
        findings.append("Does not use HTTPS")

    if suspicious_tld(url):
        score += 15
        findings.append("Uses suspicious top-level domain")

    return score, findings


# -.-.-.-.-.-.-.-.-.-.-.-.-.-.
# Risk Classification
# -.-.-.-.-.-.-.-.-.-.-.-.-.-.
def classify_risk(score):

    if score >= 60:
        return "HIGH"

    elif score >= 30:
        return "MEDIUM"

    return "LOW"


# _._._._._._._._._._._._._._.
# Report Generator
# _._._._._._._._._._._._._._.
def generate_report(url, score, findings):

    risk = classify_risk(score)

    print("\n" + "=" * 60)
    print("URL THREAT ANALYSIS REPORT")
    print("=" * 60)

    print(f"URL: {url}")
    print(f"Threat Score: {score}")
    print(f"Risk Level: {risk}")

    print("\nIndicators:")

    if findings:
        for finding in findings:
            print(f"[+] {finding}")
    else:
        print("[+] No suspicious indicators detected")

    print("\nRecommendation:")

    if risk == "HIGH":
        print("Avoid visiting this URL.")
    elif risk == "MEDIUM":
        print("Proceed with caution and verify legitimacy.")
    else:
        print("No major threats detected.")

    print("=" * 60)


# -.-.-.-.-.-.-.-.-.-.-.-.-.-.
# Main Program
# -.-.-.-.-.-.-.-.-.-.-.-.-.-.
def main():

    print("Cybersecurity URL Threat Analysis Tool")

    url = input("\nEnter URL: ").strip()

    score, findings = analyze_url(url)

    generate_report(url, score, findings)


if __name__ == "__main__":
    main()
