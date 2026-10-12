"""
URL & Domain Security Analyzer.
Analyzes hyperlinks, domain reputation, typosquatting, suspicious TLDs,
IP hosts, credential-harvesting paths, and anchor text mismatches.
"""

import re
from urllib.parse import urlparse
import unicodedata

# High-profile targets commonly spoofed in phishing campaigns
BRAND_TARGETS = [
    "paypal", "microsoft", "google", "apple", "netflix", "amazon",
    "bankofamerica", "chase", "wellsfargo", "citibank", "dhl", "fedex",
    "usps", "dropbox", "facebook", "instagram", "linkedin", "twitter",
    "coinbase", "binance", "meta", "yahoo", "outlook", "office365", "docusign",
    "adobe", "github", "gitlab", "spotify", "slack", "zoom"
]

# TLDs heavily associated with malicious campaigns & spam registration
SUSPICIOUS_TLDS = {
    "xyz", "top", "buzz", "club", "work", "rest", "tk", "ml", "ga", "cf", "gq",
    "cc", "click", "link", "stream", "date", "racing", "kim", "country", "science",
    "party", "bid", "trade", "accountant", "loan", "win", "icu", "site", "online",
    "vip", "wang", "space"
}

# Known URL shorteners that obscure real destinations
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly", "cutt.ly",
    "rebrand.ly", "shorte.st", "tiny.cc", "goo.gl", "lnkd.in"
}

# Common credential traps in path or query strings
CREDENTIAL_KEYWORDS = [
    "login", "signin", "verify", "verification", "account", "update", "banking",
    "secure", "webscr", "recovery", "wallet", "ssn", "password", "authenticate",
    "confirm", "security", "portal", "invoice", "payment", "reset"
]

# Character confusable maps for homoglyphs / typosquatting
CONFUSABLES = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '8': 'b',
    '@': 'a', '$': 's', 'vv': 'w', 'rn': 'm', 'cl': 'd'
}

def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes basic Levenshtein edit distance."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def normalize_confusables(text: str) -> str:
    res = text.lower()
    for char, rep in CONFUSABLES.items():
        res = res.replace(char, rep)
    return res

class URLAnalyzer:
    def __init__(self):
        # Comprehensive URL regex
        self.url_pattern = re.compile(
            r'https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)',
            re.IGNORECASE
        )
        self.ip_pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
        self.html_link_pattern = re.compile(
            r'<a\s+[^>]*href=["\'](https?://[^"\']+)["\'][^>]*>(.*?)</a>',
            re.IGNORECASE | re.DOTALL
        )

    def extract_urls(self, text: str) -> list[str]:
        """Extracts unique plain URLs from raw text."""
        if not text:
            return []
        found = self.url_pattern.findall(text)
        # Deduplicate while preserving order
        seen = set()
        unique = []
        for u in found:
            # Clean trailing punctuation
            u_clean = u.rstrip('.,;:)"\'>')
            if u_clean and u_clean not in seen:
                seen.add(u_clean)
                unique.append(u_clean)
        return unique

    def extract_html_anchors(self, html_text: str) -> list[dict]:
        """Extracts <a> tags to compare displayed text vs actual destination href."""
        if not html_text:
            return []
        anchors = []
        for match in self.html_link_pattern.finditer(html_text):
            href = match.group(1).strip()
            display_text = re.sub(r'<[^>]+>', '', match.group(2)).strip()
            anchors.append({"href": href, "display_text": display_text})
        return anchors

    def analyze_domain(self, domain: str) -> dict:
        """Evaluates domain characteristics, spoofing, and reputation signals."""
        domain_clean = domain.lower().strip()
        parts = domain_clean.split('.')
        tld = parts[-1] if len(parts) > 1 else ""

        is_ip = bool(self.ip_pattern.match(domain_clean))
        is_suspicious_tld = tld in SUSPICIOUS_TLDS
        is_shortener = domain_clean in URL_SHORTENERS
        subdomain_count = max(0, len(parts) - 2)
        excessive_subdomains = subdomain_count >= 3

        # Typosquatting / Brand impersonation check
        spoofed_brand = None
        typosquat_risk = 0.0

        normalized_domain = normalize_confusables(domain_clean)

        for brand in BRAND_TARGETS:
            # Direct exact match of legitimate domain (e.g., paypal.com)
            if domain_clean == f"{brand}.com" or domain_clean == f"www.{brand}.com":
                continue

            # Brand name embedded in subdomain or hyphenated domain (e.g., paypal-verify.com, update-microsoft.net)
            if brand in domain_clean:
                # If brand is in the domain but it's not the primary registered domain
                main_reg = parts[-2] if len(parts) >= 2 else ""
                if main_reg != brand:
                    spoofed_brand = brand
                    typosquat_risk = max(typosquat_risk, 0.90)
                elif len(parts) > 2 and parts[0] != "www":
                    # Subdomain manipulation (e.g., paypal.evil.com)
                    spoofed_brand = brand
                    typosquat_risk = max(typosquat_risk, 0.85)

            # Levenshtein distance check on the registered label
            reg_label = parts[-2] if len(parts) >= 2 else parts[0]
            norm_label = normalize_confusables(reg_label)
            
            # If length is close and edit distance is 1 or 2
            if abs(len(reg_label) - len(brand)) <= 2:
                dist = levenshtein_distance(norm_label, brand)
                if dist in (1, 2) and reg_label != brand:
                    spoofed_brand = brand
                    typosquat_risk = max(typosquat_risk, 0.95)

        return {
            "domain": domain_clean,
            "tld": tld,
            "is_ip": is_ip,
            "is_suspicious_tld": is_suspicious_tld,
            "is_shortener": is_shortener,
            "subdomain_count": subdomain_count,
            "excessive_subdomains": excessive_subdomains,
            "spoofed_brand": spoofed_brand,
            "typosquat_risk": typosquat_risk
        }

    def analyze_single_url(self, url: str) -> dict:
        """Detailed security assessment of an individual URL."""
        risk_score = 0.0
        reasons = []

        try:
            parsed = urlparse(url)
            scheme = parsed.scheme.lower()
            hostname = parsed.hostname or ""
            path = parsed.path.lower()
            query = parsed.query.lower()
        except Exception:
            return {
                "url": url,
                "risk_score": 0.8,
                "risk_level": "High",
                "reasons": ["Malformed or unparseable URL"]
            }

        # Check Scheme
        if scheme == "http":
            risk_score += 0.20
            reasons.append("Unencrypted HTTP protocol used for sensitive communication")

        # Check Domain
        domain_info = self.analyze_domain(hostname)
        if domain_info["is_ip"]:
            risk_score += 0.50
            reasons.append(f"Direct IP address ({hostname}) used as host instead of registered domain")

        if domain_info["is_suspicious_tld"]:
            risk_score += 0.35
            reasons.append(f"High-risk Top-Level Domain (.{domain_info['tld']}) often used in spam campaigns")

        if domain_info["is_shortener"]:
            risk_score += 0.30
            reasons.append(f"URL Shortener ({domain_info['domain']}) masks actual target location")

        if domain_info["excessive_subdomains"]:
            risk_score += 0.25
            reasons.append(f"Excessive subdomains ({domain_info['subdomain_count']}) used to obscure real origin")

        if domain_info["spoofed_brand"]:
            risk_score += 0.60
            reasons.append(f"Detected likely typosquatting / brand spoofing of '{domain_info['spoofed_brand'].upper()}'")

        # Check path & query for credential traps
        found_cred_words = []
        combined_uri = path + " " + query
        for word in CREDENTIAL_KEYWORDS:
            if word in combined_uri:
                found_cred_words.append(word)

        if len(found_cred_words) >= 2:
            risk_score += 0.30
            reasons.append(f"Path contains multiple credential harvesting indicators: {', '.join(found_cred_words[:3])}")
        elif len(found_cred_words) == 1:
            risk_score += 0.15
            reasons.append(f"Path references sensitive operation keyword: '{found_cred_words[0]}'")

        # Cap score between 0.0 and 1.0
        clamped_score = min(max(risk_score, 0.0), 1.0)
        risk_level = "Low" if clamped_score < 0.35 else ("Medium" if clamped_score < 0.65 else "High")

        return {
            "url": url,
            "hostname": hostname,
            "risk_score": round(clamped_score, 2),
            "risk_level": risk_level,
            "reasons": reasons,
            "domain_info": domain_info
        }

    def analyze_all(self, text: str, html_text: str = "") -> dict:
        """Extracts and analyzes all URLs, checking anchor mismatches."""
        urls = self.extract_urls(text)
        if html_text:
            # Also extract from HTML
            urls.extend(self.extract_urls(html_text))
            urls = list(dict.fromkeys(urls))  # Deduplicate

        analyzed_urls = [self.analyze_single_url(u) for u in urls]

        # Anchor mismatches (e.g. text displays 'paypal.com' but href goes to 'evil-phish.xyz')
        anchor_mismatches = []
        if html_text:
            anchors = self.extract_html_anchors(html_text)
            for a in anchors:
                href = a["href"].lower()
                display = a["display_text"].lower()
                # If display text looks like a domain or URL but doesn't match href domain
                for brand in BRAND_TARGETS:
                    if brand in display and brand not in href:
                        anchor_mismatches.append({
                            "display_text": a["display_text"],
                            "destination_href": a["href"],
                            "reason": f"Displayed anchor references '{brand}' but hyperlink leads to a different domain ({href})"
                        })

        # Calculate composite URL threat score
        if not analyzed_urls:
            url_threat_score = 0.0
            highest_risk_url = None
        else:
            scores = [item["risk_score"] for item in analyzed_urls]
            max_score = max(scores)
            avg_score = sum(scores) / len(scores)
            # Weighted toward the most dangerous link present
            url_threat_score = min(1.0, (max_score * 0.75) + (avg_score * 0.25))
            highest_risk_url = max(analyzed_urls, key=lambda x: x["risk_score"])

        if anchor_mismatches:
            url_threat_score = max(url_threat_score, 0.85)

        return {
            "total_urls_found": len(analyzed_urls),
            "url_threat_score": round(url_threat_score, 2),
            "urls": analyzed_urls,
            "anchor_mismatches": anchor_mismatches,
            "highest_risk_url": highest_risk_url
        }

url_analyzer = URLAnalyzer()
