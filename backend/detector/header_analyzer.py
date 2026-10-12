"""
Email Header & Sender Authentication Analyzer.
Inspects display name spoofing, sender-domain mismatches, Reply-To traps,
and simulated or parsed SPF/DKIM/DMARC authentication signals.
"""

import re
from email.utils import parseaddr

FREE_WEBMAILS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "protonmail.com", "mail.com", "zoho.com", "yandex.com", "icloud.com"
}

LEGITIMATE_ENTERPRISE_DOMAINS = {
    "paypal": "paypal.com",
    "microsoft": "microsoft.com",
    "google": "google.com",
    "apple": "apple.com",
    "netflix": "netflix.com",
    "amazon": "amazon.com",
    "bankofamerica": "bankofamerica.com",
    "chase": "chase.com",
    "dhl": "dhl.com",
    "fedex": "fedex.com",
    "meta": "meta.com",
    "facebook": "facebookmail.com",
    "docusign": "docusign.net"
}

class HeaderAnalyzer:
    def __init__(self):
        pass

    def parse_sender(self, sender_str: str) -> dict:
        """Parses display name and email address from string like 'Name <email@domain.com>'"""
        if not sender_str:
            return {"name": "", "address": "", "domain": ""}
        name, address = parseaddr(sender_str.strip())
        domain = address.split("@")[-1].lower() if "@" in address else ""
        return {
            "name": name,
            "address": address.lower(),
            "domain": domain
        }

    def analyze(self, sender: str, reply_to: str = "", raw_headers: str = "") -> dict:
        """
        Analyzes sender credentials, header discrepancies, and domain spoofing.
        """
        risk_score = 0.0
        flags = []

        sender_info = self.parse_sender(sender)
        reply_to_info = self.parse_sender(reply_to)

        sender_name = sender_info["name"].lower()
        sender_domain = sender_info["domain"]
        sender_addr = sender_info["address"]

        # 1. Display Name Impersonation
        # e.g., Name is "PayPal Security" but sender email is "someone@fake-billing.com" or "evil@gmail.com"
        for brand, official_domain in LEGITIMATE_ENTERPRISE_DOMAINS.items():
            if brand in sender_name:
                if official_domain not in sender_domain and not sender_domain.endswith("." + official_domain):
                    risk_score += 0.55
                    flags.append({
                        "severity": "CRITICAL",
                        "message": f"Display name claims to be '{brand.title()}' but sender address '{sender_addr}' is NOT from '{official_domain}'"
                    })
                    break

        # 2. Executive / Authority Display Name from Free Webmail
        if sender_domain in FREE_WEBMAILS:
            exec_titles = ["ceo", "cfo", "director", "president", "hr department", "payroll", "security team", "it helpdesk"]
            if any(title in sender_name for title in exec_titles):
                risk_score += 0.45
                flags.append({
                    "severity": "HIGH",
                    "message": f"Corporate/Executive title in sender display name using public free webmail '{sender_domain}'"
                })

        # 3. Reply-To discrepancy
        if reply_to_info["domain"] and sender_domain:
            if reply_to_info["domain"] != sender_domain:
                risk_score += 0.35
                flags.append({
                    "severity": "MEDIUM",
                    "message": f"Reply-To domain ({reply_to_info['domain']}) does not match sender domain ({sender_domain})"
                })

        # 4. Raw Headers inspection (SPF, DKIM, DMARC)
        auth_signals = {"spf": "neutral", "dkim": "neutral", "dmarc": "neutral"}
        if raw_headers:
            raw_lower = raw_headers.lower()
            if "spf=fail" in raw_lower or "received-spf: fail" in raw_lower:
                auth_signals["spf"] = "fail"
                risk_score += 0.40
                flags.append({"severity": "HIGH", "message": "Sender SPF validation failed (spoofed sender IP)"})
            elif "spf=pass" in raw_lower or "received-spf: pass" in raw_lower:
                auth_signals["spf"] = "pass"
                risk_score = max(0.0, risk_score - 0.15)

            if "dkim=fail" in raw_lower:
                auth_signals["dkim"] = "fail"
                risk_score += 0.35
                flags.append({"severity": "HIGH", "message": "DKIM digital signature failed verification"})
            elif "dkim=pass" in raw_lower:
                auth_signals["dkim"] = "pass"
                risk_score = max(0.0, risk_score - 0.10)

            if "dmarc=fail" in raw_lower:
                auth_signals["dmarc"] = "fail"
                risk_score += 0.35
                flags.append({"severity": "HIGH", "message": "DMARC policy check failed"})
            elif "dmarc=pass" in raw_lower:
                auth_signals["dmarc"] = "pass"

        normalized_score = min(1.0, round(risk_score, 2))

        return {
            "header_risk_score": normalized_score,
            "sender_parsed": sender_info,
            "reply_to_parsed": reply_to_info,
            "flags": flags,
            "auth_signals": auth_signals
        }

header_analyzer = HeaderAnalyzer()
