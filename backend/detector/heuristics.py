"""
Heuristics & Natural Language Threat Pattern Engine.
Analyzes urgency vectors, credential harvesting prompts, fear-based extortion,
financial coercion, impersonation keywords, and linguistic anomalies.
"""

import re

# Threat vector dictionaries with category weights
HEURISTIC_PATTERNS = {
    "urgency": {
        "weight": 0.35,
        "patterns": [
            r"\b(?:within\s+(?:24|12|48|2|6)\s*(?:hours|hrs|minutes|mins))\b",
            r"\b(?:immediate(?:ly)?\s+(?:action\s+)?required)\b",
            r"\b(?:urgent(?:ly)?\s+required)\b",
            r"\b(?:account\s+(?:will\s+be\s+)?suspended)\b",
            r"\b(?:permanently\s+(?:deleted|terminated|disabled|closed))\b",
            r"\b(?:act\s+now|respond\s+immediately)\b",
            r"\b(?:final\s+notice|last\s+warning)\b",
            r"\b(?:time\s+sensitive|deadline\s+approaching)\b",
            r"\b(?:failure\s+to\s+comply|fail\s+to\s+verify)\b",
            r"\b(?:unauthorized\s+access\s+detected)\b",
            r"\b(?:unusual\s+sign-?in\s+activity)\b"
        ]
    },
    "credential_harvesting": {
        "weight": 0.40,
        "patterns": [
            r"\b(?:verify\s+(?:your\s+)?(?:account|identity|password|credentials|email))\b",
            r"\b(?:confirm\s+(?:your\s+)?(?:password|pin|security\s+questions|ssn))\b",
            r"\b(?:log\s*in\s+to\s+(?:validate|restore|unlock|claim))\b",
            r"\b(?:click\s+(?:here|below)\s+to\s+(?:verify|login|restore|authenticate))\b",
            r"\b(?:update\s+(?:your\s+)?(?:billing|payment|credit\s+card|details))\b",
            r"\b(?:reset\s+(?:your\s+)?password\s+now)\b",
            r"\b(?:re-?authenticate\s+your\s+session)\b",
            r"\b(?:restore\s+(?:full\s+)?access)\b"
        ]
    },
    "financial_coercion": {
        "weight": 0.35,
        "patterns": [
            r"\b(?:unpaid\s+invoice|overdue\s+payment|outstanding\s+balance)\b",
            r"\b(?:gift\s+cards?|apple\s+cards?|steam\s+cards?)\b",
            r"\b(?:wire\s+transfer|western\s+union|moneygram)\b",
            r"\b(?:bitcoin|btc|cryptocurrency|crypto\s+wallet)\b",
            r"\b(?:tax\s+refund|irs\s+audit|penalties\s+applied)\b",
            r"\b(?:lottery\s+winner|inheritance|million\s+dollars|beneficiary)\b",
            r"\b(?:charge(?:d)?\s+\$\d+(?:\.\d{2})?)\b",
            r"\b(?:auto-?renewal\s+processed)\b",
            r"\b(?:claim\s+your\s+(?:prize|reward|refund))\b"
        ]
    },
    "brand_impersonation": {
        "weight": 0.30,
        "patterns": [
            r"\b(?:paypal\s+(?:security|team|support|service))\b",
            r"\b(?:microsoft\s+(?:365|office|security|account))\b",
            r"\b(?:apple\s+id\s+(?:security|support|locked))\b",
            r"\b(?:netflix\s+(?:support|billing|account))\b",
            r"\b(?:amazon\s+(?:order|security|fraud\s+dept))\b",
            r"\b(?:geek\s+squad|best\s+buy\s+renewal)\b",
            r"\b(?:dhl\s+express|fedex\s+tracking|usps\s+delivery)\b",
            r"\b(?:bank\s+of\s+america|chase\s+fraud|wells\s+fargo)\b",
            r"\b(?:docusign\s+envelope|review\s+document)\b",
            r"\b(?:meta\s+business|facebook\s+copyright)\b"
        ]
    },
    "generic_greetings": {
        "weight": 0.15,
        "patterns": [
            r"\b(?:dear\s+customer)\b",
            r"\b(?:dear\s+user)\b",
            r"\b(?:dear\s+client)\b",
            r"\b(?:dear\s+member)\b",
            r"\b(?:dear\s+sir\s*/?\s*madam)\b",
            r"\b(?:attention\s+(?:valued\s+)?customer)\b",
            r"\b(?:hello\s+undisclosed-?recipients)\b"
        ]
    }
}

class HeuristicAnalyzer:
    def __init__(self):
        self.compiled_rules = {}
        for category, data in HEURISTIC_PATTERNS.items():
            self.compiled_rules[category] = {
                "weight": data["weight"],
                "regexes": [re.compile(p, re.IGNORECASE) for p in data["patterns"]]
            }

    def analyze(self, text: str) -> dict:
        """
        Scans text for psychological manipulation tactics, urgency,
        brand targeting, and credential prompts.
        """
        if not text:
            return {
                "heuristic_score": 0.0,
                "detected_categories": [],
                "highlights": [],
                "anomalies": []
            }

        detected_categories = {}
        highlights = []
        anomalies = []

        total_weighted_score = 0.0

        for category, info in self.compiled_rules.items():
            category_matches = []
            for regex in info["regexes"]:
                for match in regex.finditer(text):
                    category_matches.append({
                        "phrase": match.group(0),
                        "start": match.start(),
                        "end": match.end(),
                        "category": category
                    })
                    highlights.append({
                        "phrase": match.group(0),
                        "category": category,
                        "span": [match.start(), match.end()]
                    })

            if category_matches:
                # Multi-match weight accumulation
                count = len(category_matches)
                factor = min(1.25, 0.75 + (0.20 * count))
                cat_score = info["weight"] * factor
                total_weighted_score += cat_score
                detected_categories[category] = {
                    "count": count,
                    "score": round(cat_score, 3),
                    "examples": [m["phrase"] for m in category_matches[:3]]
                }

        # Check stylistic anomalies (Caps lock screaming, multiple exclamation marks)
        caps_words = re.findall(r'\b[A-Z]{4,}\b', text)
        filtered_caps = [w for w in caps_words if w not in {"HTTP", "HTTPS", "HTML", "JSON", "REST", "IMAP", "SMTP", "DKIM", "DMARC", "SPF"}]
        if len(filtered_caps) >= 3:
            total_weighted_score += 0.10
            anomalies.append(f"Excessive capitalized shout-words ({len(filtered_caps)} found: {', '.join(filtered_caps[:4])})")

        exclamation_count = len(re.findall(r'!{2,}', text))
        if exclamation_count >= 1:
            total_weighted_score += 0.08
            anomalies.append("Multiple aggressive exclamation marks detected ('!!')")

        normalized_score = min(1.0, round(total_weighted_score, 2))

        return {
            "heuristic_score": normalized_score,
            "detected_categories": detected_categories,
            "highlights": highlights,
            "anomalies": anomalies
        }

heuristic_analyzer = HeuristicAnalyzer()
