"""
Core Orchestration & Multi-Layer Fusion Engine.
Synthesizes ML model probabilities, URL threats, linguistic heuristics,
email header forensics, and visual screenshot cues into an actionable Phishing Threat Intelligence Report.
"""

from .ml_model import ml_classifier
from .url_analyzer import url_analyzer
from .heuristics import heuristic_analyzer
from .header_analyzer import header_analyzer

class ThreatOrchestrator:
    def __init__(self):
        pass

    def generate_recommendations(self, verdict: str, flags: list[str], urls_info: dict) -> list[dict]:
        """Generates actionable mitigation advice for users and SOC analysts."""
        recommendations = []

        if verdict == "HIGH RISK PHISHING":
            recommendations.append({
                "action": "DO NOT CLICK OR DOWNLOAD",
                "details": "Avoid clicking any links, buttons, or opening attachments in this email.",
                "level": "critical"
            })
            recommendations.append({
                "action": "REPORT TO IT / SOC",
                "details": "Forward this message as an attachment to your security operations team or abuse desk.",
                "level": "critical"
            })
            recommendations.append({
                "action": "DO NOT DISCLOSE CREDENTIALS",
                "details": "Never enter your passwords, 2FA codes, or payment cards on unfamiliar portals.",
                "level": "high"
            })
        elif verdict == "SUSPICIOUS":
            recommendations.append({
                "action": "VERIFY OUT-OF-BAND",
                "details": "Contact the claimed sender directly through an official known phone number or verified website.",
                "level": "high"
            })
            recommendations.append({
                "action": "INSPECT DESTINATION URLS",
                "details": "Hover over hyperlinks to verify the true domain name before proceeding.",
                "level": "medium"
            })
        else:
            recommendations.append({
                "action": "PROCEED NORMALLY",
                "details": "No significant phishing markers detected. Standard security vigilance applies.",
                "level": "info"
            })

        if urls_info.get("anchor_mismatches"):
            recommendations.append({
                "action": "AVOID MISMATCHED HYPERLINKS",
                "details": "This email contains hyperlinks where the displayed text disguises a different destination.",
                "level": "critical"
            })

        return recommendations

    def analyze_email(
        self,
        body_text: str,
        subject: str = "",
        sender: str = "",
        reply_to: str = "",
        raw_headers: str = "",
        visual_metadata: dict = None,
        gemini_result: dict = None
    ) -> dict:
        """
        Runs comprehensive multi-factor phishing evaluation.
        """
        full_text = f"{subject}\n{body_text}".strip()

        # 1. Machine Learning Prediction
        ml_result = ml_classifier.predict(full_text)
        ml_score = ml_result["probability"]

        # 2. Heuristic Linguistic Analysis
        heuristic_result = heuristic_analyzer.analyze(full_text)
        heur_score = heuristic_result["heuristic_score"]

        # 3. URL and Domain Security Scan
        url_result = url_analyzer.analyze_all(full_text)
        url_score = url_result["url_threat_score"]

        # 4. Sender & Header Forensics
        header_result = header_analyzer.analyze(sender, reply_to, raw_headers)
        header_score = header_result["header_risk_score"]

        # 5. Visual Cue Integration (if from screenshot)
        visual_score = 0.0
        visual_flags = []
        if visual_metadata:
            visual_score = visual_metadata.get("visual_risk_contribution", 0.0)
            if visual_metadata.get("has_urgent_red_banner"):
                visual_flags.append("High-urgency red/amber visual warning banner detected")
            if visual_metadata.get("possible_qr_code"):
                visual_flags.append("High contrast 2D matrix detected: possible Quishing (QR Phishing) threat")

        # 6. Gemini Multimodal Overwrite/Boost (if available)
        gemini_boost = 0.0
        if gemini_result and isinstance(gemini_result, dict):
            if gemini_result.get("is_phishing"):
                gemini_boost = gemini_result.get("confidence_score", 0.85)

        # Unified Weighted Fusion
        # If URLs have severe typosquatting or headers have critical spoofing, elevate impact
        weights = {
            "ml": 0.30,
            "url": 0.30 if url_result["total_urls_found"] > 0 else 0.10,
            "heuristics": 0.25,
            "header": 0.15 if sender else 0.05
        }
        
        # Normalize weights
        total_w = sum(weights.values())
        combined_score = (
            (ml_score * weights["ml"]) +
            (url_score * weights["url"]) +
            (heur_score * weights["heuristics"]) +
            (header_score * weights["header"])
        ) / total_w

        # Elevate score if critical triggers found
        has_critical_typosquat = any(
            u.get("domain_info", {}).get("typosquat_risk", 0) > 0.8 for u in url_result.get("urls", [])
        )
        has_anchor_spoof = len(url_result.get("anchor_mismatches", [])) > 0
        has_header_impersonation = any(f["severity"] == "CRITICAL" for f in header_result.get("flags", []))

        if has_critical_typosquat or has_anchor_spoof or has_header_impersonation:
            combined_score = max(combined_score, 0.82)

        # Incorporate visual score
        combined_score = min(1.0, combined_score + visual_score)

        if gemini_boost > 0:
            combined_score = max(combined_score, gemini_boost)

        risk_percent = round(combined_score * 100, 1)

        # Verdict assignment
        if risk_percent >= 65.0:
            verdict = "HIGH RISK PHISHING"
            badge_color = "danger"
            summary_statement = "Severe phishing threat detected. This email exhibits strong malicious indicators designed to deceive the recipient."
        elif risk_percent >= 30.0:
            verdict = "SUSPICIOUS"
            badge_color = "warning"
            summary_statement = "Suspicious markers found. Exercise caution and independently verify the sender's request."
        else:
            verdict = "LEGITIMATE / SAFE"
            badge_color = "success"
            summary_statement = "No notable phishing indicators detected. The email appears standard."

        # Compile overall threat flags list
        threat_flags = []
        if has_critical_typosquat:
            threat_flags.append("Domain Typosquatting / Brand Impersonation in Link")
        if has_anchor_spoof:
            threat_flags.append("Deceptive Hyperlink Anchor Mismatch")
        if has_header_impersonation:
            threat_flags.append("Display Name / Sender Domain Contradiction")
        for cat, data in heuristic_result["detected_categories"].items():
            threat_flags.append(f"Psychological Vector: {cat.replace('_', ' ').title()} ({data['count']} matches)")
        for flag in header_result["flags"]:
            threat_flags.append(flag["message"])
        for v_flag in visual_flags:
            threat_flags.append(v_flag)

        # Actionable recommendations
        recommendations = self.generate_recommendations(verdict, threat_flags, url_result)

        return {
            "verdict": verdict,
            "badge_color": badge_color,
            "risk_score": risk_percent,
            "summary_statement": summary_statement,
            "threat_breakdown": {
                "ml_probability": round(ml_score * 100, 1),
                "url_risk": round(url_score * 100, 1),
                "urgency_heuristics": round(heur_score * 100, 1),
                "header_risk": round(header_score * 100, 1),
                "visual_risk": round(visual_score * 100, 1)
            },
            "ml_analysis": ml_result,
            "heuristics": heuristic_result,
            "url_analysis": url_result,
            "header_analysis": header_result,
            "threat_flags": threat_flags,
            "recommendations": recommendations,
            "gemini_vision": gemini_result
        }

threat_orchestrator = ThreatOrchestrator()
