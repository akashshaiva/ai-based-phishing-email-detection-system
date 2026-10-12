"""
End-to-End Test Suite for AI Phishing Email Detection System.
Tests ML classifier, URL typosquatting, Heuristics, Header forensics, and Screenshot Image Analysis.
"""

import sys
import os
import base64

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "backend"))

from detector.ml_model import ml_classifier
from detector.url_analyzer import url_analyzer
from detector.heuristics import heuristic_analyzer
from detector.header_analyzer import header_analyzer
from detector.ocr_vision import screenshot_analyzer
from detector.orchestrator import threat_orchestrator

def run_tests():
    print("=== 1. Testing ML Model Classifier ===")
    phish_text = "Urgent: Your account is suspended. Verify password immediately within 24 hours at http://verify-paypal.xyz"
    legit_text = "Hi team, please find attached the meeting minutes for sprint planning."
    
    p_pred = ml_classifier.predict(phish_text)
    l_pred = ml_classifier.predict(legit_text)
    print(f"Phishing Text ML Probability: {p_pred['probability']} (Phish: {p_pred['is_phishing']})")
    print(f"Legit Text ML Probability: {l_pred['probability']} (Phish: {l_pred['is_phishing']})")
    assert p_pred['probability'] > l_pred['probability'], "ML prediction failed to differentiate phishing vs legitimate!"

    print("\n=== 2. Testing URL Typosquatting & Threat Analysis ===")
    typo_url = "http://paypa1-security-verification.xyz/webscr/login?verify=true"
    url_res = url_analyzer.analyze_single_url(typo_url)
    print(f"URL: {typo_url}")
    print(f"Risk Score: {url_res['risk_score']}, Risk Level: {url_res['risk_level']}")
    print(f"Reasons: {url_res['reasons']}")
    assert url_res['risk_score'] >= 0.7, "URL Typosquatting detection score should be high!"

    print("\n=== 3. Testing Heuristics & Linguistic Urgency ===")
    heur_res = heuristic_analyzer.analyze("URGENT: Immediate action required within 24 hours or account suspended permanently!")
    print(f"Heuristics Score: {heur_res['heuristic_score']}")
    print(f"Detected Categories: {list(heur_res['detected_categories'].keys())}")
    assert heur_res['heuristic_score'] >= 0.4, "Urgency heuristics score should trigger!"

    print("\n=== 4. Testing Header Forensics ===")
    header_res = header_analyzer.analyze(
        sender="PayPal Resolution Center <service@paypa1-security.xyz>",
        reply_to="attacker@gmail.com",
        raw_headers="Received-SPF: fail\nDKIM-Signature: fail"
    )
    print(f"Header Risk Score: {header_res['header_risk_score']}")
    print(f"Flags: {[f['message'] for f in header_res['flags']]}")
    assert header_res['header_risk_score'] >= 0.6, "Header risk should be high for spoofed brand!"

    print("\n=== 5. Testing Screenshot Image Processing ===")
    screenshot_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend", "assets", "sample_phishing_screenshot.png")
    with open(screenshot_path, "rb") as f:
        img_bytes = f.read()

    img_res = screenshot_analyzer.process_screenshot(
        image_bytes=img_bytes,
        client_ocr_text="URGENT SECURITY ALERT: PAYPAL ACCOUNT TEMPORARILY SUSPENDED. FAILURE TO VERIFY WITHIN 24 HOURS WILL RESULT IN TERMINATION. http://paypa1-security.xyz/webscr/login"
    )
    print(f"Screenshot Process Success: {img_res['success']}")
    print(f"Visual Flags: {img_res['visuals']}")
    assert img_res['success'], "Screenshot processing should succeed!"
    assert img_res['visuals']['has_urgent_red_banner'], "Urgent red banner should be detected in screenshot!"

    print("\n=== 6. Testing Full Threat Orchestrator ===")
    final_report = threat_orchestrator.analyze_email(
        body_text=img_res['extracted_text'],
        subject="URGENT: PayPal Account Suspended",
        sender="PayPal Support <service@paypa1-security.xyz>",
        visual_metadata=img_res['visuals']
    )
    print(f"Final Verdict: {final_report['verdict']}")
    print(f"Total Risk Score: {final_report['risk_score']}%")
    print(f"Threat Flags Count: {len(final_report['threat_flags'])}")
    print(f"Recommendations Count: {len(final_report['recommendations'])}")
    assert final_report['verdict'] == "HIGH RISK PHISHING", "Final verdict should be HIGH RISK PHISHING!"

    print("\n>>> ALL TEST SUITES PASSED FLAWLESSLY! <<<")

if __name__ == "__main__":
    run_tests()
