"""
Generates a realistic mock email screenshot for testing OCR and visual phishing detection.
"""

import os
from PIL import Image, ImageDraw, ImageFont

def generate_sample_screenshot():
    width, height = 750, 480
    img = Image.new("RGB", (width, height), color="#ffffff")
    draw = ImageDraw.Draw(img)

    # 1. Draw urgent red alert banner at top
    draw.rectangle([0, 0, width, 55], fill="#dc2626")
    draw.text((25, 18), "URGENT SECURITY ALERT: PAYPAL ACCOUNT TEMPORARILY SUSPENDED", fill="#ffffff")

    # 2. Draw mock email client header
    draw.rectangle([0, 55, width, 140], fill="#f8fafc")
    draw.line([(0, 140), (width, 140)], fill="#e2e8f0", width=1)
    
    draw.text((25, 68), "From: PayPal Resolution Support <service-notice@paypa1-security.xyz>", fill="#334155")
    draw.text((25, 90), "To: user@company.com", fill="#64748b")
    draw.text((25, 112), "Subject: Final Notice: Immediate Action Required Within 24 Hours", fill="#0f172a")

    # 3. Draw email body
    body_lines = [
        "Dear Customer,",
        "",
        "We detected unauthorized sign-in attempts on your PayPal account from Moscow, Russia.",
        "For your security, your balance has been restricted and withdrawals are locked.",
        "",
        "FAILURE TO VERIFY WITHIN 24 HOURS WILL RESULT IN PERMANENT ACCOUNT TERMINATION.",
        "",
        "Please confirm your password, SSN, and debit card details immediately to restore access:",
        "http://paypa1-security.xyz/webscr/login?verify=true",
        "",
        "Thank you for choosing PayPal Identity Protection,",
        "Customer Security Team"
    ]

    y = 160
    for line in body_lines:
        color = "#b91c1c" if "FAILURE TO VERIFY" in line else ("#2563eb" if "http://" in line else "#1e293b")
        draw.text((25, y), line, fill=color)
        y += 22

    # 4. Draw mock verification CTA button
    btn_box = [25, y + 5, 260, y + 42]
    draw.rectangle(btn_box, fill="#0284c7")
    draw.text((45, y + 14), "VERIFY MY ACCOUNT NOW", fill="#ffffff")

    output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend", "assets")
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, "sample_phishing_screenshot.png")
    img.save(out_path)
    print(f"Generated sample email screenshot at: {out_path}")
    return out_path

if __name__ == "__main__":
    generate_sample_screenshot()
