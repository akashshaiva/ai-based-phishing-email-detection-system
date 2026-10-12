"""
Screenshot & Image Analysis Engine.
Handles OCR extraction from email screenshots, visual manipulation cues,
QR code detection (quishing), and optional Multimodal Gemini Vision analysis.
"""

import os
import io
import re
import base64
import requests
from PIL import Image, ImageStat

# Try importing pytesseract
try:
    import pytesseract
    PYTESSERACT_AVAILABLE = True
except ImportError:
    PYTESSERACT_AVAILABLE = False

class ScreenshotAnalyzer:
    def __init__(self):
        self.tesseract_available = PYTESSERACT_AVAILABLE

    def extract_text_pytesseract(self, image: Image.Image) -> tuple[str, float]:
        """Attempts OCR with local pytesseract if installed."""
        if not self.tesseract_available:
            return "", 0.0
        try:
            # Convert to RGB / Grayscale
            gray = image.convert('L')
            text = pytesseract.image_to_string(gray)
            return text.strip(), 0.85
        except Exception as e:
            # Tesseract binary might not be in PATH
            return "", 0.0

    def analyze_image_visuals(self, image: Image.Image) -> dict:
        """
        Extracts visual cues from email screenshots:
        - Dominant color palettes and high-urgency red/amber alert banners
        - Aspect ratio (vertical typical of email client vs square)
        - Potential QR code presence (quishing)
        """
        width, height = image.size
        aspect_ratio = round(height / max(1, width), 2)
        
        # Color statistics
        stat = ImageStat.Stat(image)
        mean_colors = stat.mean[:3] if len(stat.mean) >= 3 else [128, 128, 128]

        # Check for prominent emergency red / urgent alert coloring
        # In RGB: High R, significantly lower G and B in horizontal banner strips
        has_urgent_red_banner = False
        try:
            # Check horizontal slices across the top 35% of the image
            scan_limit = max(10, int(height * 0.35))
            step = 25
            for y in range(0, scan_limit, step):
                slice_crop = image.crop((0, y, width, min(height, y + step)))
                sr, sg, sb = ImageStat.Stat(slice_crop).mean[:3]
                if sr > 135 and (sr > sg + 35 and sr > sb + 35):
                    has_urgent_red_banner = True
                    break
        except Exception:
            pass

        # Basic Quishing / QR check heuristic:
        # High contrast black-and-white square clusters in lower half
        possible_qr_code = False
        try:
            small = image.resize((100, 100)).convert('L')
            std_dev = ImageStat.Stat(small).stddev[0]
            # QR codes typically produce very high local standard deviation
            if std_dev > 75:
                possible_qr_code = True
        except Exception:
            pass

        return {
            "resolution": f"{width}x{height}",
            "aspect_ratio": aspect_ratio,
            "has_urgent_red_banner": has_urgent_red_banner,
            "possible_qr_code": possible_qr_code,
            "visual_risk_contribution": 0.20 if has_urgent_red_banner else 0.0
        }

    def analyze_with_gemini_vision(self, image_bytes: bytes, api_key: str, mime_type: str = "image/png") -> dict:
        """
        Calls Gemini Multimodal API if an API key is provided for deep vision inspection.
        """
        if not api_key:
            return None

        endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
        encoded_image = base64.b64encode(image_bytes).decode('utf-8')

        prompt = (
            "Analyze this email screenshot for cybersecurity phishing threats. "
            "Examine visual logos, domain names, sender display mismatches, fake urgent buttons, "
            "and visual deception tricks. "
            "Respond in JSON format with: "
            "{\"is_phishing\": true|false, \"confidence_score\": 0.0-1.0, \"spoofed_brand\": string|null, "
            "\"visual_red_flags\": [string], \"extracted_summary\": string, \"verdict\": string}"
        )

        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": prompt},
                        {
                            "inline_data": {
                                "mime_type": mime_type,
                                "data": encoded_image
                            }
                        }
                    ]
                }
            ],
            "generationConfig": {
                "temperature": 0.2,
                "response_mime_type": "application/json"
            }
        }

        try:
            resp = requests.post(endpoint, json=payload, timeout=20)
            if resp.status_code == 200:
                data = resp.json()
                text_response = data["candidates"][0]["content"]["parts"][0]["text"]
                import json
                parsed = json.loads(text_response)
                return parsed
        except Exception as e:
            print(f"[Gemini Vision Error]: {e}")

        return None

    def process_screenshot(
        self,
        image_bytes: bytes,
        client_ocr_text: str = "",
        gemini_api_key: str = "",
        mime_type: str = "image/png"
    ) -> dict:
        """
        Complete processing pipeline for email screenshots.
        Combines local OCR, client browser OCR, visual heuristics, and optional LLM vision.
        """
        try:
            image = Image.open(io.BytesIO(image_bytes))
        except Exception as e:
            return {
                "success": False,
                "error": f"Invalid image format: {str(e)}",
                "extracted_text": "",
                "visuals": {}
            }

        visual_info = self.analyze_image_visuals(image)

        # Determine best extracted text
        extracted_text = ""
        ocr_source = "none"

        # 1. Check if client browser provided high-accuracy Tesseract.js OCR text
        if client_ocr_text and client_ocr_text.strip():
            extracted_text = client_ocr_text.strip()
            ocr_source = "client_tesseract_js"
        else:
            # 2. Fall back to local pytesseract if available
            local_text, conf = self.extract_text_pytesseract(image)
            if local_text:
                extracted_text = local_text
                ocr_source = "backend_pytesseract"

        # 3. Optional Gemini Multimodal Vision analysis
        gemini_analysis = None
        if gemini_api_key:
            gemini_analysis = self.analyze_with_gemini_vision(image_bytes, gemini_api_key, mime_type)

        return {
            "success": True,
            "extracted_text": extracted_text,
            "ocr_source": ocr_source,
            "visuals": visual_info,
            "gemini_vision": gemini_analysis
        }

screenshot_analyzer = ScreenshotAnalyzer()
