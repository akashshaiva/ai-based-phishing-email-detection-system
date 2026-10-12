# PhishShield AI — AI-Based Phishing Email Detection & Screenshot Analysis System

An enterprise-grade, multimodal cybersecurity application designed to detect and dissect phishing emails in real time. **PhishShield AI** combines Machine Learning NLP classification, optical character recognition (OCR) of email screenshots, domain typosquatting intelligence, email header forensics, and psychological coercion analysis into a unified Cyber SOC dashboard.

---

## Key Highlights & Features

### 1. 📸 Screenshot & Screen Capture Analysis (Core Feature)
- **Live Screen Capture**: Capture your active email window (Outlook, Gmail, Thunderbird, browser tab) with one click using the built-in browser capture tool (`getDisplayMedia`).
- **Direct Clipboard Paste**: Simply press **`Ctrl + V`** anywhere on the dashboard to immediately analyze a copied screenshot.
- **Drag-and-Drop & File Upload**: Inspect PNG, JPG, and WEBP email screenshots.
- **In-Browser Client OCR (Tesseract.js)**: 100% self-contained client-side optical character recognition that extracts text, URLs, and headers directly in your browser without requiring external binaries.
- **Visual Deception Detection**: Detects urgent red alert banners, fake security dialogs, and Quishing (QR code phishing).
- **Optional Gemini Multimodal Vision**: Optionally input your Google Gemini API key to enable multimodal generative AI analysis for brand logo spoofing.

### 2. ✉️ Email Text & Header Forensics
- **NLP ML Classifier**: Pre-trained TF-IDF vectorizer + Logistic Regression ensemble model for instant scoring of linguistic phishing patterns.
- **Sender Spoofing & Header Analysis**: Detects display name impersonation (e.g., display name "PayPal Support" with an unauthorized sender address), Reply-To discrepancies, and SPF/DKIM/DMARC status.
- **Psychological Trigger Scoring**: Identifies urgency vectors (*"within 24 hours"*, *"account suspended"*), financial extortion, credential traps, and generic salutations.

### 3. 🔗 Deep URL & Domain Inspector
- **Brand Typosquatting Engine**: Detects homoglyph substitutions and Levenshtein edit distances targeting brands like PayPal, Microsoft, Google, Apple, Amazon, Netflix, Chase, Bank of America, etc. (e.g., `paypa1-security.xyz`).
- **Suspicious TLD & Host Detection**: Flags high-risk TLDs (`.xyz`, `.top`, `.buzz`, `.cc`, etc.), raw IP hostnames, URL shorteners, and excessive subdomains.
- **Anchor Mismatch Alert**: Exposes hyperlinks where the displayed text disguises a different destination URL.

### 4. 📊 Cyber SOC Threat Intelligence Console
- **Dynamic Risk Gauge**: Radial SVG meter (0–100%) with animated color shifts (Safe, Suspicious, High Risk Phishing).
- **Multi-Vector Risk Breakdown**: Separate rating bars for Machine Learning, URL Risk, Urgency Heuristics, Header Integrity, and Visual Anomalies.
- **Interactive Highlight Viewer**: Highlights detected threat phrases directly in the email text.
- **Actionable Incident Defense Protocol**: Immediate security guidance for recipients and SOC analysts.
- **Incident Export**: Export full threat intelligence reports to JSON or Print to PDF.
- **Audit Scan History**: View previous scans in an interactive slide-out drawer.

---

## Project Structure

```
ai based phishing email detection system/
│
├── backend/
│   ├── detector/
│   │   ├── ml_model.py            # TF-IDF + Classifier trained on phishing corpora
│   │   ├── url_analyzer.py        # Typosquatting, TLDs, IP hosts, & link security
│   │   ├── heuristics.py          # Urgency, fear, & credential pattern engine
│   │   ├── header_analyzer.py     # Display name spoofing & SPF/DKIM validation
│   │   ├── ocr_vision.py          # Screenshot OCR & visual feature processor
│   │   ├── orchestrator.py        # Multi-factor calibrated risk fusion engine
│   │   └── samples.py             # Preloaded real-world phishing & legit samples
│   ├── models/                    # Serialized machine learning models (.joblib)
│   ├── main.py                    # FastAPI application & REST endpoints
│   ├── generate_test_screenshot.py # Generator for mock phishing email screenshot
│   └── test_detection_engine.py   # Comprehensive automated test suite
│
├── frontend/
│   ├── index.html                 # Modern Cyber SOC dashboard interface
│   ├── css/
│   │   └── style.css              # Dark mode, glassmorphism, & responsive styles
│   ├── js/
│   │   └── app.js                 # Screen capture, clipboard paste, OCR, & UI logic
│   └── assets/                    # Assets and sample screenshot
│
├── run.bat                        # 1-click Windows batch startup script
├── run.ps1                        # 1-click Windows PowerShell startup script
├── requirements.txt               # Backend Python dependencies
└── README.md                      # Documentation & Architecture Guide
```

---

## Quick Start Guide

### Option 1: 1-Click Launch (Windows)
Double-click `run.bat` or run:
```cmd
run.bat
```
This script will verify Python, install any missing dependencies from `requirements.txt`, launch the server, and open `http://127.0.0.1:8000` in your default browser.

### Option 2: PowerShell
```powershell
.\run.ps1
```

### Option 3: Manual Terminal Startup
1. **Install dependencies:**
   ```bash
   python -m pip install -r requirements.txt
   ```
2. **Start the backend server:**
   ```bash
   python -m uvicorn main:app --host 127.0.0.1 --port 8000 --app-dir backend --reload
   ```
3. **Open the web application:**
   Navigate to [http://127.0.0.1:8000](http://127.0.0.1:8000) in your browser.

---

## How to Test the Screenshot Feature

1. Open [http://127.0.0.1:8000](http://127.0.0.1:8000).
2. Go to the **"Screenshot & Image"** tab.
3. Test using any of the following 3 methods:
   - **Method A (Live Screen Capture)**: Click `Live Screen Capture` and select your Outlook, Gmail, or web window.
   - **Method B (Clipboard Paste)**: Take a screenshot with `Win + Shift + S`, click anywhere on the page, and press **`Ctrl + V`**.
   - **Method C (Drag & Drop)**: Drag `frontend/assets/sample_phishing_screenshot.png` directly onto the dropzone.
4. Watch the OCR progress bar extract the text and click **"Analyze Screenshot for Phishing"**.
5. Inspect the generated Threat Intelligence Report!

---

## Automated Test Suite

To verify all detection engines (ML, URL, Heuristics, Header forensics, and Screenshot OCR):
```bash
python backend/test_detection_engine.py
```

Expected output:
```
=== 1. Testing ML Model Classifier ===
Phishing Text ML Probability: 0.7093 (Phish: True)
Legit Text ML Probability: 0.3204 (Phish: False)

=== 2. Testing URL Typosquatting & Threat Analysis ===
URL: http://paypa1-security-verification.xyz/webscr/login?verify=true
Risk Score: 0.85, Risk Level: High

=== 3. Testing Heuristics & Linguistic Urgency ===
Heuristics Score: 0.44

=== 4. Testing Header Forensics ===
Header Risk Score: 1.0

=== 5. Testing Screenshot Image Processing ===
Screenshot Process Success: True
Visual Flags: {'has_urgent_red_banner': True, ...}

=== 6. Testing Full Threat Orchestrator ===
Final Verdict: HIGH RISK PHISHING
Total Risk Score: 100.0%

>>> ALL TEST SUITES PASSED FLAWLESSLY! <<<
```

---

## API Endpoints

- `GET /` — Serves the Cyber SOC web dashboard.
- `POST /api/analyze/text` — Analyzes raw email text, subject, sender, and headers.
- `POST /api/analyze/image-base64` — Analyzes base64 screenshot images (captured or pasted).
- `POST /api/analyze/image` — Analyzes multipart uploaded screenshot images.
- `POST /api/analyze/url` — Deep-scans an individual URL for typosquatting and threats.
- `GET /api/samples` — Returns the library of preloaded real-world attack samples.
- `GET /api/history` — Returns recent audit scan logs.
- `GET /api/health` — Engine health and capabilities status.
- `GET /docs` — Interactive OpenAPI / Swagger UI.
