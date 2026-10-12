"""
Machine Learning Classifier for Phishing Email Detection.
Uses TF-IDF Vectorization with an optimized classifier trained on
a curated corpus of phishing and legitimate emails.
"""

import os
import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models")
MODEL_PATH = os.path.join(MODEL_DIR, "phishing_model.joblib")

# Curated training data covering diverse phishing vectors and legitimate corporate/personal emails
TRAINING_DATA = [
    # --- PHISHING SAMPLES ---
    ("Urgent: Your PayPal account has been limited due to suspicious activity. Click here to verify your identity and restore access immediately or your funds will be frozen within 24 hours.", 1),
    ("Security Alert: We detected an unauthorized login to your Microsoft 365 account from Russia. Please reset your password immediately at http://login-microsoft365-verify.com to prevent termination.", 1),
    ("Dear customer, your Netflix subscription payment failed. Your account will be cancelled today unless you update your credit card details now: http://netflix-billing-update.cc/verify", 1),
    ("Your package delivery from DHL could not be completed due to missing address info. Pay $2.99 customs fee at http://dhl-express-tracking-parcel.top/pay to reschedule delivery.", 1),
    ("FINAL NOTICE: Your Amazon account has been locked. Unusual orders of $949.99 iPhone 15 Pro Max detected. If you did not place this order, cancel immediately at http://amazon-dispute-order.xyz", 1),
    ("Internal Memo from CEO: Are you at your desk right now? I need you to purchase 5 Apple gift cards for the client presentation today. Please send codes directly to my personal email.", 1),
    ("Bank of America: We detected a suspicious debit of $1,250.00. If this was not you, confirm your card details and SSN at http://bofa-fraud-prevention.net/dispute to prevent further charges.", 1),
    ("HR Department: Please review your updated 2026 Employee Health Benefits and Salary Adjustment by logging in with your corporate credentials here: http://hr-portal-sso-login.site", 1),
    ("You have won $2,500,000.00 in the International Google Mega Lottery! To claim your inheritance prize, send your full name, passport, and bank account details to our claim agent.", 1),
    ("URGENT IT SERVICE DESK: Mailbox storage limit reached 99%. Your email will stop receiving new messages in 12 hours. Upgrade your quota here: http://webmail-storage-quota-upgrade.biz", 1),
    ("Apple Support: Your iCloud storage is full and your photos will be permanently deleted in 48 hours. Claim 50GB free by confirming your Apple ID and password at http://appleid-cloud-backup.info", 1),
    ("Geek Squad Renewal: Your auto-debit for Best Buy Geek Squad Lifetime Security Protection of $499.00 has been processed. If you want a refund, call +1-888-555-0199 or click http://geeksquad-refund.link", 1),
    ("DocuSign: Financial Controller sent you 'Q3 Tax Audit & Wire Agreement.pdf' to review and sign. View document now at http://docusign-secure-document-sign.me/auth", 1),
    ("IRS Tax Refund Notification: You are eligible to receive a tax refund of $1,420.50. Submit your tax refund claim form and direct deposit details at http://irs-tax-refund-portal.us", 1),
    ("Suspicious sign-in detected on your Google Account from unknown device in Moscow. Secure your account now before password change is finalized: http://google-account-recovery-sec.xyz", 1),
    ("ATTENTION: Unpaid invoice #88921 is overdue. Failure to settle balance within 2 hours will result in legal action by our collection agency. Download attachment or pay online at http://invoice-settlement.top", 1),
    ("Meta Facebook Security: Your page has violated copyright rules and will be permanently disabled in 24 hours. Submit an appeal to verify ownership: http://meta-business-appeal-case.cc", 1),
    ("Chase Online: Your account has been temporarily restricted for security reasons. Complete identity verification to unlock: http://chase-security-verify-id.link", 1),
    ("Dropbox: 3 confidential files have been shared with you by executive management. Sign in with your work email to decrypt: http://dropbox-shared-file-access.site", 1),
    ("Cryptocurrency Alert: 0.85 BTC transferred to your Binance wallet. Confirm receipt or dispute transaction at http://binance-wallet-transfer-verify.xyz", 1),

    # --- LEGITIMATE SAMPLES ---
    ("Hi Team, please find attached the meeting minutes from yesterday's product design sync. Let me know if you have any questions or items to add to next week's agenda.", 0),
    ("Your weekly GitHub digest: 14 pull requests merged, 3 issues closed in the repository main branch. Keep up the great work!", 0),
    ("Hey John, are we still meeting for lunch at 12:30 pm today at the cafe downstairs? Let me know if that time still works for you.", 0),
    ("Here is your receipt for your order #44921 from Amazon.com. Your item has shipped via UPS and estimated delivery is Thursday. Track your package in your Amazon orders dashboard.", 0),
    ("Invitation: Project Sprint Retrospective on Friday from 3:00 PM to 4:00 PM in Conference Room B. Google Meet video call link is included in your Google Calendar invite.", 0),
    ("Thanks for subscribing to the Python Weekly Newsletter! In this issue: high-performance async programming, best practices with FastAPI, and modern type annotations in Python 3.14.", 0),
    ("Your monthly electricity bill from City Power & Light for September is ready. Total amount due: $78.45. Auto-pay is scheduled for October 25th. No action is required.", 0),
    ("Hi Sarah, can you review the draft slides for the upcoming client presentation when you get a chance? I left comments on slide 4 and slide 9 for your input.", 0),
    ("Your flight reservation is confirmed. Flight AA1402 departs from JFK to LAX on Nov 15 at 8:15 AM. Check-in opens 24 hours prior to departure via the official American Airlines app.", 0),
    ("Welcome to our developer community! Check out our documentation, community forum guidelines, and join our Discord channel to connect with other engineers.", 0),
    ("Reminder: All-Hands company meeting scheduled for tomorrow at 10 AM EST. The CEO will share Q3 business results and answer questions submitted via the internal Slido board.", 0),
    ("Attached is the quarterly financial summary report prepared by the accounting team for internal leadership review. Please treat this document as confidential company data.", 0),
    ("Hi everyone, the office will be closed on Monday in observance of the public holiday. Please ensure any urgent customer support tickets are delegated before Friday evening.", 0),
    ("Your code review request for PR #108 'Fix CSS grid alignment on dashboard cards' has been approved by the tech lead. You may merge whenever ready.", 0),
    ("Thank you for attending the Web Security & Cyber Defense Webinar. Slides and recorded video have been uploaded to our learning portal for registered participants.", 0),
    ("Hey Alex, do you have a few minutes this afternoon for a quick 1-on-1 catch-up regarding the Q4 engineering roadmap? Let me know your availability.", 0),
    ("Your order confirmation from Starbucks: Iced Vanilla Latte and Blueberry Muffin. Thank you for using Starbucks Mobile Order & Pay.", 0),
    ("System notification: Your scheduled database maintenance backup completed successfully at 02:00 AM UTC. 0 errors detected across all replicas.", 0),
    ("Hi mom, just letting you know we landed safely in Chicago. Will call you once we get our luggage from the baggage claim. Love you!", 0),
    ("Spotify: Your favorite artist just released a new album. Listen now on Spotify and discover curated tracks matching your music taste.", 0)
]

class PhishingMLClassifier:
    def __init__(self):
        self.model = None
        self._load_or_train()

    def _train(self):
        texts = [item[0] for item in TRAINING_DATA]
        labels = [item[1] for item in TRAINING_DATA]

        pipeline = Pipeline([
            ('tfidf', TfidfVectorizer(
                ngram_range=(1, 2),
                sublinear_tf=True,
                token_pattern=r'(?u)\b\w+\b',
                max_features=4000
            )),
            ('clf', LogisticRegression(
                C=2.5,
                max_iter=1000,
                class_weight='balanced',
                random_state=42
            ))
        ])

        pipeline.fit(texts, labels)
        self.model = pipeline
        
        # Save model
        try:
            os.makedirs(MODEL_DIR, exist_ok=True)
            joblib.dump(self.model, MODEL_PATH)
        except Exception as e:
            print(f"[Warning] Could not persist ML model to disk: {e}")

    def _load_or_train(self):
        if os.path.exists(MODEL_PATH):
            try:
                self.model = joblib.load(MODEL_PATH)
                return
            except Exception as e:
                print(f"[Notice] Reloading/retraining ML model: {e}")
        self._train()

    def predict(self, text: str) -> dict:
        """
        Predict phishing likelihood for input text.
        Returns probability (0.0 - 1.0), label, and top keywords.
        """
        if not text or not text.strip():
            return {
                "probability": 0.0,
                "is_phishing": False,
                "confidence": 0.0,
                "salient_features": []
            }

        if self.model is None:
            self._load_or_train()

        proba = float(self.model.predict_proba([text])[0][1])
        is_phishing = proba >= 0.5

        # Extract salient terms if possible
        salient_features = []
        try:
            tfidf = self.model.named_steps['tfidf']
            clf = self.model.named_steps['clf']
            feature_names = np.array(tfidf.get_feature_names_out())
            coefs = clf.coef_[0]
            
            # Transform text
            vec = tfidf.transform([text]).toarray()[0]
            active_indices = np.where(vec > 0)[0]
            if len(active_indices) > 0:
                # Rank features by coef * tfidf
                impacts = coefs[active_indices] * vec[active_indices]
                top_indices = active_indices[np.argsort(impacts)[::-1][:6]]
                for idx in top_indices:
                    term = feature_names[idx]
                    weight = float(coefs[idx])
                    if weight > 0:
                        salient_features.append({"term": term, "weight": round(weight, 3)})
        except Exception:
            pass

        return {
            "probability": round(proba, 4),
            "is_phishing": is_phishing,
            "confidence": round(abs(proba - 0.5) * 2, 4),
            "salient_features": salient_features
        }

# Global singleton
ml_classifier = PhishingMLClassifier()
