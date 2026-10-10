"""
CyberGuard QR Analyzer Service
Analyses decoded QR content for security indicators.

Exact scoring logic from the original main.py, moved into a reusable
service function.  Adds ``confidence`` and ``analysis_engine`` fields
while keeping every original field the frontend already expects.
"""

from __future__ import annotations

import re

from app.schemas import QRRequest, QRResponse
from app.services.risk_engine import build_analysis_result


# ------------------------------------------------------------------ #
# Keyword lists
# ------------------------------------------------------------------ #

SUSPICIOUS_KEYWORDS_QR = [
    "login",
    "verify",
    "verification",
    "account",
    "secure",
    "password",
    "update",
    "wallet",
    "claim",
    "bonus",
    "free",
    "gift",
    "otp",
    "payment",
]

QR_SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "cutt.ly",
    "shorturl.at",
]

DOWNLOAD_KEYWORDS = [
    "download",
    ".apk",
    "install",
    "app-download",
    "play.google.com",
    "apps.apple.com",
]

CREDENTIAL_KEYWORDS = [
    "password",
    "passwd",
    "username",
    "credential",
    "otp",
    "cvv",
    "pin",
    "card number",
]

URGENCY_KEYWORDS = [
    "urgent",
    "immediately",
    "act now",
    "limited time",
    "expires",
    "final warning",
    "verify now",
]


# ------------------------------------------------------------------ #
# Content-type classifier
# ------------------------------------------------------------------ #

def classify_qr_content(content: str) -> str:
    """
    Return a human-readable content type label for *content*.
    """
    text = content.strip()

    if text.lower().startswith("upi://"):
        return "UPI Payment QR"
    if text.lower().startswith("wifi:"):
        return "Wi-Fi Configuration"
    if text.lower().startswith("mailto:"):
        return "Email Address"
    if text.lower().startswith("tel:"):
        return "Phone Number"
    if text.lower().startswith("smsto:") or text.lower().startswith("sms:"):
        return "SMS Message"
    if re.match(r"^https?://", text, re.IGNORECASE):
        return "Website URL"
    if text.lower().startswith("www."):
        return "Website URL"
    if re.search(r"\.apk$", text, re.IGNORECASE) or "play.google.com" in text.lower():
        return "App Download Link"
    if len(text) > 200:
        return "Long Text"
    return "Text"


# ------------------------------------------------------------------ #
# Service function
# ------------------------------------------------------------------ #

def analyse_qr(request: QRRequest) -> QRResponse:
    """
    Analyse *request.content* for security indicators.

    Scoring (max 100):
        +10  QR contains a website URL
        +35  URL contains sensitive/phishing keywords
        +20  QR URL uses HTTP instead of HTTPS
        +25  URL shortener detected
        +30  IP address in URL
        +15  @ character in URL
        +10  Payment-related content
        +15  App / download link
        +30  Credential / sensitive-information request
        +15  Urgency / pressure language
    """
    content = request.content.strip()

    if not content:
        return QRResponse(
            success=False,
            content_type="Unknown",
            decoded_content="",
            score=0,
            risk="LOW",
            indicators=["QR content is required."],
            recommendation="Please upload a QR code image or enter its content.",
        )

    text = content.lower()
    indicators: list[str] = []
    score = 0

    # ---- Content type classification ---------------------------------
    content_type = classify_qr_content(content)

    # ---- URL analysis ------------------------------------------------
    is_url = bool(re.match(r"^https?://", text) or text.startswith("www."))

    if is_url:
        score += 10
        indicators.append("QR code contains a website URL.")

        # Sensitive keywords
        found_keywords = [
            kw for kw in SUSPICIOUS_KEYWORDS_QR if kw in text
        ]
        if found_keywords:
            kw_score = min(len(found_keywords) * 7, 35)
            score += kw_score
            indicators.append(
                "URL contains potentially sensitive / phishing-related keywords: "
                + ", ".join(found_keywords)
            )

        # HTTP vs HTTPS
        if text.startswith("http://"):
            score += 20
            indicators.append(
                "QR destination uses HTTP instead of HTTPS."
            )

        # URL shorteners
        found_shortener = None
        for shortener in QR_SHORTENERS:
            if shortener in text:
                found_shortener = shortener
                break
        if found_shortener:
            score += 25
            indicators.append(
                f"URL shortener detected: {found_shortener}"
            )

        # IP address
        ip_pattern = r"https?://(?:\d{1,3}\.){3}\d{1,3}"
        if re.search(ip_pattern, text):
            score += 30
            indicators.append(
                "QR destination uses an IP address instead of a normal domain."
            )

        # @ symbol
        if "@" in text:
            score += 15
            indicators.append("URL contains an @ character.")

    # ---- Payment QR --------------------------------------------------
    if text.startswith("upi://"):
        indicators.append("UPI payment QR detected.")
        score += 10

    found_payment = False
    for kw in ["upi://", "pay?", "pa=", "upi", "payment", "merchant"]:
        if kw in text:
            found_payment = True
            break
    if found_payment and "UPI payment QR detected." not in indicators:
        indicators.append("Payment-related QR content detected.")
        score += 10

    # ---- App / download ----------------------------------------------
    found_downloads = [kw for kw in DOWNLOAD_KEYWORDS if kw in text]
    if found_downloads:
        score += 15
        indicators.append(
            "Application / download-related content detected."
        )

    # ---- Credential request ------------------------------------------
    found_credentials = [kw for kw in CREDENTIAL_KEYWORDS if kw in text]
    if found_credentials:
        score += 30
        indicators.append(
            "Credential or sensitive-information request detected."
        )

    # ---- Urgency / social engineering --------------------------------
    found_urgency = [kw for kw in URGENCY_KEYWORDS if kw in text]
    if found_urgency:
        score += 15
        indicators.append("Urgency or pressure language detected.")

    # ---- Build result ------------------------------------------------
    result = build_analysis_result(
        score=score,
        indicators=indicators,
        engine_name="CyberGuard QR Security Engine v2",
        confidence=75,
    )

    return QRResponse(
        success=True,
        content_type=content_type,
        decoded_content=content,
        **result,
    )
