"""
CyberGuard Email Analyzer Service
Analyses email content for phishing and social-engineering indicators.

Exact scoring logic from the original main.py, moved into a reusable
service function.  Adds ``confidence`` and ``analysis_engine`` fields
while keeping every original field the frontend already expects.
"""

from __future__ import annotations

import re

from app.schemas import EmailRequest, EmailResponse
from app.services.risk_engine import build_analysis_result
from app.utils.validators import is_valid_email, extract_email_domain
from app.utils.helpers import escape_html


# ------------------------------------------------------------------ #
# Keyword lists
# ------------------------------------------------------------------ #

FREE_DOMAINS = [
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "proton.me",
]

PHISHING_KEYWORDS = [
    "verify",
    "verification",
    "urgent",
    "immediately",
    "password",
    "account suspended",
    "account blocked",
    "click here",
    "confirm",
    "login",
    "security alert",
    "payment",
    "bank",
    "otp",
    "refund",
    "winner",
    "prize",
    "claim",
    "limited time",
]

URGENCY_KEYWORDS = [
    "urgent",
    "immediately",
    "within 24 hours",
    "act now",
    "last warning",
    "final warning",
    "your account will be closed",
    "your account will be suspended",
]

CREDENTIAL_KEYWORDS = [
    "otp",
    "one time password",
    "cvv",
    "pin",
    "password",
    "credit card",
    "debit card",
]

ATTACHMENT_KEYWORDS = [
    "open attachment",
    "download attachment",
    "attached file",
    "invoice attached",
    "document attached",
]


# ------------------------------------------------------------------ #
# Service function
# ------------------------------------------------------------------ #

def analyse_email(request: EmailRequest) -> EmailResponse:
    """
    Analyse email fields for phishing indicators.

    Scoring (max 100):
        +20  Invalid sender format
        +5   Free email provider
        +min(len×6, 40)  Phishing keywords
        +15  URL(s) found in email
        +15  Urgency/pressure language
        +20  Credential/OTP requests
        +10  Suspicious attachment language
    """
    sender = request.sender.strip()
    subject = request.subject.strip()
    body = request.body.strip()

    if not sender and not subject and not body:
        return EmailResponse(
            success=False,
            score=0,
            risk="LOW",
            indicators=["Email information is required."],
            recommendation="Please provide sender, subject, or body content.",
        )

    combined = f"{sender} {subject} {body}"
    lower_text = combined.lower()

    indicators: list[str] = []
    score = 0

    # ---- Sender format -----------------------------------------------
    if sender and not is_valid_email(sender):
        score += 20
        indicators.append("Sender email format appears invalid.")

    # ---- Free email provider ------------------------------------------
    domain = extract_email_domain(sender) if sender else ""
    if domain in FREE_DOMAINS:
        score += 5
        indicators.append("Sender uses a common free email provider.")

    # ---- Phishing keywords --------------------------------------------
    found_keywords = [kw for kw in PHISHING_KEYWORDS if kw in lower_text]
    if found_keywords:
        kw_score = min(len(found_keywords) * 6, 40)
        score += kw_score
        indicators.append(
            "Potential phishing keywords detected: "
            + ", ".join(found_keywords)
        )

    # ---- URL detection ------------------------------------------------
    urls = re.findall(r"https?://[^\s]+", combined, re.IGNORECASE)
    if urls:
        score += 15
        indicators.append("Email contains clickable URL(s).")

    # ---- Urgency / pressure -------------------------------------------
    found_urgency = [kw for kw in URGENCY_KEYWORDS if kw in lower_text]
    if found_urgency:
        score += 15
        indicators.append("Urgency or pressure language detected.")

    # ---- Credential requests ------------------------------------------
    found_credentials = [
        kw for kw in CREDENTIAL_KEYWORDS if kw in lower_text
    ]
    if found_credentials:
        score += 20
        indicators.append(
            "Email may be requesting sensitive credentials or financial information."
        )

    # ---- Attachment language ------------------------------------------
    found_attachments = [
        kw for kw in ATTACHMENT_KEYWORDS if kw in lower_text
    ]
    if found_attachments:
        score += 10
        indicators.append(
            "Email references potentially sensitive attachments."
        )

    # ---- Build result -------------------------------------------------
    result = build_analysis_result(
        score=score,
        indicators=indicators,
        engine_name="CyberGuard Email Engine v2",
        confidence=65,
    )

    return EmailResponse(
        success=True,
        detected_urls=urls,
        **result,
    )
