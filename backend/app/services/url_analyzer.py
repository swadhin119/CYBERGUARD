"""
CyberGuard URL Analyzer Service
Analyses a URL for phishing and suspicious indicators.

This is the exact scoring logic from the original main.py, extracted
into a reusable service function.  Response fields are extended with
``confidence`` and ``analysis_engine`` while keeping every original
field the frontend already expects.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from app.schemas import URLRequest, URLResponse
from app.services.risk_engine import build_analysis_result
from app.utils.helpers import (
    URL_SHORTENERS,
    SUSPICIOUS_KEYWORDS_URL,
    normalize_url,
    is_ip_address,
    is_punycode,
    is_url_shortener,
    count_subdomain_depth,
    detect_suspicious_tld,
)


def analyse_url(request: URLRequest) -> URLResponse:
    """
    Analyse *request.url* and return a full URLResponse.

    Scoring (max 100):
        +20  Not HTTPS
        +25  Raw IP address in hostname
        +15  @ symbol in URL
        +10  URL longer than 100 characters
        +min(len × 8, 30)  Suspicious keywords
        +20  URL shortener detected
        +15  Punycode hostname
        +10  Suspicious TLD
        +10  Excessive subdomain depth (≥4)
    """
    original_url = request.url.strip()

    if not original_url:
        return URLResponse(
            success=False,
            url=original_url,
            normalized_url="",
            hostname="",
            score=0,
            risk="LOW",
            indicators=["URL is required."],
            recommendation="Please provide a URL to analyse.",
        )

    url = normalize_url(original_url)

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
    except Exception:
        return URLResponse(
            success=False,
            url=original_url,
            normalized_url=url,
            hostname="",
            score=0,
            risk="LOW",
            indicators=["URL could not be parsed."],
            recommendation="Please check the URL format and try again.",
        )

    indicators: list[str] = []
    score = 0

    # ---- HTTPS check ------------------------------------------------
    if parsed.scheme.lower() != "https":
        score += 20
        indicators.append("Website is not using HTTPS.")

    # ---- IP address -------------------------------------------------
    if is_ip_address(hostname):
        score += 25
        indicators.append(
            "URL uses an IP address instead of a domain name."
        )

    # ---- @ symbol ---------------------------------------------------
    if "@" in url:
        score += 15
        indicators.append("URL contains an @ symbol.")

    # ---- URL length -------------------------------------------------
    if len(url) > 100:
        score += 10
        indicators.append("URL is unusually long.")

    # ---- Suspicious keywords ----------------------------------------
    lower_url = url.lower()
    found_keywords = [
        kw for kw in SUSPICIOUS_KEYWORDS_URL if kw in lower_url
    ]
    if found_keywords:
        kw_score = min(len(found_keywords) * 8, 30)
        score += kw_score
        indicators.append(
            "Suspicious keywords detected: "
            + ", ".join(found_keywords)
        )

    # ---- URL shortener ----------------------------------------------
    shortener = is_url_shortener(hostname)
    if shortener:
        score += 20
        indicators.append(
            f"URL shortener detected: {shortener}"
        )

    # ---- Punycode ---------------------------------------------------
    if is_punycode(hostname):
        score += 15
        indicators.append(
            "Hostname uses punycode encoding, which can indicate "
            "homograph or internationalised domain spoofing."
        )

    # ---- Suspicious TLD ---------------------------------------------
    suspicious_tld = detect_suspicious_tld(hostname)
    if suspicious_tld:
        score += 10
        indicators.append(
            f"Hostname uses a suspicious TLD: {suspicious_tld}"
        )

    # ---- Subdomain depth ---------------------------------------------
    depth = count_subdomain_depth(hostname)
    if depth >= 4:
        score += 10
        indicators.append(
            f"Excessive subdomain depth ({depth} levels)."
        )

    # ---- Build result via unified engine -----------------------------
    result = build_analysis_result(
        score=score,
        indicators=indicators,
        engine_name="CyberGuard URL Engine v2",
        confidence=70,
    )

    return URLResponse(
        success=True,
        url=original_url,
        normalized_url=url,
        hostname=hostname,
        **result,
    )
