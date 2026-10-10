"""
CyberGuard Social Media Impersonation Analyzer Service
Defensive heuristic analysis for suspicious username and profile patterns.

This is a heuristic-only analysis. It does NOT access any external platform
API, scrape profiles, or claim verification status. All findings are
probability indicators, not definitive proof.
"""

from __future__ import annotations

import re

from app.schemas import SocialRequest, SocialResponse
from app.services.risk_engine import build_analysis_result
from app.utils.validators import validate_social_username, validate_platform


# ------------------------------------------------------------------ #
# Constants
# ------------------------------------------------------------------ #

SUSPICIOUS_USERNAME_TERMS = [
    "official",
    "support",
    "admin",
    "help",
    "customer",
    "security",
    "verify",
    "real",
    "original",
    "verified",
    "realsupport",
    "techsupport",
]

BRAND_IMPOSTER_PATTERNS = [
    r"official[\s_.-]?support",
    r"support[\s_.-]?team",
    r"help[\s_.-]?desk",
    r"security[\s_.-]?team",
    r"admin[\s_.-]?official",
    r"verify[\s_.-]?now",
    r"real[\s_.-]?account",
]


# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #

def _numeric_sequence_score(username: str) -> tuple[int, str]:
    """Detect large numeric sequences in username."""
    numbers = re.findall(r"\d{3,}", username)
    if numbers:
        return 10, f"Username contains large numeric sequence(s): {', '.join(numbers)}"
    return 0, ""


def _length_score(username: str) -> tuple[int, str]:
    """Flag unusually long usernames."""
    if len(username) > 30:
        return 10, "Username is unusually long, which may indicate impersonation."
    return 0, ""


def _suspicious_terms_score(username: str) -> tuple[int, list[str]]:
    """Detect impersonation-related terms in username."""
    lower = username.lower()
    found = []
    for term in SUSPICIOUS_USERNAME_TERMS:
        if term in lower:
            found.append(term)
    if found:
        return min(len(found) * 8, 30), found
    return 0, []


def _display_similarity_score(username: str, display_name: str) -> tuple[int, str]:
    """Check if username and display name are suspiciously similar (lookalike pattern)."""
    if not display_name:
        return 0, ""

    u = re.sub(r"[@_.0-9]", "", username).lower()
    d = re.sub(r"\s", "", display_name).lower()

    if u and d and u == d:
        return 10, "Username closely matches display name with only special characters or numbers differing."

    # Check for lookalike character substitutions
    leet_map = {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t"}
    u_normalised = "".join(leet_map.get(c, c) for c in u)
    d_normalised = "".join(leet_map.get(c, c) for c in d)

    if u_normalised == d_normalised and u != d:
        return 10, "Username uses lookalike character substitutions matching display name."

    return 0, ""


def _brand_pattern_score(username: str) -> tuple[int, list[str]]:
    """Detect brand impersonation patterns."""
    lower = username.lower()
    found = []
    for pattern in BRAND_IMPOSTER_PATTERNS:
        if re.search(pattern, lower):
            found.append(pattern.replace(r"[\s_.-]? ", " ").replace(r"[\s_.-]?", " "))
    if found:
        return min(len(found) * 10, 20), found
    return 0, []


def _profile_url_score(profile_url: str) -> tuple[int, str]:
    """Check profile URL for suspicious patterns."""
    if not profile_url:
        return 0, ""

    url_lower = profile_url.lower()

    # Flag IP addresses in profile URLs
    ip_re = re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}")
    if ip_re.search(url_lower):
        return 15, "Profile URL contains an IP address instead of a domain name."

    # Flag URL shorteners
    shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "shorturl.at"]
    for shortener in shorteners:
        if shortener in url_lower:
            return 10, f"Profile URL uses a URL shortener: {shortener}."

    return 0, ""


# ------------------------------------------------------------------ #
# Service function
# ------------------------------------------------------------------ #

def analyse_social(request: SocialRequest) -> SocialResponse:
    """
    Analyse social media username and profile data for impersonation indicators.

    This is a heuristic-only analysis. It does NOT verify accounts through
    any external API. All findings are indicators, not proofs.

    Scoring (max 100):
        +min(len×8, 30)  Suspicious username terms (official, admin, support, etc.)
        +10   Brand impersonation pattern
        +10   Large numeric sequence
        +10   Unusually long username
        +10   Username closely matches display name
        +15   Profile URL contains IP address
        +10   Profile URL uses shortener
    """
    # Validate inputs
    valid_platform, platform_error = validate_platform(request.platform)
    if not valid_platform:
        return SocialResponse(
            success=False,
            platform=request.platform,
            username=request.username,
            score=0,
            risk="LOW",
            indicators=[platform_error],
            recommendation="Please provide a valid platform name.",
        )

    valid_username, username_error = validate_social_username(request.username)
    if not valid_username:
        return SocialResponse(
            success=False,
            platform=request.platform,
            username=request.username,
            score=0,
            risk="LOW",
            indicators=[username_error],
            recommendation="Please provide a valid username.",
        )

    username = request.username.strip()
    display_name = request.display_name.strip()
    profile_url = request.profile_url.strip()

    indicators: list[str] = []
    score = 0

    # ---- Suspicious terms in username ----------------------------------
    term_score, found_terms = _suspicious_terms_score(username)
    score += term_score
    if found_terms:
        indicators.append(
            "Username contains impersonation/authority-related terms: "
            + ", ".join(found_terms)
        )

    # ---- Brand impersonation patterns ----------------------------------
    brand_score, found_patterns = _brand_pattern_score(username)
    score += brand_score
    if found_patterns:
        indicators.append(
            "Username matches known brand-impersonation patterns: "
            + ", ".join(found_patterns)
        )

    # ---- Numeric sequence ----------------------------------------------
    num_score, num_msg = _numeric_sequence_score(username)
    score += num_score
    if num_msg:
        indicators.append(num_msg)

    # ---- Length ---------------------------------------------------------
    len_score, len_msg = _length_score(username)
    score += len_score
    if len_msg:
        indicators.append(len_msg)

    # ---- Display name similarity ----------------------------------------
    sim_score, sim_msg = _display_similarity_score(username, display_name)
    score += sim_score
    if sim_msg:
        indicators.append(sim_msg)

    # ---- Profile URL checks ---------------------------------------------
    url_score, url_msg = _profile_url_score(profile_url)
    score += url_score
    if url_msg:
        indicators.append(url_msg)

    # ---- Build result ---------------------------------------------------
    result = build_analysis_result(
        score=score,
        indicators=indicators,
        engine_name="CyberGuard Social Engine v1",
        confidence=60,
    )

    return SocialResponse(
        success=True,
        platform=request.platform,
        username=username,
        **result,
    )
