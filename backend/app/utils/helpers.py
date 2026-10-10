"""
CyberGuard Utility Modules
Shared helpers used across the application.
"""

from __future__ import annotations

import html
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any

import unicodedata


logger = logging.getLogger("cyberguard")


# ------------------------------------------------------------------ #
# Logging
# ------------------------------------------------------------------ #

def setup_logging(debug: bool = False) -> None:
    """Configure structured application logging."""
    level = logging.DEBUG if debug else logging.INFO

    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Quiet noisy libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)


def log_security_event(event_type: str, details: dict[str, Any]) -> None:
    """Log a security-relevant event."""
    logger.info(
        "SECURITY | %s | %s",
        event_type,
        {k: str(v)[:200] for k, v in details.items()},
    )


# ------------------------------------------------------------------ #
# String helpers
# ------------------------------------------------------------------ #

def escape_html(value: Any) -> str:
    """Escape a value for safe HTML rendering."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def truncate(value: str, max_length: int = 500) -> str:
    """Truncate a string to max_length characters with an ellipsis."""
    if not value:
        return ""
    value = value.strip()
    return value[:max_length] + ("…" if len(value) > max_length else "")


def generate_event_id() -> str:
    """Generate a unique event identifier."""
    return f"{uuid.uuid4().hex[:12]}"


# ------------------------------------------------------------------ #
# Risk helpers
# ------------------------------------------------------------------ #

RISK_THRESHOLDS = {
    "HIGH": 70,
    "SUSPICIOUS": 40,
    "LOW": 0,
}


def score_to_risk(score: int) -> str:
    """Map a numeric score to a risk label."""
    score = max(0, min(100, score))
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "SUSPICIOUS"
    return "LOW"


def risk_class(risk: str) -> str:
    """Return a CSS class suffix for a risk label."""
    value = str(risk or "").upper()
    if value == "HIGH":
        return "danger"
    if value == "SUSPICIOUS":
        return "warning"
    return "safe"


# ------------------------------------------------------------------ #
# URL helpers
# ------------------------------------------------------------------ #

URL_SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "cutt.ly",
    "shorturl.at",
    "ow.ly",
    "rb.gy",
    "tiny.cc",
]

SUSPICIOUS_TLDS = [
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".top",
    ".xyz",
    ".club",
    ".info",
    ".buzz",
    ".monster",
    ".rest",
    ".bid",
    ".click",
    ".link",
    ".online",
    ".site",
    ".website",
    ".space",
    ".fun",
    ".live",
    ".loan",
    ".win",
    ".cfd",
]

SUSPICIOUS_KEYWORDS_URL = [
    "login",
    "verify",
    "verification",
    "password",
    "account",
    "secure",
    "update",
    "bank",
    "payment",
    "confirm",
    "signin",
    "wallet",
    "crypto",
    "bitcoin",
    "reset",
    "unlock",
    "suspended",
    "blocked",
]


def extract_hostname(url: str) -> str:
    """Extract the hostname from a URL string."""
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        return parsed.hostname or ""
    except Exception:
        return ""


def is_ip_address(hostname: str) -> bool:
    """Check if a hostname is a raw IP address."""
    ipv4 = re.match(r"^(\d{1,3}\.){3}\d{1,3}$", hostname)
    if ipv4:
        return True
    return hostname.startswith("[") and "]" in hostname  # IPv6 literal


def is_punycode(hostname: str) -> bool:
    """Detect punycode / xn-- encoded hostnames."""
    return "xn--" in hostname.lower()


def is_url_shortener(hostname: str) -> str | None:
    """Return the matching shortener domain or None."""
    lower = hostname.lower()
    for shortener in URL_SHORTENERS:
        if shortener in lower:
            return shortener
    return None


def count_subdomain_depth(hostname: str) -> int:
    """Count the number of subdomain labels (depth)."""
    parts = hostname.split(".")
    # Subtract TLD + second-level domain for depth
    return max(0, len(parts) - 2)


def detect_suspicious_tld(hostname: str) -> str | None:
    """Return the matching suspicious TLD or None."""
    lower = hostname.lower()
    for tld in SUSPICIOUS_TLDS:
        if lower.endswith(tld):
            return tld
    return None


def normalize_url(raw: str) -> str:
    """Ensure a URL has a scheme prefix."""
    raw = raw.strip()
    if not raw:
        return raw
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        return "https://" + raw
    return raw


# ------------------------------------------------------------------ #
# Datetime helpers
# ------------------------------------------------------------------ #

def utc_now() -> datetime:
    """Return the current UTC datetime."""
    return datetime.now(timezone.utc)
