"""
CyberGuard Input Validators
Reusable validation functions for URLs, emails, files, usernames, etc.
"""

from __future__ import annotations

import re

from app.utils.helpers import (
    URL_SHORTENERS,
    SUSPICIOUS_KEYWORDS_URL,
    SUSPICIOUS_TLDS,
    normalize_url,
    extract_hostname,
    is_ip_address,
    is_punycode,
    count_subdomain_depth,
)


# ------------------------------------------------------------------ #
# Email validation
# ------------------------------------------------------------------ #

_EMAIL_RE = re.compile(
    r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$"
)


def is_valid_email(value: str) -> bool:
    """Return True if value looks like a valid email address."""
    if not value or not value.strip():
        return False
    return bool(_EMAIL_RE.match(value.strip()))


def extract_email_domain(email: str) -> str:
    """Return the domain part of an email address."""
    parts = email.strip().split("@")
    return parts[-1].lower() if len(parts) > 1 else ""


# ------------------------------------------------------------------ #
# URL validation
# ------------------------------------------------------------------ #

_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def validate_url(raw: str, max_length: int = 2048) -> tuple[str, str | None]:
    """
    Validate and normalise a URL.

    Returns:
        (normalised_url, error_string | None)

    error_string is None when the URL is valid.
    """
    raw = raw.strip()

    if not raw:
        return "", "URL is empty."

    if len(raw) > max_length:
        return "", f"URL exceeds maximum length of {max_length} characters."

    url = normalize_url(raw)

    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
    except Exception:
        return "", "URL could not be parsed."

    if not parsed.hostname:
        return "", "URL does not contain a valid hostname."

    if is_ip_address(parsed.hostname):
        # Not an error — flagged as suspicious by the analyzer
        return url, None

    return url, None


# ------------------------------------------------------------------ #
# File validation
# ------------------------------------------------------------------ #

ALLOWED_IMAGE_MIME_TYPES = {
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "image/bmp",
    "image/tiff",
}

ALLOWED_VIDEO_MIME_TYPES = {
    "video/mp4",
    "video/webm",
    "video/ogg",
    "video/avi",
    "video/quicktime",
    "video/x-msvideo",
}

ALLOWED_IMAGE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tiff", ".tif"
}

ALLOWED_VIDEO_EXTENSIONS = {
    ".mp4", ".webm", ".ogg", ".avi", ".mov", ".mkv", ".flv"
}


def validate_image_file(filename: str, mime_type: str, size_bytes: int,
                        max_size_mb: int = 50) -> tuple[bool, str]:
    """
    Validate an uploaded image file.

    Returns:
        (is_valid, error_message)
    """
    import os

    ext = os.path.splitext(filename)[1].lower()

    if ext not in ALLOWED_IMAGE_EXTENSIONS:
        return False, f"Image extension '{ext}' is not allowed."

    if mime_type not in ALLOWED_IMAGE_MIME_TYPES:
        return False, f"Image MIME type '{mime_type}' is not allowed."

    max_bytes = max_size_mb * 1024 * 1024
    if size_bytes > max_bytes:
        size_mb = size_bytes / (1024 * 1024)
        return False, (
            f"Image file is {size_mb:.1f} MB, "
            f"which exceeds the {max_size_mb} MB limit."
        )

    return True, ""


def validate_video_file(filename: str, mime_type: str, size_bytes: int,
                        max_size_mb: int = 50) -> tuple[bool, str]:
    """
    Validate an uploaded video file.

    Returns:
        (is_valid, error_message)
    """
    import os

    ext = os.path.splitext(filename)[1].lower()

    if ext not in ALLOWED_VIDEO_EXTENSIONS:
        return False, f"Video extension '{ext}' is not allowed."

    if mime_type not in ALLOWED_VIDEO_MIME_TYPES:
        return False, f"Video MIME type '{mime_type}' is not allowed."

    max_bytes = max_size_mb * 1024 * 1024
    if size_bytes > max_bytes:
        size_mb = size_bytes / (1024 * 1024)
        return False, (
            f"Video file is {size_mb:.1f} MB, "
            f"which exceeds the {max_size_mb} MB limit."
        )

    return True, ""


# ------------------------------------------------------------------ #
# Social media username validation
# ------------------------------------------------------------------ #

def validate_social_username(username: str) -> tuple[bool, str]:
    """Validate a social media username."""
    username = username.strip()
    if not username:
        return False, "Username is required."
    if len(username) > 100:
        return False, "Username is too long."
    # Allow alphanumeric, underscores, hyphens, dots
    if not re.match(r"^[A-Za-z0-9_.-]+$", username):
        return False, "Username contains invalid characters."
    return True, ""


def validate_platform(platform: str) -> tuple[bool, str]:
    """Validate a social media platform name."""
    platform = platform.strip()
    if not platform:
        return False, "Platform is required."
    if len(platform) > 50:
        return False, "Platform name is too long."
    return True, ""
