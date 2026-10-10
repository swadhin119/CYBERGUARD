"""
CyberGuard Image Security / Authenticity Analyzer Service

Performs technical image analysis including file validation, metadata
inspection, and basic integrity checks.

AI authenticity / deepfake detection is NOT faked. When no ML model is
available, the service clearly reports technical findings and notes that
AI authenticity analysis is unavailable.
"""

from __future__ import annotations

import io
import os
from typing import Any

from PIL import Image, ExifTags
from PIL.ExifTags import TAGS

from app.schemas import ImageResponse
from app.services.risk_engine import build_analysis_result
from app.utils.helpers import escape_html
from app.utils.validators import validate_image_file, ALLOWED_IMAGE_MIME_TYPES


# ------------------------------------------------------------------ #
# EXIF helpers
# ------------------------------------------------------------------ #

def _extract_exif_summary(image: Image.Image) -> tuple[dict[str, Any], list[str]]:
    """Extract key EXIF metadata from an image."""
    exif_summary: dict[str, Any] = {}
    suspicious: list[str] = []

    try:
        raw_exif = image._getexif()
        if not raw_exif:
            return exif_summary, suspicious

        for tag_id, value in raw_exif.items():
            tag_name = TAGS.get(tag_id, tag_id)
            if tag_name in ("Make", "Model", "Software", "DateTime", "DateTimeOriginal",
                            "GPSLatitude", "GPSLongitude", "Artist", "Copyright",
                            "ImageDescription", "Orientation"):
                exif_summary[str(tag_name)] = str(value)

        # Flag GPS data as sensitive
        if "GPSLatitude" in exif_summary or "GPSLongitude" in exif_summary:
            suspicious.append("Image contains GPS location metadata.")

        # Flag editing software
        software = exif_summary.get("Software", "").lower()
        editing_keywords = ["photoshop", "gimp", "affinity", "lightroom", "paint.net", "paint.net"]
        if any(kw in software for kw in editing_keywords):
            suspicious.append(
                f"Image editing software detected in metadata: {software}"
            )

    except Exception:
        pass

    return exif_summary, suspicious


# ------------------------------------------------------------------ #
# Service function
# ------------------------------------------------------------------ #

def analyse_image(
    filename: str,
    content: bytes,
    mime_type: str,
) -> ImageResponse:
    """
    Analyse an uploaded image for security-relevant characteristics.

    *filename* is used for extension validation only — never stored.
    *content* is the raw bytes, processed in-memory and never persisted.

    AI authenticity detection is NOT performed (no model loaded).
    """
    # ---- File validation -----------------------------------------------
    valid, error = validate_image_file(filename, mime_type, len(content))
    if not valid:
        return ImageResponse(
            success=False,
            filename=os.path.basename(filename),
            file_size_mb=round(len(content) / (1024 * 1024), 2),
            mime_type=mime_type,
            file_type="unknown",
            score=0,
            risk="LOW",
            indicators=[error],
            recommendation="Please upload a valid image file.",
        )

    file_size_mb = round(len(content) / (1024 * 1024), 2)

    # ---- Open image ----------------------------------------------------
    try:
        image = Image.open(io.BytesIO(content))
        width, height = image.size
        file_type = image.format or "unknown"
    except Exception as exc:
        return ImageResponse(
            success=False,
            filename=os.path.basename(filename),
            file_size_mb=file_size_mb,
            mime_type=mime_type,
            file_type="unknown",
            score=0,
            risk="LOW",
            indicators=[f"Image could not be opened: {exc}"],
            recommendation="The file appears to be corrupted or not a valid image.",
        )

    # ---- Analyse -------------------------------------------------------
    indicators: list[str] = []
    score = 0

    # Large file
    if file_size_mb > 10:
        score += 5
        indicators.append(f"Image file is unusually large ({file_size_mb:.1f} MB).")

    # High dimensions
    if width > 8000 or height > 8000:
        score += 5
        indicators.append(
            f"Image has unusually high dimensions ({width}×{height}px)."
        )

    # EXIF metadata
    exif_summary, exif_suspicious = _extract_exif_summary(image)
    indicators.extend(exif_suspicious)
    if exif_suspicious:
        score += min(len(exif_suspicious) * 10, 20)

    # ---- Build result --------------------------------------------------
    result = build_analysis_result(
        score=score,
        indicators=indicators,
        engine_name="CyberGuard Image Engine v1",
        confidence=55,
    )

    return ImageResponse(
        success=True,
        filename=os.path.basename(filename),
        file_size_mb=file_size_mb,
        width=width,
        height=height,
        mime_type=mime_type,
        file_type=file_type,
        exif_summary=exif_summary or None,
        suspicious_metadata=exif_suspicious,
        **result,
    )
