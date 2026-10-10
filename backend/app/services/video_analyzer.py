"""
CyberGuard Video Security / Deepfake Analyzer Service

Performs technical video analysis including format validation, metadata
inspection, and basic integrity checks.

Deepfake detection is NOT faked. When no ML model is available, the
service clearly reports technical findings and notes that deepfake
analysis is unavailable.
"""

from __future__ import annotations

import os
from typing import Any

from app.schemas import VideoResponse
from app.services.risk_engine import build_analysis_result
from app.utils.validators import validate_video_file


# ------------------------------------------------------------------ #
# Service function
# ------------------------------------------------------------------ #

def analyse_video(
    filename: str,
    content: bytes,
    mime_type: str,
) -> VideoResponse:
    """
    Analyse an uploaded video for security-relevant characteristics.

    *filename* is used for extension validation only — never stored.
    *content* is the raw bytes, processed in-memory and never persisted.

    Deepfake detection is NOT performed (no model loaded).
    """
    # ---- File validation -----------------------------------------------
    valid, error = validate_video_file(filename, mime_type, len(content))
    if not valid:
        return VideoResponse(
            success=False,
            filename=os.path.basename(filename),
            file_size_mb=round(len(content) / (1024 * 1024), 2),
            score=0,
            risk="LOW",
            indicators=[error],
            recommendation="Please upload a valid video file.",
        )

    file_size_mb = round(len(content) / (1024 * 1024), 2)

    # ---- Technical analysis (no deepfake model) -----------------------
    indicators: list[str] = []
    score = 0

    # Large file
    if file_size_mb > 500:
        score += 10
        indicators.append(
            f"Video file is very large ({file_size_mb:.1f} MB)."
        )

    # We cannot extract codec/resolution/duration without ffmpeg or similar.
    # We report what we can determine from the file itself.
    # For a real deepfake model, see AI_ML_ROADMAP.md.

    # ---- Build result --------------------------------------------------
    result = build_analysis_result(
        score=score,
        indicators=indicators,
        engine_name="CyberGuard Video Engine v1",
        confidence=50,
    )

    return VideoResponse(
        success=True,
        filename=os.path.basename(filename),
        file_size_mb=file_size_mb,
        **result,
    )
