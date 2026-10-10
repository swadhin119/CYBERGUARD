"""
CyberGuard Image Security Analysis Route
POST /api/analyze-image
Accepts a file upload (multipart/form-data).
"""

from __future__ import annotations

from fastapi import APIRouter, File, Form, UploadFile, status

from app.schemas import ImageResponse
from app.services.image_analyzer import analyse_image

router = APIRouter()


@router.post(
    "/analyze-image",
    response_model=ImageResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyse an uploaded image for security indicators.",
    tags=["Image Analysis"],
)
async def post_analyze_image(
    file: UploadFile = File(..., description="Image file to analyse."),
) -> ImageResponse:
    """
    Analyse the supplied image file for technical security indicators
    such as suspicious metadata, unusual dimensions, or file anomalies.

    AI authenticity / deepfake detection is NOT performed.
    When no ML model is available, technical findings are reported
    and ``ai_model_status`` indicates the model is unavailable.

    **Request (multipart/form-data):**

    - ``file`` *(file, required)* — Image file (PNG, JPEG, GIF, WebP, BMP, TIFF).
      Maximum size: 50 MB.

    **Response:**

    - ``success`` *(bool)*
    - ``filename`` *(string)*
    - ``file_size_mb`` *(float)*
    - ``width`` *(int | null)*
    - ``height`` *(int | null)*
    - ``mime_type`` *(string)*
    - ``file_type`` *(string)*
    - ``exif_summary`` *(dict | null)* — Key EXIF fields
    - ``suspicious_metadata`` *(list of strings)*
    - ``score`` *(int, 0–100)*
    - ``risk`` *(string)*
    - ``indicators`` *(list of strings)*
    - ``recommendation`` *(string)*
    - ``ai_model_status`` *(string)*
    - ``confidence`` *(int, 0–100)*
    - ``analysis_engine`` *(string)*
    """
    content = await file.read()
    mime_type = file.content_type or "application/octet-stream"
    filename = file.filename or "unknown"

    return analyse_image(filename=filename, content=content, mime_type=mime_type)
