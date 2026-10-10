"""
CyberGuard Video Security Analysis Route
POST /api/analyze-video
Accepts a file upload (multipart/form-data).
"""

from __future__ import annotations

from fastapi import APIRouter, File, UploadFile, status

from app.schemas import VideoResponse
from app.services.video_analyzer import analyse_video

router = APIRouter()


@router.post(
    "/analyze-video",
    response_model=VideoResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyse an uploaded video for security indicators.",
    tags=["Video Analysis"],
)
async def post_analyze_video(
    file: UploadFile = File(..., description="Video file to analyse."),
) -> VideoResponse:
    """
    Analyse the supplied video file for technical security indicators.

    Deepfake detection is NOT performed. When no ML model is available,
    technical findings are reported and ``ai_model_status`` indicates
    the model is unavailable.

    **Request (multipart/form-data):**

    - ``file`` *(file, required)* — Video file (MP4, WebM, OGG, AVI, MOV, MKV).
      Maximum size: 50 MB.

    **Response:**

    - ``success`` *(bool)*
    - ``filename`` *(string)*
    - ``file_size_mb`` *(float)*
    - ``duration_seconds`` *(float | null)*
    - ``width`` *(int | null)*
    - ``height`` *(int | null)*
    - ``codec`` *(string)*
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

    return analyse_video(filename=filename, content=content, mime_type=mime_type)
