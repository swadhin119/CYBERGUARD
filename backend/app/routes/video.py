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


@router.post("/analyze-video-ai", summary="AI-assisted video review")
async def post_analyze_video_ai(file: UploadFile = File(...)):
    """Review a short uploaded video with a vision model. This is not a certified deepfake detector."""
    import base64, json, os
    import httpx
    from fastapi import HTTPException

    content = await file.read()
    if not content or len(content) > 15 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Upload a non-empty video up to 15 MB for inline AI review.")
    mime = (file.content_type or "").lower()
    if mime not in {"video/mp4", "video/webm", "video/quicktime", "video/mpeg"}:
        raise HTTPException(status_code=415, detail="Supported videos: MP4, WebM, MOV, MPEG.")
    key = os.getenv("GEMINI_API_KEY")
    if not key:
        raise HTTPException(status_code=503, detail="AI model is not configured. Add GEMINI_API_KEY in Render environment variables.")
    prompt = (
      "Review this video and its sampled visual content for possible synthetic/edited-media cues. "
      "Do not state that it is definitely a deepfake; visual review alone cannot prove authenticity. "
      "Return ONLY JSON with keys: summary (string), assessment (one of 'Possible manipulation cues', 'No obvious cues in reviewed content', 'Inconclusive'), "
      "observations (array of strings), limitations (string), recommendation (string). Mention that audio, frame-by-frame forensics and provenance were not independently verified."
    )
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={key}"
    payload = {"contents":[{"parts":[{"text":prompt},{"inline_data":{"mime_type":mime,"data":base64.b64encode(content).decode("ascii")}}]}],"generationConfig":{"responseMimeType":"application/json","temperature":0.1}}
    async with httpx.AsyncClient(timeout=90) as client:
      resp = await client.post(url, json=payload)
    if resp.status_code >= 400:
      raise HTTPException(status_code=502, detail="AI provider request failed. Check the Render key, video format and provider quota.")
    data = resp.json()
    try:
      text = data["candidates"][0]["content"]["parts"][0]["text"]
      result = json.loads(text)
    except (KeyError, IndexError, TypeError, ValueError):
      raise HTTPException(status_code=502, detail="AI provider returned an unreadable response.")
    return {"success": True, "filename": os.path.basename(file.filename or "video"), "analysis_engine": "Gemini video-assisted review", "ai_model_status": "configured", **result}
