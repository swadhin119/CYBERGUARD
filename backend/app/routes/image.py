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


@router.post("/analyze-image-ai", summary="AI-assisted image authenticity review")
async def post_analyze_image_ai(file: UploadFile = File(...)):
    """Use Gemini vision to describe an image and assess visual manipulation cues.
    This is an assessment, not a definitive forensic detector. Set GEMINI_API_KEY on Render.
    """
    import base64, json, os
    import httpx
    from fastapi import HTTPException

    content = await file.read()
    if not content or len(content) > 15 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Upload a non-empty image up to 15 MB.")
    mime = (file.content_type or "").lower()
    if not mime.startswith("image/") or mime not in {"image/jpeg", "image/png", "image/webp", "image/gif"}:
        raise HTTPException(status_code=415, detail="Supported images: JPEG, PNG, WebP, GIF.")
    key = os.getenv("GEMINI_API_KEY")
    if not key:
        raise HTTPException(status_code=503, detail="AI model is not configured. Add GEMINI_API_KEY in Render environment variables.")
    prompt = (
      "You are a cautious visual media review assistant. Analyze the image content and visible visual cues that may suggest synthetic generation or editing. "
      "Do not claim certainty from appearance alone; do not invent metadata or invisible forensic evidence. "
      "Return ONLY JSON with keys: image_description (string), assessment (one of 'Possible AI/editing cues', 'No obvious visual cues', 'Inconclusive'), "
      "observations (array of strings), limitations (string), recommendation (string). Be concise and explicitly say this is not a definitive forensic determination."
    )
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={key}"
    payload = {"contents":[{"parts":[{"text":prompt},{"inline_data":{"mime_type":mime,"data":base64.b64encode(content).decode("ascii")}}]}],"generationConfig":{"responseMimeType":"application/json","temperature":0.1}}
    async with httpx.AsyncClient(timeout=60) as client:
      resp = await client.post(url, json=payload)
    if resp.status_code >= 400:
      raise HTTPException(status_code=502, detail="AI provider request failed. Check the Render key and provider quota.")
    data = resp.json()
    try:
      text = data["candidates"][0]["content"]["parts"][0]["text"]
      result = json.loads(text)
    except (KeyError, IndexError, TypeError, ValueError):
      raise HTTPException(status_code=502, detail="AI provider returned an unreadable response.")
    return {"success": True, "filename": os.path.basename(file.filename or "image"), "analysis_engine": "Gemini vision-assisted review", "ai_model_status": "configured", **result}
