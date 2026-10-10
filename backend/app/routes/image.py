"""
CyberGuard Image Security Analysis Route
POST /api/analyze-image
POST /api/analyze-image-ai
"""

from __future__ import annotations

import base64
import json
import logging
import os
from pathlib import Path as FilePath

import httpx
from fastapi import APIRouter, File, HTTPException, UploadFile, status

from app.schemas import ImageResponse
from app.services.image_analyzer import analyse_image

router = APIRouter()
logger = logging.getLogger("cyberguard.image")

# Change this model name here if you verify a different model is enabled
# for your Google AI Studio API key.
GEMINI_MODEL = os.getenv("GEMINI_IMAGE_MODEL", "gemini-2.5-flash")


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
    """Inspect image metadata and technical security indicators."""
    content = await file.read()
    mime_type = file.content_type or "application/octet-stream"
    filename = file.filename or "unknown"

    return analyse_image(filename=filename, content=content, mime_type=mime_type)


@router.post(
    "/analyze-image-ai",
    summary="AI-assisted image authenticity review",
    tags=["Image Analysis"],
)
async def post_analyze_image_ai(file: UploadFile = File(...)):
    """
    Send an image to Gemini for a cautious visual review.
    This is not a definitive forensic/deepfake detector.
    Set GEMINI_API_KEY in the Render environment.
    """
    content = await file.read()

    if not content:
        raise HTTPException(status_code=400, detail="The uploaded image is empty.")

    if len(content) > 15 * 1024 * 1024:
        raise HTTPException(
            status_code=413,
            detail="Upload a non-empty image up to 15 MB.",
        )

    mime = (file.content_type or "").lower().split(";")[0].strip()
    supported_mimes = {
        "image/jpeg",
        "image/png",
        "image/webp",
        "image/gif",
    }
    if mime not in supported_mimes:
        raise HTTPException(
            status_code=415,
            detail="Supported images: JPEG, PNG, WebP, GIF.",
        )

    key = os.getenv("GEMINI_API_KEY", "").strip()
    if not key:
        raise HTTPException(
            status_code=503,
            detail="AI model is not configured. Add GEMINI_API_KEY in Render environment variables.",
        )

    prompt = (
        "You are a cautious visual media review assistant. Analyze the image content "
        "and visible visual cues that may suggest synthetic generation or editing. "
        "Do not claim certainty from appearance alone. Do not invent metadata or "
        "invisible forensic evidence. Return ONLY JSON with keys: "
        "image_description (string), assessment (one of 'Possible AI/editing cues', "
        "'No obvious visual cues', 'Inconclusive'), observations (array of strings), "
        "limitations (string), recommendation (string). Be concise and explicitly "
        "say this is not a definitive forensic determination."
    )

    provider_url = (
        "https://generativelanguage.googleapis.com/v1beta/"
        f"models/{GEMINI_MODEL}:generateContent"
    )
    payload = {
        "contents": [
            {
                "parts": [
                    {"text": prompt},
                    {
                        "inline_data": {
                            "mime_type": mime,
                            "data": base64.b64encode(content).decode("ascii"),
                        }
                    },
                ]
            }
        ],
        "generationConfig": {
            "responseMimeType": "application/json",
            "temperature": 0.1,
        },
    }

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                provider_url,
                params={"key": key},
                json=payload,
            )
    except httpx.TimeoutException:
        logger.exception("Gemini image request timed out.")
        raise HTTPException(
            status_code=504,
            detail="Gemini image request timed out. Try again with a smaller image.",
        )
    except httpx.HTTPError as exc:
        logger.exception("Could not connect to Gemini image API: %s", type(exc).__name__)
        raise HTTPException(
            status_code=502,
            detail="Could not connect to the Gemini provider. Check Render outbound access and try again.",
        )

    if response.status_code >= 400:
        # Never log the API key or request URL.
        provider_detail = response.text[:1200]
        logger.error(
            "Gemini image API failed: model=%s status=%s body=%s",
            GEMINI_MODEL,
            response.status_code,
            provider_detail,
        )

        if response.status_code == 400:
            detail = "Gemini rejected the request (400). Check request format and model access in Render Logs."
        elif response.status_code in (401, 403):
            detail = "Gemini denied the request. Check GEMINI_API_KEY and API access."
        elif response.status_code == 404:
            detail = (
                f"Gemini model '{GEMINI_MODEL}' was not found or is unavailable for this API key (404). "
                "Set GEMINI_IMAGE_MODEL to a model listed by the Gemini API for your key, then redeploy."
            )
        elif response.status_code == 429:
            detail = "Gemini quota or rate limit reached (429). Check your Google AI Studio quota."
        else:
            detail = f"Gemini provider request failed (HTTP {response.status_code}). Check Render Logs."

        raise HTTPException(status_code=502, detail=detail)

    try:
        provider_data = response.json()
        generated_text = provider_data["candidates"][0]["content"]["parts"][0]["text"]
        result = json.loads(generated_text)
    except (ValueError, KeyError, IndexError, TypeError):
        logger.exception("Gemini returned an unreadable image-analysis response.")
        raise HTTPException(
            status_code=502,
            detail="Gemini returned an unreadable response. Check Render Logs.",
        )

    if not isinstance(result, dict):
        raise HTTPException(
            status_code=502,
            detail="Gemini returned an unexpected response format.",
        )

    observations = result.get("observations", [])
    if not isinstance(observations, list):
        observations = []

    return {
        "success": True,
        "filename": FilePath(file.filename or "image").name,
        "analysis_engine": f"Gemini vision-assisted review ({GEMINI_MODEL})",
        "ai_model_status": "configured",
        "image_description": str(result.get("image_description", "Not available")),
        "assessment": str(result.get("assessment", "Inconclusive")),
        "observations": [str(item) for item in observations],
        "limitations": str(
            result.get(
                "limitations",
                "Visual AI review is not definitive forensic proof.",
            )
        ),
        "recommendation": str(
            result.get(
                "recommendation",
                "Verify important media using trusted original sources.",
            )
        ),
    }
