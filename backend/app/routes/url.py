"""
CyberGuard URL Analysis Route
POST /api/analyze-url
"""

from fastapi import APIRouter, status

from app.schemas import URLRequest, URLResponse
from app.services.url_analyzer import analyse_url

router = APIRouter()


@router.post(
    "/analyze-url",
    response_model=URLResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyse a URL for phishing and suspicious indicators.",
    tags=["URL Analysis"],
)
def post_analyze_url(request: URLRequest) -> URLResponse:
    """
    Analyse the supplied URL and return a risk score (0–100),
    risk level, detected indicators, and a recommendation.

    **Request body:**

    - ``url`` *(string, required)* — The URL to analyse.

    **Response:**

    - ``success`` *(bool)*
    - ``url`` *(string)* — Original URL
    - ``normalized_url`` *(string)* — Normalised URL with scheme
    - ``hostname`` *(string)* — Extracted hostname
    - ``score`` *(int, 0–100)*
    - ``risk`` *(string)* — LOW, SUSPICIOUS, or HIGH
    - ``indicators`` *(list of strings)*
    - ``recommendation`` *(string)*
    - ``confidence`` *(int, 0–100)*
    - ``analysis_engine`` *(string)*
    """
    return analyse_url(request)
