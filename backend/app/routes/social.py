"""
CyberGuard Social Media Impersonation Route
POST /api/analyze-social
"""

from fastapi import APIRouter, status

from app.schemas import SocialRequest, SocialResponse
from app.services.social_analyzer import analyse_social

router = APIRouter()


@router.post(
    "/analyze-social",
    response_model=SocialResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyse a social media profile for impersonation indicators.",
    tags=["Social Media Analysis"],
)
def post_analyze_social(request: SocialRequest) -> SocialResponse:
    """
    Analyse the supplied social media username and profile data for
    impersonation indicators using heuristic checks only.

    This endpoint does NOT access any external platform API.
    All findings are probability indicators, not definitive proof.

    **Request body:**

    - ``platform`` *(string, required)* — Platform name (e.g. Instagram, X).
    - ``username`` *(string, required)* — The username / handle to analyse.
    - ``display_name`` *(string, optional)* — The profile display name.
    - ``profile_url`` *(string, optional)* — The profile URL.

    **Response:**

    - ``success`` *(bool)*
    - ``platform`` *(string)*
    - ``username`` *(string)*
    - ``score`` *(int, 0–100)*
    - ``risk`` *(string)* — LOW, SUSPICIOUS, or HIGH
    - ``indicators`` *(list of strings)*
    - ``recommendation`` *(string)*
    - ``confidence`` *(int, 0–100)*
    - ``analysis_engine`` *(string)*
    """
    return analyse_social(request)
