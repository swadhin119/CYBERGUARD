"""
CyberGuard Email Analysis Route
POST /api/analyze-email
"""

from fastapi import APIRouter, status

from app.schemas import EmailRequest, EmailResponse
from app.services.email_analyzer import analyse_email

router = APIRouter()


@router.post(
    "/analyze-email",
    response_model=EmailResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyse email content for phishing indicators.",
    tags=["Email Analysis"],
)
def post_analyze_email(request: EmailRequest) -> EmailResponse:
    """
    Analyse the supplied email fields for phishing, scam, and
    social-engineering indicators.

    **Request body:**

    - ``sender`` *(string, optional)* — Sender email address.
    - ``subject`` *(string, optional)* — Email subject line.
    - ``body`` *(string, optional)* — Email body content.

    **Response:**

    - ``success`` *(bool)*
    - ``score`` *(int, 0–100)*
    - ``risk`` *(string)* — LOW, SUSPICIOUS, or HIGH
    - ``indicators`` *(list of strings)*
    - ``recommendation`` *(string)*
    - ``detected_urls`` *(list of strings)* — URLs found in the email
    - ``confidence`` *(int, 0–100)*
    - ``analysis_engine`` *(string)*
    """
    return analyse_email(request)
