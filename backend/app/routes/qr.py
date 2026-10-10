"""
CyberGuard QR Analysis Route
POST /api/analyze-qr
"""

from fastapi import APIRouter, status

from app.schemas import QRRequest, QRResponse
from app.services.qr_analyzer import analyse_qr

router = APIRouter()


@router.post(
    "/analyze-qr",
    response_model=QRResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyse decoded QR content for security indicators.",
    tags=["QR Analysis"],
)
def post_analyze_qr(request: QRRequest) -> QRResponse:
    """
    Analyse the supplied QR code content for security indicators.

    **Request body:**

    - ``content`` *(string, optional)* — The decoded QR content.

    **Response:**

    - ``success`` *(bool)*
    - ``content_type`` *(string)* — Classified content type
    - ``decoded_content`` *(string)* — The original content
    - ``score`` *(int, 0–100)*
    - ``risk`` *(string)* — LOW, SUSPICIOUS, or HIGH
    - ``indicators`` *(list of strings)*
    - ``recommendation`` *(string)*
    - ``confidence`` *(int, 0–100)*
    - ``analysis_engine`` *(string)*
    """
    return analyse_qr(request)
