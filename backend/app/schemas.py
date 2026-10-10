"""
CyberGuard Pydantic Schemas
Request and response models for all API endpoints.
"""

from pydantic import BaseModel, Field, ConfigDict
from typing import Any


# ------------------------------------------------------------------ #
# Shared
# ------------------------------------------------------------------ #

class HealthResponse(BaseModel):
    status: str
    service: str


class RootResponse(BaseModel):
    status: str
    message: str
    version: str


class ErrorResponse(BaseModel):
    success: bool = False
    message: str


# ------------------------------------------------------------------ #
# URL Analysis
# ------------------------------------------------------------------ #

class URLRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048, description="The URL to analyse.")


class URLResponse(BaseModel):
    success: bool
    url: str
    normalized_url: str
    hostname: str
    score: int
    risk: str
    indicators: list[str]
    recommendation: str
    confidence: int = 70
    analysis_engine: str = "CyberGuard URL Engine v2"


# ------------------------------------------------------------------ #
# Email Analysis
# ------------------------------------------------------------------ #

class EmailRequest(BaseModel):
    sender: str = Field(default="", max_length=500)
    subject: str = Field(default="", max_length=1000)
    body: str = Field(default="", max_length=10_000)


class EmailResponse(BaseModel):
    success: bool
    score: int
    risk: str
    indicators: list[str]
    recommendation: str
    detected_urls: list[str] = []
    confidence: int = 65
    analysis_engine: str = "CyberGuard Email Engine v2"


# ------------------------------------------------------------------ #
# QR Analysis
# ------------------------------------------------------------------ #

class QRRequest(BaseModel):
    content: str = Field(default="", max_length=10_000)


class QRResponse(BaseModel):
    success: bool
    content_type: str
    decoded_content: str
    score: int
    risk: str
    indicators: list[str]
    recommendation: str
    confidence: int = 75
    analysis_engine: str = "CyberGuard QR Security Engine v2"


# ------------------------------------------------------------------ #
# Social Media Analysis
# ------------------------------------------------------------------ #

class SocialRequest(BaseModel):
    platform: str = Field(default="", max_length=50)
    username: str = Field(default="", min_length=1, max_length=100)
    display_name: str = Field(default="", max_length=200)
    profile_url: str = Field(default="", max_length=500)


class SocialResponse(BaseModel):
    success: bool
    platform: str
    username: str
    score: int
    risk: str
    indicators: list[str]
    recommendation: str
    confidence: int = 60
    analysis_engine: str = "CyberGuard Social Engine v1"


# ------------------------------------------------------------------ #
# Image Analysis
# ------------------------------------------------------------------ #

class ImageResponse(BaseModel):
    success: bool
    filename: str
    file_size_mb: float
    width: int | None = None
    height: int | None = None
    mime_type: str
    file_type: str
    exif_summary: dict[str, Any] | None = None
    suspicious_metadata: list[str] = []
    score: int
    risk: str
    indicators: list[str]
    recommendation: str
    ai_model_status: str = "AI authenticity model not configured"
    confidence: int = 55
    analysis_engine: str = "CyberGuard Image Engine v1"


# ------------------------------------------------------------------ #
# Video Analysis
# ------------------------------------------------------------------ #

class VideoResponse(BaseModel):
    success: bool
    filename: str
    file_size_mb: float
    duration_seconds: float | None = None
    width: int | None = None
    height: int | None = None
    codec: str = "unknown"
    score: int
    risk: str
    indicators: list[str]
    recommendation: str
    ai_model_status: str = "Deepfake model not configured"
    confidence: int = 50
    analysis_engine: str = "CyberGuard Video Engine v1"


# ------------------------------------------------------------------ #
# Authentication
# ------------------------------------------------------------------ #

class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., max_length=255)
    password: str = Field(..., min_length=8, max_length=128)


class UserLogin(BaseModel):
    username: str = Field(..., min_length=1, max_length=50)
    password: str = Field(..., min_length=1, max_length=128)


class UserProfileResponse(BaseModel):
    id: str
    username: str
    email: str
    role: str
    is_active: bool
    created_at: str | None = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: str


# ------------------------------------------------------------------ #
# Dashboard
# ------------------------------------------------------------------ #

class DashboardStats(BaseModel):
    total_scans: int = 0
    high_risk: int = 0
    suspicious: int = 0
    low_risk: int = 0
    url_analyses: int = 0
    email_analyses: int = 0
    qr_scans: int = 0
    social_analyses: int = 0
    image_analyses: int = 0
    video_analyses: int = 0
    average_score: int = 0


class RecentEvent(BaseModel):
    id: str
    type: str
    input: str
    score: int
    risk: str
    source: str
    timestamp: str


class DashboardResponse(BaseModel):
    stats: DashboardStats
    categories: dict[str, int]
    recent_events: list[RecentEvent]


# ------------------------------------------------------------------ #
# Admin
# ------------------------------------------------------------------ #

class AdminUserSummary(BaseModel):
    id: str
    username: str
    email: str
    role: str
    is_active: bool
    total_scans: int
    created_at: str | None = None


class AdminOverview(BaseModel):
    total_users: int
    total_analyses: int
    high_risk_count: int
    suspicious_count: int
    low_risk_count: int
    recent_events: list[RecentEvent]
