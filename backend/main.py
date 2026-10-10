"""
CyberGuard Backend — Application Entry Point
Modular FastAPI application with structured routing, environment-based
configuration, CORS, security headers, and structured logging.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from app.config import settings
from app.routes import dashboard, email, qr, social, url, video, image, auth
from app.utils.helpers import setup_logging

# ------------------------------------------------------------------ #
# Logging
# ------------------------------------------------------------------ #

setup_logging(debug=settings.DEBUG)
logger = logging.getLogger("cyberguard")

logger.info(
    "Starting %s v%s | debug=%s",
    settings.APP_NAME,
    settings.APP_VERSION,
    settings.DEBUG,
)

# ------------------------------------------------------------------ #
# FastAPI application
# ------------------------------------------------------------------ #

app = FastAPI(
    title=settings.APP_NAME,
    description=(
        "AI-powered cybersecurity and digital threat analysis platform. "
        "Analyses URLs, emails, QR codes, social media profiles, "
        "images, and videos for suspicious indicators."
    ),
    version=settings.APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ------------------------------------------------------------------ #
# CORS — origins from environment variable
# ------------------------------------------------------------------ #

cors_origins = [
    origin.strip()
    for origin in settings.CORS_ORIGINS.split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins if cors_origins else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------------------------------------------ #
# Trusted host — only enforce in production
# ------------------------------------------------------------------ #

if not settings.DEBUG:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["*"],  # Configure for production domains
    )

# ------------------------------------------------------------------ #
# Security headers middleware
# ------------------------------------------------------------------ #

@app.middleware("http")
async def security_headers_middleware(request, call_next):  # type: ignore[no-untyped-def]
    """Add security-relevant HTTP headers to every response."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if not settings.DEBUG:
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
    return response

# ------------------------------------------------------------------ #
# Request logging middleware
# ------------------------------------------------------------------ #

@app.middleware("http")
async def log_requests(request, call_next):  # type: ignore[no-untyped-def]
    """Log every incoming request."""
    logger.info(
        "REQUEST | %s %s | client=%s",
        request.method,
        request.url.path,
        request.client.host if request.client else "unknown",
    )
    response = await call_next(request)
    logger.info(
        "RESPONSE | %s %s | status=%s",
        request.method,
        request.url.path,
        response.status_code,
    )
    return response

# ------------------------------------------------------------------ #
# Database initialization (development)
# ------------------------------------------------------------------ #

from app.database import Base, engine  # noqa: E402

Base.metadata.create_all(bind=engine)
logger.info("Database tables initialized.")

# ------------------------------------------------------------------ #
# Route registration
# ------------------------------------------------------------------ #

app.include_router(url.router, prefix="/api")
app.include_router(email.router, prefix="/api")
app.include_router(qr.router, prefix="/api")
app.include_router(social.router, prefix="/api")
app.include_router(image.router, prefix="/api")
app.include_router(video.router, prefix="/api")
app.include_router(auth.router, prefix="/api")
app.include_router(dashboard.router, prefix="/api")

# ------------------------------------------------------------------ #
# Health & root
# ------------------------------------------------------------------ #

@app.get(
    "/",
    tags=["Health"],
    summary="Service health check.",
    response_model=dict,
)
def root() -> dict:
    """
    Return service status, message, and version.
    """
    return {
        "status": "online",
        "message": "CyberGuard Backend is running",
        "version": settings.APP_VERSION,
    }


@app.get(
    "/health",
    tags=["Health"],
    summary="Detailed health check.",
    response_model=dict,
)
def health() -> dict:
    """
    Return service health status.
    """
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
    }


# ------------------------------------------------------------------ #
# Startup / shutdown events
# ------------------------------------------------------------------ #

@app.on_event("startup")
async def on_startup() -> None:
    """Log application startup."""
    logger.info("CyberGuard backend ready on %s:%s", settings.HOST, settings.PORT)


@app.on_event("shutdown")
async def on_shutdown() -> None:
    """Log application shutdown."""
    logger.info("CyberGuard backend shutting down.")
