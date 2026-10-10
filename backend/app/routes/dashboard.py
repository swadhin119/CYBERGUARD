"""
CyberGuard Dashboard Route
User dashboard and admin overview endpoints.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Cookie, Depends, HTTPException, status

from app.database import get_db
from app.models import AnalysisEvent, User
from app.schemas import AdminOverview, DashboardResponse, RecentEvent
from app.security import decode_token
from app.utils.helpers import utc_now
from sqlalchemy import func, select
from sqlalchemy.orm import Session

router = APIRouter()


# ------------------------------------------------------------------ #
# Dependency — extract user from token cookie
# ------------------------------------------------------------------ #

def get_current_user(
    token: str | None = Cookie(default=None, alias="access_token"),
    db: Session = Depends(get_db),
) -> User | None:
    """Extract the current authenticated user from the JWT cookie."""
    if not token:
        return None
    payload = decode_token(token)
    if not payload:
        return None
    username = payload.get("sub")
    if not username:
        return None
    result = db.execute(
        select(User).where(User.username == username, User.is_active == True)
    )
    return result.scalar_one_or_none()


def require_admin(current_user: User | None = Depends(get_current_user)) -> User:
    """Require an admin user. Raises 401/403 if not authenticated or not admin."""
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )
    if current_user.role != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required.",
        )
    return current_user


# ------------------------------------------------------------------ #
# User dashboard
# ------------------------------------------------------------------ #

@router.get(
    "/dashboard",
    response_model=DashboardResponse,
    summary="Get the current user's dashboard statistics.",
    tags=["Dashboard"],
)
def get_dashboard(
    current_user: User | None = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DashboardResponse:
    """
    Return the current user's analysis statistics, category breakdown,
    and recent events. If not authenticated, returns an empty dashboard.
    """
    from app.schemas import DashboardStats

    if not current_user:
        return DashboardResponse(
            stats=DashboardStats(),
            categories={},
            recent_events=[],
        )

    user_events = db.execute(
        select(AnalysisEvent).where(AnalysisEvent.user_id == current_user.id)
    ).scalars().all()

    stats = DashboardStats(total_scans=len(user_events))

    categories: dict[str, int] = {}
    recent: list[RecentEvent] = []

    for event in user_events:
        risk_label = str(event.risk or "LOW").upper()
        if risk_label == "HIGH":
            stats.high_risk += 1
        elif risk_label == "SUSPICIOUS":
            stats.suspicious += 1
        else:
            stats.low_risk += 1

        atype = event.analysis_type or "other"
        categories[atype] = categories.get(atype, 0) + 1

        if atype == "url":
            stats.url_analyses += 1
        elif atype == "email":
            stats.email_analyses += 1
        elif atype == "qr":
            stats.qr_scans += 1
        elif atype == "social":
            stats.social_analyses += 1
        elif atype == "image":
            stats.image_analyses += 1
        elif atype == "video":
            stats.video_analyses += 1

    # Average score
    scores = [e.score or 0 for e in user_events]
    stats.average_score = round(sum(scores) / len(scores)) if scores else 0

    # Recent events
    for event in user_events:
        ts = event.created_at.strftime("%Y-%m-%dT%H:%M:%SZ") if event.created_at else ""
        recent.append(RecentEvent(
            id=event.id,
            type=event.analysis_type or "other",
            input=event.input_label or "",
            score=event.score or 0,
            risk=str(event.risk or "LOW").upper(),
            source="CyberGuard",
            timestamp=ts,
        ))

    recent.sort(key=lambda x: x.timestamp, reverse=True)
    recent = recent[:20]

    return DashboardResponse(stats=stats, categories=categories, recent_events=recent)


# ------------------------------------------------------------------ #
# Admin overview
# ------------------------------------------------------------------ #

@router.get(
    "/dashboard/admin",
    response_model=AdminOverview,
    summary="Get system-wide statistics (admin only).",
    tags=["Admin"],
)
def get_admin_overview(
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AdminOverview:
    """Return system-wide statistics. Requires admin role."""
    total_users = db.execute(select(func.count(User.id))).scalar() or 0
    total_analyses = db.execute(select(func.count(AnalysisEvent.id))).scalar() or 0

    high_risk = db.execute(
        select(func.count(AnalysisEvent.id)).where(AnalysisEvent.risk == "HIGH")
    ).scalar() or 0
    suspicious_count = db.execute(
        select(func.count(AnalysisEvent.id)).where(AnalysisEvent.risk == "SUSPICIOUS")
    ).scalar() or 0
    low_risk = db.execute(
        select(func.count(AnalysisEvent.id)).where(AnalysisEvent.risk == "LOW")
    ).scalar() or 0

    recent_events_rows = db.execute(
        select(AnalysisEvent).order_by(AnalysisEvent.created_at.desc()).limit(20)
    ).scalars().all()

    recent_events = []
    for event in recent_events_rows:
        ts = event.created_at.strftime("%Y-%m-%dT%H:%M:%SZ") if event.created_at else ""
        recent_events.append(RecentEvent(
            id=event.id,
            type=event.analysis_type or "other",
            input=event.input_label or "",
            score=event.score or 0,
            risk=str(event.risk or "LOW").upper(),
            source="CyberGuard",
            timestamp=ts,
        ))

    return AdminOverview(
        total_users=total_users,
        total_analyses=total_analyses,
        high_risk_count=high_risk,
        suspicious_count=suspicious_count,
        low_risk_count=low_risk,
        recent_events=recent_events,
    )
