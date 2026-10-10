"""
CyberGuard Authentication Route
Register, login, logout, and profile endpoints.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Cookie, Depends, HTTPException, status
from fastapi.responses import JSONResponse

from app.config import settings
from app.database import Base, engine, get_db
from app.models import User
from app.schemas import UserLogin, UserProfileResponse, UserRegister
from app.security import create_access_token, decode_token, hash_password, verify_password
from app.utils.helpers import generate_event_id, log_security_event
from sqlalchemy import select
from sqlalchemy.orm import Session

router = APIRouter()


# ------------------------------------------------------------------ #
# Dependency — extract user from token
# ------------------------------------------------------------------ #

def _get_current_user(
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
    stmt = select(User).where(User.username == username, User.is_active == True)
    result = db.execute(stmt)
    return result.scalar_one_or_none()


def _require_admin(user: User | None) -> User:
    """Require an admin user. Raises 403 if not admin."""
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )
    if user.role != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required.",
        )
    return user


# ------------------------------------------------------------------ #
# Register
# ------------------------------------------------------------------ #

@router.post(
    "/auth/register",
    response_model=dict,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user.",
    tags=["Authentication"],
)
def register(
    request: UserRegister,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """
    Create a new user account. Passwords are hashed with bcrypt.

    The first registered user is assigned the ADMIN role.
    Subsequent users are assigned the USER role.

    Returns success status and a message. No token is returned —
    the user must log in after registration.
    """
    # Check if username exists
    existing = db.execute(
        select(User).where(User.username == request.username)
    ).scalar_one_or_none()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered.",
        )

    # Check if email exists
    existing_email = db.execute(
        select(User).where(User.email == request.email)
    ).scalar_one_or_none()
    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered.",
        )

    # First user gets ADMIN role
    total_users = db.execute(select(User)).scalars().all()
    role = "ADMIN" if len(total_users) == 0 else "USER"

    user = User(
        username=request.username,
        email=request.email,
        hashed_password=hash_password(request.password),
        role=role,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    log_security_event("user_registered", {"username": user.username, "role": role})

    return {
        "success": True,
        "message": f"Account created. Role: {role}.",
        "role": role,
    }


# ------------------------------------------------------------------ #
# Login
# ------------------------------------------------------------------ #

@router.post(
    "/auth/login",
    response_model=dict,
    summary="Log in and receive an access token.",
    tags=["Authentication"],
)
def login(
    request: UserLogin,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """
    Authenticate with username and password. Returns a JWT access token
    set as an HttpOnly cookie.
    """
    user = db.execute(
        select(User).where(User.username == request.username)
    ).scalar_one_or_none()

    if not user or not verify_password(request.password, user.hashed_password):
        log_security_event("login_failed", {"username": request.username})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled.",
        )

    token = create_access_token({"sub": user.username})

    log_security_event("login_success", {"username": user.username, "role": user.role})

    response = JSONResponse(
        content={
            "success": True,
            "username": user.username,
            "role": user.role,
        }
    )
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        samesite="lax",
        secure=not settings.DEBUG,
    )
    return response


# ------------------------------------------------------------------ #
# Logout
# ------------------------------------------------------------------ #

@router.post(
    "/auth/logout",
    summary="Log out (clear the access token cookie).",
    tags=["Authentication"],
)
def logout() -> dict[str, Any]:
    """Clear the access token cookie."""
    response = JSONResponse(content={"success": True, "message": "Logged out."})
    response.delete_cookie("access_token")
    return response


# ------------------------------------------------------------------ #
# Profile
# ------------------------------------------------------------------ #

@router.get(
    "/auth/me",
    response_model=UserProfileResponse,
    summary="Get current user profile.",
    tags=["Authentication"],
)
def get_profile(current_user: User | None = Depends(_get_current_user)) -> UserProfileResponse:
    """Return the current authenticated user's profile."""
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated.",
        )
    return UserProfileResponse(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        role=current_user.role,
        is_active=current_user.is_active,
        created_at=current_user.created_at.isoformat() if current_user.created_at else None,
    )


# ------------------------------------------------------------------ #
# Init tables (development only — not an API endpoint)
# ------------------------------------------------------------------ #

def init_database() -> None:
    """Create all database tables. Call this once at startup in development."""
    Base.metadata.create_all(bind=engine)
