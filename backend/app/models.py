"""
CyberGuard ORM Models
SQLAlchemy database table definitions.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.database import Base
from app.utils.helpers import utc_now


# ------------------------------------------------------------------ #
# Mixin — common timestamps
# ------------------------------------------------------------------ #

class TimestampMixin:
    """Add created_at / updated_at columns automatically."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )


# ------------------------------------------------------------------ #
# User
# ------------------------------------------------------------------ #

class User(Base, TimestampMixin):
    """
    Application user.

    Roles: ``USER`` or ``ADMIN``.
    Passwords are stored as bcrypt hashes — never plaintext.
    """

    __tablename__ = "users"

    # Use UUID on PostgreSQL, string fallback for SQLite
    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    username: Mapped[str] = mapped_column(
        String(50),
        unique=True,
        nullable=False,
        index=True,
    )
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
    )
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(20), default="USER", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


# ------------------------------------------------------------------ #
# AnalysisEvent
# ------------------------------------------------------------------ #

class AnalysisEvent(Base, TimestampMixin):
    """
    A single security analysis event.

    Stores the result of a URL, email, QR, social, image, or video scan.
    Does NOT store raw sensitive inputs (email body, QR content, etc.)
    — only metadata sufficient for the dashboard and history.
    """

    __tablename__ = "analysis_events"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    user_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        nullable=True,
        index=True,
    )
    analysis_type: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        index=True,
    )
    input_label: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
    )
    score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk: Mapped[str] = mapped_column(String(20), nullable=False, default="LOW")
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    indicators: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    recommendation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


# ------------------------------------------------------------------ #
# SecurityLog
# ------------------------------------------------------------------ #

class SecurityLog(Base, TimestampMixin):
    """
    Security and audit log entries.

    Records authentication events, rate-limit violations,
    and other security-relevant actions.
    """

    __tablename__ = "security_logs"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    event_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
