"""
CyberGuard Database Configuration
SQLAlchemy engine and session management.
Uses SQLite for development; switch DATABASE_URL in .env for PostgreSQL.
"""

from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session

from app.config import settings

# ------------------------------------------------------------------ #
# Engine
# ------------------------------------------------------------------ #

connect_args: dict[str, Any] = {}
if settings.DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    echo=settings.DEBUG,
)

# ------------------------------------------------------------------ #
# Session factory
# ------------------------------------------------------------------ #

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

# ------------------------------------------------------------------ #
# Base class for ORM models
# ------------------------------------------------------------------ #

Base = declarative_base()


# ------------------------------------------------------------------ #
# Dependency — used by FastAPI route dependencies
# ------------------------------------------------------------------ #

def get_db() -> Session:
    """
    Yield a database session for the duration of a request.

    Usage in FastAPI::

        def my_route(db: Session = Depends(get_db)):
            ...
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
