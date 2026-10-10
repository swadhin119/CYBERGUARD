"""
CyberGuard Backend Configuration
Loads settings from environment variables with safe defaults.
Production secrets must be supplied via .env — never hardcoded.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ------------------------------------------------------------------ #
    # Application
    # ------------------------------------------------------------------ #
    APP_NAME: str = "CyberGuard API"
    APP_VERSION: str = "2.0.0"
    DEBUG: bool = False

    # ------------------------------------------------------------------ #
    # Server
    # ------------------------------------------------------------------ #
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    RELOAD: bool = True

    # ------------------------------------------------------------------ #
    # CORS
    # Comma-separated origin list.  "*" is development-friendly but
    # must be replaced with explicit origins in production.
    # ------------------------------------------------------------------ #
    CORS_ORIGINS: str = "*"

    # ------------------------------------------------------------------ #
    # Trusted hosts (production only)
    # ------------------------------------------------------------------ #
    TRUSTED_HOSTS: str = ""

    # ------------------------------------------------------------------ #
    # Authentication
    # Must be set to a strong random value in production.
    # ------------------------------------------------------------------ #
    SECRET_KEY: str = "cyberguard-dev-secret-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # ------------------------------------------------------------------ #
    # Database
    # SQLite for local development.
    # Switch DATABASE_URL to a PostgreSQL DSN for production, e.g.:
    #   postgresql://user:password@host:5432/cyberguard
    # ------------------------------------------------------------------ #
    DATABASE_URL: str = "sqlite:///./cyberguard.db"

    # ------------------------------------------------------------------ #
    # Analysis limits
    # ------------------------------------------------------------------ #
    MAX_EMAIL_BODY_LENGTH: int = 10_000
    MAX_QR_CONTENT_LENGTH: int = 10_000
    MAX_URL_LENGTH: int = 2_048
    MAX_SOCIAL_USERNAME_LENGTH: int = 100
    MAX_DISPLAY_NAME_LENGTH: int = 200
    MAX_FILE_SIZE_MB: int = 50

    # ------------------------------------------------------------------ #
    # Threat Intelligence API keys (optional)
    # Leave blank to use local analysis engines only.
    # ------------------------------------------------------------------ #
    VIRUSTOTAL_API_KEY: str = ""
    GOOGLE_SAFE_BROWSING_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    URLHAUS_API_KEY: str = ""

    # ------------------------------------------------------------------ #
    # Rate limiting
    # ------------------------------------------------------------------ #
    RATE_LIMIT_DEFAULT: str = "100/minute"
    RATE_LIMIT_ANALYSIS: str = "20/minute"


settings = Settings()
