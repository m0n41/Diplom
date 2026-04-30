import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from datetime import datetime
from pydantic_settings import BaseSettings
from pydantic import Field, PostgresDsn, validator


class Settings(BaseSettings):
    # Application
    HOST: str = Field("0.0.0.0", description="FastAPI host")
    PORT: int = Field(8000, description="FastAPI port")
    DEBUG: bool = Field(
        False, description="Enable reload in development", env="APP_DEBUG"
    )
    TITLE: str = Field(
        "Automated Information System for Authentication and Access Control with Centralized Audit",
        description="Application title",
    )

    # Security
    JWT_SECRET_KEY: str = Field(..., env="JWT_SECRET_KEY")
    JWT_ALGORITHM: str = Field("HS256", description="Algorithm for JWT")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(15, description="Access token lifetime")
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(30, description="Refresh token lifetime")
    BCRYPT_ROUNDS: int = Field(12, description="Bcrypt work factor")

    # Database
    POSTGRES_DSN: PostgresDsn = Field(..., env="POSTGRES_DSN")
    DATABASE_ECHO: bool = Field(False, description="SQLAlchemy echo flag")

    # Misc
    LOG_LEVEL: str = Field("INFO", description="Logging level")

    @validator("LOG_LEVEL")
    def validate_log_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v.upper() not in allowed:
            raise ValueError(f"Invalid LOG_LEVEL '{v}'. Must be one of {allowed}")
        return v.upper()

    @validator("DEBUG", pre=True)
    def parse_debug(cls, v):
        """
        Convert various string representations to bool.
        Accepts: 'true', '1', 'yes', 'on' → True
        Anything else (e.g., 'release', 'false', '') → False
        """
        if isinstance(v, str):
            return v.strip().lower() in {"true", "1", "yes", "on"}
        return bool(v)

    class Config:
        env_file = ".env"
        case_sensitive = True

    def utcnow(self) -> datetime:
        """Return current UTC datetime. Used throughout the project for timestamps."""
        return datetime.utcnow()


# Instantiate settings for import elsewhere
settings = Settings()
