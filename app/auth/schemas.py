from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, UUID4


class TokenResponse(BaseModel):
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field("bearer", description="Token type")


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=150)
    password: str = Field(..., min_length=6)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(..., description="Refresh token issued at login")


class LogoutRequest(BaseModel):
    refresh_token: str = Field(..., description="Refresh token to revoke")
