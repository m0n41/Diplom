import time
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.config import settings

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: bytes) -> bool:
    """
    Verify a plain password against a stored bcrypt hash.
    """
    return pwd_context.verify(plain_password, hashed_password.decode("utf-8"))


def get_password_hash(password: str) -> bytes:
    """
    Generate a bcrypt hash for the given password.
    Returns the hash as UTF‑8 encoded bytes to match the DB column type.
    """
    return pwd_context.hash(password).encode("utf-8")


def create_access_token(
    subject: Dict[str, Any], expires_delta: Optional[timedelta] = None
) -> str:
    """
    Create a signed JWT access token.
    ``subject`` must contain at least ``sub`` (user id) and can include any additional claims.
    """
    to_encode = subject.copy()
    now = datetime.utcnow()
    to_encode.update({"iat": now, "nbf": now})

    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})

    encoded_jwt = jwt.encode(
        to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM
    )
    return encoded_jwt


def create_refresh_token(
    subject: Dict[str, Any], expires_delta: Optional[timedelta] = None
) -> str:
    """
    Create a signed JWT refresh token.
    The payload is minimal – only ``sub`` and ``jti`` (unique token identifier).
    """
    to_encode = {"sub": str(subject.get("sub"))}
    now = datetime.utcnow()
    to_encode.update({"iat": now, "nbf": now})

    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "jti": str(int(time.time() * 1_000_000))})
    encoded_jwt = jwt.encode(
        to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM
    )
    return encoded_jwt


def decode_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Decode a JWT token without verification (used only for extracting ``jti`` when needed).
    Returns ``None`` on error.
    """
    try:
        return jwt.get_unverified_claims(token)
    except JWTError:
        return None


def verify_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Verify signature and expiration of a JWT.
    Returns the decoded payload on success, ``None`` otherwise.
    """
    try:
        payload = jwt.decode(
            token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
        return payload
    except JWTError:
        return None
