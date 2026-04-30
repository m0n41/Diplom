from datetime import timedelta
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.config import settings
from app.core.security import (
    get_password_hash,
    verify_password,
    create_access_token,
    create_refresh_token,
)
from app.db.session import get_db
from app.models.models import RefreshToken, User
from app.auth.schemas import LoginRequest, TokenResponse, RefreshRequest, LogoutRequest
from app.audit.service import log_audit_event

router = APIRouter()

# Simple in‑memory brute‑force guard (username → {count, first_attempt})
_brute_force: Dict[str, Dict[str, Any]] = {}


def _reset_brute_force(username: str):
    _brute_force.pop(username, None)


def _check_brute_force(username: str):
    data = _brute_force.get(username)
    if not data:
        return
    # block after 5 attempts within 5 minutes
    if data["count"] >= 5 and (settings.utcnow() - data["first"]).total_seconds() < 300:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts, try again later",
        )
    if (
        data["count"] >= 5
        and (settings.utcnow() - data["first"]).total_seconds() >= 300
    ):
        _reset_brute_force(username)


def _store_refresh_token(db: Session, user: User, token: str) -> RefreshToken:
    """
    Store a hashed refresh token linked to the user.
    """
    token_hash = get_password_hash(token)
    rt = RefreshToken(
        user_id=user.id,
        token_hash=token_hash,
        issued_at=settings.utcnow(),
        expires_at=settings.utcnow()
        + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        revoked=False,
    )
    db.add(rt)
    db.commit()
    db.refresh(rt)
    return rt


@router.post("/login", response_model=TokenResponse, tags=["auth"])
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    # Brute‑force check
    _check_brute_force(payload.username)

    user = db.query(User).filter(User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.password_hash):
        # record failed attempt
        entry = _brute_force.setdefault(
            payload.username, {"count": 0, "first": settings.utcnow()}
        )
        entry["count"] += 1
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    _reset_brute_force(payload.username)

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User is inactive",
        )

    subject = {
        "sub": str(user.id),
        "roles": [{"name": role.name} for role in user.roles],
    }
    access_token = create_access_token(subject)
    refresh_token = create_refresh_token(subject)

    _store_refresh_token(db, user, refresh_token)

    log_audit_event(
        db=db,
        user_id=user.id,
        action="login",
        resource_id=None,
        decision="PERMIT",
        permission_id=None,
        deny_reason=None,
        context_snapshot={"ip_address": "N/A", "client_type": "N/A"},
    )

    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


@router.post("/refresh", response_model=TokenResponse, tags=["auth"])
def refresh(payload: RefreshRequest, db: Session = Depends(get_db)):
    possible_tokens = (
        db.query(RefreshToken).filter(RefreshToken.revoked == False).all()  # noqa: E712
    )
    token_record: RefreshToken | None = None
    for rt in possible_tokens:
        if verify_password(payload.refresh_token, rt.token_hash):
            token_record = rt
            break

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token invalid or revoked",
        )

    if token_record.expires_at < settings.utcnow():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token expired",
        )

    user = db.query(User).filter(User.id == token_record.user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User is inactive",
        )

    subject = {"sub": str(user.id)}
    new_access = create_access_token(subject)

    log_audit_event(
        db=db,
        user_id=user.id,
        action="refresh",
        resource_id=None,
        decision="PERMIT",
        permission_id=None,
        deny_reason=None,
        context_snapshot={"ip_address": "N/A", "client_type": "N/A"},
    )

    return TokenResponse(access_token=new_access, refresh_token=payload.refresh_token)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT, tags=["auth"])
def logout(payload: LogoutRequest, db: Session = Depends(get_db)):
    possible_tokens = (
        db.query(RefreshToken).filter(RefreshToken.revoked == False).all()  # noqa: E712
    )
    token_record: RefreshToken | None = None
    for rt in possible_tokens:
        if verify_password(payload.refresh_token, rt.token_hash):
            token_record = rt
            break

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Refresh token not found or already revoked",
        )

    token_record.revoked = True
    db.add(token_record)
    db.commit()

    log_audit_event(
        db=db,
        user_id=token_record.user_id,
        action="logout",
        resource_id=None,
        decision="PERMIT",
        permission_id=None,
        deny_reason=None,
        context_snapshot={"ip_address": "N/A", "client_type": "N/A"},
    )
