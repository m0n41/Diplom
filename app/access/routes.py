from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from typing import Any

from app.access.schemas import AccessCheckRequest
from app.authorization.pdp import get_default_pdp, DecisionResult
from app.audit.service import log_audit_event
from app.core.security import verify_token
from app.db.session import get_db

router = APIRouter()


@router.post("/check", tags=["access"])
def check_access(
    request: Request,
    body: AccessCheckRequest,
    db: Session = Depends(get_db),
):
    """
    Проверка доступа к ресурсу.
    Верифицирует JWT, вызывает PDP, логирует решение в аудит.
    """
    # 1. Извлечь и верифицировать JWT
    auth = request.headers.get("Authorization")
    if not auth or not auth.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = auth.split(" ", 1)[1]
    payload = verify_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 2. Построить environment
    client_ip = request.client.host if request.client else "unknown"
    client_type = request.headers.get("User-Agent", "unknown")
    environment = {
        "timestamp": datetime.utcnow(),
        "ip_address": client_ip,
        "client_type": client_type,
    }

    # 3. Вызвать PDP
    pdp = get_default_pdp()
    decision: DecisionResult = pdp.decide(
        db=db,
        subject=payload,
        action=body.action,
        resource_id=body.resource_id,
        environment=environment,
    )

    # 4. Аудит
    log_audit_event(
        db=db,
        user_id=payload.get("sub"),
        action=f"{body.action}:{body.resource_id}",
        resource_id=body.resource_id,
        decision="PERMIT" if decision.permit else "DENY",
        permission_id=None,
        deny_reason=decision.reason,
        context_snapshot=environment,
    )

    # 5. Вернуть результат
    if decision.permit:
        return {
            "decision": "PERMIT",
            "resource_id": body.resource_id,
            "action": body.action,
        }
    else:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "decision": "DENY",
                "reason": decision.reason,
                "details": decision.details,
            },
        )
