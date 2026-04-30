from datetime import datetime
from typing import Any, Dict

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.security import verify_token
from app.db.session import get_db
from app.authorization.pdp import get_default_pdp, DecisionResult
from app.audit.service import log_audit_event


def pep_dependency(
    request: Request,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    FastAPI dependency acting as Policy Enforcement Point.
    It extracts the JWT, validates it, builds the full context,
    invokes the PDP and logs the decision.
    On denial it raises HTTPException with appropriate status.
    Returns the decoded token payload when access is permitted.
    """
    # ------------------------------------------------------------------ #
    # 1️⃣ Extract JWT from Authorization header
    # ------------------------------------------------------------------ #
    auth: str | None = request.headers.get("Authorization")
    if not auth or not auth.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = auth.split(" ", 1)[1]

    # ------------------------------------------------------------------ #
    # 2️⃣ Verify token signature & expiration
    # ------------------------------------------------------------------ #
    payload = verify_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # ------------------------------------------------------------------ #
    # 3️⃣ Build evaluation context
    # ------------------------------------------------------------------ #
    # Extract request‑specific data
    client_ip = request.client.host if request.client else "unknown"
    client_type = request.headers.get("User-Agent", "unknown")
    environment = {
        "timestamp": datetime.utcnow(),
        "ip_address": client_ip,
        "client_type": client_type,
    }

    # Identify the requested action and resource
    # Convention: HTTP method + path as action, path param ``resource_id`` if present
    action = f"{request.method}:{request.url.path}"
    # Attempt to extract a ``resource_id`` path parameter (FastAPI stores it in request.path_params)
    resource_id = request.path_params.get("resource_id") or request.path_params.get(
        "id"
    )

    # ------------------------------------------------------------------ #
    # 4️⃣ Decision
    # ------------------------------------------------------------------ #
    pdp = get_default_pdp()
    decision: DecisionResult = pdp.decide(
        db=db,
        subject=payload,
        action=action,
        resource_id=str(resource_id) if resource_id else None,
        environment=environment,
    )

    # ------------------------------------------------------------------ #
    # 5️⃣ Audit log (best‑effort – never interrupt main flow)
    # ------------------------------------------------------------------ #
    log_audit_event(
        db=db,
        user_id=payload.get("sub"),
        action=action,
        resource_id=str(resource_id) if resource_id else None,
        decision="PERMIT" if decision.permit else "DENY",
        permission_id=None,
        deny_reason=decision.reason,
        context_snapshot=environment,
    )

    # ------------------------------------------------------------------ #
    # 6️⃣ Enforce decision
    # ------------------------------------------------------------------ #
    if not decision.permit:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied: {decision.reason}",
        )

    # Return the verified token payload for downstream handlers
    return payload
