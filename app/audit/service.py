from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from app.models.models import AuditEvent
from app.config import settings


def log_audit_event(
    *,
    db: Session,
    user_id: Optional[str],
    action: str,
    resource_id: Optional[str],
    decision: str,
    permission_id: Optional[str],
    deny_reason: Optional[str],
    context_snapshot: Dict[str, Any],
) -> AuditEvent:
    """
    Persist an immutable audit event.
    This function never raises – any DB error is caught and ignored to avoid breaking the main flow.
    """
    event = AuditEvent(
        timestamp=datetime.utcnow(),
        user_id=user_id,
        action=action,
        resource_id=resource_id,
        decision=decision,
        permission_id=permission_id,
        deny_reason=deny_reason,
        context_snapshot=str(context_snapshot),
        ip_address=context_snapshot.get("ip_address"),
        client_type=context_snapshot.get("client_type"),
    )
    try:
        db.add(event)
        db.commit()
        db.refresh(event)
    except Exception:
        # Swallow any logging failure – audit must not affect business logic
        db.rollback()
    return event
