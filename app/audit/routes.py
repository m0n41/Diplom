from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from typing import List, Optional

from app.db.session import get_db
from app.models.models import AuditEvent
from app.authorization.pep import pep_dependency

router = APIRouter()


@router.get("/events", response_model=List[dict], tags=["audit"])
def list_audit_events(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    payload: dict = Depends(pep_dependency),  # protected by PEP
):
    """
    Retrieve audit events. Requires a valid token and passing PDP.
    """
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Access denied"
        )
    events = (
        db.query(AuditEvent)
        .order_by(AuditEvent.timestamp.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    # Convert to simple dicts for JSON serialization
    return [e.__dict__ for e in events]
