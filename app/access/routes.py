from fastapi import APIRouter, Depends, HTTPException
from typing import Any

from app.authorization.pep import pep_dependency

router = APIRouter()


@router.get("/check", tags=["access"])
def check_access(payload: Any = Depends(pep_dependency)):
    """
    Simple endpoint to demonstrate the PEP.
    Returns the decoded JWT payload when access is permitted.
    """
    return {"detail": "access granted", "payload": payload}
