from datetime import datetime, time as dtime
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.core.identity_provider import IdentityProvider
from app.models.models import Permission, Resource, Role, User


class DecisionResult:
    """
    Simple container for PDP decision.
    ``permit`` – bool indicating if access is allowed.
    ``reason`` – machine‑readable denial reason (e.g. ``AUTH``, ``RBAC``, ``ABAC``, ``ERROR``).
    ``details`` – optional dict with extra diagnostic information.
    """

    def __init__(
        self,
        permit: bool,
        reason: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        self.permit = permit
        self.reason = reason
        self.details = details or {}

    def as_dict(self) -> Dict[str, Any]:
        return {"permit": self.permit, "reason": self.reason, "details": self.details}


class PDP:
    """
    Policy Decision Point – pure business logic, no FastAPI dependencies.
    The decision flow follows the strict order defined in the specification:

    1️⃣  Validate token (handled by PEP – we receive a *subject* payload that is already trusted).
    2️⃣  Load user, check ``is_active``.
    3️⃣  RBAC – check whether the user has a permission that matches the requested ``action`` on the ``resource``.
    4️⃣  ABAC – evaluate static predicates (time‑based, IP‑based). These predicates can only *restrict*.
    5️⃣  Return deterministic decision with explicit ``reason`` when denied.
    """

    def __init__(self, identity_provider: IdentityProvider):
        self.idp = identity_provider

    # --------------------------------------------------------------------- #
    # ABAC predicates – can be expanded later
    # --------------------------------------------------------------------- #
    @staticmethod
    def _time_allowed(environment: Dict[str, Any]) -> bool:
        """
        Allow access only between 08:00 and 18:00 UTC.
        The ``environment`` dict must contain a ``timestamp`` key with a ``datetime``.
        """
        ts: datetime = environment.get("timestamp")
        if not isinstance(ts, datetime):
            return False
        start = dtime(hour=8, minute=0, second=0)
        end = dtime(hour=18, minute=0, second=0)
        return start <= ts.time() <= end

    @staticmethod
    def _ip_allowed(environment: Dict[str, Any]) -> bool:
        """
        Example restriction: block access from known malicious ranges.
        Here we simply deny private‑network addresses as a placeholder.
        """
        ip: str = environment.get("ip_address", "")
        if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
            return False
        return True

    # --------------------------------------------------------------------- #
    # Core decision algorithm
    # --------------------------------------------------------------------- #
    def decide(
        self,
        db: Session,
        subject: Dict[str, Any],
        action: str,
        resource_id: str,
        environment: Dict[str, Any],
    ) -> DecisionResult:
        """
        ``subject`` – dict from validated JWT, must contain at least ``sub`` (user UUID).
        ``resource_id`` – string/UUID of the target resource.
        ``environment`` – dict with ``timestamp``, ``ip_address`` and optionally ``client_type``.
        Returns a ``DecisionResult``.
        """

        # 1️⃣  Load user and check activity
        user = self.idp.get_user_by_id(db, subject.get("sub"))
        if not user:
            return DecisionResult(
                False, reason="AUTH", details={"msg": "user not found"}
            )
        if not user.is_active:
            return DecisionResult(
                False, reason="AUTH", details={"msg": "user inactive"}
            )

        # 2️⃣  Load resource
        resource = self.idp.get_resource_by_id(db, resource_id)
        if not resource:
            return DecisionResult(
                False, reason="ERROR", details={"msg": "resource not found"}
            )

        # 3️⃣  RBAC evaluation
        roles = self.idp.get_roles_for_user(db, user)
        perms = self.idp.get_permissions_for_roles(db, roles)

        # Build a set of tuples (resource_id, action) for fast lookup
        allowed = {(p.resource_id, p.action) for p in perms}
        if (resource.id, action) not in allowed:
            return DecisionResult(
                False, reason="RBAC", details={"msg": "permission missing"}
            )

        # 4️⃣  ABAC evaluation – predicates can only **restrict**
        if not self._time_allowed(environment):
            return DecisionResult(
                False, reason="ABAC", details={"msg": "outside permitted time window"}
            )
        if not self._ip_allowed(environment):
            return DecisionResult(
                False, reason="ABAC", details={"msg": "blocked IP address"}
            )

        # 5️⃣  All checks passed → Permit
        return DecisionResult(True, reason=None, details={"msg": "access granted"})


# ------------------------------------------------------------------------- #
# Helper to instantiate a global PDP with the default provider.
# ------------------------------------------------------------------------- #
def get_default_pdp() -> PDP:
    from app.core.identity_provider import LocalDatabaseProvider

    return PDP(identity_provider=LocalDatabaseProvider())
