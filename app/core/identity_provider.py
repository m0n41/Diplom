from abc import ABC, abstractmethod
from typing import Optional, Sequence

from sqlalchemy.orm import Session

from app.models.models import User, Role, Permission, Resource


class IdentityProvider(ABC):
    """
    Abstract base class for identity sources.
    Implementations must provide methods to retrieve users, roles and permissions.
    """

    @abstractmethod
    def get_user_by_username(self, db: Session, username: str) -> Optional[User]: ...

    @abstractmethod
    def get_user_by_id(self, db: Session, user_id) -> Optional[User]: ...

    @abstractmethod
    def get_roles_for_user(self, db: Session, user: User) -> Sequence[Role]: ...

    @abstractmethod
    def get_permissions_for_roles(
        self, db: Session, roles: Sequence[Role]
    ) -> Sequence[Permission]: ...

    @abstractmethod
    def get_resource_by_id(self, db: Session, resource_id) -> Optional[Resource]: ...


class LocalDatabaseProvider(IdentityProvider):
    """
    Default provider that uses the local PostgreSQL database.
    """

    def get_user_by_username(self, db: Session, username: str) -> Optional[User]:
        return db.query(User).filter(User.username == username).first()

    def get_user_by_id(self, db: Session, user_id) -> Optional[User]:
        return db.query(User).filter(User.id == user_id).first()

    def get_roles_for_user(self, db: Session, user: User) -> Sequence[Role]:
        # ``user.roles`` is already loaded lazily by SQLAlchemy
        return user.roles

    def get_permissions_for_roles(
        self, db: Session, roles: Sequence[Role]
    ) -> Sequence[Permission]:
        perms = []
        for role in roles:
            perms.extend(role.permissions)
        # De‑duplicate while preserving order
        seen = set()
        unique = []
        for p in perms:
            if p.id not in seen:
                seen.add(p.id)
                unique.append(p)
        return unique

    def get_resource_by_id(self, db: Session, resource_id) -> Optional[Resource]:
        return db.query(Resource).filter(Resource.id == resource_id).first()
