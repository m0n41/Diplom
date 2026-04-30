from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from typing import List

from app.db.session import get_db
from app.models.models import (
    User,
    Role,
    Permission,
    Resource,
    user_role_table,
    role_permission_table,
)
from app.identity.schemas import (
    UserRead,
    UserCreate,
    UserUpdate,
    RoleRead,
    RoleCreate,
    RoleUpdate,
    PermissionRead,
    PermissionCreate,
    PermissionUpdate,
    ResourceRead,
    ResourceCreate,
    ResourceUpdate,
    AssignRoleToUser,
    AssignPermissionToRole,
)
from app.core.security import get_password_hash, verify_password, verify_token
from app.authorization.pep import pep_dependency
from app.audit.service import log_audit_event

router = APIRouter()


async def get_current_user(request: Request):
    """
    Simple JWT authentication dependency.
    Expects 'Authorization: Bearer <token>' header.
    Returns decoded token payload or raises 401.
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = auth_header.split(" ", 1)[1]
    payload = verify_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload


def _admin_required(payload: dict = Depends(get_current_user)):
    # Simplified admin check: user must have a role named "admin"
    user_roles = payload.get("roles", [])
    if "admin" not in [r.get("name") for r in user_roles]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return payload


@router.get("/users", response_model=List[UserRead], tags=["identity"])
def list_users(
    db: Session = Depends(get_db), payload: dict = Depends(get_current_user)
):
    # Require any authenticated user; admin can see all, others see only themselves
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    user_id = payload.get("sub")
    if "admin" in [r.get("name") for r in payload.get("roles", [])]:
        users = db.query(User).all()
    else:
        users = db.query(User).filter(User.id == user_id).all()
    return users


@router.post("/users", response_model=UserRead, tags=["identity"])
def create_user(
    user_in: UserCreate,
    db: Session = Depends(get_db),
    payload: dict = Depends(_admin_required),
):
    # Create a new user with hashed password
    hashed = get_password_hash(user_in.password)
    new_user = User(
        username=user_in.username,
        email=user_in.email,
        password_hash=hashed,
        is_active=True,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    log_audit_event(
        db=db,
        user_id=payload.get("sub"),
        action="create_user",
        resource_id=str(new_user.id),
        decision="PERMIT",
        permission_id=None,
        deny_reason=None,
        context_snapshot={"ip_address": "N/A", "client_type": "N/A"},
    )
    return new_user


@router.put("/users/{user_id}", response_model=UserRead, tags=["identity"])
def update_user(
    user_id: str,
    user_in: UserUpdate,
    db: Session = Depends(get_db),
    payload: dict = Depends(_admin_required),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    if user_in.email is not None:
        user.email = user_in.email
    if user_in.is_active is not None:
        user.is_active = user_in.is_active
    if user_in.password is not None:
        user.password_hash = get_password_hash(user_in.password)

    db.add(user)
    db.commit()
    db.refresh(user)

    log_audit_event(
        db=db,
        user_id=payload.get("sub"),
        action="update_user",
        resource_id=str(user.id),
        decision="PERMIT",
        permission_id=None,
        deny_reason=None,
        context_snapshot={"ip_address": "N/A", "client_type": "N/A"},
    )
    return user


@router.delete(
    "/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["identity"]
)
def delete_user(
    user_id: str,
    db: Session = Depends(get_db),
    payload: dict = Depends(_admin_required),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    # Logical deletion
    user.is_active = False
    db.add(user)
    db.commit()

    log_audit_event(
        db=db,
        user_id=payload.get("sub"),
        action="delete_user",
        resource_id=str(user.id),
        decision="PERMIT",
        permission_id=None,
        deny_reason=None,
        context_snapshot={"ip_address": "N/A", "client_type": "N/A"},
    )
    return


# ===== Role Routes =====
@router.get("/roles", response_model=List[RoleRead], tags=["identity"])
def list_roles(db: Session = Depends(get_db), payload: dict = Depends(_admin_required)):
    """List all roles (admin only)."""
    return db.query(Role).all()


@router.post("/roles", response_model=RoleRead, tags=["identity"])
def create_role(
    role_in: RoleCreate,
    db: Session = Depends(get_db),
    payload: dict = Depends(_admin_required),
):
    """Create a new role (admin only)."""
    # Check if role name already exists
    existing = db.query(Role).filter(Role.name == role_in.name).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Role with this name already exists",
        )
    new_role = Role(name=role_in.name, description=role_in.description)
    db.add(new_role)
    db.commit()
    db.refresh(new_role)

    log_audit_event(
        db=db,
        user_id=payload.get("sub"),
        action="create_role",
        resource_id=str(new_role.id),
        decision="PERMIT",
        permission_id=None,
        deny_reason=None,
        context_snapshot={"role_name": role_in.name},
    )
    return new_role


@router.get("/roles/{role_id}", response_model=RoleRead, tags=["identity"])
def get_role(
    role_id: str,
    db: Session = Depends(get_db),
    payload: dict = Depends(_admin_required),
):
    """Get role details (admin only)."""
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Role not found"
        )
    return role


# ===== Test ABAC Endpoint =====
@router.get("/test/abac", tags=["test"], include_in_schema=True)
def test_abac(
    request: Request,
    payload: dict = Depends(get_current_user),
):
    """
    Simple endpoint to verify ABAC enforcement without requiring a resource ID.
    It evaluates the same ABAC predicates (time window and IP filtering) that
    the PEP uses, but skips the RBAC/resource lookup which would otherwise
    cause a failure when no resource_id is supplied.
    """
    # Build environment dictionary (same as in pep_dependency)
    from datetime import datetime
    from app.authorization.pdp import PDP

    environment = {
        "timestamp": datetime.utcnow(),
        "ip_address": request.client.host if request.client else "unknown",
        "client_type": request.headers.get("User-Agent", "unknown"),
    }

    # Apply ABAC predicates – they can only restrict
    if not PDP._time_allowed(environment):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: ABAC (outside permitted time window)",
        )
    if not PDP._ip_allowed(environment):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: ABAC (blocked IP address)",
        )

    return {"detail": "ABAC check passed – access granted"}
    """
    Simple endpoint to verify ABAC enforcement.
    Returns 200 if all ABAC predicates pass,
    otherwise the PEP will raise 403 (or 401) with the denial reason.
    """
    return {"detail": "ABAC check passed – access granted"}


@router.put("/roles/{role_id}", response_model=RoleRead, tags=["identity"])
def update_role(
    role_id: str,
    role_in: RoleUpdate,
    db: Session = Depends(get_db),
    payload: dict = Depends(_admin_required),
):
    """Update a role (admin only)."""
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Role not found"
        )
    if role_in.name is not None:
        # Check for duplicate name
        existing = (
            db.query(Role).filter(Role.name == role_in.name, Role.id != role_id).first()
        )
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Role with this name already exists",
            )
        role.name = role_in.name
    if role_in.description is not None:
        role.description = role_in.description

    db.add(role)
    db.commit()
    db.refresh(role)

    log_audit_event(
        db=db,
        user_id=payload.get("sub"),
        action="update_role",
        resource_id=str(role.id),
        decision="PERMIT",
        permission_id=None,
        deny_reason=None,
        context_snapshot={"role_name": role.name},
    )
    return role


@router.delete(
    "/roles/{role_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["identity"]
)
def delete_role(
    role_id: str,
    db: Session = Depends(get_db),
    payload: dict = Depends(_admin_required),
):
    """Delete a role (admin only). Fails if role is assigned to users."""
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Role not found"
        )
    # Check if role is assigned to any users
    if role.users:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete role assigned to users",
        )
    db.delete(role)
    db.commit()

    log_audit_event(
        db=db,
        user_id=payload.get("sub"),
        action="delete_role",
        resource_id=str(role.id),
        decision="PERMIT",
        permission_id=None,
        deny_reason=None,
        context_snapshot={"role_name": role.name},
    )


# ===== Resource Routes =====
@router.get("/resources", response_model=List[ResourceRead], tags=["identity"])
def list_resources(
    db: Session = Depends(get_db), payload: dict = Depends(_admin_required)
):
    """List all resources (admin only)."""
    return db.query(Resource).all()


@router.post("/resources", response_model=ResourceRead, tags=["identity"])
def create_resource(
    resource_in: ResourceCreate,
    db: Session = Depends(get_db),
    payload: dict = Depends(_admin_required),
):
    """Create a new resource (admin only)."""
    new_resource = Resource(
        name=resource_in.name,
        category=resource_in.category,
        criticality=resource_in.criticality,
    )
    db.add(new_resource)
    db.commit()
    db.refresh(new_resource)

    log_audit_event(
        db=db,
        user_id=payload.get("sub"),
        action="create_resource",
        resource_id=str(new_resource.id),
        decision="PERMIT",
        permission_id=None,
        deny_reason=None,
        context_snapshot={"resource_name": resource_in.name},
    )
    return new_resource


@router.get("/resources/{resource_id}", response_model=ResourceRead, tags=["identity"])
def get_resource(
    resource_id: str,
    db: Session = Depends(get_db),
    payload: dict = Depends(_admin_required),
):
    """Get resource details (admin only)."""
    resource = db.query(Resource).filter(Resource.id == resource_id).first()
    if not resource:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found"
        )
    return resource


@router.put("/resources/{resource_id}", response_model=ResourceRead, tags=["identity"])
def update_resource(
    resource_id: str,
    resource_in: ResourceUpdate,
    db: Session = Depends(get_db),
    payload: dict = Depends(_admin_required),
):
    """Update a resource (admin only)."""
    resource = db.query(Resource).filter(Resource.id == resource_id).first()
    if not resource:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found"
        )
    if resource_in.name is not None:
        resource.name = resource_in.name
    if resource_in.category is not None:
        resource.category = resource_in.category
    if resource_in.criticality is not None:
        resource.criticality = resource_in.criticality

    db.add(resource)
    db.commit()
    db.refresh(resource)

    log_audit_event(
        db=db,
        user_id=payload.get("sub"),
        action="update_resource",
        resource_id=str(resource.id),
        decision="PERMIT",
        permission_id=None,
        deny_reason=None,
        context_snapshot={"resource_name": resource.name},
    )
    return resource


@router.delete(
    "/resources/{resource_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["identity"],
)
def delete_resource(
    resource_id: str,
    db: Session = Depends(get_db),
    payload: dict = Depends(_admin_required),
):
    """Delete a resource (admin only). Fails if resource has permissions."""
    resource = db.query(Resource).filter(Resource.id == resource_id).first()
    if not resource:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found"
        )
    if resource.permissions:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete resource with existing permissions",
        )
    db.delete(resource)
    db.commit()

    log_audit_event(
        db=db,
        user_id=payload.get("sub"),
        action="delete_resource",
        resource_id=str(resource.id),
        decision="PERMIT",
        permission_id=None,
        deny_reason=None,
        context_snapshot={"resource_name": resource.name},
    )


# ===== Permission Routes =====
@router.get("/permissions", response_model=List[PermissionRead], tags=["identity"])
def list_permissions(
    db: Session = Depends(get_db), payload: dict = Depends(_admin_required)
):
    """List all permissions (admin only)."""
    return db.query(Permission).all()


@router.post("/permissions", response_model=PermissionRead, tags=["identity"])
def create_permission(
    permission_in: PermissionCreate,
    db: Session = Depends(get_db),
    payload: dict = Depends(_admin_required),
):
    """Create a new permission for a resource (admin only)."""
    # Check if resource exists
    resource = (
        db.query(Resource).filter(Resource.id == permission_in.resource_id).first()
    )
    if not resource:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found"
        )
    # Check for duplicate permission (resource_id, action)
    existing = (
        db.query(Permission)
        .filter(
            Permission.resource_id == permission_in.resource_id,
            Permission.action == permission_in.action,
        )
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Permission already exists for this resource and action",
        )
    new_permission = Permission(
        action=permission_in.action,
        description=permission_in.description,
        resource_id=permission_in.resource_id,
    )
    db.add(new_permission)
    db.commit()
    db.refresh(new_permission)

    log_audit_event(
        db=db,
        user_id=payload.get("sub"),
        action="create_permission",
        resource_id=str(new_permission.id),
        decision="PERMIT",
        permission_id=str(new_permission.id),
        deny_reason=None,
        context_snapshot={"action": permission_in.action},
    )
    return new_permission


@router.get(
    "/permissions/{permission_id}", response_model=PermissionRead, tags=["identity"]
)
def get_permission(
    permission_id: str,
    db: Session = Depends(get_db),
    payload: dict = Depends(_admin_required),
):
    """Get permission details (admin only)."""
    permission = db.query(Permission).filter(Permission.id == permission_id).first()
    if not permission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Permission not found"
        )
    return permission


@router.put(
    "/permissions/{permission_id}", response_model=PermissionRead, tags=["identity"]
)
def update_permission(
    permission_id: str,
    permission_in: PermissionUpdate,
    db: Session = Depends(get_db),
    payload: dict = Depends(_admin_required),
):
    """Update a permission (admin only)."""
    permission = db.query(Permission).filter(Permission.id == permission_id).first()
    if not permission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Permission not found"
        )
    if permission_in.action is not None:
        permission.action = permission_in.action
    if permission_in.description is not None:
        permission.description = permission_in.description

    db.add(permission)
    db.commit()
    db.refresh(permission)

    log_audit_event(
        db=db,
        user_id=payload.get("sub"),
        action="update_permission",
        resource_id=str(permission.id),
        decision="PERMIT",
        permission_id=str(permission.id),
        deny_reason=None,
        context_snapshot={"action": permission.action},
    )
    return permission


@router.delete(
    "/permissions/{permission_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["identity"],
)
def delete_permission(
    permission_id: str,
    db: Session = Depends(get_db),
    payload: dict = Depends(_admin_required),
):
    """Delete a permission (admin only). Fails if permission is assigned to roles."""
    permission = db.query(Permission).filter(Permission.id == permission_id).first()
    if not permission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Permission not found"
        )
    if permission.roles:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete permission assigned to roles",
        )
    db.delete(permission)
    db.commit()

    log_audit_event(
        db=db,
        user_id=payload.get("sub"),
        action="delete_permission",
        resource_id=str(permission.id),
        decision="PERMIT",
        permission_id=str(permission.id),
        deny_reason=None,
        context_snapshot={"action": permission.action},
    )


# ===== User-Role Assignment =====
@router.post("/users/{user_id}/roles", response_model=UserRead, tags=["identity"])
def assign_role_to_user(
    user_id: str,
    assignment: AssignRoleToUser,
    db: Session = Depends(get_db),
    payload: dict = Depends(_admin_required),
):
    """Assign a role to a user (admin only)."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    role = db.query(Role).filter(Role.id == assignment.role_id).first()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Role not found"
        )
    # Check if already assigned
    existing = (
        db.query(user_role_table)
        .filter(
            user_role_table.c.user_id == user_id,
            user_role_table.c.role_id == assignment.role_id,
        )
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Role already assigned to user",
        )
    user.roles.append(role)
    db.add(user)
    db.commit()

    log_audit_event(
        db=db,
        user_id=payload.get("sub"),
        action="assign_role_to_user",
        resource_id=str(user.id),
        decision="PERMIT",
        permission_id=None,
        deny_reason=None,
        context_snapshot={"role_id": str(assignment.role_id)},
    )
    return user


@router.delete(
    "/users/{user_id}/roles/{role_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["identity"],
)
def remove_role_from_user(
    user_id: str,
    role_id: str,
    db: Session = Depends(get_db),
    payload: dict = Depends(_admin_required),
):
    """Remove a role from a user (admin only)."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Role not found"
        )
    if role not in user.roles:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Role not assigned to user",
        )
    user.roles.remove(role)
    db.add(user)
    db.commit()

    log_audit_event(
        db=db,
        user_id=payload.get("sub"),
        action="remove_role_from_user",
        resource_id=str(user.id),
        decision="PERMIT",
        permission_id=None,
        deny_reason=None,
        context_snapshot={"role_id": role_id},
    )


# ===== Role-Permission Assignment =====
@router.post("/roles/{role_id}/permissions", response_model=RoleRead, tags=["identity"])
def assign_permission_to_role(
    role_id: str,
    assignment: AssignPermissionToRole,
    db: Session = Depends(get_db),
    payload: dict = Depends(_admin_required),
):
    """Assign a permission to a role (admin only)."""
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Role not found"
        )
    permission = (
        db.query(Permission).filter(Permission.id == assignment.permission_id).first()
    )
    if not permission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Permission not found"
        )
    # Check if already assigned
    existing = (
        db.query(role_permission_table)
        .filter(
            role_permission_table.c.role_id == role_id,
            role_permission_table.c.permission_id == assignment.permission_id,
        )
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Permission already assigned to role",
        )
    role.permissions.append(permission)
    db.add(role)
    db.commit()

    log_audit_event(
        db=db,
        user_id=payload.get("sub"),
        action="assign_permission_to_role",
        resource_id=str(role.id),
        decision="PERMIT",
        permission_id=str(assignment.permission_id),
        deny_reason=None,
        context_snapshot={"permission_id": str(assignment.permission_id)},
    )
    return role


@router.delete(
    "/roles/{role_id}/permissions/{permission_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["identity"],
)
def remove_permission_from_role(
    role_id: str,
    permission_id: str,
    db: Session = Depends(get_db),
    payload: dict = Depends(_admin_required),
):
    """Remove a permission from a role (admin only)."""
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Role not found"
        )
    permission = db.query(Permission).filter(Permission.id == permission_id).first()
    if not permission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Permission not found"
        )
    if permission not in role.permissions:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Permission not assigned to role",
        )
    role.permissions.remove(permission)
    db.add(role)
    db.commit()

    log_audit_event(
        db=db,
        user_id=payload.get("sub"),
        action="remove_permission_from_role",
        resource_id=str(role.id),
        decision="PERMIT",
        permission_id=str(permission_id),
        deny_reason=None,
        context_snapshot={"permission_id": permission_id},
    )
