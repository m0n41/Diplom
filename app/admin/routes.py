from fastapi import (
    APIRouter,
    Depends,
    Request,
    Cookie,
    Response,
    HTTPException,
    status,
    Form,
)
from fastapi.responses import HTMLResponse, RedirectResponse
from app.core.security import (
    verify_token,
    create_access_token,
    create_refresh_token,
    verify_password,
)

# Removed unused LoginRequest import
from sqlalchemy.orm import Session
from sqlalchemy import func
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.db.session import get_db
from app.models.models import (
    User,
    Role,
    Permission,
    Resource,
    AuditEvent,
    role_permission_table,
)
import json

from app.audit.service import log_audit_event

router = APIRouter()


def get_client_ip(request: Request) -> str:
    """Extract real client IP from request headers."""
    x_forwarded_for = request.headers.get("X-Forwarded-For")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


def _audit_ctx(request: Request, extra: dict = None) -> dict:
    """Build audit context snapshot with IP and optional extra data."""
    ctx = {"ip_address": get_client_ip(request)}
    if extra:
        ctx.update(extra)
    return ctx


# Helper to get current user from cookie
async def get_current_user_from_cookie(access_token: str = Cookie(None)):
    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = verify_token(access_token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload


def admin_required(payload: dict = Depends(get_current_user_from_cookie)):
    # Simplified admin check
    if "admin" not in [r.get("name") for r in payload.get("roles", [])]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return payload


# Admin login page
@router.get("/login", response_class=HTMLResponse, tags=["admin"])
def admin_login_page(request: Request):
    templates = get_templates(request)
    rendered = templates.get_template("login.html").render({"request": request})
    return HTMLResponse(rendered)


@router.get("/logout", tags=["admin"])
def admin_logout():
    response = RedirectResponse(
        url="/admin/login", status_code=status.HTTP_303_SEE_OTHER
    )
    response.delete_cookie(key="access_token", path="/admin", httponly=True)
    response.delete_cookie(key="access_token", path="/", httponly=True)
    return response


# Admin login submit
@router.post("/login", tags=["admin"])
def admin_login_submit(
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User is inactive",
        )
    subject = {"sub": str(user.id), "roles": [{"name": r.name} for r in user.roles]}
    access_token = create_access_token(subject)
    refresh_token = create_refresh_token(subject)
    response = RedirectResponse(url="/admin/", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        max_age=60 * 60 * 24,
        path="/",
    )
    return response


# Главная страница админ‑панели
@router.get(
    "/",
    response_class=HTMLResponse,
    tags=["admin"],
    dependencies=[Depends(admin_required)],
)
def admin_dashboard(request: Request):
    """
    Render the main admin dashboard page.
    We render the template manually to avoid Jinja2 caching issues
    caused by passing a mutable context dict directly to TemplateResponse.
    """
    templates = get_templates(request)
    # Render the Jinja2 template manually
    rendered = templates.get_template("dashboard.html").render({"request": request})
    return HTMLResponse(rendered)


def get_templates(request: Request) -> Jinja2Templates:
    """
    Retrieve the Jinja2Templates instance stored in the FastAPI app state.
    """
    return request.app.state.templates


# ----- Users -----
@router.get(
    "/users",
    response_class=HTMLResponse,
    tags=["admin"],
    dependencies=[Depends(admin_required)],
)
def admin_users(request: Request, db: Session = Depends(get_db)):
    users = db.query(User).all()
    templates = get_templates(request)
    rendered = templates.get_template("users.html").render(
        {"request": request, "users": users}
    )
    return HTMLResponse(rendered)


# ----- User CRUD -----
@router.get(
    "/users/create",
    response_class=HTMLResponse,
    tags=["admin"],
    dependencies=[Depends(admin_required)],
)
def admin_user_create_form(request: Request):
    templates = get_templates(request)
    return templates.get_template("user_form.html").render(
        {"request": request, "user": None}
    )


@router.post(
    "/users/create",
    tags=["admin"],
    dependencies=[Depends(admin_required)],
)
def admin_user_create(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
    payload: dict = Depends(admin_required),
):
    from app.core.security import get_password_hash

    hashed = get_password_hash(password)
    user = User(username=username, email=email, password_hash=hashed, is_active=True)
    db.add(user)
    db.commit()
    db.refresh(user)
    log_audit_event(
        db=db,
        user_id=payload.get("sub"),
        action="user_created",
        resource_id=str(user.id),
        decision="PERMIT",
        permission_id=None,
        deny_reason=None,
        context_snapshot=_audit_ctx(request, {"username": username, "email": email}),
    )
    return RedirectResponse(
        url="/admin/users?success=User+created",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get(
    "/users/{user_id}/edit",
    response_class=HTMLResponse,
    tags=["admin"],
    dependencies=[Depends(admin_required)],
)
def admin_user_edit_form(request: Request, user_id: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404)
    all_roles = db.query(Role).all()
    user_role_ids = {str(r.id) for r in user.roles}
    templates = get_templates(request)
    return templates.get_template("user_form.html").render(
        {
            "request": request,
            "user": user,
            "all_roles": all_roles,
            "user_role_ids": user_role_ids,
        }
    )


@router.post(
    "/users/{user_id}/edit",
    tags=["admin"],
    dependencies=[Depends(admin_required)],
)
def admin_user_edit(
    request: Request,
    user_id: str,
    username: str = Form(...),
    email: str = Form(...),
    is_active: bool = Form(False),
    role_ids: list[str] = Form(default=[]),
    db: Session = Depends(get_db),
    payload: dict = Depends(admin_required),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404)
    user.username = username
    user.email = email
    user.is_active = is_active

    # Update role assignments
    selected_roles = (
        db.query(Role).filter(Role.id.in_(role_ids)).all() if role_ids else []
    )
    user.roles = selected_roles

    db.commit()

    assigned_role_names = [r.name for r in selected_roles]
    log_audit_event(
        db=db,
        user_id=payload.get("sub"),
        action="user_roles_updated",
        resource_id=str(user.id),
        decision="PERMIT",
        permission_id=None,
        deny_reason=None,
        context_snapshot=_audit_ctx(
            request, {"username": username, "assigned_roles": assigned_role_names}
        ),
    )
    return RedirectResponse(
        url="/admin/users?success=User+updated",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post(
    "/users/{user_id}/delete",
    tags=["admin"],
    dependencies=[Depends(admin_required)],
)
def admin_user_delete(
    request: Request,
    user_id: str,
    payload: dict = Depends(admin_required),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404)
    user.is_active = False
    db.commit()
    log_audit_event(
        db=db,
        user_id=payload.get("sub"),
        action="user_deactivated",
        resource_id=str(user.id),
        decision="PERMIT",
        permission_id=None,
        deny_reason=None,
        context_snapshot=_audit_ctx(request, {"username": user.username}),
    )
    return RedirectResponse(
        url="/admin/users?success=User+deactivated",
        status_code=status.HTTP_303_SEE_OTHER,
    )


# ----- Roles -----
@router.get(
    "/roles",
    response_class=HTMLResponse,
    tags=["admin"],
    dependencies=[Depends(admin_required)],
)
def admin_roles(request: Request, db: Session = Depends(get_db)):
    roles = db.query(Role).all()
    templates = get_templates(request)
    rendered = templates.get_template("roles.html").render(
        {"request": request, "roles": roles}
    )
    return HTMLResponse(rendered)


# ----- Role CRUD -----
@router.get(
    "/roles/create",
    response_class=HTMLResponse,
    tags=["admin"],
    dependencies=[Depends(admin_required)],
)
def admin_role_create_form(request: Request):
    templates = get_templates(request)
    return templates.get_template("role_form.html").render(
        {"request": request, "role": None, "permissions": []}
    )


@router.post(
    "/roles/create",
    tags=["admin"],
    dependencies=[Depends(admin_required)],
)
def admin_role_create(
    request: Request,
    name: str = Form(...),
    description: str = Form(None),
    db: Session = Depends(get_db),
    payload: dict = Depends(admin_required),
):
    role = Role(name=name, description=description)
    db.add(role)
    db.commit()
    db.refresh(role)
    log_audit_event(
        db=db,
        user_id=payload.get("sub"),
        action="role_created",
        resource_id=str(role.id),
        decision="PERMIT",
        permission_id=None,
        deny_reason=None,
        context_snapshot=_audit_ctx(request, {"name": name}),
    )
    return RedirectResponse(
        url="/admin/roles?success=Role+created",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get(
    "/roles/{role_id}/edit",
    response_class=HTMLResponse,
    tags=["admin"],
    dependencies=[Depends(admin_required)],
)
def admin_role_edit_form(request: Request, role_id: str, db: Session = Depends(get_db)):
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(status_code=404)

    # Load all permissions with resource names for grouping
    all_perms = (
        db.query(
            Permission.id,
            Permission.action,
            Permission.description,
            Resource.name.label("resource_name"),
        )
        .join(Resource, Permission.resource_id == Resource.id)
        .order_by(Resource.name, Permission.action)
        .all()
    )
    role_perm_ids = {str(p.id) for p in role.permissions}

    templates = get_templates(request)
    return templates.get_template("role_form.html").render(
        {
            "request": request,
            "role": role,
            "all_permissions": all_perms,
            "role_perm_ids": role_perm_ids,
        }
    )


@router.post(
    "/roles/{role_id}/edit",
    tags=["admin"],
    dependencies=[Depends(admin_required)],
)
def admin_role_edit(
    request: Request,
    role_id: str,
    name: str = Form(...),
    description: str = Form(None),
    permission_ids: list[str] = Form(default=[]),
    db: Session = Depends(get_db),
    payload: dict = Depends(admin_required),
):
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(status_code=404)
    role.name = name
    role.description = description

    # Update permission assignments
    selected_perms = (
        db.query(Permission).filter(Permission.id.in_(permission_ids)).all()
        if permission_ids
        else []
    )
    role.permissions = selected_perms

    db.commit()

    assigned_perm_actions = [p.action for p in selected_perms]
    log_audit_event(
        db=db,
        user_id=payload.get("sub"),
        action="role_permissions_updated",
        resource_id=str(role.id),
        decision="PERMIT",
        permission_id=None,
        deny_reason=None,
        context_snapshot=_audit_ctx(
            request, {"role_name": name, "assigned_permissions": assigned_perm_actions}
        ),
    )
    return RedirectResponse(
        url="/admin/roles?success=Role+updated",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post(
    "/roles/{role_id}/delete",
    tags=["admin"],
    dependencies=[Depends(admin_required)],
)
def admin_role_delete(
    request: Request,
    role_id: str,
    payload: dict = Depends(admin_required),
    db: Session = Depends(get_db),
):
    # Prevent deletion if role is assigned to any user
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(status_code=404)

    assigned_count = db.query(User).filter(User.roles.any(id=role_id)).count()
    if assigned_count > 0:
        log_audit_event(
            db=db,
            user_id=payload.get("sub"),
            action="role_deleted",
            resource_id=str(role.id),
            decision="DENY",
            permission_id=None,
            deny_reason=f"Role is assigned to {assigned_count} user(s)",
            context_snapshot=_audit_ctx(
                request, {"name": role.name, "assigned_users": assigned_count}
            ),
        )
        return RedirectResponse(
            url=f"/admin/roles?error=Cannot+delete+role:+it+is+assigned+to+{assigned_count}+user(s)",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    db.delete(role)
    db.commit()
    log_audit_event(
        db=db,
        user_id=payload.get("sub"),
        action="role_deleted",
        resource_id=str(role.id),
        decision="PERMIT",
        permission_id=None,
        deny_reason=None,
        context_snapshot=_audit_ctx(request, {"name": role.name}),
    )
    return RedirectResponse(
        url="/admin/roles?success=Role+deleted",
        status_code=status.HTTP_303_SEE_OTHER,
    )


# ----- Permissions -----
@router.get(
    "/permissions",
    response_class=HTMLResponse,
    tags=["admin"],
    dependencies=[Depends(admin_required)],
)
def admin_permissions(request: Request, db: Session = Depends(get_db)):
    """
    List all permissions with count of assigned roles and resource name.
    """
    perms = (
        db.query(
            Permission.id,
            Permission.action,
            Permission.description,
            Permission.resource_id,
            Resource.name.label("resource_name"),
            func.count(Role.id).label("role_count"),
        )
        .join(Resource, Permission.resource_id == Resource.id)
        .outerjoin(
            role_permission_table,
            Permission.id == role_permission_table.c.permission_id,
        )
        .outerjoin(Role, role_permission_table.c.role_id == Role.id)
        .group_by(Permission.id, Resource.name)
        .all()
    )
    permissions = [
        {
            "id": row.id,
            "action": row.action,
            "description": row.description,
            "resource_id": row.resource_id,
            "resource_name": row.resource_name,
            "role_count": row.role_count,
        }
        for row in perms
    ]
    templates = get_templates(request)
    rendered = templates.get_template("permissions.html").render(
        {"request": request, "permissions": permissions}
    )
    return HTMLResponse(rendered)


# ----- Permission CRUD -----
@router.get(
    "/permissions/create",
    response_class=HTMLResponse,
    tags=["admin"],
    dependencies=[Depends(admin_required)],
)
def admin_permission_create_form(request: Request, db: Session = Depends(get_db)):
    resources = db.query(Resource).all()
    templates = get_templates(request)
    return templates.get_template("permission_form.html").render(
        {"request": request, "permission": None, "resources": resources}
    )


@router.post(
    "/permissions/create",
    tags=["admin"],
    dependencies=[Depends(admin_required)],
)
def admin_permission_create(
    request: Request,
    name: str = Form(...),
    description: str = Form(None),
    resource_id: str = Form(...),
    db: Session = Depends(get_db),
    payload: dict = Depends(admin_required),
):
    # Validate uniqueness of (resource_id, action)
    existing = (
        db.query(Permission)
        .filter(Permission.resource_id == resource_id, Permission.action == name)
        .first()
    )
    if existing:
        log_audit_event(
            db=db,
            user_id=payload["sub"],
            action="permission_created",
            resource_id=str(existing.id),
            decision="DENY",
            permission_id=str(existing.id),
            deny_reason="Duplicate (resource, action)",
            context_snapshot=_audit_ctx(
                request, {"name": name, "resource_id": resource_id}
            ),
        )
        return RedirectResponse(
            url="/admin/permissions/create?error=Permission+with+this+resource+and+action+already+exists",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    perm = Permission(action=name, description=description, resource_id=resource_id)
    db.add(perm)
    db.commit()
    db.refresh(perm)
    log_audit_event(
        db=db,
        user_id=payload["sub"],
        action="permission_created",
        resource_id=str(perm.id),
        decision="PERMIT",
        permission_id=str(perm.id),
        deny_reason=None,
        context_snapshot=_audit_ctx(
            request, {"name": name, "resource_id": resource_id}
        ),
    )
    return RedirectResponse(
        url="/admin/permissions?success=Permission+created",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get(
    "/permissions/{perm_id}/edit",
    response_class=HTMLResponse,
    tags=["admin"],
    dependencies=[Depends(admin_required)],
)
def admin_permission_edit_form(
    request: Request, perm_id: str, db: Session = Depends(get_db)
):
    perm = db.query(Permission).filter(Permission.id == perm_id).first()
    if not perm:
        raise HTTPException(status_code=404)
    resources = db.query(Resource).all()
    templates = get_templates(request)
    return templates.get_template("permission_form.html").render(
        {"request": request, "permission": perm, "resources": resources}
    )


@router.post(
    "/permissions/{perm_id}/edit",
    tags=["admin"],
    dependencies=[Depends(admin_required)],
)
def admin_permission_edit(
    request: Request,
    perm_id: str,
    name: str = Form(...),
    description: str = Form(None),
    resource_id: str = Form(None),
    db: Session = Depends(get_db),
    payload: dict = Depends(admin_required),
):
    perm = db.query(Permission).filter(Permission.id == perm_id).first()
    if not perm:
        raise HTTPException(status_code=404)
    # Disallow changing core fields if permission is assigned to any role
    assigned_count = db.query(Role).filter(Role.permissions.any(id=perm_id)).count()
    if assigned_count > 0 and (
        name != perm.action or (resource_id and resource_id != str(perm.resource_id))
    ):
        return RedirectResponse(
            url=f"/admin/permissions?error=Cannot+edit+core+fields:+permission+is+used+by+{assigned_count}+role(s)",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    perm.action = name
    perm.description = description
    if resource_id:
        perm.resource_id = resource_id
    db.commit()
    log_audit_event(
        db=db,
        user_id=payload.get("sub"),
        action="permission_updated",
        resource_id=str(perm.id),
        decision="PERMIT",
        permission_id=None,
        deny_reason=None,
        context_snapshot=_audit_ctx(
            request, {"name": name, "resource_id": str(perm.resource_id)}
        ),
    )
    return RedirectResponse(
        url="/admin/permissions?success=Permission+updated",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post(
    "/permissions/{perm_id}/delete",
    tags=["admin"],
    dependencies=[Depends(admin_required)],
)
def admin_permission_delete(
    request: Request,
    perm_id: str,
    payload: dict = Depends(admin_required),
    db: Session = Depends(get_db),
):
    perm = db.query(Permission).filter(Permission.id == perm_id).first()
    if not perm:
        raise HTTPException(status_code=404)

    assigned_count = db.query(Role).filter(Role.permissions.any(id=perm_id)).count()
    if assigned_count > 0:
        log_audit_event(
            db=db,
            user_id=payload["sub"],
            action="permission_deleted",
            resource_id=str(perm.id),
            decision="DENY",
            permission_id=str(perm.id),
            deny_reason=f"Permission is used by {assigned_count} role(s)",
            context_snapshot=_audit_ctx(
                request, {"action": perm.action, "assigned_roles": assigned_count}
            ),
        )
        return RedirectResponse(
            url=f"/admin/permissions?error=Cannot+delete:+permission+is+used+by+{assigned_count}+role(s)",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    db.delete(perm)
    db.commit()
    log_audit_event(
        db=db,
        user_id=payload.get("sub"),
        action="permission_deleted",
        resource_id=str(perm.id),
        decision="PERMIT",
        permission_id=str(perm.id),
        deny_reason=None,
        context_snapshot=_audit_ctx(request, {"action": perm.action}),
    )
    return RedirectResponse(
        url="/admin/permissions?success=Permission+deleted",
        status_code=status.HTTP_303_SEE_OTHER,
    )


# ----- Resources -----
@router.get(
    "/resources",
    response_class=HTMLResponse,
    tags=["admin"],
    dependencies=[Depends(admin_required)],
)
def admin_resources(request: Request, db: Session = Depends(get_db)):
    """List all resources with count of associated permissions."""
    resources = (
        db.query(
            Resource.id,
            Resource.name,
            Resource.category,
            Resource.criticality,
            func.count(Permission.id).label("perm_count"),
        )
        .outerjoin(Permission, Resource.id == Permission.resource_id)
        .group_by(Resource.id)
        .all()
    )
    templates = get_templates(request)
    rendered = templates.get_template("resources.html").render(
        {"request": request, "resources": resources}
    )
    return HTMLResponse(rendered)


@router.get(
    "/resources/create",
    response_class=HTMLResponse,
    tags=["admin"],
    dependencies=[Depends(admin_required)],
)
def admin_resource_create_form(request: Request):
    templates = get_templates(request)
    return templates.get_template("resource_form.html").render({"request": request})


@router.post(
    "/resources/create",
    tags=["admin"],
    dependencies=[Depends(admin_required)],
)
def admin_resource_create(
    request: Request,
    name: str = Form(...),
    category: str = Form(...),
    criticality: int = Form(1),
    db: Session = Depends(get_db),
    payload: dict = Depends(admin_required),
):
    resource = Resource(name=name, category=category, criticality=criticality)
    db.add(resource)
    db.commit()
    db.refresh(resource)
    log_audit_event(
        db=db,
        user_id=payload.get("sub"),
        action="resource_created",
        resource_id=str(resource.id),
        decision="PERMIT",
        permission_id=None,
        deny_reason=None,
        context_snapshot=_audit_ctx(request, {"name": name, "category": category}),
    )
    return RedirectResponse(
        url="/admin/resources?success=Resource+created",
        status_code=status.HTTP_303_SEE_OTHER,
    )


# ----- Policies (ABAC) -----
@router.get(
    "/policies",
    response_class=HTMLResponse,
    tags=["admin"],
    dependencies=[Depends(admin_required)],
)
def admin_policies(request: Request):
    """
    Read-only view of current ABAC policies implemented in the system.
    This page demonstrates that ABAC is not 'magic' but concrete rules.
    """
    policies = [
        {
            "name": "business_hours_only",
            "description": "Доступ разрешён только в рабочее время (08:00–18:00 UTC)",
            "type": "ABAC",
            "status": "Active",
            "condition": "08:00 <= ts.time() <= 18:00",
            "source": "app/authorization/pdp.py::_time_allowed()",
        },
        {
            "name": "no_private_ip",
            "description": "Блокировка доступа с приватных IP-адресов (10.x, 192.168.x, 172.x)",
            "type": "ABAC",
            "status": "Active",
            "condition": "not ip.startswith('10.') and not ip.startswith('192.168.') and not ip.startswith('172.')",
            "source": "app/authorization/pdp.py::_ip_allowed()",
        },
    ]

    json_example = json.dumps(
        [
            {
                "name": "business_hours_only",
                "description": "Access allowed only during business hours 08:00–18:00 UTC",
                "condition": "8 <= request_hour <= 18",
            },
            {
                "name": "no_private_ip",
                "description": "Block access from private network ranges",
                "condition": "not ip_address.startswith('10.') and not ip_address.startswith('192.168.')",
            },
        ],
        indent=2,
        ensure_ascii=False,
    )

    templates = get_templates(request)
    rendered = templates.get_template("policies.html").render(
        {"request": request, "policies": policies, "json_example": json_example}
    )
    return HTMLResponse(rendered)


# ----- Audit Log -----
@router.get(
    "/audit",
    response_class=HTMLResponse,
    tags=["admin"],
    dependencies=[Depends(admin_required)],
)
def admin_audit_list(
    request: Request,
    db: Session = Depends(get_db),
    page: int = 1,
    per_page: int = 20,
    user_id: str = None,
    decision: str = None,
    action: str = None,
    date_from: str = None,
    date_to: str = None,
):
    """
    List audit events with optional filtering and pagination.
    """
    query = db.query(AuditEvent)

    if user_id:
        query = query.filter(AuditEvent.user_id == user_id)
    if decision:
        query = query.filter(AuditEvent.decision == decision.upper())
    if action:
        query = query.filter(AuditEvent.action.ilike(f"%{action}%"))
    if date_from:
        query = query.filter(AuditEvent.timestamp >= date_from)
    if date_to:
        query = query.filter(AuditEvent.timestamp <= date_to)

    total = query.count()
    events = (
        query.order_by(AuditEvent.timestamp.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    templates = get_templates(request)
    rendered = templates.get_template("audit.html").render(
        {
            "request": request,
            "events": events,
            "page": page,
            "per_page": per_page,
            "total": total,
            "user_id": user_id or "",
            "decision": decision or "",
            "action": action or "",
            "date_from": date_from or "",
            "date_to": date_to or "",
        }
    )
    return HTMLResponse(rendered)


@router.get(
    "/audit/{event_id}",
    response_class=HTMLResponse,
    tags=["admin"],
    dependencies=[Depends(admin_required)],
)
def admin_audit_detail(event_id: str, request: Request, db: Session = Depends(get_db)):
    """
    Read‑only detail view for a single audit event.
    """
    ev = db.query(AuditEvent).filter(AuditEvent.id == event_id).first()
    if not ev:
        raise HTTPException(status_code=404, detail="Audit event not found")

    # Format context_snapshot as pretty JSON
    context_formatted = ""
    if ev.context_snapshot:
        try:
            ctx_dict = json.loads(ev.context_snapshot.replace("'", '"'))
            context_formatted = json.dumps(ctx_dict, indent=2, ensure_ascii=False)
        except Exception:
            context_formatted = ev.context_snapshot

    templates = get_templates(request)
    rendered = templates.get_template("audit_detail.html").render(
        {"request": request, "ev": ev, "context_formatted": context_formatted}
    )
    return HTMLResponse(rendered)
