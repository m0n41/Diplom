from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.db.session import get_db
from app.models.models import User, Role, Permission, AuditEvent
from app.audit.service import log_audit_event

router = APIRouter()


# Главная страница админ‑панели
@router.get("/", response_class=HTMLResponse, tags=["admin"])
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
@router.get("/users", response_class=HTMLResponse, tags=["admin"])
def admin_users(request: Request, db: Session = Depends(get_db)):
    users = db.query(User).all()
    templates = get_templates(request)
    rendered = templates.get_template("users.html").render(
        {"request": request, "users": users}
    )
    return HTMLResponse(rendered)


# ----- Roles -----
@router.get("/roles", response_class=HTMLResponse, tags=["admin"])
def admin_roles(request: Request, db: Session = Depends(get_db)):
    roles = db.query(Role).all()
    templates = get_templates(request)
    rendered = templates.get_template("roles.html").render(
        {"request": request, "roles": roles}
    )
    return HTMLResponse(rendered)


# ----- Permissions -----
@router.get("/permissions", response_class=HTMLResponse, tags=["admin"])
def admin_permissions(request: Request, db: Session = Depends(get_db)):
    perms = db.query(Permission).all()
    templates = get_templates(request)
    rendered = templates.get_template("permissions.html").render(
        {"request": request, "permissions": perms}
    )
    return HTMLResponse(rendered)


# ----- Audit Log -----
@router.get("/audit", response_class=HTMLResponse, tags=["admin"])
def admin_audit(request: Request, db: Session = Depends(get_db)):
    events = db.query(AuditEvent).order_by(AuditEvent.id.desc()).limit(100).all()
    templates = get_templates(request)
    rendered = templates.get_template("audit.html").render(
        {"request": request, "events": events}
    )
    return HTMLResponse(rendered)
