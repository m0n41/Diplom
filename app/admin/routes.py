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
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.db.session import get_db
from app.models.models import User, Role, Permission, AuditEvent
from app.audit.service import log_audit_event

router = APIRouter()


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
    response = RedirectResponse(url="/admin/")
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        max_age=60 * 60 * 24,
        path="/admin",
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


# ----- Permissions -----
@router.get(
    "/permissions",
    response_class=HTMLResponse,
    tags=["admin"],
    dependencies=[Depends(admin_required)],
)
def admin_permissions(request: Request, db: Session = Depends(get_db)):
    perms = db.query(Permission).all()
    templates = get_templates(request)
    rendered = templates.get_template("permissions.html").render(
        {"request": request, "permissions": perms}
    )
    return HTMLResponse(rendered)


# ----- Audit Log -----
@router.get(
    "/audit",
    response_class=HTMLResponse,
    tags=["admin"],
    dependencies=[Depends(admin_required)],
)
def admin_audit(request: Request, db: Session = Depends(get_db)):
    events = db.query(AuditEvent).order_by(AuditEvent.id.desc()).limit(100).all()
    templates = get_templates(request)
    rendered = templates.get_template("audit.html").render(
        {"request": request, "events": events}
    )
    return HTMLResponse(rendered)
