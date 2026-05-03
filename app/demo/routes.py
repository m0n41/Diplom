from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Request, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session
from fastapi.templating import Jinja2Templates

from app.db.session import get_db
from app.models.models import User, Resource
from app.core.security import verify_token, verify_password, create_access_token
from app.authorization.pdp import get_default_pdp
from app.audit.service import log_audit_event

router = APIRouter()
templates = Jinja2Templates(directory="app/demo/templates")


def _msk_time_filter(value):
    if value is None:
        return ""
    msk = timezone(timedelta(hours=3))
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(msk).strftime("%Y-%m-%d %H:%M:%S")


templates.env.filters["msk_time"] = _msk_time_filter


def _extract_demo_user(request: Request, db: Session) -> Optional[User]:
    token = request.cookies.get("access_token")
    if not token:
        return None
    payload = verify_token(token)
    if not payload:
        return None
    user = db.query(User).filter(User.id == payload.get("sub")).first()
    if not user or not user.is_active:
        return None
    return user


def _check_resource_access(request: Request, db: Session, user: User, resource_name: str):
    resource = db.query(Resource).filter(Resource.name == resource_name).first()
    client_ip = request.client.host if request.client else "unknown"
    client_type = request.headers.get("User-Agent", "unknown")
    environment = {
        "timestamp": datetime.now(timezone.utc),
        "ip_address": client_ip,
        "client_type": client_type,
    }

    if not resource:
        log_audit_event(
            db=db,
            user_id=str(user.id),
            action="demo_access",
            resource_id=None,
            decision="DENY",
            permission_id=None,
            deny_reason="Resource not found",
            context_snapshot={
                "ip_address": client_ip,
                "resource_name": resource_name,
                "action_requested": "read",
                "deny_detail": f"Ресурс '{resource_name}' не настроен в БД",
            },
        )
        return None, "Ресурс не настроен"

    # Администратор имеет доступ ко всем демо-ресурсам
    if any(r.name == "admin" for r in user.roles):
        log_audit_event(
            db=db,
            user_id=str(user.id),
            action="demo_access",
            resource_id=str(resource.id),
            decision="PERMIT",
            permission_id=None,
            deny_reason=None,
            context_snapshot={
                "ip_address": client_ip,
                "resource_name": resource_name,
                "action_requested": "read",
                "admin_override": True,
            },
        )
        return resource, None

    subject = {
        "sub": str(user.id),
        "roles": [{"name": r.name} for r in user.roles],
    }
    pdp = get_default_pdp()
    decision = pdp.decide(db, subject, "read", str(resource.id), environment)

    if decision.permit:
        log_audit_event(
            db=db,
            user_id=str(user.id),
            action="demo_access",
            resource_id=str(resource.id),
            decision="PERMIT",
            permission_id=None,
            deny_reason=None,
            context_snapshot={
                "ip_address": client_ip,
                "resource_name": resource_name,
                "action_requested": "read",
            },
        )
        return resource, None
    else:
        log_audit_event(
            db=db,
            user_id=str(user.id),
            action="demo_access",
            resource_id=str(resource.id),
            decision="DENY",
            permission_id=None,
            deny_reason=decision.reason,
            context_snapshot={
                "ip_address": client_ip,
                "resource_name": resource_name,
                "action_requested": "read",
                "deny_detail": decision.details.get("msg", ""),
            },
        )
        return None, decision.reason


@router.get("/login", response_class=HTMLResponse)
def demo_login_page(request: Request, error: str = ""):
    return templates.TemplateResponse(
        "demo_login.html", {"request": request, "error": error}
    )


@router.post("/login")
def demo_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.username == username).first()
    client_ip = request.client.host if request.client else "unknown"
    client_type = request.headers.get("User-Agent", "unknown")

    if not user or not verify_password(password, user.password_hash):
        # Аудит неудачной попытки входа
        if user:
            log_audit_event(
                db=db,
                user_id=str(user.id),
                action="login",
                resource_id=None,
                decision="DENY",
                permission_id=None,
                deny_reason="Invalid credentials",
                context_snapshot={
                    "ip_address": client_ip,
                    "client_type": client_type,
                    "username": username,
                },
            )
        return RedirectResponse(
            url="/demo/login?error=Invalid+credentials", status_code=302
        )

    subject = {
        "sub": str(user.id),
        "roles": [{"name": r.name} for r in user.roles],
    }
    access_token = create_access_token(subject)

    # Аудит успешного входа
    log_audit_event(
        db=db,
        user_id=str(user.id),
        action="login",
        resource_id=None,
        decision="PERMIT",
        permission_id=None,
        deny_reason=None,
        context_snapshot={
            "ip_address": client_ip,
            "client_type": client_type,
            "username": username,
        },
    )

    response = RedirectResponse(url="/demo", status_code=302)
    response.set_cookie(key="access_token", value=access_token, httponly=True, path="/")
    return response


@router.get("/logout")
def demo_logout(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("access_token")
    client_ip = request.client.host if request.client else "unknown"
    client_type = request.headers.get("User-Agent", "unknown")

    if token:
        payload = verify_token(token)
        if payload:
            log_audit_event(
                db=db,
                user_id=payload.get("sub"),
                action="logout",
                resource_id=None,
                decision="PERMIT",
                permission_id=None,
                deny_reason=None,
                context_snapshot={
                    "ip_address": client_ip,
                    "client_type": client_type,
                },
            )

    response = RedirectResponse(url="/demo/login", status_code=302)
    response.delete_cookie(key="access_token", path="/")
    return response


@router.get("/", response_class=HTMLResponse)
def demo_index(request: Request, db: Session = Depends(get_db)):
    user = _extract_demo_user(request, db)
    if not user:
        return RedirectResponse(url="/demo/login", status_code=302)
    return templates.TemplateResponse(
        "demo_index.html",
        {
            "request": request,
            "user": user,
            "roles": [r.name for r in user.roles],
        },
    )


@router.get("/documents", response_class=HTMLResponse)
def demo_documents(request: Request, db: Session = Depends(get_db)):
    user = _extract_demo_user(request, db)
    if not user:
        return RedirectResponse(url="/demo/login", status_code=302)

    resource, deny_reason = _check_resource_access(request, db, user, "documents")
    if deny_reason:
        return templates.TemplateResponse(
            "demo_denied.html",
            {
                "request": request,
                "user": user,
                "resource_name": "Documents",
                "deny_reason": deny_reason,
            },
        )

    fake_data = [
        {"id": 1, "name": "Q4 Financial Report", "author": "Ivan P.", "date": "2024-01-15", "status": "Approved"},
        {"id": 2, "name": "Project Proposal", "author": "Anna K.", "date": "2024-01-20", "status": "Draft"},
        {"id": 3, "name": "Security Policy v2.0", "author": "Admin", "date": "2024-01-22", "status": "Active"},
    ]
    return templates.TemplateResponse(
        "demo_resource.html",
        {
            "request": request,
            "user": user,
            "resource_name": "Documents",
            "description": "Corporate document repository",
            "columns": ["ID", "Document Name", "Author", "Date", "Status"],
            "rows": fake_data,
        },
    )


@router.get("/finance", response_class=HTMLResponse)
def demo_finance(request: Request, db: Session = Depends(get_db)):
    user = _extract_demo_user(request, db)
    if not user:
        return RedirectResponse(url="/demo/login", status_code=302)

    resource, deny_reason = _check_resource_access(request, db, user, "finance")
    if deny_reason:
        return templates.TemplateResponse(
            "demo_denied.html",
            {
                "request": request,
                "user": user,
                "resource_name": "Finance Reports",
                "deny_reason": deny_reason,
            },
        )

    fake_data = [
        {"id": 1, "name": "January Budget", "period": "Jan 2024", "amount": "500,000 ₽", "status": "Closed"},
        {"id": 2, "name": "Q1 Forecast", "period": "Q1 2024", "amount": "1,200,000 ₽", "status": "Open"},
        {"id": 3, "name": "Annual Revenue 2023", "period": "Year 2023", "amount": "8,400,000 ₽", "status": "Approved"},
    ]
    return templates.TemplateResponse(
        "demo_resource.html",
        {
            "request": request,
            "user": user,
            "resource_name": "Finance Reports",
            "description": "Financial data and budget reports",
            "columns": ["ID", "Report Name", "Period", "Amount", "Status"],
            "rows": fake_data,
        },
    )


@router.get("/hr", response_class=HTMLResponse)
def demo_hr(request: Request, db: Session = Depends(get_db)):
    user = _extract_demo_user(request, db)
    if not user:
        return RedirectResponse(url="/demo/login", status_code=302)

    resource, deny_reason = _check_resource_access(request, db, user, "hr")
    if deny_reason:
        return templates.TemplateResponse(
            "demo_denied.html",
            {
                "request": request,
                "user": user,
                "resource_name": "HR Department",
                "deny_reason": deny_reason,
            },
        )

    fake_data = [
        {"id": 1, "name": "Ivan Petrov", "department": "IT", "position": "Developer", "status": "Active"},
        {"id": 2, "name": "Anna Sidorova", "department": "Finance", "position": "Accountant", "status": "Active"},
        {"id": 3, "name": "Dmitry Kozlov", "department": "HR", "position": "Manager", "status": "Active"},
    ]
    return templates.TemplateResponse(
        "demo_resource.html",
        {
            "request": request,
            "user": user,
            "resource_name": "HR Department",
            "description": "Employee records and personnel data",
            "columns": ["ID", "Employee Name", "Department", "Position", "Status"],
            "rows": fake_data,
        },
    )
