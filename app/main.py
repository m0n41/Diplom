import uvicorn
from fastapi import FastAPI, Request
from fastapi.openapi.utils import get_openapi
from fastapi.security import HTTPBearer
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.auth.routes import router as auth_router
from app.identity.routes import router as identity_router

# from app.authorization.routes import router as authorization_router  # No routes defined in this module
from app.access.routes import router as access_router
from app.audit.routes import router as audit_router
from app.admin.routes import router as admin_router

templates = Jinja2Templates(directory="app/admin/templates")

app = FastAPI(
    title="Automated Information System for Authentication and Access Control with Centralized Audit",
    version="0.1.0",
    openapi_url="/openapi.json",
    docs_url="/docs",
)

# Ensure all tables exist (create if missing)
from app.db.base import Base
from app.db.session import engine

Base.metadata.create_all(bind=engine)

# Настройка JWT Bearer аутентификации
security = HTTPBearer()


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title="Automated Information System for Authentication and Access Control with Centralized Audit",
        version="0.1.0",
        description="Authentication and Access Control with Centralized Audit",
        routes=app.routes,
    )
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
        }
    }
    openapi_schema["security"] = [{"BearerAuth": []}]
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi

# Mount static files for admin UI (CSS/JS)
app.mount("/static", StaticFiles(directory="app/static"), name="static")
# Make the Jinja2 templates available globally
app.state.templates = templates

# Register routers
app.include_router(auth_router, prefix="/auth", tags=["auth"])
app.include_router(identity_router, prefix="/identity", tags=["identity"])
# app.include_router(authorization_router, prefix="/access", tags=["authorization"])
app.include_router(access_router, prefix="/access", tags=["access"])
app.include_router(audit_router, prefix="/audit", tags=["audit"])
app.include_router(admin_router, prefix="/admin", tags=["admin"])


@app.get("/health", tags=["monitoring"])
async def health_check():
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
    )
