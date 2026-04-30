# Automated Information System for Authentication and Access Control with Centralized Audit

## Overview

This repository contains a **production‑ready prototype** of an information‑security backend built with **FastAPI**, **SQLAlchemy 2**, **PostgreSQL**, and **Docker**.  
The architecture follows a strict **layered modular monolith**:

1. **Presentation Layer** – FastAPI routers (HTTP transport)
2. **Application Layer** – Service orchestration (future expansion)
3. **Domain Layer** – Pure business logic, policies, and Pydantic models (framework‑independent)
4. **Infrastructure Layer** – Database, cryptography, external providers

Key features:

- Centralized authentication (JWT + refresh tokens)
- RBAC baseline + ABAC restrictive overlay (time‑window & IP checks)
- Deterministic, fail‑safe authorization decision point (PDP) and enforcement point (PEP)
- Immutable audit logging with full context snapshots
- Minimal admin UI (Jinja2) – placeholders for future development
- Full Dockerised development environment with Alembic migrations

## Project Structure

```
app/
├─ main.py                 # FastAPI entrypoint
├─ config.py               # Pydantic Settings (env vars)
├─ db/
│   ├─ base.py              # Declarative Base
│   └─ session.py           # Session/engine factory
├─ core/
│   ├─ security.py          # Password hashing, JWT helpers
│   └─ identity_provider.py # IdP abstraction
├─ auth/
│   ├─ schemas.py           # Pydantic request/response models
│   └─ routes.py            # /login, /refresh, /logout
├─ identity/
│   └─ routes.py            # Placeholder for user/role management
├─ authorization/
│   ├─ pdp.py               # Policy Decision Point (framework‑independent)
│   └─ pep.py               # FastAPI dependency (Policy Enforcement Point)
├─ access/
│   └─ routes.py            # Demo /access/check endpoint
├─ audit/
│   ├─ service.py           # Immutable audit logger (best‑effort)
│   └─ routes.py            # Retrieve audit events (protected)
├─ admin/
│   └─ routes.py            # Placeholder for server‑rendered admin UI
├─ models/
│   ├─ __init__.py
│   └─ models.py            # ORM entities (User, Role, Permission, …)
└─ static/                  # Static assets for admin UI (optional)

Dockerfile
docker-compose.yml
requirements.txt
alembic/
    ├─ alembic.ini
    ├─ env.py
    └─ versions/
        └─ 0001_initial.py
.env.example                # Template for environment variables
README.md
```

## Prerequisites

- **Docker & Docker‑Compose** (latest stable)
- **Python 3.11+** (if you want to run locally without Docker)
- No LDAP or external IdP required – a local PostgreSQL database is used by default.

## Quick Start (Docker)

```bash
# 1. Clone the repository
git clone <repo‑url>
cd Diplom_new

# 2. Copy the example env file and adjust if needed
cp .env.example .env

# 3. Build and start containers
docker compose up --build

# 4. Apply database migrations (container will run this automatically)
#    If you need to run manually:
docker compose exec api alembic upgrade head
```

The API will be reachable at `http://localhost:8000`.

### Example Requests

```bash
# Register a user directly via DB (or implement a signup endpoint later)
# For demo purposes, insert a user with bcrypt password hash.

# Login
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"secret"}'

# Refresh token
curl -X POST http://localhost:8000/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<your_refresh_token>"}'

# Protected check (demo)
curl -H "Authorization: Bearer <access_token>" http://localhost:8000/access/check
```

## Development (without Docker)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Export required env vars (use .env.example as reference)
export $(cat .env.example | xargs)

# Run Alembic migrations
alembic upgrade head

# Start the API
uvicorn app.main:app --reload
```

## Security Highlights

- **Password hashing** – `passlib` with bcrypt (configurable rounds).
- **JWT** – Signed with a secret provided solely via environment variable.
- **Refresh tokens** – Stored hashed in DB, revocable, short‑lived access tokens.
- **Fail‑safe authorization** – Any error or missing data results in `DENY`.
- **ABAC predicates** – Time‑based (08:00‑18:00 UTC) and private‑IP restriction (example).
- **Immutable audit events** – No UPDATE/DELETE, best‑effort logging, never blocks the main flow.
- **Layered architecture** – Business logic (PDP) is pure Python, independent of FastAPI.

## Next Steps (TODO)

- Implement full **identity management** endpoints (CRUD for users, roles, permissions, resources).
- Flesh out **admin UI** with Jinja2 templates (pages for users, roles, permissions, audit logs).
- Add **brute‑force protection** (login attempt counters or exponential back‑off).
- Extend **ABAC** with richer predicates (device type, location, clearance level).
- Comprehensive **unit/integration test suite**.
- Documentation of the security model and threat analysis for diploma defense.

---

_Prepared for diploma‑level defense in Information Security._
