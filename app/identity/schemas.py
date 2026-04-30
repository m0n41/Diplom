from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, Field, UUID4


class RoleRead(BaseModel):
    id: UUID4
    name: str
    description: Optional[str] = None

    class Config:
        orm_mode = True


class PermissionRead(BaseModel):
    id: UUID4
    action: str
    description: Optional[str] = None
    resource_id: UUID4

    class Config:
        orm_mode = True


class ResourceRead(BaseModel):
    id: UUID4
    name: str
    category: str
    criticality: int

    class Config:
        orm_mode = True


class UserRead(BaseModel):
    id: UUID4
    username: str
    email: str
    is_active: bool
    roles: List[RoleRead] = []

    class Config:
        orm_mode = True


class UserCreate(BaseModel):
    username: str = Field(..., min_length=1, max_length=150)
    email: str = Field(..., max_length=255)
    password: str = Field(..., min_length=6)


class UserUpdate(BaseModel):
    email: Optional[str] = None
    password: Optional[str] = None
    is_active: Optional[bool] = None


# ===== Role Schemas =====
class RoleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None


class RoleUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = None


# ===== Permission Schemas =====
class PermissionCreate(BaseModel):
    action: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None
    resource_id: UUID4


class PermissionUpdate(BaseModel):
    action: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = None


# ===== Resource Schemas =====
class ResourceCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    category: str = Field(..., min_length=1, max_length=100)
    criticality: int = Field(..., ge=1, le=5)  # 1=low, 5=critical


class ResourceUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    category: Optional[str] = Field(None, min_length=1, max_length=100)
    criticality: Optional[int] = Field(None, ge=1, le=5)


# ===== Assignment Schemas =====
class AssignRoleToUser(BaseModel):
    role_id: UUID4


class AssignPermissionToRole(BaseModel):
    permission_id: UUID4
