from pydantic import BaseModel, Field


class AccessCheckRequest(BaseModel):
    resource_id: str = Field(..., description="UUID ресурса")
    action: str = Field(..., description="Действие, например: read, write, delete")
