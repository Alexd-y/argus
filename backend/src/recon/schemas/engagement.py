"""Engagement API request/response schemas."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from src.recon.schemas.base import EngagementStatus, Environment
from src.recon.schemas.scope import ScopeConfig


class ContactInfo(BaseModel):
    """Engagement contact metadata."""
    name: str
    role: str = ""
    email: str = ""
    phone: str = ""
    notes: str = ""


class EngagementCreate(BaseModel):
    """Create engagement request."""
    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = None
    scope_config: ScopeConfig = Field(default_factory=ScopeConfig)
    contacts: list[ContactInfo] = Field(default_factory=list)
    environment: Environment = Environment.PRODUCTION


class EngagementUpdate(BaseModel):
    """Partial update engagement request."""
    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = None
    scope_config: ScopeConfig | None = None
    contacts: list[ContactInfo] | None = None
    environment: Environment | None = None
    status: EngagementStatus | None = None


class EngagementResponse(BaseModel):
    """Engagement response with stats."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    name: str
    description: str | None = None
    status: str
    scope_config: dict | None = None
    contacts: dict | None = None
    environment: str
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
    target_count: int = 0
    job_count: int = 0
    finding_count: int = 0


class EngagementListResponse(BaseModel):
    """Paginated engagement list."""
    items: list[EngagementResponse]
    total: int
    offset: int
    limit: int
