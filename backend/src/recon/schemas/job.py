"""Scan job API request/response schemas."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field



class ScanJobCreate(BaseModel):
    """Create scan job request."""
    target_id: str
    stage: int = Field(..., ge=0, le=18)
    tool_name: str = Field(..., min_length=1, max_length=100)
    config: dict | None = None
    operator: str | None = None


class ScanJobResponse(BaseModel):
    """Scan job response."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    engagement_id: str
    target_id: str
    stage: int
    stage_name: str
    tool_name: str
    status: str
    config: dict | None = None
    result_summary: dict | None = None
    error_message: str | None = None
    operator: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class ScanJobListResponse(BaseModel):
    """Paginated job list."""
    items: list[ScanJobResponse]
    total: int
