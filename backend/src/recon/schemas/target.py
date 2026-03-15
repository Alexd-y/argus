"""Target API request/response schemas."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from src.recon.schemas.base import TargetType


class ReconTargetCreate(BaseModel):
    """Create target request."""
    domain: str = Field(..., min_length=1, max_length=512)
    target_type: TargetType = TargetType.DOMAIN
    extra_data: dict | None = None


class ReconTargetResponse(BaseModel):
    """Target response with counts."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    engagement_id: str
    domain: str
    target_type: str
    extra_data: dict | None = None
    created_at: datetime
    job_count: int = 0
    finding_count: int = 0
