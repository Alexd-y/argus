"""Hypothesis API request/response schemas."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from src.recon.schemas.base import HypothesisPriority, HypothesisStatus


class HypothesisCreate(BaseModel):
    """Create hypothesis request."""
    title: str = Field(..., min_length=1, max_length=500)
    description: str | None = None
    category: str = Field(..., min_length=1, max_length=100)
    priority: HypothesisPriority = HypothesisPriority.MEDIUM
    evidence_refs: list[str] = Field(default_factory=list)
    target_id: str | None = None


class HypothesisUpdate(BaseModel):
    """Update hypothesis request."""
    title: str | None = Field(None, max_length=500)
    description: str | None = None
    priority: HypothesisPriority | None = None
    status: HypothesisStatus | None = None


class HypothesisResponse(BaseModel):
    """Hypothesis response."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    engagement_id: str
    target_id: str | None = None
    title: str
    description: str | None = None
    category: str
    priority: str
    evidence_refs: dict | None = None
    status: str
    created_at: datetime
    updated_at: datetime
