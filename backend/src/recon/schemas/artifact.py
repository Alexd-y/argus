"""Artifact API response schemas."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ArtifactResponse(BaseModel):
    """Artifact metadata response."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    engagement_id: str
    target_id: str | None = None
    job_id: str | None = None
    artifact_type: str
    stage: int | None = None
    filename: str
    content_type: str
    object_key: str
    size_bytes: int | None = None
    checksum_sha256: str | None = None
    extra_data: dict | None = None
    created_at: datetime
    download_url: str | None = None


class ArtifactListResponse(BaseModel):
    """Artifact list."""
    items: list[ArtifactResponse]
    total: int
