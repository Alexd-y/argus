"""SQLAlchemy models for execution mode / LAB scope / leases."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from src.db.models import Base, gen_uuid

_JSON_PAYLOAD = JSONB().with_variant(JSON, "sqlite")


class LabScopeManifestRow(Base):
    """Persisted LabScopeManifest (tenant-owned, RLS)."""

    __tablename__ = "lab_scope_manifests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    engagement_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False
    )
    mode: Mapped[str] = mapped_column(String(32), nullable=False, default="lab_unrestricted")
    payload: Mapped[dict[str, Any]] = mapped_column(_JSON_PAYLOAD, nullable=False)
    signature: Mapped[str | None] = mapped_column(String(128), nullable=True)
    capture_full: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_by: Mapped[str] = mapped_column(String(36), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_lab_scope_manifests_tenant_engagement", "tenant_id", "engagement_id"),
        Index("ix_lab_scope_manifests_expires", "expires_at"),
    )


class LabExecutionLeaseRow(Base):
    """Persisted LAB execution lease."""

    __tablename__ = "lab_execution_leases"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    engagement_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False
    )
    manifest_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("lab_scope_manifests.id", ondelete="CASCADE"), nullable=False
    )
    mode: Mapped[str] = mapped_column(String(32), nullable=False, default="lab_unrestricted")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    boundary_proof: Mapped[str] = mapped_column(String(128), nullable=False)
    capture_full: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    k8s_namespace: Mapped[str | None] = mapped_column(String(253), nullable=True)
    payload: Mapped[dict[str, Any] | None] = mapped_column(_JSON_PAYLOAD, nullable=True)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoke_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index("ix_lab_execution_leases_tenant_engagement", "tenant_id", "engagement_id"),
        Index("ix_lab_execution_leases_status", "status", "expires_at"),
    )


class EngagementExecutionModeRow(Base):
    """Immutable execution mode binding for an engagement."""

    __tablename__ = "engagement_execution_modes"

    engagement_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("engagements.id", ondelete="CASCADE"), primary_key=True
    )
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    #: production | lab_unrestricted | quick — validated in Pydantic, not a DB CHECK.
    mode: Mapped[str] = mapped_column(String(32), nullable=False, default="production")
    first_execution_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (Index("ix_engagement_execution_modes_tenant", "tenant_id", "mode"),)
