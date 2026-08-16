"""SQLAlchemy rows for logical findings, occurrences, assessments, retests."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from src.db.models import Base, gen_uuid

_JSON_PAYLOAD = JSONB().with_variant(JSON, "sqlite")


class LogicalFindingRow(Base):
    """Persisted logical finding (tenant-owned, RLS). Not ``findings`` scan-vuln rows."""

    __tablename__ = "logical_findings"

    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), primary_key=True
    )
    finding_key: Mapped[str] = mapped_column(String(64), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(String(36), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="candidate")
    title: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    category: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    evidence_refs: Mapped[list[Any]] = mapped_column(_JSON_PAYLOAD, nullable=False)
    occurrence_keys: Mapped[list[Any]] = mapped_column(_JSON_PAYLOAD, nullable=False)
    scan_ids: Mapped[list[Any]] = mapped_column(_JSON_PAYLOAD, nullable=False)
    coverage_equivalent: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    payload: Mapped[dict[str, Any]] = mapped_column(_JSON_PAYLOAD, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (Index("ix_logical_findings_tenant_engagement", "tenant_id", "engagement_id"),)


class LogicalFindingScanSnapshotRow(Base):
    """Per-scan snapshot of a logical finding for diff/report (append/replace, never delete)."""

    __tablename__ = "logical_finding_scan_snapshots"

    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), primary_key=True
    )
    scan_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    finding_key: Mapped[str] = mapped_column(String(64), primary_key=True)
    payload: Mapped[dict[str, Any]] = mapped_column(_JSON_PAYLOAD, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class FindingOccurrenceRow(Base):
    """Scanner occurrence bound to a logical finding."""

    __tablename__ = "finding_occurrences"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    engagement_id: Mapped[str] = mapped_column(String(36), nullable=False)
    finding_key: Mapped[str] = mapped_column(String(64), nullable=False)
    occurrence_key: Mapped[str] = mapped_column(String(64), nullable=False)
    scanner: Mapped[str] = mapped_column(String(64), nullable=False)
    detector_id: Mapped[str] = mapped_column(String(256), nullable=False)
    detector_version: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_refs: Mapped[list[Any] | None] = mapped_column(_JSON_PAYLOAD, nullable=True)
    scan_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("ix_finding_occurrences_tenant_scan", "tenant_id", "scan_id"),
        Index("ix_finding_occurrences_tenant_finding", "tenant_id", "finding_key"),
    )


class FindingAssessmentRow(Base):
    """Append-only assessment payload. Never deletes the parent finding."""

    __tablename__ = "finding_assessments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    finding_key: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(_JSON_PAYLOAD, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class RetestJobRow(Base):
    """Persisted retest job for a logical finding."""

    __tablename__ = "retest_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    engagement_id: Mapped[str] = mapped_column(String(36), nullable=False)
    finding_key: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    result: Mapped[str | None] = mapped_column(String(32), nullable=True)
    coverage_equivalent: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    payload: Mapped[dict[str, Any] | None] = mapped_column(_JSON_PAYLOAD, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
