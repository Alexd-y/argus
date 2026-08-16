"""SQLAlchemy rows for Quick execution mode (String(36) UUIDs, tenant_id, RLS-ready)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from src.db.models import Base, gen_uuid


class QuickScanConfigRow(Base):
    """Persisted QuickScanConfig bound 1:1 to a scan."""

    __tablename__ = "quick_scan_configs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    profile: Mapped[str] = mapped_column(String(32), nullable=False)
    wall_clock_budget_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    ai_budget_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    reserve_for_validation_percent: Mapped[int] = mapped_column(Integer, nullable=False)
    max_targets: Mapped[int] = mapped_column(Integer, nullable=False)
    max_urls_per_host: Mapped[int] = mapped_column(Integer, nullable=False)
    crawl_depth: Mapped[int] = mapped_column(Integer, nullable=False)
    severity_floor: Mapped[str] = mapped_column(String(32), nullable=False)
    enable_ai: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    enable_oast: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    enable_headless_on_signal: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    authenticated_context_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    template_policy_id: Mapped[str] = mapped_column(
        String(128), nullable=False, default="quick-default"
    )
    cloud_llm_allowed: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    deadline_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        UniqueConstraint("scan_id", name="uq_quick_scan_configs_scan_id"),
        Index("ix_quick_scan_configs_tenant_scan", "tenant_id", "scan_id"),
        Index("ix_quick_scan_configs_deadline", "deadline_at"),
    )


class QuickScanPlanRow(Base):
    """Append-only Quick plan revisions. Unique (scan_id, plan_version)."""

    __tablename__ = "quick_scan_plans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    plan_version: Mapped[int] = mapped_column(Integer, nullable=False)
    prompt_version: Mapped[str] = mapped_column(String(128), nullable=False)
    model_route: Mapped[str] = mapped_column(String(128), nullable=False)
    deadline_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    budget: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    stages: Mapped[list[Any] | dict[str, Any]] = mapped_column(JSONB, nullable=False)
    tasks: Mapped[list[Any] | dict[str, Any]] = mapped_column(JSONB, nullable=False)
    fallbacks: Mapped[list[Any] | dict[str, Any]] = mapped_column(JSONB, nullable=False)
    coverage_intent: Mapped[list[Any] | dict[str, Any]] = mapped_column(JSONB, nullable=False)
    assumptions: Mapped[list[Any] | dict[str, Any]] = mapped_column(JSONB, nullable=False)
    revision_reason: Mapped[str | None] = mapped_column(String(512), nullable=True)
    evidence_ids: Mapped[list[Any] | dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    cost_estimate_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        UniqueConstraint("scan_id", "plan_version", name="uq_quick_scan_plans_scan_version"),
        Index("ix_quick_scan_plans_tenant_scan", "tenant_id", "scan_id"),
    )


class QuickTaskRow(Base):
    """Scheduled Quick task with idempotency key and optional Celery id."""

    __tablename__ = "quick_tasks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    plan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("quick_scan_plans.id", ondelete="CASCADE"), nullable=False
    )
    stage: Mapped[str] = mapped_column(String(32), nullable=False)
    target_ref: Mapped[str] = mapped_column(String(256), nullable=False)
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False)
    capability_id: Mapped[str] = mapped_column(String(256), nullable=False)
    estimated_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    estimated_requests: Mapped[int] = mapped_column(Integer, nullable=False)
    priority_score: Mapped[float] = mapped_column(Float, nullable=False)
    depends_on: Mapped[list[Any] | dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    success_signal: Mapped[list[Any] | dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    stop_conditions: Mapped[list[Any] | dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    policy_decision_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    budget_lease_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    idempotency_key: Mapped[str] = mapped_column(String(256), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued")
    celery_task_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_quick_tasks_idempotency_key"),
        Index("ix_quick_tasks_tenant_scan", "tenant_id", "scan_id"),
        Index("ix_quick_tasks_plan_status", "plan_id", "status"),
    )


class QuickBudgetLeaseRow(Base):
    """Wall-clock / request / concurrency lease issued by QuickBudgetManager (QUICK-002)."""

    __tablename__ = "quick_budget_leases"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    task_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("quick_tasks.id", ondelete="SET NULL"), nullable=True
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    granted: Mapped[int] = mapped_column(Integer, nullable=False)
    consumed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        Index("ix_quick_budget_leases_tenant_scan", "tenant_id", "scan_id"),
        Index("ix_quick_budget_leases_status_expires", "status", "expires_at"),
    )
