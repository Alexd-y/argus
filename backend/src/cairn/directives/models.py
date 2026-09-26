"""SQLAlchemy model for generated pentest directives (§18.3)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from src.db.models import Base, gen_uuid

DIRECTIVE_STATUSES: tuple[str, ...] = (
    "proposed",
    "accepted",
    "running",
    "concluded",
    "rejected",
    "expired",
)


class CairnDirective(Base):
    """A generated pentest directive — a typed, focused next step."""

    __tablename__ = "cairn_directives"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    ref: Mapped[str] = mapped_column(String(16), nullable=False)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cairn_projects.id", ondelete="CASCADE"), nullable=False
    )
    scan_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    directive_text: Mapped[str] = mapped_column(Text, nullable=False)
    focus: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    success_criterion: Mapped[str] = mapped_column(Text, nullable=False, default="")
    proof_requirement: Mapped[str] = mapped_column(
        String(32), nullable=False, default="tool_output"
    )
    intrusiveness: Mapped[str] = mapped_column(String(32), nullable=False, default="active_safe")
    priority_score: Mapped[float] = mapped_column(
        Float, nullable=False, default=0.0, server_default=text("0")
    )
    priority_rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    scope_guard: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    basis: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="proposed")
    intent_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("cairn_intents.id", ondelete="SET NULL"), nullable=True
    )
    outcome_fact_ref: Mapped[str | None] = mapped_column(String(16), nullable=True)
    llm_provenance: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        UniqueConstraint("project_id", "ref", name="uq_cairn_directives_project_ref"),
        Index("ix_cairn_directives_scan_status", "tenant_id", "scan_id", "status"),
        Index("ix_cairn_directives_priority", "tenant_id", "priority_score"),
    )
