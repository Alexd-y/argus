"""SQLAlchemy model for DB-backed Cairn worker configuration (§12.2).

Replaces upstream's ``dispatch.yaml``: workers are rows, secrets stay in
``ProviderConfig`` / env (never here). Tenant-scoped with FORCE RLS.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from src.db.models import Base, gen_uuid

WORKER_TYPES: tuple[str, ...] = ("wrb", "claudecode", "codex", "pi", "mock")


class CairnWorker(Base):
    """A configured Cairn worker (driver + limits + task types)."""

    __tablename__ = "cairn_workers"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    type: Mapped[str] = mapped_column(String(32), nullable=False, default="wrb")
    task_types: Mapped[list[Any]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
    max_running: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default=text("1")
    )
    priority: Mapped[int] = mapped_column(
        Integer, nullable=False, default=100, server_default=text("100")
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("true")
    )
    provider_config_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (UniqueConstraint("tenant_id", "name", name="uq_cairn_workers_tenant_name"),)
