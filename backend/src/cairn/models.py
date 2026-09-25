"""SQLAlchemy models for the Cairn blackboard subsystem (Phase 1).

Ported from ``_external/Cairn/cairn/src/cairn/server/db.py`` (AGPL-3.0). The
upstream schema is SQLite with a single-writer dispatcher; here every table is
tenant-scoped (RLS enforced in migration ``066``), uses ``String(36)`` UUID PKs
per the ARGUS convention (see ``src/db/models.py`` ``gen_uuid``), and carries the
extra columns ARGUS needs for distributed writers (fence tokens), evidence
linkage, cost accounting and durable task tracking.

Deliberate deviations from upstream are documented in
``docs/cairn_port_deviations.md``:
  * distributed writers (Postgres ``FOR UPDATE`` + ``fence_token``) instead of the
    single-writer dispatcher;
  * ``CairnTaskRun`` replaces the in-memory ``futures`` dict;
  * ``CairnWorkerBackoff`` replaces in-memory ``worker_unhealthy_until`` /
    ``worker_rejected_until`` maps;
  * ``CairnIntent.is_completion`` boolean replaces the upstream
    ``to_fact_id == 'goal'`` sentinel check (``goal`` is a ``ref`` here, not a UUID);
  * project-level counters live in a dedicated ``cairn_tenant_counters`` table
    rather than overloading ``scoped_counters`` with a sentinel ``project_id``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from src.db.models import Base, gen_uuid

# --- closed vocabularies (mirrored in migration CHECK constraints) -----------

PROJECT_STATUSES: tuple[str, ...] = ("active", "stopped", "completed")
TASK_TYPES: tuple[str, ...] = ("bootstrap", "reason", "explore", "external")
TASK_RUN_STATES: tuple[str, ...] = (
    "queued",
    "running",
    "succeeded",
    "failed",
    "cancelled",
    "rejected",
    "unhealthy",
)
BACKOFF_KINDS: tuple[str, ...] = ("unhealthy", "rejected")
COUNTER_KINDS: tuple[str, ...] = ("fact", "intent", "hint")


class CairnProject(Base):
    """A Cairn search project — the blackboard for one Fact–Intent graph."""

    __tablename__ = "cairn_projects"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    ref: Mapped[str] = mapped_column(String(32), nullable=False)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    scan_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )
    engagement_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")
    bootstrap_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("true")
    )
    execution_mode: Mapped[str] = mapped_column(String(32), nullable=False, default="production")
    origin_fact_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    goal_fact_id: Mapped[str | None] = mapped_column(String(36), nullable=True)

    # reason-lease (exclusive per project)
    reason_worker: Mapped[str | None] = mapped_column(String(128), nullable=True)
    reason_trigger: Mapped[str | None] = mapped_column(String(128), nullable=True)
    reason_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    reason_last_heartbeat_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    reason_fence_token: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default=text("0")
    )

    # stop conditions
    budget_usd_limit: Mapped[float | None] = mapped_column(Numeric(12, 4), nullable=True)
    max_iterations: Mapped[int | None] = mapped_column(Integer, nullable=True)
    deadline_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    options: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        UniqueConstraint("tenant_id", "ref", name="uq_cairn_projects_tenant_ref"),
        CheckConstraint(
            "status IN ('active','stopped','completed')",
            name="ck_cairn_projects_status",
        ),
        Index("ix_cairn_projects_tenant_status", "tenant_id", "status"),
        Index("ix_cairn_projects_scan", "scan_id"),
    )


class CairnFact(Base):
    """A confirmed objective observation — a node in the graph.

    Special facts ``origin`` and ``goal`` are created with the project.
    """

    __tablename__ = "cairn_facts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    ref: Mapped[str] = mapped_column(String(16), nullable=False)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cairn_projects.id", ondelete="CASCADE"), nullable=False
    )
    description: Mapped[str] = mapped_column(Text, nullable=False)
    created_by: Mapped[str] = mapped_column(String(128), nullable=False, default="system")
    source_task_type: Mapped[str | None] = mapped_column(String(16), nullable=True)
    evidence_refs: Mapped[list[Any]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
    evidence_tier: Mapped[int | None] = mapped_column(Integer, nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    artifact_object_key: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    finding_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        UniqueConstraint("project_id", "ref", name="uq_cairn_facts_project_ref"),
        Index("ix_cairn_facts_project", "project_id"),
        Index("ix_cairn_facts_tenant", "tenant_id"),
    )


class CairnIntent(Base):
    """A declared research direction — an edge ``from: [fact_ids] -> to: fact_id | null``.

    While ``to_fact_id`` is ``NULL`` the intent is open. ``is_completion`` marks the
    special intent that concludes the project towards ``goal`` (ARGUS replaces the
    upstream ``to_fact_id == 'goal'`` sentinel with this boolean because ``goal`` is
    a ``ref`` here, not a UUID).
    """

    __tablename__ = "cairn_intents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    ref: Mapped[str] = mapped_column(String(16), nullable=False)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cairn_projects.id", ondelete="CASCADE"), nullable=False
    )
    to_fact_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("cairn_facts.id", ondelete="SET NULL"), nullable=True
    )
    is_completion: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    description: Mapped[str] = mapped_column(Text, nullable=False)
    creator: Mapped[str] = mapped_column(String(128), nullable=False)
    worker: Mapped[str | None] = mapped_column(String(128), nullable=True)
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    fence_token: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default=text("0")
    )
    attempts: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    concluded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint("project_id", "ref", name="uq_cairn_intents_project_ref"),
        Index("ix_cairn_intents_open", "project_id", "to_fact_id", "worker"),
        Index("ix_cairn_intents_tenant", "tenant_id"),
    )


class CairnIntentSource(Base):
    """Ordered ``from`` edge: which facts an intent departs from."""

    __tablename__ = "cairn_intent_sources"

    intent_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("cairn_intents.id", ondelete="CASCADE"),
        primary_key=True,
    )
    fact_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("cairn_facts.id", ondelete="CASCADE"),
        primary_key=True,
    )
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    position: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )

    __table_args__ = (Index("ix_cairn_intent_sources_fact", "fact_id"),)


class CairnHint(Base):
    """A human hint — injected at any time, read by agents on the next pass."""

    __tablename__ = "cairn_hints"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    ref: Mapped[str] = mapped_column(String(16), nullable=False)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cairn_projects.id", ondelete="CASCADE"), nullable=False
    )
    content: Mapped[str] = mapped_column(Text, nullable=False)
    creator: Mapped[str] = mapped_column(String(128), nullable=False)
    author_user_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        UniqueConstraint("project_id", "ref", name="uq_cairn_hints_project_ref"),
        Index("ix_cairn_hints_project", "project_id"),
    )


class CairnSettings(Base):
    """Per-tenant Cairn settings (one row per tenant).

    Upstream Cairn defaults (15s) assume a 3s tick. ARGUS steps are long (tools run
    for minutes) so defaults are raised. The invariant ``timeout > tick_interval``
    (upstream D-02) is preserved and validated in config + service layers.
    """

    __tablename__ = "cairn_settings"

    tenant_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        primary_key=True,
    )
    intent_timeout: Mapped[int] = mapped_column(
        Integer, nullable=False, default=900, server_default=text("900")
    )
    reason_timeout: Mapped[int] = mapped_column(
        Integer, nullable=False, default=900, server_default=text("900")
    )
    max_intents: Mapped[int] = mapped_column(
        Integer, nullable=False, default=3, server_default=text("3")
    )
    max_workers: Mapped[int] = mapped_column(
        Integer, nullable=False, default=8, server_default=text("8")
    )
    max_running_projects: Mapped[int] = mapped_column(
        Integer, nullable=False, default=3, server_default=text("3")
    )
    max_project_workers: Mapped[int] = mapped_column(
        Integer, nullable=False, default=4, server_default=text("4")
    )
    tick_interval_sec: Mapped[int] = mapped_column(
        Integer, nullable=False, default=10, server_default=text("10")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        CheckConstraint("intent_timeout >= 5", name="ck_cairn_settings_intent_timeout"),
        CheckConstraint("reason_timeout >= 5", name="ck_cairn_settings_reason_timeout"),
    )


class CairnScopedCounter(Base):
    """Per-project monotonic counters for human-readable refs (``f001``/``i001``/``h001``)."""

    __tablename__ = "cairn_scoped_counters"

    project_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("cairn_projects.id", ondelete="CASCADE"),
        primary_key=True,
    )
    kind: Mapped[str] = mapped_column(String(16), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    value: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default=text("0"))

    __table_args__ = (
        CheckConstraint("kind IN ('fact','intent','hint')", name="ck_cairn_scoped_counter_kind"),
    )


class CairnTenantCounter(Base):
    """Per-tenant monotonic counter for project refs (``proj_001``).

    Kept in a dedicated table (rather than overloading ``cairn_scoped_counters``
    with a sentinel ``project_id``) — documented deviation from upstream's global
    ``counters`` table, which cannot be tenant-scoped safely.
    """

    __tablename__ = "cairn_tenant_counters"

    tenant_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        primary_key=True,
    )
    kind: Mapped[str] = mapped_column(String(16), primary_key=True)
    value: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default=text("0"))


class CairnTaskRun(Base):
    """Durable record of a worker task run — replaces the in-memory ``futures`` dict.

    Makes the dispatcher stateless and restartable: a crashed dispatcher recovers
    running tasks from these rows.
    """

    __tablename__ = "cairn_task_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cairn_projects.id", ondelete="CASCADE"), nullable=False
    )
    intent_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("cairn_intents.id", ondelete="SET NULL"), nullable=True
    )
    task_type: Mapped[str] = mapped_column(String(16), nullable=False)
    worker_name: Mapped[str] = mapped_column(String(128), nullable=False)
    state: Mapped[str] = mapped_column(
        String(16), nullable=False, default="queued", server_default="queued"
    )
    outcome: Mapped[str | None] = mapped_column(String(32), nullable=True)
    fence_token: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default=text("0")
    )
    celery_task_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    prompt_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    llm_model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    tokens_in: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tokens_out: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cost_usd: Mapped[float | None] = mapped_column(Numeric(12, 4), nullable=True)
    trace: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    # incremented by the dispatcher when a terminal task's post-effect (backoff /
    # reason-checkpoint) has been applied, so ``tick`` reaping is idempotent.
    post_effect_applied: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("ix_cairn_task_runs_tenant_project_state", "tenant_id", "project_id", "state"),
        Index("ix_cairn_task_runs_worker_state", "worker_name", "state"),
    )


class CairnWorkerBackoff(Base):
    """Worker backoff windows — replaces in-memory unhealthy/rejected maps (D-10).

    ``unhealthy`` blocks a worker globally; ``rejected`` blocks it for a specific
    ``(project_id, task_type)`` pair. A ``NULL`` project/task means the global scope.
    """

    __tablename__ = "cairn_worker_backoff"

    tenant_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        primary_key=True,
    )
    worker_name: Mapped[str] = mapped_column(String(128), primary_key=True)
    kind: Mapped[str] = mapped_column(String(16), primary_key=True)
    # empty string sentinel keeps these as non-null PK columns while representing
    # the "global" scope for unhealthy backoff.
    project_id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default="", server_default=""
    )
    task_type: Mapped[str] = mapped_column(
        String(16), primary_key=True, default="", server_default=""
    )
    blocked_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        CheckConstraint("kind IN ('unhealthy','rejected')", name="ck_cairn_worker_backoff_kind"),
        Index("ix_cairn_worker_backoff_until", "blocked_until"),
    )
