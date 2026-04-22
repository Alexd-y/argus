"""SQLAlchemy models — tenants, users, targets, scans, findings, reports, audit_logs, etc."""

import uuid
from datetime import datetime
from typing import Any, Final, Literal

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, validates

from src.owasp_top10_2025 import findings_owasp_category_check_sql

#: Closed taxonomy for ``Tenant.pdf_archival_format`` (B6-T02 / T48 / D-4).
#: Mirrored verbatim in the Alembic 029 ``CHECK`` constraint and the admin
#: ``TenantPatch`` Pydantic schema. A single source of truth keeps the three
#: layers in lock-step.
PdfArchivalFormat = Literal["standard", "pdfa-2u"]
PDF_ARCHIVAL_FORMAT_VALUES: Final[tuple[PdfArchivalFormat, ...]] = (
    "standard",
    "pdfa-2u",
)
PDF_ARCHIVAL_FORMAT_DEFAULT: Final[PdfArchivalFormat] = "standard"

# PK/FK ids: VARCHAR(36) per Alembic 001 — ORM must use String(36), not dialect UUID, or UPDATEs get
# ::uuid binds and Postgres raises: operator does not exist (character varying = uuid).


def gen_uuid() -> str:
    """Generate UUID string for default."""
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    """Base for all models."""

    type_annotation_map = {
        str: String(255),
    }


class Tenant(Base):
    """Tenant — top-level isolation."""

    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    #: When true, tenant may call scan findings SARIF/JUnit export routes (T04).
    exports_sarif_junit_enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    #: Optional override — max API/MCP requests per minute (null = platform default).
    rate_limit_rpm: Mapped[int | None] = mapped_column(Integer, nullable=True)
    #: Optional hostname/path patterns blocked from in-scope scanning (null = default policy).
    scope_blacklist: Mapped[list[Any] | None] = mapped_column(JSONB, nullable=True)
    #: Optional data retention override in days (null = platform default).
    retention_days: Mapped[int | None] = mapped_column(Integer, nullable=True)
    #: PDF archival format selector (B6-T02 / T48 / D-4).
    #:
    #: ``'standard'`` (default) keeps the existing WeasyPrint / legacy LaTeX
    #: render path. ``'pdfa-2u'`` opts the tenant into PDF/A-2u archival
    #: rendering — see ``backend/src/reports/generators.py`` for precedence
    #: rules and ``backend/templates/reports/_latex/_preamble/pdfa.tex.j2``
    #: for the preamble injection.
    #:
    #: Mirrored by the Alembic 029 ``CHECK`` constraint on the same column.
    pdf_archival_format: Mapped[PdfArchivalFormat] = mapped_column(
        String(16),
        nullable=False,
        default=PDF_ARCHIVAL_FORMAT_DEFAULT,
        server_default=PDF_ARCHIVAL_FORMAT_DEFAULT,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        CheckConstraint(
            "pdf_archival_format IN ('standard', 'pdfa-2u')",
            name="ck_tenants_pdf_archival_format",
        ),
    )

    @validates("pdf_archival_format")
    def _validate_pdf_archival_format(self, _key: str, value: object) -> PdfArchivalFormat:
        """Reject taxonomy violations at the ORM layer.

        SQLAlchemy ``@validates`` fires on attribute assignment, *before* the
        DB roundtrip. We surface a clean ``ValueError`` here so a misuse from
        Python code (e.g. seed scripts, fixtures) fails fast with a readable
        message — without depending on the dialect-specific CHECK constraint
        violation that Postgres / SQLite would otherwise return.
        """
        if value not in PDF_ARCHIVAL_FORMAT_VALUES:
            allowed = ", ".join(repr(v) for v in PDF_ARCHIVAL_FORMAT_VALUES)
            raise ValueError(
                f"pdf_archival_format must be one of {{{allowed}}}, got {value!r}"
            )
        return value  # type: ignore[return-value]


class User(Base):
    """User — belongs to tenant."""

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (Index("ix_users_tenant_email", "tenant_id", "email", unique=True),)


class Subscription(Base):
    """Subscription — plan, limits, billing per tenant."""

    __tablename__ = "subscriptions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    plan: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False)
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class Target(Base):
    """Target — scan target, tenant-scoped."""

    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    scope_config: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Scan(Base):
    """Scan — tenant-scoped."""

    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    target_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("targets.id", ondelete="SET NULL"), nullable=True
    )
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="pending")
    progress: Mapped[int] = mapped_column(Integer, default=0)
    phase: Mapped[str] = mapped_column(String(50), default="init")
    options: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    #: quick | standard | deep (Strix-style scan mode).
    scan_mode: Mapped[str] = mapped_column(
        String(20), nullable=False, default="standard", server_default=text("'standard'")
    )
    cost_summary: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        Index("ix_scans_tenant_status", "tenant_id", "status"),
        Index("ix_scans_tenant_created", "tenant_id", "created_at"),
    )


class ScanSchedule(Base):
    """Operator-managed recurring scan schedule — tenant-scoped (T32 / ARG-056).

    Data-layer foundation for Cycle 6 Batch 4 scheduled scans. Business logic
    (CRUD endpoints, RedBeat reconciliation, maintenance-window evaluation)
    lives in T33/T34 and intentionally does not reach this model.
    """

    __tablename__ = "scan_schedules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    #: Operator-visible label — unique per tenant.
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    #: 5-field cron expression; T34 validates with croniter before persist.
    cron_expression: Mapped[str] = mapped_column(String(64), nullable=False)
    #: Absolute URL of the scan target; T33 validates against tenant scope.
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    #: quick | standard | deep — matches ``Scan.scan_mode`` taxonomy.
    scan_mode: Mapped[str] = mapped_column(String(50), nullable=False)
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("true")
    )
    #: Optional cron window during which firings are suppressed (null = always on).
    maintenance_window_cron: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_scan_schedules_tenant_name"),
        Index("ix_scan_schedules_tenant_enabled", "tenant_id", "enabled"),
        Index("ix_scan_schedules_next_run_at", "next_run_at"),
    )

    def __repr__(self) -> str:  # pragma: no cover — debug aid only
        return (
            f"<ScanSchedule id={self.id!r} tenant_id={self.tenant_id!r} "
            f"name={self.name!r} enabled={self.enabled!r}>"
        )


class WebhookDlqEntry(Base):
    """Webhook DLQ entry — one failed-after-retry delivery (T37 / ARG-053).

    Persistent dead-letter store for webhook deliveries that exhausted the
    retry budget inside ``NotifierBase.send_with_retry``. Backs the
    ``/admin/webhooks/dlq`` admin surface (T39) and the daily
    ``argus.notifications.webhook_dlq_replay`` Celery beat task (T40).

    Idempotency key: ``(tenant_id, adapter_name, event_id)`` — re-enqueueing
    the same logical delivery is a no-op (UNIQUE violation surfaces as a
    silent merge in the DAO layer T38).

    The target URL is never persisted in clear; ``target_url_hash`` stores
    ``hash_target(url)`` from
    ``backend/src/mcp/services/notifications/_base.py``.
    """

    __tablename__ = "webhook_dlq_entries"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    adapter_name: Mapped[str] = mapped_column(String(64), nullable=False)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    event_id: Mapped[str] = mapped_column(String(64), nullable=False)
    target_url_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    last_error_code: Mapped[str] = mapped_column(String(64), nullable=False)
    last_status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    attempt_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    next_retry_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    replayed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    abandoned_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    abandoned_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "adapter_name",
            "event_id",
            name="uq_webhook_dlq_tenant_adapter_event",
        ),
        Index(
            "ix_webhook_dlq_tenant_status",
            "tenant_id",
            "abandoned_at",
            "replayed_at",
        ),
        Index("ix_webhook_dlq_created_at", "created_at"),
    )


class ScanStep(Base):
    """Scan step — sub-step of a scan."""

    __tablename__ = "scan_steps"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    step_name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="pending")
    order_index: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class ScanEvent(Base):
    """Scan event — event log for scan (SSE source)."""

    __tablename__ = "scan_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    event: Mapped[str] = mapped_column(String(100), nullable=False)
    phase: Mapped[str] = mapped_column(String(50), nullable=True)
    progress: Mapped[int] = mapped_column(Integer, nullable=True)
    message: Mapped[str] = mapped_column(Text, nullable=True)
    data: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    duration_sec: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (Index("ix_scan_events_scan_created", "scan_id", "created_at"),)


class ScanTimeline(Base):
    """Scan timeline — ordered entries for report."""

    __tablename__ = "scan_timeline"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    phase: Mapped[str] = mapped_column(String(50), nullable=False)
    order_index: Mapped[int] = mapped_column(Integer, default=0)
    entry: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Asset(Base):
    """Asset — discovered assets (subdomains, ports, tech)."""

    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    asset_type: Mapped[str] = mapped_column(String(100), nullable=False)
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    extra_data: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)  # metadata, renamed to avoid SA reserved
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Report(Base):
    """Report — scan report, tenant-scoped."""

    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )
    target: Mapped[str] = mapped_column(String(2048), nullable=False)
    tier: Mapped[str] = mapped_column(String(32), nullable=False, default="midgard")
    generation_status: Mapped[str] = mapped_column(String(32), nullable=False, default="ready")
    template_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    prompt_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    #: Sanitized short message for operators only; no tracebacks or raw exception text.
    last_error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    requested_formats: Mapped[list[Any] | dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    #: Extension JSON; no secrets or PII; prefer an allowlisted key set at API boundaries.
    report_metadata: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    summary: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    technologies: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("ix_reports_tenant_target_created", "tenant_id", "target", "created_at"),
        Index("ix_reports_scan_tier", "scan_id", "tier"),
    )


class Finding(Base):
    """Finding — vulnerability finding, tenant-scoped."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    report_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("reports.id", ondelete="CASCADE"), nullable=True
    )
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    cwe: Mapped[str] = mapped_column(String(20), nullable=True)
    cvss: Mapped[float] = mapped_column(Float, nullable=True)
    #: OWASP Top 10:2025 short id (``A01``…``A10``); see ``src/owasp_top10_2025.py``.
    owasp_category: Mapped[str | None] = mapped_column(String(8), nullable=True)
    proof_of_concept: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    #: confirmed | likely | possible | advisory (T4).
    confidence: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="likely",
        server_default=text("'likely'"),
    )
    #: observed | tool_output | version_match | cve_correlation | threat_model_inference (T4).
    evidence_type: Mapped[str | None] = mapped_column(String(40), nullable=True)
    evidence_refs: Mapped[list[Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'[]'::jsonb")
    )
    reproducible_steps: Mapped[str | None] = mapped_column(Text, nullable=True)
    applicability_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    adversarial_score: Mapped[float | None] = mapped_column(Float, nullable=True, default=None)
    #: unique | duplicate | unchecked (Strix-style LLM dedup).
    dedup_status: Mapped[str | None] = mapped_column(
        String(20), nullable=True, default="unchecked", server_default=text("'unchecked'")
    )
    false_positive: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    false_positive_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("ix_findings_scan_id", "scan_id"),
        Index("ix_findings_report_id", "report_id"),
        CheckConstraint(findings_owasp_category_check_sql(), name="ck_findings_owasp_category"),
    )


class FindingNote(Base):
    """Operator note attached to a finding (tenant-scoped)."""

    __tablename__ = "finding_notes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    finding_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    author: Mapped[str] = mapped_column(String(255), nullable=False, default="system")
    note: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (Index("ix_finding_notes_finding_id", "finding_id"),)


class ToolRun(Base):
    """Tool run — tool execution record; input, output, object_key."""

    __tablename__ = "tool_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    tool_name: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="pending")
    input_params: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    output_raw: Mapped[str] = mapped_column(Text, nullable=True)
    output_object_key: Mapped[str] = mapped_column(String(512), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Evidence(Base):
    """Evidence — PoC files; object_key points to MinIO."""

    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    finding_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    object_key: Mapped[str] = mapped_column(String(512), nullable=False)
    content_type: Mapped[str] = mapped_column(String(100), nullable=True)
    description: Mapped[str] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AuditLog(Base):
    """Audit log — append-only, immutable. No UPDATE/DELETE."""

    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[str] = mapped_column(String(36), nullable=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(100), nullable=True)
    resource_id: Mapped[str] = mapped_column(String(36), nullable=True)
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("ix_audit_logs_tenant_created", "tenant_id", "created_at"),
        {"comment": "Append-only. RLS and triggers prevent UPDATE/DELETE."},
    )


class Policy(Base):
    """Policy — policy config (approval gates, scope)."""

    __tablename__ = "policies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    policy_type: Mapped[str] = mapped_column(String(100), nullable=False)
    config: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class UsageMetering(Base):
    """Usage metering — usage metrics (scans, tokens, etc.)."""

    __tablename__ = "usage_metering"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    metric_type: Mapped[str] = mapped_column(String(100), nullable=False)
    value: Mapped[int] = mapped_column(Integer, nullable=False)
    extra_data: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)  # metadata, renamed to avoid SA reserved
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ProviderConfig(Base):
    """Provider config — LLM provider config per tenant."""

    __tablename__ = "provider_configs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    provider_key: Mapped[str] = mapped_column(String(100), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    config: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class ProviderHealth(Base):
    """Provider health — provider status, last check."""

    __tablename__ = "provider_health"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    provider_key: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False)
    last_error: Mapped[str] = mapped_column(Text, nullable=True)
    last_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class PhaseInput(Base):
    """Phase input — persisted phase input contracts."""

    __tablename__ = "phase_inputs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    phase: Mapped[str] = mapped_column(String(50), nullable=False)
    input_data: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class PhaseOutput(Base):
    """Phase output — persisted phase output contracts."""

    __tablename__ = "phase_outputs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    phase: Mapped[str] = mapped_column(String(50), nullable=False)
    output_data: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ReportObject(Base):
    """Report object — report artifacts in MinIO (PDF, HTML, etc.)."""

    __tablename__ = "report_objects"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    report_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("reports.id", ondelete="CASCADE"), nullable=False
    )
    format: Mapped[str] = mapped_column(String(48), nullable=False)
    object_key: Mapped[str] = mapped_column(String(512), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Screenshot(Base):
    """Screenshot — screenshot metadata; object_key, url_or_email."""

    __tablename__ = "screenshots"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    object_key: Mapped[str] = mapped_column(String(512), nullable=False)
    url_or_email: Mapped[str] = mapped_column(String(2048), nullable=True)
    content_type: Mapped[str] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AdminUser(Base):
    """Admin / operator account — cross-tenant by design (ISS-T20-003 Phase 1).

    This table is intentionally separate from :class:`User` (which is a
    tenant-scoped end-user with JWT credentials). AdminUser rows authenticate
    operators, admins, and super-admins of the ARGUS console itself; they are
    never end-users of a tenant, and they are NOT subject to tenant RLS — the
    super-admin role MUST be able to act across tenants for triage, emergency
    stop, and audit-log forensics.

    Password hashes are bcrypt at rest (rounds >= 12) and are produced
    out-of-band (operator workflow); the bootstrap path
    (``ADMIN_BOOTSTRAP_SUBJECT`` + ``ADMIN_BOOTSTRAP_PASSWORD_HASH``) only
    accepts a *pre-hashed* value so plaintext credentials never appear in the
    runtime environment, the audit log, or the Alembic chain.

    ``mfa_secret`` is a Phase 1 placeholder kept for backwards compatibility
    with deployments that already ran migrations 028–030. The Phase 2 (C7)
    MFA columns added by Alembic 032 are ``mfa_enabled``,
    ``mfa_secret_encrypted`` and ``mfa_backup_codes_hash`` — see
    :mod:`backend.src.auth.admin_mfa`.
    """

    __tablename__ = "admin_users"

    #: Canonical admin identifier (typically an email). PRIMARY KEY — there is
    #: exactly one row per admin subject across the entire deployment.
    subject: Mapped[str] = mapped_column(String(255), primary_key=True)
    #: bcrypt hash of the admin password (passlib format, rounds >= 12).
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    #: Closed taxonomy: operator | admin | super-admin (mirrors X-Admin-Role).
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    #: Optional tenant pin for operator/admin roles. ``NULL`` = super-admin
    #: (cross-tenant authority).
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    #: Legacy Phase 1 placeholder. Always ``NULL`` going forward — Phase 2
    #: stores the TOTP secret in the Fernet-encrypted ``mfa_secret_encrypted``
    #: column instead. Kept nullable so the 028–030 → 032 chain is additive.
    mfa_secret: Mapped[str | None] = mapped_column(String(255), nullable=True)
    #: C7-T01 — true once :func:`admin_mfa.confirm_enrollment` succeeds.
    #: Gates the second-factor challenge in :mod:`admin_auth`. Defaults to
    #: ``False`` so existing rows are non-MFA until explicitly enrolled.
    mfa_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false"), default=False
    )
    #: C7-T01 — Fernet ciphertext of the base32 TOTP secret. Encryption key
    #: comes from ``Settings.admin_mfa_keyring`` (CSV of base64 keys, newest
    #: first). Plaintext NEVER hits disk and MUST NOT be logged. ``NULL``
    #: until ``enroll_totp`` runs.
    mfa_secret_encrypted: Mapped[bytes | None] = mapped_column(
        LargeBinary, nullable=True
    )
    #: C7-T01 — bcrypt hashes of one-time backup codes (cost ≥ 12). Issued
    #: 10 at a time by ``regenerate_backup_codes``; consumed atomically by
    #: ``consume_backup_code`` so a single code can never be redeemed twice.
    #: Postgres → ``TEXT[]``; SQLite (test/dev only) → JSON array.
    mfa_backup_codes_hash: Mapped[list[str] | None] = mapped_column(
        ARRAY(String).with_variant(JSON, "sqlite"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    #: Soft-delete marker. When non-NULL, ``verify_credentials`` MUST refuse
    #: the row even if the password matches — the operator was off-boarded.
    disabled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class AdminSession(Base):
    """Authenticated admin/operator session — cross-tenant (ISS-T20-003 Phase 1).

    Backs the cookie-based admin session introduced as the canonical admin
    auth surface (Phase 1, dual-mode). Session IDs are CSPRNG-generated
    URL-safe base64 strings (~64 chars from ``secrets.token_urlsafe(48)``);
    they are random, opaque, and looked up via ``hmac.compare_digest`` to
    avoid timing oracles on the equality check.

    Cross-tenant by design — RLS is intentionally NOT enabled on this table.
    Sessions belong to operators, not tenants; the ``tenant_id`` column is
    a *role context* hint (matches ``admin_users.tenant_id``) and not a
    tenant-isolation key. Enforcing RLS here would silently break the
    super-admin login flow whose role is itself cross-tenant.

    ``ip_hash`` and ``user_agent_hash`` are sha256 fingerprints (no salt
    needed — they are non-PII surrogates of forensic value, not tenant-scoped
    metric labels). The raw IP / user-agent never hit the database.

    Sliding-window TTL: ``resolve_session`` extends ``expires_at`` and
    ``last_used_at`` to ``now() + ADMIN_SESSION_TTL_SECONDS`` on every
    successful resolution so an active operator never gets logged out
    mid-flow. ``revoked_at`` is tombstone-only — once set, the session is
    permanently invalid.
    """

    __tablename__ = "admin_sessions"

    #: URL-safe base64 session id — opaque, CSPRNG-generated.
    #:
    #: Stays PRIMARY KEY during the 030 → 031 grace window so a deploy
    #: rollback does not invalidate live tokens. New writes mirror the raw
    #: token here only when ``ADMIN_SESSION_LEGACY_RAW_WRITE=true`` (default
    #: ON). After two TTL windows (≥24 h) in production set the flag OFF and
    #: run Alembic 031 to drop this column; ``session_token_hash`` then
    #: becomes the sole primary key.
    session_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    #: At-rest hash ``sha256(ADMIN_SESSION_PEPPER || raw_token)``. Hex digest,
    #: 64 chars. UNIQUE-indexed; primary lookup column for resolve / revoke
    #: after Alembic 030 (ISS-T20-003 hardening — defeat replay-from-DB-leak).
    #: NULL only for pre-030 rows backfilled when ``ADMIN_SESSION_PEPPER`` was
    #: unset; such rows are unreachable from the hash path and invalidate
    #: after one TTL window.
    session_token_hash: Mapped[str | None] = mapped_column(
        String(64), nullable=True, unique=True, index=True
    )
    #: Admin subject (matches ``admin_users.subject``); kept denormalized so
    #: revocation lookups never need a join.
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    #: Closed taxonomy: operator | admin | super-admin.
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    #: Optional tenant pin (matches admin_users.tenant_id; super-admin → NULL).
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    last_used_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    #: sha256 fingerprint of the client IP at session creation (forensic only).
    ip_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    #: sha256 fingerprint of the User-Agent at session creation (forensic only).
    user_agent_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    #: Tombstone — set on logout, admin revoke, or password change. Once set,
    #: ``resolve_session`` MUST refuse the row.
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    #: C7-T01 — timestamp of the most recent successful MFA challenge for
    #: this session. ``NULL`` means MFA has never been satisfied (or the
    #: subject is not MFA-enrolled). Compared against
    #: ``Settings.admin_mfa_reauth_window_seconds`` to gate sensitive
    #: actions; refreshed by :func:`admin_mfa.mark_session_mfa_passed`.
    mfa_passed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        Index("ix_admin_sessions_subject_revoked", "subject", "revoked_at"),
        Index("ix_admin_sessions_expires_at", "expires_at"),
    )
