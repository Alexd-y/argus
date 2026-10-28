"""SQLAlchemy row for Dark Web Monitoring observations (tenant-owned, RLS).

House style (see ``src.db.models``): manual ``id`` / ``tenant_id`` / timestamps,
``String(36)`` UUIDs (never native pg UUID — asyncpg emits ``::uuid`` binds
against VARCHAR otherwise), no ``relationship()``, no mixin. JSONB columns use
the sqlite variant so the aiosqlite alembic smoke test keeps working.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKey, Index, Integer, String, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from src.db.models import Base, gen_uuid

_JSON_PAYLOAD = JSONB().with_variant(JSON, "sqlite")


class DarkWebObservation(Base):
    """A single dark-web / leak observation discovered for an authorized target.

    Each row carries a reproducible provenance (``source_ref`` + ``observed_at`` /
    ``collected_at`` + ``raw_sha256`` + ``raw_object_key`` + ``chain_hash``). The
    ``evidence_tier`` is CAPPED at 2 (SUSPECTED); DWM never asserts CONFIRMED.
    """

    __tablename__ = "dark_web_observations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    #: Set by the per-finding correlation pass (T2); NULL for scan-level sweeps (T1).
    finding_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("findings.id", ondelete="SET NULL"), nullable=True
    )

    #: domain | email | finding | keyword | infra
    selector_kind: Mapped[str] = mapped_column(String(20), nullable=False)
    #: sha256 of the selector value (email is never stored plaintext in an indexable column).
    selector_value_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    #: tor | i2p | telegram | forum | clearnet_index | breach_db | paste | feed | repo
    source_network: Mapped[str] = mapped_column(String(20), nullable=False)
    #: onion url / channel / breach name / repo url (never a secret).
    source_ref: Mapped[str | None] = mapped_column(Text, nullable=True)

    #: credential | stealer_log | pii | secret_key | mention | access_sale | document
    exposure_type: Mapped[str] = mapped_column(String(30), nullable=False)
    #: critical | high | medium | low | info
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="info")
    #: likely | possible | advisory — NEVER "confirmed".
    confidence: Mapped[str] = mapped_column(
        String(20), nullable=False, default="advisory", server_default=text("'advisory'")
    )
    #: 1=INFORMATIONAL, 2=SUSPECTED. HARD CAP: a DWM signal never exceeds 2.
    evidence_tier: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default=text("1"),
        comment="1=INFORMATIONAL, 2=SUSPECTED (DWM hard cap = 2, never 3/4)",
    )

    #: When the data appeared in the source (if known).
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    #: When ARGUS collected it.
    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    #: MinIO (argus-darkweb) object key — the encrypted raw record.
    raw_object_key: Mapped[str | None] = mapped_column(String(512), nullable=True)
    #: sha256 of the raw record (provenance; invariant "no artifact is lost").
    raw_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    #: Hash-chain link (policy-plane audit).
    chain_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    #: Report-safe, masked summary (no plaintext secrets / PII).
    redacted_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: Structured provenance / enrichment blob (no secrets).
    provenance: Mapped[dict[str, Any] | None] = mapped_column(_JSON_PAYLOAD, nullable=True)
    #: Collector name + catalog version.
    collector: Mapped[str | None] = mapped_column(String(60), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("ix_dark_web_observations_tenant_scan", "tenant_id", "scan_id"),
        Index("ix_dark_web_observations_finding_id", "finding_id"),
        Index("ix_dark_web_observations_source_network", "source_network"),
        Index("ix_dark_web_observations_exposure_type", "exposure_type"),
    )
