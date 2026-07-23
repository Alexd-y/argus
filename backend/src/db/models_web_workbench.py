"""SQLAlchemy models — Web Security Workbench foundation (WB-P1-FOUNDATION).

Additive, tenant-scoped, RLS-enforced tables for the Web Security Workbench:

* :class:`WebWorkbenchProject` — root aggregate for a workbench engagement.
* :class:`WbScopeRule` — persisted include/exclude scope rules for a project;
  these translate 1:1 into :class:`src.policy.scope.ScopeRule` and are enforced
  by the shared :class:`~src.policy.scope.ScopeEngine` (no bespoke matching).
* :class:`WebWorkbenchEapRecord` — persisted, signed
  :class:`~src.policy.engagement_authorization.EngagementAuthorizationProfile`
  bound to a project. The signed profile JSON is the source of truth; verified
  metadata columns exist only for indexing / display and are re-derived from the
  signed blob at load time (fail-closed).

All identifiers are ``String(36)`` UUID strings (per Alembic 001), tenant
isolation is enforced with PostgreSQL RLS (see the accompanying migration).
Follow the canonical column pattern used across ``models.py`` / ``models_recon``
— no ORM ``relationship()`` graph, only foreign-key columns.
"""

from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from src.db.models import Base, gen_uuid


class WebWorkbenchProject(Base):
    """Root aggregate for a Web Security Workbench engagement — tenant-scoped.

    A project owns its scope rules, EAP, proxy listeners, traffic, principals,
    findings and organizer collections. ``config`` holds project-level options
    (proxy defaults, scan presets); it never stores raw secrets — those live in
    the secret plane referenced by ``secrets_ref``.
    """

    __tablename__ = "wb_projects"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    config: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    #: Reference (not the value) into the secret plane for project secrets.
    secrets_ref: Mapped[str | None] = mapped_column(String(256), nullable=True)
    #: Hash of the operator subject that created the project (no raw identity).
    created_by_subject_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    #: Optimistic-locking version — bumped on every concurrent-editable update.
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_wb_projects_tenant_name"),
        Index("ix_wb_projects_tenant_status", "tenant_id", "status"),
    )


class WbScopeRule(Base):
    """One include/exclude scope rule for a workbench project — tenant-scoped.

    Mirrors :class:`src.policy.scope.ScopeRule`: ``kind`` is a
    :class:`~src.policy.scope.ScopeKind` value, ``ports`` is an optional JSON
    list of ``{"low": int, "high": int}`` ranges. ``deny=True`` rules shadow
    allow rules — enforced by the shared engine, not here.
    """

    __tablename__ = "wb_scope_rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("wb_projects.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    pattern: Mapped[str] = mapped_column(String(2048), nullable=False)
    deny: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    ports: Mapped[list[dict[str, int]] | None] = mapped_column(JSONB, nullable=True)
    note: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (Index("ix_wb_scope_rules_project", "tenant_id", "project_id"),)


class WebWorkbenchEapRecord(Base):
    """Persisted, signed Engagement Authorization Profile bound to a project.

    ``signed_profile`` is the canonical, cryptographically-signed JSON blob
    (see :class:`~src.policy.engagement_authorization.EngagementAuthorizationProfile`).
    The scalar columns (``engagement_id``, ``expires``, ``signer_key_id``,
    ``status``) are display / index projections re-derived from the signed blob;
    the blob — not the columns — is authoritative and is re-verified fail-closed
    on load. Signatures are never widened by editing the scalar columns.
    """

    __tablename__ = "wb_eap"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("wb_projects.id", ondelete="CASCADE"), nullable=False
    )
    engagement_id: Mapped[str] = mapped_column(String(128), nullable=False)
    #: Full signed EAP as JSON (source of truth). Verified on load.
    signed_profile: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    signer_key_id: Mapped[str | None] = mapped_column(String(16), nullable=True)
    #: Display status: ``verified`` | ``invalid`` | ``expired`` (re-derived).
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="invalid")
    expires: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        Index("ix_wb_eap_project", "tenant_id", "project_id"),
        Index("ix_wb_eap_engagement", "tenant_id", "engagement_id"),
    )


class WbProxyListener(Base):
    """A workbench intercepting-proxy listener configuration — tenant-scoped.

    Owns the per-listener MITM CA: ``ca_cert_pem`` holds the *public* CA
    certificate (safe to distribute to clients); the private key is NEVER
    stored here — only a reference (``ca_secrets_ref``) into the secret plane
    where the encrypted key lives. ``intercept_rules`` is a serialized
    :class:`~src.web_workbench.proxy.intercept_rules.InterceptRuleSet`.
    """

    __tablename__ = "wb_proxy_listeners"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("wb_projects.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    host: Mapped[str] = mapped_column(String(255), nullable=False, default="127.0.0.1")
    port: Mapped[int] = mapped_column(Integer, nullable=False, default=8080)
    #: ``active`` | ``disabled`` | ``killed`` (kill switch — never forwards).
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="disabled")
    intercept_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    intercept_rules: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    config: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    #: Public CA certificate (PEM). Distributable; never the private key.
    ca_cert_pem: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: Reference to the KEK that sealed the CA key (e.g. ``env:WB_CA_SEALING_KEY``).
    ca_secrets_ref: Mapped[str | None] = mapped_column(String(256), nullable=True)
    #: CA private key SEALED (Fernet ciphertext) with the KEK — never plaintext,
    #: never logged. Decryptable only with the referenced KEK.
    ca_sealed_key: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    ca_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        UniqueConstraint("tenant_id", "project_id", "name", name="uq_wb_listeners_project_name"),
        Index("ix_wb_listeners_project", "tenant_id", "project_id"),
    )


class WbTrafficMessage(Base):
    """One captured HTTP request/response pair — tenant-scoped.

    Bodies are stored out-of-line in :class:`WbTrafficBodyArtifact` (referenced
    by ``request_body_id`` / ``response_body_id``) so this row stays small. The
    normalized head lives in the ``*_headers`` JSON columns; the byte-exact raw
    head is reconstructable from the normalized view (ADR-WB-3). ``forward_outcome``
    records the mandatory :class:`~src.web_workbench.proxy.forward_gate.ForwardGate`
    verdict; ``block_reason`` is a closed-taxonomy summary.
    """

    __tablename__ = "wb_traffic_messages"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("wb_projects.id", ondelete="CASCADE"), nullable=False
    )
    listener_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("wb_proxy_listeners.id", ondelete="SET NULL"),
        nullable=True,
    )
    #: Origin tool: ``proxy`` | ``repeater`` | ``intruder`` | ``scanner`` | ``manual``.
    source: Mapped[str] = mapped_column(String(16), nullable=False, default="proxy")
    method: Mapped[str] = mapped_column(String(32), nullable=False)
    scheme: Mapped[str] = mapped_column(String(8), nullable=False, default="https")
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False, default=443)
    path: Mapped[str] = mapped_column(Text, nullable=False, default="/")
    query: Mapped[str | None] = mapped_column(Text, nullable=True)
    http_version: Mapped[str] = mapped_column(String(16), nullable=False, default="HTTP/1.1")
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    request_headers: Mapped[list[Any] | None] = mapped_column(JSONB, nullable=True)
    response_headers: Mapped[list[Any] | None] = mapped_column(JSONB, nullable=True)
    request_body_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    response_body_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    #: ``forward`` | ``blocked`` (mandatory forward-gate verdict).
    forward_outcome: Mapped[str] = mapped_column(String(16), nullable=False, default="forward")
    block_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    in_scope: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    tags: Mapped[list[Any] | None] = mapped_column(JSONB, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("ix_wb_traffic_project_created", "tenant_id", "project_id", "created_at"),
        Index("ix_wb_traffic_host", "tenant_id", "host"),
    )


class WbTrafficBodyArtifact(Base):
    """A stored HTTP body (request or response) for a traffic message.

    ``storage_backend`` is ``inline`` (small bodies held in ``inline_bytes``),
    ``s3`` (spilled to the object store, addressed by ``object_key``) or
    ``none`` (body exceeded the hard capture cap and was dropped — only
    ``sha256`` + ``size_bytes`` are retained, ``truncated=True``). Body bytes
    are NEVER logged.
    """

    __tablename__ = "wb_traffic_body_artifacts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("wb_projects.id", ondelete="CASCADE"), nullable=False
    )
    message_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("wb_traffic_messages.id", ondelete="CASCADE"),
        nullable=False,
    )
    #: ``request`` | ``response``.
    direction: Mapped[str] = mapped_column(String(8), nullable=False)
    #: ``inline`` | ``s3`` | ``none``.
    storage_backend: Mapped[str] = mapped_column(String(8), nullable=False)
    inline_bytes: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    object_key: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    content_type: Mapped[str | None] = mapped_column(String(256), nullable=True)
    truncated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (Index("ix_wb_body_message", "tenant_id", "message_id"),)


class WbMessageRevision(Base):
    """An edit revision of a traffic message's raw head (Repeater/manual edits).

    Stores the byte-exact raw head override for a message so edits are auditable
    and replayable without mutating the original captured message.
    """

    __tablename__ = "wb_message_revisions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("wb_projects.id", ondelete="CASCADE"), nullable=False
    )
    message_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("wb_traffic_messages.id", ondelete="CASCADE"),
        nullable=False,
    )
    revision_no: Mapped[int] = mapped_column(Integer, nullable=False)
    editor_subject_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    raw_head: Mapped[str] = mapped_column(Text, nullable=False)
    note: Mapped[str | None] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        UniqueConstraint("tenant_id", "message_id", "revision_no", name="uq_wb_revision_no"),
        Index("ix_wb_revision_message", "tenant_id", "message_id"),
    )


class WbOrganizerCollection(Base):
    """A named folder that groups saved requests/notes within a project (WB-P3c).

    The workbench analogue of Burp's Organizer collections. Tenant-scoped and
    concurrent-editable (optimistic ``version``); collection names are unique per
    project.
    """

    __tablename__ = "wb_organizer_collections"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("wb_projects.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        UniqueConstraint("tenant_id", "project_id", "name", name="uq_wb_org_collection_name"),
        Index("ix_wb_org_collection_project", "tenant_id", "project_id"),
    )


class WbOrganizerItem(Base):
    """A saved request/note inside an organizer collection (WB-P3c).

    Holds a human title, optional saved raw request/response bytes (byte-exact),
    free-form notes, and a ``tags`` list for organisation/search. ``source_message_id``
    optionally links back to the captured traffic message it was saved from.
    """

    __tablename__ = "wb_organizer_items"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("wb_projects.id", ondelete="CASCADE"), nullable=False
    )
    collection_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("wb_organizer_collections.id", ondelete="CASCADE"),
        nullable=False,
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    method: Mapped[str | None] = mapped_column(String(32), nullable=True)
    host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    url: Mapped[str | None] = mapped_column(Text, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    tags: Mapped[list[Any] | None] = mapped_column(JSONB, nullable=True)
    raw_request: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    raw_response: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    source_message_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("wb_traffic_messages.id", ondelete="SET NULL"),
        nullable=True,
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        Index("ix_wb_org_item_collection", "tenant_id", "collection_id"),
        Index("ix_wb_org_item_host", "tenant_id", "project_id", "host"),
    )


class WbRepeaterTab(Base):
    """A saved, editable request slot for the Repeater (WB-P3b-2).

    Holds the byte-exact raw request the operator edits and replays. Derived
    ``scheme``/``host``/``port`` are display metadata (the raw bytes remain the
    source of truth for the actual send). Concurrent edits use optimistic
    ``version``.
    """

    __tablename__ = "wb_repeater_tabs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("wb_projects.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    raw_request: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    scheme: Mapped[str | None] = mapped_column(String(8), nullable=True)
    host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (Index("ix_wb_repeater_tab_project", "tenant_id", "project_id"),)


class WbRepeaterExchange(Base):
    """One replay attempt recorded against a tab (WB-P3b-2).

    Every replay — forwarded or blocked — is recorded (audit invariant). On a
    block the sender was never invoked: ``forward_outcome='blocked'``,
    ``block_reason`` set, response columns ``NULL``. ``raw_request`` is stored
    byte-exact; ``raw_response`` is bounded (``truncated`` when capped).
    """

    __tablename__ = "wb_repeater_exchanges"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("wb_projects.id", ondelete="CASCADE"), nullable=False
    )
    tab_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("wb_repeater_tabs.id", ondelete="CASCADE"),
        nullable=False,
    )
    raw_request: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    forward_outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    block_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    raw_response: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    response_size: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    truncated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (Index("ix_wb_repeater_exchange_tab", "tenant_id", "tab_id", "created_at"),)


class WbScannerTask(Base):
    """A scanner/crawler run against a project's in-scope surface (WB-P5b).

    A task drives passive and/or active audit of captured or crawled traffic.
    ``kind`` is ``crawl`` | ``audit`` | ``passive``; ``status`` is a lifecycle
    value (``queued`` | ``running`` | ``paused`` | ``completed`` | ``cancelled``
    | ``failed`` — ``cancelled`` acts as a kill switch). ``config`` holds run
    options (template filters, scope preset), ``checkpoint`` holds resumable
    progress state; neither stores raw secrets.
    """

    __tablename__ = "wb_scanner_tasks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("wb_projects.id", ondelete="CASCADE"), nullable=False
    )
    #: ``crawl`` | ``audit`` | ``passive``.
    kind: Mapped[str] = mapped_column(String(16), nullable=False, default="passive")
    #: ``queued`` | ``running`` | ``paused`` | ``completed`` | ``cancelled`` | ``failed``.
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="queued")
    config: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    checkpoint: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    #: Counters for live progress (requests issued / findings raised).
    requests_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    findings_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_reason: Mapped[str | None] = mapped_column(String(256), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (Index("ix_wb_scanner_task_project", "tenant_id", "project_id", "status"),)


class WbScannerIssueLink(Base):
    """Links a scanner task to a produced finding (WB-P5b).

    The ``FindingDTO`` itself is persisted through the shared pipeline finding
    store; this table only records the association (which task raised which
    finding, with what passive/active confidence) so the workbench can present a
    per-task issue list without duplicating the finding contract.
    """

    __tablename__ = "wb_scanner_issue_links"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("wb_projects.id", ondelete="CASCADE"), nullable=False
    )
    task_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("wb_scanner_tasks.id", ondelete="CASCADE"),
        nullable=False,
    )
    #: Foreign finding id from the shared pipeline finding store (not FK-enforced
    #: here — the finding lives in a different aggregate).
    finding_id: Mapped[str] = mapped_column(String(36), nullable=False)
    #: Passive check code / active rule id that raised the issue.
    code: Mapped[str] = mapped_column(String(64), nullable=False)
    #: ``suspected`` | ``likely`` | ``confirmed`` | ``exploitable`` (ConfidenceLevel).
    confidence: Mapped[str] = mapped_column(String(16), nullable=False, default="suspected")
    #: Source message this issue was derived from (optional link-back).
    source_message_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("wb_traffic_messages.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        UniqueConstraint("tenant_id", "task_id", "finding_id", name="uq_wb_scanner_issue_link"),
        Index("ix_wb_scanner_issue_task", "tenant_id", "task_id"),
    )


class WbIntruderAttack(Base):
    """An Intruder attack definition + run against an in-scope target (WB-P4b).

    ``attack_type`` mirrors the classic position/payload strategies
    (``sniper`` | ``battering_ram`` | ``pitchfork`` | ``cluster_bomb``).
    ``raw_request_template`` is the byte-exact base request with position markers;
    ``positions`` records the marker offsets. ``payload_config`` holds ONLY
    references into the signed :class:`~src.payloads` registry (set ids +
    processing rules) — never raw payload material, so unapproved payloads cannot
    be injected. ``status`` is a lifecycle value where ``cancelled`` is the kill
    switch (no further requests are forwarded). Concurrent edits use optimistic
    ``version``.
    """

    __tablename__ = "wb_intruder_attacks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("wb_projects.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    #: ``sniper`` | ``battering_ram`` | ``pitchfork`` | ``cluster_bomb``.
    attack_type: Mapped[str] = mapped_column(String(16), nullable=False, default="sniper")
    #: ``queued`` | ``running`` | ``paused`` | ``completed`` | ``cancelled`` | ``failed``.
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="queued")
    #: Byte-exact base request with position markers (source of truth for replay).
    raw_request_template: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    #: List of ``{"start": int, "end": int}`` payload-position offsets.
    positions: Mapped[list[dict[str, int]] | None] = mapped_column(JSONB, nullable=True)
    #: References into the signed payload registry (set ids + processing) — NOT raw payloads.
    payload_config: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    #: Run options (concurrency cap, throttle, risk class); no raw secrets.
    config: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    #: Resumable progress state (pause/resume/checkpoint).
    checkpoint: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    requests_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    requests_completed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    findings_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_reason: Mapped[str | None] = mapped_column(String(256), nullable=True)
    created_by_subject_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        UniqueConstraint("tenant_id", "project_id", "name", name="uq_wb_intruder_attack_name"),
        Index("ix_wb_intruder_attack_project", "tenant_id", "project_id", "status"),
    )


class WbIntruderRequest(Base):
    """One request result recorded during an Intruder attack (WB-P4b).

    High-volume, so this row stays metadata-only: response bodies are NOT stored
    inline here (bounded body handling / object store is applied by the service).
    ``payload_label`` / ``payload_index`` identify which registry payload was
    used (reconstructable from the signed set — the raw payload value is not
    duplicated). Every attempt is recorded (audit invariant); on a
    forward-gate block the sender was never invoked
    (``forward_outcome='blocked'``, ``block_reason`` set, response columns NULL).
    """

    __tablename__ = "wb_intruder_requests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("wb_projects.id", ondelete="CASCADE"), nullable=False
    )
    attack_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("wb_intruder_attacks.id", ondelete="CASCADE"),
        nullable=False,
    )
    #: 0-based ordinal of this request within the attack.
    request_index: Mapped[int] = mapped_column(Integer, nullable=False)
    #: Payload set/label + index used (reference, not the raw payload value).
    payload_label: Mapped[str | None] = mapped_column(String(256), nullable=True)
    payload_index: Mapped[int | None] = mapped_column(Integer, nullable=True)
    #: ``forward`` | ``blocked`` (mandatory forward-gate verdict).
    forward_outcome: Mapped[str] = mapped_column(String(16), nullable=False, default="forward")
    block_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_length: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_time_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    #: Operator/analyzer marked this result as interesting.
    flagged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    error_reason: Mapped[str | None] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "attack_id", "request_index", name="uq_wb_intruder_request_index"
        ),
        Index("ix_wb_intruder_request_attack", "tenant_id", "attack_id"),
        Index("ix_wb_intruder_request_flagged", "tenant_id", "attack_id", "flagged"),
    )


class WbSessionMacro(Base):
    """A login / session-setup macro for authenticated testing (WB-P6b).

    ``steps`` is an ordered list of request specs replayed to establish a session
    (e.g. login flow). It holds NO raw secrets: any credential/token is a
    ``secret_ref`` placeholder resolved from the secret plane at replay time
    (split-plane secrets, SI-3). ``match_rules`` describes how a logged-in
    response is recognised. Concurrent edits use optimistic ``version``.
    """

    __tablename__ = "wb_session_macros"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("wb_projects.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    #: Ordered replay steps (request specs with ``secret_ref`` placeholders).
    steps: Mapped[list[Any] | None] = mapped_column(JSONB, nullable=True)
    #: Rules to detect an authenticated session (status/header/body markers).
    match_rules: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    config: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        UniqueConstraint("tenant_id", "project_id", "name", name="uq_wb_session_macro_name"),
        Index("ix_wb_session_macro_project", "tenant_id", "project_id"),
    )


class WbSessionPrincipal(Base):
    """An identity used for authorization testing (WB-P6b) — tenant-scoped.

    Represents an owner / attacker / anonymous principal in owner-vs-attacker
    replay diffing. Credentials/tokens are NEVER stored here — only
    ``secrets_ref`` into the secret plane (split-plane, SI-3). ``role`` is
    ``owner`` | ``attacker`` | ``anonymous``. An optional ``macro_id`` links the
    login macro used to (re)establish this principal's session.
    """

    __tablename__ = "wb_session_principals"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("wb_projects.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    #: ``owner`` | ``attacker`` | ``anonymous``.
    role: Mapped[str] = mapped_column(String(16), nullable=False, default="owner")
    #: Reference (not the value) into the secret plane for this principal's creds.
    secrets_ref: Mapped[str | None] = mapped_column(String(256), nullable=True)
    macro_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("wb_session_macros.id", ondelete="SET NULL"),
        nullable=True,
    )
    config: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        UniqueConstraint("tenant_id", "project_id", "name", name="uq_wb_session_principal_name"),
        Index("ix_wb_session_principal_project", "tenant_id", "project_id", "role"),
    )


__all__ = [
    "WbIntruderAttack",
    "WbIntruderRequest",
    "WbMessageRevision",
    "WbOrganizerCollection",
    "WbOrganizerItem",
    "WbProxyListener",
    "WbRepeaterExchange",
    "WbRepeaterTab",
    "WbScannerIssueLink",
    "WbScannerTask",
    "WbScopeRule",
    "WbSessionMacro",
    "WbSessionPrincipal",
    "WbTrafficBodyArtifact",
    "WbTrafficMessage",
    "WebWorkbenchEapRecord",
    "WebWorkbenchProject",
]
