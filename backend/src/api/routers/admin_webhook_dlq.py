"""T39 (Cycle 6 Batch 5, ARG-053) — webhook DLQ admin API.

Three endpoints:
    GET    /admin/webhooks/dlq                           — list with filters/pagination.
    POST   /admin/webhooks/dlq/{entry_id}/replay         — re-dispatch via NotifierBase.
    POST   /admin/webhooks/dlq/{entry_id}/abandon        — mark as abandoned (operator).

RBAC:
    - operator → 403 forbidden.
    - admin    → own tenant only (X-Admin-Tenant required; entry.tenant_id must match).
    - super-admin → any tenant (X-Admin-Tenant optional; when present, filters list).

Auth envelope: same cookie-shim used by Batches 2-4 (X-Admin-Key + X-Admin-Role
+ X-Admin-Tenant + X-Operator-Subject). ISS-T20-003 (JWT/session-bound auth)
is deferred to Cycle 7 / pre-launch.

Errors map to the closed WEBHOOK_DLQ_FAILURE_TAXONOMY (13 codes). Cross-tenant
probes return 404 dlq_entry_not_found (existence-leak protection) — never a
distinct 403, so admins cannot enumerate other tenants' rows via the
discriminator status code.

Plan: ai_docs/develop/plans/2026-04-22-argus-cycle6-b5.md (T39).
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Final, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import ValidationError

from src.api.routers.admin import require_admin
from src.api.routers.admin_bulk_ops import _operator_subject_dep
from src.api.routers.admin_emergency import _emit_audit
from src.api.routers.admin_findings import _admin_role_dep, _admin_tenant_dep
from src.auth.admin_dependencies import require_admin_mfa_passed
from src.api.schemas import (
    WebhookDlqAbandonRequest,
    WebhookDlqAbandonResponse,
    WebhookDlqEntryItem,
    WebhookDlqListResponse,
    WebhookDlqReplayRequest,
    WebhookDlqReplayResponse,
)
from src.core.observability import tenant_hash, user_id_hash
from src.db.models import WebhookDlqEntry, gen_uuid
from src.db.session import async_session_factory
from src.mcp.services.notifications import (
    AlreadyTerminalError,
    DlqEntryNotFoundError,
    JiraAdapter,
    LinearAdapter,
    NotificationEvent,
    NotifierBase,
    SlackNotifier,
)
from src.mcp.services.notifications import webhook_dlq_persistence as dlq_dao

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(
    prefix="/admin/webhooks/dlq",
    tags=["admin", "webhooks-dlq"],
)


# ---------------------------------------------------------------------------
# Closed-taxonomy detail strings (subset of WEBHOOK_DLQ_FAILURE_TAXONOMY).
# Mirrors `Frontend/src/lib/adminWebhookDlq.ts` so the SDK switch on the
# ``detail`` token stays type-safe across the wire. NEVER add a sentence /
# i18n string here — the frontend `detailToWebhookDlqActionCode` table
# expects short snake_case keys only.
# ---------------------------------------------------------------------------

_DETAIL_FORBIDDEN: Final[str] = "forbidden"
_DETAIL_TENANT_REQUIRED: Final[str] = "tenant_required"
_DETAIL_DLQ_ENTRY_NOT_FOUND: Final[str] = "dlq_entry_not_found"
_DETAIL_ALREADY_REPLAYED: Final[str] = "already_replayed"
_DETAIL_ALREADY_ABANDONED: Final[str] = "already_abandoned"
_DETAIL_STORE_UNAVAILABLE: Final[str] = "store_unavailable"
_DETAIL_SERVER_ERROR: Final[str] = "server_error"

#: Audit-log ``action`` taxonomy persisted by these endpoints.
EVENT_DLQ_REPLAY: Final[str] = "webhook_dlq.replay"
EVENT_DLQ_ABANDON: Final[str] = "webhook_dlq.abandon"

#: Closed enum of valid abandon reasons accepted by the DAO. The admin
#: surface always records ``operator`` (free-text justification lives in
#: the audit row, not the persisted ``abandoned_reason`` column).
_ABANDON_REASON_OPERATOR: Final[str] = "operator"

#: Adapter factory — admin replay constructs a fresh adapter per call so
#: it never reuses dispatcher-side circuit-breaker / dedup state. The
#: operator's "force replay" semantically overrides those auto-protections.
_ADAPTER_FACTORY: Final[dict[str, type[NotifierBase]]] = {
    SlackNotifier.name: SlackNotifier,
    LinearAdapter.name: LinearAdapter,
    JiraAdapter.name: JiraAdapter,
}


# ---------------------------------------------------------------------------
# RBAC helpers — local copies that emit closed-taxonomy snake_case detail
# strings (sister routers admin_emergency / admin_schedules use slightly
# different detail vocabularies; keeping ours local pins the contract for
# the WEBHOOK_DLQ_FAILURE_TAXONOMY mirror).
# ---------------------------------------------------------------------------


def _require_admin_or_super(role: str) -> None:
    """Raise 403 ``forbidden`` unless role is ``admin`` or ``super-admin``."""
    if role not in {"admin", "super-admin"}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=_DETAIL_FORBIDDEN,
        )


def _resolve_effective_tenant(role: str, role_tenant: str | None) -> str | None:
    """Return the tenant scope filter for the DAO call.

    * ``admin``       → ``role_tenant`` MUST be set (else 403 ``tenant_required``).
    * ``super-admin`` → ``role_tenant`` optional; ``None`` means cross-tenant.

    The DAO layer accepts ``tenant_id=None`` as the cross-tenant projection
    and a concrete value as the tenant-scoped projection. Cross-tenant
    probes by an admin (``role_tenant`` does not match the row) return
    ``DlqEntryNotFoundError`` from the DAO so the discriminator status
    code stays at 404 — never a distinct 403 — closing the existence-leak
    side channel.
    """
    if role == "admin":
        if not role_tenant:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=_DETAIL_TENANT_REQUIRED,
            )
        return role_tenant
    return role_tenant


# ---------------------------------------------------------------------------
# Projection helpers
# ---------------------------------------------------------------------------


def _derive_triage_status(
    entry: WebhookDlqEntry,
) -> Literal["pending", "replayed", "abandoned"]:
    """Derive the operator-facing ``triage_status`` from the row state."""
    if entry.replayed_at is not None:
        return "replayed"
    if entry.abandoned_at is not None:
        return "abandoned"
    return "pending"


def _to_entry_item(entry: WebhookDlqEntry) -> WebhookDlqEntryItem:
    """Project an ORM ``WebhookDlqEntry`` onto the response item schema.

    ``target_url_hash`` is forwarded as-is — the raw URL is never
    persisted (see :class:`src.db.models.WebhookDlqEntry`) so the
    frontend can only ever see the opaque fingerprint.
    """
    return WebhookDlqEntryItem(
        id=UUID(entry.id),
        tenant_id=UUID(entry.tenant_id),
        adapter_name=entry.adapter_name,
        event_type=entry.event_type,
        event_id=entry.event_id,
        target_url_hash=entry.target_url_hash,
        attempt_count=entry.attempt_count,
        last_error_code=entry.last_error_code,
        last_status_code=entry.last_status_code,
        next_retry_at=entry.next_retry_at,
        created_at=entry.created_at,
        replayed_at=entry.replayed_at,
        abandoned_at=entry.abandoned_at,
        abandoned_reason=entry.abandoned_reason,
        triage_status=_derive_triage_status(entry),
    )


def _classify_terminal_detail(entry: WebhookDlqEntry) -> str:
    """Return the closed-taxonomy detail token for an already-terminal row."""
    if entry.replayed_at is not None:
        return _DETAIL_ALREADY_REPLAYED
    return _DETAIL_ALREADY_ABANDONED


def _reconstruct_event(entry: WebhookDlqEntry) -> NotificationEvent:
    """Reconstruct the original :class:`NotificationEvent` from ``payload_json``.

    T40 (the daily replay beat task) persists the serialized event
    verbatim into ``payload_json`` so the admin replay path can re-issue
    a byte-for-byte equivalent dispatch. Pydantic validation here is the
    last line of defence against a corrupted row — failures surface as
    500 ``server_error`` (the row data, not the request, is the fault;
    the operator cannot fix it without re-enqueueing or abandoning).
    """
    try:
        return NotificationEvent.model_validate(entry.payload_json)
    except ValidationError as exc:
        logger.error(
            "admin.webhook_dlq.payload_reconstruction_failed",
            extra={
                "event": "argus.admin.webhook_dlq.payload_reconstruction_failed",
                "entry_id": entry.id,
                "adapter_name": entry.adapter_name,
                "tenant_id_hash": tenant_hash(entry.tenant_id),
                "error_count": len(exc.errors()),
            },
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=_DETAIL_SERVER_ERROR,
        ) from exc


def _build_adapter(adapter_name: str) -> NotifierBase:
    """Instantiate a fresh adapter for a one-shot operator replay.

    Each replay constructs a dedicated adapter so it never inherits
    long-lived dispatcher state (in-process circuit breaker, dedup
    bucket). Operators clicking "replay" are explicitly bypassing the
    auto-protections that would otherwise short-circuit the call.
    Unknown adapter names are a row-corruption signal and surface as
    500 ``server_error``.
    """
    factory = _ADAPTER_FACTORY.get(adapter_name)
    if factory is None:
        logger.error(
            "admin.webhook_dlq.unknown_adapter",
            extra={
                "event": "argus.admin.webhook_dlq.unknown_adapter",
                "adapter_name": adapter_name,
            },
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=_DETAIL_SERVER_ERROR,
        )
    return factory()


# ---------------------------------------------------------------------------
# GET /admin/webhooks/dlq
# ---------------------------------------------------------------------------


@router.get(
    "",
    response_model=WebhookDlqListResponse,
    summary="List webhook DLQ entries (admin own tenant; super-admin cross-tenant)",
)
async def list_webhook_dlq(
    status_filter: Literal["pending", "replayed", "abandoned"] | None = Query(
        default=None,
        alias="status",
        description=(
            "Optional triage-status filter: pending (no terminal column set), "
            "replayed, or abandoned."
        ),
    ),
    adapter_name: str | None = Query(
        default=None, description="Optional exact-match adapter filter (slack/linear/jira)."
    ),
    created_after: datetime | None = Query(
        default=None, description="Lower-bound on ``created_at`` (inclusive)."
    ),
    created_before: datetime | None = Query(
        default=None, description="Upper-bound on ``created_at`` (inclusive)."
    ),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _: None = Depends(require_admin),
    role: str = Depends(_admin_role_dep),
    role_tenant: str | None = Depends(_admin_tenant_dep),
    operator_subject: str = Depends(_operator_subject_dep),
) -> WebhookDlqListResponse:
    """Return a paginated DLQ slice for the operator console.

    RBAC: operator → 403; admin → own tenant only (X-Admin-Tenant required);
    super-admin → any tenant (X-Admin-Tenant optional, filters when provided).
    """
    _require_admin_or_super(role)
    effective_tenant = _resolve_effective_tenant(role, role_tenant)

    async with async_session_factory() as session:
        rows, total = await dlq_dao.list_for_tenant(
            session,
            tenant_id=effective_tenant,
            status=status_filter,
            adapter_name=adapter_name,
            created_after=created_after,
            created_before=created_before,
            limit=limit,
            offset=offset,
        )

    items = [_to_entry_item(row) for row in rows]
    logger.info(
        "admin.webhook_dlq.list",
        extra={
            "event": "argus.admin.webhook_dlq.list",
            "user_id_hash": user_id_hash(operator_subject),
            "role": role,
            "tenant_id_hash": (
                tenant_hash(effective_tenant) if effective_tenant else None
            ),
            "status_filter": status_filter,
            "adapter_name": adapter_name,
            "total": total,
            "result_count": len(items),
            "limit": limit,
            "offset": offset,
        },
    )
    return WebhookDlqListResponse(
        items=items, total=total, limit=limit, offset=offset
    )


# ---------------------------------------------------------------------------
# POST /admin/webhooks/dlq/{entry_id}/replay
# ---------------------------------------------------------------------------


@router.post(
    "/{entry_id}/replay",
    response_model=WebhookDlqReplayResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Re-dispatch a DLQ entry via NotifierBase (admin own tenant; super-admin any)",
)
async def replay_webhook_dlq(
    entry_id: UUID,
    body: WebhookDlqReplayRequest,
    _: None = Depends(require_admin_mfa_passed),
    role: str = Depends(_admin_role_dep),
    role_tenant: str | None = Depends(_admin_tenant_dep),
    operator_subject: str = Depends(_operator_subject_dep),
) -> WebhookDlqReplayResponse:
    """Operator-driven replay of a single DLQ entry.

    Steps (single transaction so the audit row + DAO mutation share ACID):

    1. RBAC + tenant scope resolution.
    2. ``get_by_id`` (tenant-scoped) → 404 on miss / cross-tenant.
    3. Already-terminal short-circuit → 409 ``already_replayed`` /
       ``already_abandoned`` (existence-leak safe: cross-tenant rows
       never reach this point).
    4. Reconstruct ``NotificationEvent`` from ``payload_json``;
       corrupted payload → 500 ``server_error``.
    5. Dispatch via a fresh adapter's :meth:`NotifierBase.send_with_retry`
       (intentionally bypasses dispatcher-side circuit / dedup since the
       operator is overriding auto-protections).
    6. On ``delivered=True`` → ``mark_replayed`` (terminal); on failure
       → ``increment_attempt`` (row stays in DLQ).
    7. ``_emit_audit("webhook_dlq.replay", ...)`` and commit.

    The ``adapter.aclose()`` call releases the per-replay httpx client
    eagerly so we do not leak file descriptors under high replay
    concurrency.
    """
    _require_admin_or_super(role)
    effective_tenant = _resolve_effective_tenant(role, role_tenant)
    entry_id_str = str(entry_id)

    async with async_session_factory() as session:
        entry = await dlq_dao.get_by_id(
            session, entry_id=entry_id_str, tenant_id=effective_tenant
        )
        if entry is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=_DETAIL_DLQ_ENTRY_NOT_FOUND,
            )
        if entry.replayed_at is not None or entry.abandoned_at is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=_classify_terminal_detail(entry),
            )

        captured_tenant_id = entry.tenant_id
        captured_adapter_name = entry.adapter_name
        captured_event_id = entry.event_id

        event = _reconstruct_event(entry)
        adapter = _build_adapter(captured_adapter_name)
        try:
            result = await adapter.send_with_retry(
                event, tenant_id=captured_tenant_id
            )
        finally:
            await adapter.aclose()

        delivered = bool(result.delivered)
        try:
            if delivered:
                updated = await dlq_dao.mark_replayed(
                    session,
                    entry_id=entry_id_str,
                    tenant_id=effective_tenant,
                )
                new_status: Literal["replayed", "pending"] = "replayed"
                message_code: Literal[
                    "replay_succeeded", "replay_failed"
                ] = "replay_succeeded"
            else:
                updated = await dlq_dao.increment_attempt(
                    session,
                    entry_id=entry_id_str,
                    last_error_code=(
                        result.error_code or result.skipped_reason or "unknown_error"
                    ),
                    last_status_code=result.status_code,
                )
                new_status = "pending"
                message_code = "replay_failed"
        except DlqEntryNotFoundError as exc:
            await session.rollback()
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=_DETAIL_DLQ_ENTRY_NOT_FOUND,
            ) from exc
        except AlreadyTerminalError as exc:
            await session.rollback()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=_DETAIL_ALREADY_REPLAYED,
            ) from exc

        audit_id = gen_uuid()
        _emit_audit(
            session,
            audit_id=audit_id,
            tenant_id=captured_tenant_id,
            action=EVENT_DLQ_REPLAY,
            operator_subject=operator_subject,
            details={
                "entry_id": entry_id_str,
                "adapter_name": captured_adapter_name,
                "event_id": captured_event_id,
                "tenant_id_hash": tenant_hash(captured_tenant_id),
                "success": delivered,
                "attempt_count": int(updated.attempt_count),
                "reason": body.reason,
                "last_error_code": updated.last_error_code,
                "last_status_code": updated.last_status_code,
            },
        )
        await session.commit()

    logger.info(
        "admin.webhook_dlq.replay",
        extra={
            "event": "argus.admin.webhook_dlq.replay",
            "user_id_hash": user_id_hash(operator_subject),
            "role": role,
            "tenant_id_hash": tenant_hash(captured_tenant_id),
            "entry_id": entry_id_str,
            "adapter_name": captured_adapter_name,
            "success": delivered,
            "attempt_count": int(updated.attempt_count),
            "audit_id": audit_id,
            "message_code": message_code,
        },
    )
    return WebhookDlqReplayResponse(
        entry_id=entry_id,
        success=delivered,
        attempt_count=int(updated.attempt_count),
        new_status=new_status,
        audit_id=UUID(audit_id),
        message_code=message_code,
    )


# ---------------------------------------------------------------------------
# POST /admin/webhooks/dlq/{entry_id}/abandon
# ---------------------------------------------------------------------------


@router.post(
    "/{entry_id}/abandon",
    response_model=WebhookDlqAbandonResponse,
    status_code=status.HTTP_200_OK,
    summary="Mark a DLQ entry abandoned (admin own tenant; super-admin any)",
)
async def abandon_webhook_dlq(
    entry_id: UUID,
    body: WebhookDlqAbandonRequest,
    _: None = Depends(require_admin_mfa_passed),
    role: str = Depends(_admin_role_dep),
    role_tenant: str | None = Depends(_admin_tenant_dep),
    operator_subject: str = Depends(_operator_subject_dep),
) -> WebhookDlqAbandonResponse:
    """Operator-driven abandon of a single DLQ entry.

    Steps (single transaction so the audit row + DAO mutation share ACID):

    1. RBAC + tenant scope resolution.
    2. ``get_by_id`` (tenant-scoped) → 404 on miss / cross-tenant.
    3. Already-terminal short-circuit → 409 ``already_replayed`` /
       ``already_abandoned``.
    4. ``mark_abandoned(reason='operator')`` flips ``abandoned_at`` +
       ``abandoned_reason`` (terminal). Free-text justification from
       ``body.reason`` is recorded ONLY in the audit details (not in
       the persisted ``abandoned_reason`` enum) — operators sometimes
       paste customer-sensitive context here, and the audit row is the
       proper home for it.
    5. ``_emit_audit("webhook_dlq.abandon", ...)`` and commit.
    """
    _require_admin_or_super(role)
    effective_tenant = _resolve_effective_tenant(role, role_tenant)
    entry_id_str = str(entry_id)

    async with async_session_factory() as session:
        entry = await dlq_dao.get_by_id(
            session, entry_id=entry_id_str, tenant_id=effective_tenant
        )
        if entry is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=_DETAIL_DLQ_ENTRY_NOT_FOUND,
            )
        if entry.replayed_at is not None or entry.abandoned_at is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=_classify_terminal_detail(entry),
            )

        captured_tenant_id = entry.tenant_id
        captured_adapter_name = entry.adapter_name
        captured_event_id = entry.event_id

        try:
            await dlq_dao.mark_abandoned(
                session,
                entry_id=entry_id_str,
                tenant_id=effective_tenant,
                reason=_ABANDON_REASON_OPERATOR,
            )
        except DlqEntryNotFoundError as exc:
            await session.rollback()
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=_DETAIL_DLQ_ENTRY_NOT_FOUND,
            ) from exc
        except AlreadyTerminalError as exc:
            await session.rollback()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=_DETAIL_ALREADY_ABANDONED,
            ) from exc

        audit_id = gen_uuid()
        _emit_audit(
            session,
            audit_id=audit_id,
            tenant_id=captured_tenant_id,
            action=EVENT_DLQ_ABANDON,
            operator_subject=operator_subject,
            details={
                "entry_id": entry_id_str,
                "adapter_name": captured_adapter_name,
                "event_id": captured_event_id,
                "tenant_id_hash": tenant_hash(captured_tenant_id),
                "reason": body.reason,
                "abandoned_reason": _ABANDON_REASON_OPERATOR,
            },
        )
        await session.commit()

    logger.info(
        "admin.webhook_dlq.abandon",
        extra={
            "event": "argus.admin.webhook_dlq.abandon",
            "user_id_hash": user_id_hash(operator_subject),
            "role": role,
            "tenant_id_hash": tenant_hash(captured_tenant_id),
            "entry_id": entry_id_str,
            "adapter_name": captured_adapter_name,
            "audit_id": audit_id,
        },
    )
    return WebhookDlqAbandonResponse(
        entry_id=entry_id,
        new_status="abandoned",
        audit_id=UUID(audit_id),
    )


__all__ = [
    "EVENT_DLQ_ABANDON",
    "EVENT_DLQ_REPLAY",
    "abandon_webhook_dlq",
    "list_webhook_dlq",
    "replay_webhook_dlq",
    "router",
]
