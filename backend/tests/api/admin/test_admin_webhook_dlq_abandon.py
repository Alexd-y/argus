"""T39 acceptance — `POST /admin/webhooks/dlq/{entry_id}/abandon`.

Cycle 6 Batch 5, ARG-053. Covers the ABANDON endpoint:

* RBAC matrix — operator / admin (own + cross-tenant) / super-admin.
* Happy path — 200, `new_status="abandoned"`, row's `abandoned_at` and
  `abandoned_reason="operator"` populated, AuditLog emitted with
  `event_type="webhook_dlq.abandon"`.
* Already terminal — 409 `already_replayed` / `already_abandoned`.
* Validation — missing / too-short / too-long `reason` → 422.
* Cross-tenant existence-leak — admin scoped to A trying to abandon a row
  in B → 404 `dlq_entry_not_found`, no row mutation, no audit emit.
* AuditLog details shape — must include `entry_id`, `adapter_name`,
  `event_id`, `reason`.

Plan: ai_docs/develop/plans/2026-04-22-argus-cycle6-b5.md (T39).
"""

from __future__ import annotations

from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.schemas import (
    WEBHOOK_DLQ_REASON_MAX_LEN,
)
from tests.api.admin.conftest import (
    DEFAULT_REASON,
    EVENT_DLQ_ABANDON,
    TENANT_A,
    TENANT_B,
    AuditEmitter,
    enqueue_dlq_entry,
    force_terminal_abandoned,
    force_terminal_replayed,
    headers_admin,
    headers_admin_no_tenant,
    headers_operator,
    headers_super_admin,
    random_uuid,
    seed_tenant,
)

ABANDON_PATH = "/admin/webhooks/dlq/{entry_id}/abandon"


# ===========================================================================
# RBAC matrix
# ===========================================================================


class TestAbandonRbac:
    async def test_abandon_403_for_operator(
        self,
        api_client: AsyncClient,
        session: AsyncSession,
        audit_emitter: AuditEmitter,
    ) -> None:
        await seed_tenant(session, tenant_id=TENANT_A, name="alpha")
        entry = await enqueue_dlq_entry(
            session, tenant_id=TENANT_A, event_id="evt-abandon-op"
        )

        r = await api_client.post(
            ABANDON_PATH.format(entry_id=entry.id),
            headers=headers_operator(),
            json={"reason": DEFAULT_REASON},
        )

        assert r.status_code == 403
        assert r.json()["detail"] == "forbidden"
        audit_emitter.assert_not_called()

        await session.refresh(entry)
        assert entry.abandoned_at is None
        assert entry.replayed_at is None

    async def test_abandon_403_admin_without_tenant_header(
        self,
        api_client: AsyncClient,
        session: AsyncSession,
        audit_emitter: AuditEmitter,
    ) -> None:
        await seed_tenant(session, tenant_id=TENANT_A, name="alpha")
        entry = await enqueue_dlq_entry(
            session,
            tenant_id=TENANT_A,
            event_id="evt-abandon-admin-no-tenant",
        )

        r = await api_client.post(
            ABANDON_PATH.format(entry_id=entry.id),
            headers=headers_admin_no_tenant(),
            json={"reason": DEFAULT_REASON},
        )

        assert r.status_code == 403
        assert r.json()["detail"] == "tenant_required"
        audit_emitter.assert_not_called()

        await session.refresh(entry)
        assert entry.abandoned_at is None

    async def test_abandon_404_admin_cross_tenant_existence_leak(
        self,
        api_client: AsyncClient,
        session: AsyncSession,
        audit_emitter: AuditEmitter,
    ) -> None:
        await seed_tenant(session, tenant_id=TENANT_A, name="alpha")
        await seed_tenant(session, tenant_id=TENANT_B, name="bravo")
        target = await enqueue_dlq_entry(
            session,
            tenant_id=TENANT_B,
            event_id="evt-abandon-cross-tenant",
        )

        r = await api_client.post(
            ABANDON_PATH.format(entry_id=target.id),
            headers=headers_admin(TENANT_A),
            json={"reason": DEFAULT_REASON},
        )

        # MUST be 404 — never 403 — so admins cannot enumerate other tenants.
        assert r.status_code == 404, (
            f"expected 404 for cross-tenant probe, got {r.status_code}; "
            f"body={r.text!r}"
        )
        assert r.json()["detail"] == "dlq_entry_not_found"
        audit_emitter.assert_not_called()

        await session.refresh(target)
        assert target.abandoned_at is None
        assert target.replayed_at is None
        assert target.abandoned_reason is None

    async def test_abandon_200_super_admin_any_tenant(
        self,
        api_client: AsyncClient,
        session: AsyncSession,
        audit_emitter: AuditEmitter,
    ) -> None:
        await seed_tenant(session, tenant_id=TENANT_A, name="alpha")
        await seed_tenant(session, tenant_id=TENANT_B, name="bravo")
        entry = await enqueue_dlq_entry(
            session, tenant_id=TENANT_B, event_id="evt-abandon-super"
        )

        r = await api_client.post(
            ABANDON_PATH.format(entry_id=entry.id),
            headers=headers_super_admin(),
            json={"reason": DEFAULT_REASON},
        )

        assert r.status_code == 200
        body = r.json()
        assert body["new_status"] == "abandoned"
        assert body["entry_id"] == entry.id

        await session.refresh(entry)
        assert entry.abandoned_at is not None
        assert entry.abandoned_reason == "operator"
        assert entry.replayed_at is None


# ===========================================================================
# Happy path + audit shape
# ===========================================================================


class TestAbandonHappyPath:
    async def test_abandon_200_admin_own_tenant_marks_row_and_emits_audit(
        self,
        api_client: AsyncClient,
        session: AsyncSession,
        audit_emitter: AuditEmitter,
    ) -> None:
        await seed_tenant(session, tenant_id=TENANT_A, name="alpha")
        entry = await enqueue_dlq_entry(
            session,
            tenant_id=TENANT_A,
            event_id="evt-abandon-happy",
            adapter_name="slack",
        )

        r = await api_client.post(
            ABANDON_PATH.format(entry_id=entry.id),
            headers=headers_admin(TENANT_A),
            json={"reason": DEFAULT_REASON},
        )

        assert r.status_code == 200
        body = r.json()
        assert body["new_status"] == "abandoned"
        assert body["entry_id"] == entry.id
        assert isinstance(body["audit_id"], str) and body["audit_id"]

        await session.refresh(entry)
        assert entry.abandoned_at is not None
        assert entry.abandoned_reason == "operator"
        assert entry.replayed_at is None

        assert audit_emitter.call_count == 1
        call = audit_emitter.last()
        assert call["action"] == EVENT_DLQ_ABANDON
        assert call["tenant_id"] == TENANT_A

        details: dict[str, Any] = call["details"]
        assert details["entry_id"] == entry.id
        assert details["adapter_name"] == "slack"
        assert details["event_id"] == entry.event_id
        assert details["reason"] == DEFAULT_REASON
        assert details["abandoned_reason"] == "operator"


# ===========================================================================
# Already-terminal short-circuit
# ===========================================================================


class TestAbandonAlreadyTerminal:
    async def test_abandon_409_already_replayed(
        self,
        api_client: AsyncClient,
        session: AsyncSession,
        audit_emitter: AuditEmitter,
    ) -> None:
        await seed_tenant(session, tenant_id=TENANT_A, name="alpha")
        entry = await enqueue_dlq_entry(
            session,
            tenant_id=TENANT_A,
            event_id="evt-abandon-already-replayed",
        )
        await force_terminal_replayed(session, entry_id=entry.id)

        r = await api_client.post(
            ABANDON_PATH.format(entry_id=entry.id),
            headers=headers_admin(TENANT_A),
            json={"reason": DEFAULT_REASON},
        )

        assert r.status_code == 409
        assert r.json()["detail"] == "already_replayed"
        audit_emitter.assert_not_called()

    async def test_abandon_409_already_abandoned(
        self,
        api_client: AsyncClient,
        session: AsyncSession,
        audit_emitter: AuditEmitter,
    ) -> None:
        await seed_tenant(session, tenant_id=TENANT_A, name="alpha")
        entry = await enqueue_dlq_entry(
            session,
            tenant_id=TENANT_A,
            event_id="evt-abandon-already-abandoned",
        )
        await force_terminal_abandoned(session, entry_id=entry.id)

        r = await api_client.post(
            ABANDON_PATH.format(entry_id=entry.id),
            headers=headers_admin(TENANT_A),
            json={"reason": DEFAULT_REASON},
        )

        assert r.status_code == 409
        assert r.json()["detail"] == "already_abandoned"
        audit_emitter.assert_not_called()


# ===========================================================================
# Validation — body.reason
# ===========================================================================


class TestAbandonValidation:
    async def test_abandon_422_missing_reason(
        self,
        api_client: AsyncClient,
        session: AsyncSession,
        audit_emitter: AuditEmitter,
    ) -> None:
        await seed_tenant(session, tenant_id=TENANT_A, name="alpha")
        entry = await enqueue_dlq_entry(
            session,
            tenant_id=TENANT_A,
            event_id="evt-abandon-missing-reason",
        )

        r = await api_client.post(
            ABANDON_PATH.format(entry_id=entry.id),
            headers=headers_admin(TENANT_A),
            json={},
        )

        assert r.status_code == 422
        audit_emitter.assert_not_called()

        await session.refresh(entry)
        assert entry.abandoned_at is None

    async def test_abandon_422_reason_too_short(
        self,
        api_client: AsyncClient,
        session: AsyncSession,
        audit_emitter: AuditEmitter,
    ) -> None:
        await seed_tenant(session, tenant_id=TENANT_A, name="alpha")
        entry = await enqueue_dlq_entry(
            session,
            tenant_id=TENANT_A,
            event_id="evt-abandon-short-reason",
        )

        r = await api_client.post(
            ABANDON_PATH.format(entry_id=entry.id),
            headers=headers_admin(TENANT_A),
            json={"reason": "too short"},
        )

        assert r.status_code == 422
        audit_emitter.assert_not_called()

        await session.refresh(entry)
        assert entry.abandoned_at is None

    async def test_abandon_422_reason_too_long(
        self,
        api_client: AsyncClient,
        session: AsyncSession,
        audit_emitter: AuditEmitter,
    ) -> None:
        await seed_tenant(session, tenant_id=TENANT_A, name="alpha")
        entry = await enqueue_dlq_entry(
            session,
            tenant_id=TENANT_A,
            event_id="evt-abandon-long-reason",
        )

        r = await api_client.post(
            ABANDON_PATH.format(entry_id=entry.id),
            headers=headers_admin(TENANT_A),
            json={"reason": "x" * (WEBHOOK_DLQ_REASON_MAX_LEN + 1)},
        )

        assert r.status_code == 422
        audit_emitter.assert_not_called()

        await session.refresh(entry)
        assert entry.abandoned_at is None


# ===========================================================================
# Edge cases — random unknown id, audit-details shape completeness.
# ===========================================================================


class TestAbandonEdgeCases:
    async def test_abandon_404_random_unknown_entry_id(
        self,
        api_client: AsyncClient,
        session: AsyncSession,
        audit_emitter: AuditEmitter,
    ) -> None:
        await seed_tenant(session, tenant_id=TENANT_A, name="alpha")
        unknown_id = random_uuid()

        r = await api_client.post(
            ABANDON_PATH.format(entry_id=unknown_id),
            headers=headers_admin(TENANT_A),
            json={"reason": DEFAULT_REASON},
        )

        assert r.status_code == 404
        assert r.json()["detail"] == "dlq_entry_not_found"
        audit_emitter.assert_not_called()

    async def test_abandon_audit_details_complete_shape(
        self,
        api_client: AsyncClient,
        session: AsyncSession,
        audit_emitter: AuditEmitter,
    ) -> None:
        await seed_tenant(session, tenant_id=TENANT_A, name="alpha")
        entry = await enqueue_dlq_entry(
            session,
            tenant_id=TENANT_A,
            event_id="evt-abandon-audit-shape",
            adapter_name="jira",
        )

        custom_reason = (
            "Customer requested permanent suppression for this delivery."
        )
        r = await api_client.post(
            ABANDON_PATH.format(entry_id=entry.id),
            headers=headers_admin(TENANT_A),
            json={"reason": custom_reason},
        )

        assert r.status_code == 200
        assert audit_emitter.call_count == 1
        call = audit_emitter.last()
        assert call["action"] == EVENT_DLQ_ABANDON
        assert call["tenant_id"] == TENANT_A

        details: dict[str, Any] = call["details"]
        required_keys = {"entry_id", "adapter_name", "event_id", "reason"}
        missing = required_keys - set(details.keys())
        assert not missing, (
            f"audit details missing required keys: {missing}; "
            f"details={details!r}"
        )
        assert details["entry_id"] == entry.id
        assert details["adapter_name"] == "jira"
        assert details["event_id"] == entry.event_id
        assert details["reason"] == custom_reason
