"""T39 acceptance — `POST /admin/webhooks/dlq/{entry_id}/replay`.

Cycle 6 Batch 5, ARG-053. Covers the REPLAY endpoint:

* RBAC matrix — operator / admin (own + cross-tenant) / super-admin.
* Happy path (delivered=True) → 202, `success=True`,
  `new_status="replayed"`, `message_code="replay_succeeded"`,
  `replayed_at` populated, AuditLog emitted.
* Failure path (delivered=False) → 202, `success=False`,
  `new_status="pending"`, `message_code="replay_failed"`,
  `attempt_count` incremented, AuditLog emitted with `details.success=False`.
* Already terminal — 409 `already_replayed` / `already_abandoned`.
* Validation — missing / too-short / too-long `reason` → 422.
* Cross-tenant existence-leak probe — admin scoped to A trying to replay
  a row in B → 404 `dlq_entry_not_found`, NO row mutation, NO audit.
* AuditLog details shape — must include `entry_id`, `adapter_name`,
  `event_id`, `success`, `attempt_count`, `reason`.
* Pure pydantic schema unit cases — accept / reject reason length variants.

Plan: ai_docs/develop/plans/2026-04-22-argus-cycle6-b5.md (T39).
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import AsyncClient
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.schemas import (
    WEBHOOK_DLQ_REASON_MAX_LEN,
    WEBHOOK_DLQ_REASON_MIN_LEN,
    WebhookDlqReplayRequest,
)
from src.mcp.services.notifications.schemas import AdapterResult
from tests.api.admin.conftest import (
    DEFAULT_REASON,
    EVENT_DLQ_REPLAY,
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

REPLAY_PATH = "/admin/webhooks/dlq/{entry_id}/replay"


# ---------------------------------------------------------------------------
# Adapter mocking helpers — patch `_build_adapter` on the router so each
# test injects its own AdapterResult without touching real HTTP egress.
# ---------------------------------------------------------------------------


def _make_adapter_stub(result: AdapterResult) -> MagicMock:
    """Build a stub matching the `NotifierBase` surface the router uses."""
    stub = MagicMock()
    stub.send_with_retry = AsyncMock(return_value=result)
    stub.aclose = AsyncMock(return_value=None)
    return stub


def _patch_adapter(
    monkeypatch: pytest.MonkeyPatch, stub: MagicMock
) -> None:
    """Replace `_build_adapter` so every replay returns the given stub."""
    monkeypatch.setattr(
        "src.api.routers.admin_webhook_dlq._build_adapter",
        lambda adapter_name: stub,
    )


def _adapter_result(
    *,
    delivered: bool,
    event_id: str = "evt-test-0000",
    adapter_name: str = "slack",
    status_code: int | None = 200,
    error_code: str | None = None,
    target_redacted: str = "abcdef012345",
) -> AdapterResult:
    """Build an `AdapterResult` with the required minimum shape."""
    return AdapterResult(
        adapter_name=adapter_name,
        event_id=event_id,
        delivered=delivered,
        status_code=status_code if delivered else (status_code or 503),
        attempts=1,
        target_redacted=target_redacted,
        error_code=error_code if not delivered else None,
        skipped_reason=None,
        duplicate_of=None,
    )


# ===========================================================================
# Pure pydantic — `WebhookDlqReplayRequest` reason validation.
# 4 unit cases (no DB / no HTTP / no event-loop).
# ===========================================================================


class TestReplayRequestSchema:
    """Pure-Pydantic unit tests on the request schema."""

    def test_replay_request_schema_accepts_valid_reason(self) -> None:
        r = WebhookDlqReplayRequest(reason=DEFAULT_REASON)
        assert r.reason == DEFAULT_REASON

    def test_replay_request_schema_rejects_short_reason(self) -> None:
        with pytest.raises(ValidationError):
            WebhookDlqReplayRequest(
                reason="x" * (WEBHOOK_DLQ_REASON_MIN_LEN - 1)
            )

    def test_replay_request_schema_rejects_long_reason(self) -> None:
        with pytest.raises(ValidationError):
            WebhookDlqReplayRequest(
                reason="x" * (WEBHOOK_DLQ_REASON_MAX_LEN + 1)
            )

    def test_replay_request_schema_rejects_extra_field(self) -> None:
        with pytest.raises(ValidationError):
            WebhookDlqReplayRequest.model_validate(
                {"reason": DEFAULT_REASON, "stowaway": "no"}
            )


# ===========================================================================
# RBAC matrix
# ===========================================================================


class TestReplayRbac:
    async def test_replay_403_for_operator(
        self,
        api_client: AsyncClient,
        session: AsyncSession,
        audit_emitter: AuditEmitter,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        await seed_tenant(session, tenant_id=TENANT_A, name="alpha")
        entry = await enqueue_dlq_entry(
            session, tenant_id=TENANT_A, event_id="evt-rbac-op"
        )
        # Adapter MUST never be invoked on a 403 path.
        adapter = _make_adapter_stub(
            _adapter_result(delivered=True, event_id=entry.event_id)
        )
        _patch_adapter(monkeypatch, adapter)

        r = await api_client.post(
            REPLAY_PATH.format(entry_id=entry.id),
            headers=headers_operator(),
            json={"reason": DEFAULT_REASON},
        )

        assert r.status_code == 403
        assert r.json()["detail"] == "forbidden"
        adapter.send_with_retry.assert_not_awaited()
        audit_emitter.assert_not_called()

    async def test_replay_403_admin_without_tenant_header(
        self,
        api_client: AsyncClient,
        session: AsyncSession,
        audit_emitter: AuditEmitter,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        await seed_tenant(session, tenant_id=TENANT_A, name="alpha")
        entry = await enqueue_dlq_entry(
            session, tenant_id=TENANT_A, event_id="evt-rbac-admin-no-tenant"
        )
        adapter = _make_adapter_stub(
            _adapter_result(delivered=True, event_id=entry.event_id)
        )
        _patch_adapter(monkeypatch, adapter)

        r = await api_client.post(
            REPLAY_PATH.format(entry_id=entry.id),
            headers=headers_admin_no_tenant(),
            json={"reason": DEFAULT_REASON},
        )

        assert r.status_code == 403
        assert r.json()["detail"] == "tenant_required"
        adapter.send_with_retry.assert_not_awaited()
        audit_emitter.assert_not_called()

    async def test_replay_404_admin_cross_tenant_existence_leak(
        self,
        api_client: AsyncClient,
        session: AsyncSession,
        audit_emitter: AuditEmitter,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Admin A tries to replay a row owned by B → 404 (NOT 403).
        # Existence-leak protection mandated by the closed taxonomy.
        await seed_tenant(session, tenant_id=TENANT_A, name="alpha")
        await seed_tenant(session, tenant_id=TENANT_B, name="bravo")
        target = await enqueue_dlq_entry(
            session, tenant_id=TENANT_B, event_id="evt-cross-tenant-target"
        )
        adapter = _make_adapter_stub(
            _adapter_result(delivered=True, event_id=target.event_id)
        )
        _patch_adapter(monkeypatch, adapter)

        r = await api_client.post(
            REPLAY_PATH.format(entry_id=target.id),
            headers=headers_admin(TENANT_A),
            json={"reason": DEFAULT_REASON},
        )

        # MUST be 404 — never 403 — to prevent enumeration of other tenants' rows.
        assert r.status_code == 404, (
            f"expected 404 for cross-tenant probe, got {r.status_code}; "
            f"body={r.text!r}"
        )
        assert r.json()["detail"] == "dlq_entry_not_found"

        adapter.send_with_retry.assert_not_awaited()
        audit_emitter.assert_not_called()

        # Row in tenant B must remain pending — no mutation occurred.
        await session.refresh(target)
        assert target.replayed_at is None
        assert target.abandoned_at is None
        assert target.attempt_count == 0

    async def test_replay_202_admin_own_tenant_happy_path(
        self,
        api_client: AsyncClient,
        session: AsyncSession,
        audit_emitter: AuditEmitter,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        await seed_tenant(session, tenant_id=TENANT_A, name="alpha")
        entry = await enqueue_dlq_entry(
            session, tenant_id=TENANT_A, event_id="evt-admin-own"
        )
        adapter = _make_adapter_stub(
            _adapter_result(delivered=True, event_id=entry.event_id)
        )
        _patch_adapter(monkeypatch, adapter)

        r = await api_client.post(
            REPLAY_PATH.format(entry_id=entry.id),
            headers=headers_admin(TENANT_A),
            json={"reason": DEFAULT_REASON},
        )

        assert r.status_code == 202
        body = r.json()
        assert body["success"] is True
        assert body["new_status"] == "replayed"
        assert body["message_code"] == "replay_succeeded"
        assert body["entry_id"] == entry.id

    async def test_replay_202_super_admin_any_tenant_happy_path(
        self,
        api_client: AsyncClient,
        session: AsyncSession,
        audit_emitter: AuditEmitter,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        await seed_tenant(session, tenant_id=TENANT_A, name="alpha")
        await seed_tenant(session, tenant_id=TENANT_B, name="bravo")
        entry = await enqueue_dlq_entry(
            session, tenant_id=TENANT_B, event_id="evt-super-cross"
        )
        adapter = _make_adapter_stub(
            _adapter_result(delivered=True, event_id=entry.event_id)
        )
        _patch_adapter(monkeypatch, adapter)

        # No X-Admin-Tenant — super-admin can hit any tenant's rows.
        r = await api_client.post(
            REPLAY_PATH.format(entry_id=entry.id),
            headers=headers_super_admin(),
            json={"reason": DEFAULT_REASON},
        )

        assert r.status_code == 202
        body = r.json()
        assert body["success"] is True
        assert body["new_status"] == "replayed"
        assert body["entry_id"] == entry.id


# ===========================================================================
# Happy path detail assertions + AuditLog shape
# ===========================================================================


class TestReplaySuccessPath:
    async def test_replay_marks_row_replayed_and_emits_audit(
        self,
        api_client: AsyncClient,
        session: AsyncSession,
        audit_emitter: AuditEmitter,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        await seed_tenant(session, tenant_id=TENANT_A, name="alpha")
        entry = await enqueue_dlq_entry(
            session,
            tenant_id=TENANT_A,
            event_id="evt-success-shape",
            adapter_name="linear",
        )
        adapter = _make_adapter_stub(
            _adapter_result(
                delivered=True,
                event_id=entry.event_id,
                adapter_name="linear",
            )
        )
        _patch_adapter(monkeypatch, adapter)

        r = await api_client.post(
            REPLAY_PATH.format(entry_id=entry.id),
            headers=headers_admin(TENANT_A),
            json={"reason": DEFAULT_REASON},
        )

        assert r.status_code == 202
        body = r.json()
        assert body["entry_id"] == entry.id
        assert body["success"] is True
        assert body["new_status"] == "replayed"
        assert body["message_code"] == "replay_succeeded"
        assert body["attempt_count"] == 0  # mark_replayed does not bump
        assert isinstance(body["audit_id"], str) and body["audit_id"]

        # Row must now be terminal (replayed_at populated).
        await session.refresh(entry)
        assert entry.replayed_at is not None
        assert entry.abandoned_at is None

        # Audit log was emitted exactly once with the correct event taxonomy.
        assert audit_emitter.call_count == 1
        call = audit_emitter.last()
        assert call["action"] == EVENT_DLQ_REPLAY
        assert call["tenant_id"] == TENANT_A
        details: dict[str, Any] = call["details"]
        assert details["entry_id"] == entry.id
        assert details["adapter_name"] == "linear"
        assert details["event_id"] == entry.event_id
        assert details["success"] is True
        assert details["attempt_count"] == 0
        assert details["reason"] == DEFAULT_REASON


# ===========================================================================
# Failure path
# ===========================================================================


class TestReplayFailurePath:
    async def test_replay_failure_increments_attempt_and_keeps_pending(
        self,
        api_client: AsyncClient,
        session: AsyncSession,
        audit_emitter: AuditEmitter,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        await seed_tenant(session, tenant_id=TENANT_A, name="alpha")
        entry = await enqueue_dlq_entry(
            session,
            tenant_id=TENANT_A,
            event_id="evt-failure-path",
            attempt_count=2,
        )
        adapter = _make_adapter_stub(
            _adapter_result(
                delivered=False,
                event_id=entry.event_id,
                error_code="http_5xx",
                status_code=503,
            )
        )
        _patch_adapter(monkeypatch, adapter)

        r = await api_client.post(
            REPLAY_PATH.format(entry_id=entry.id),
            headers=headers_admin(TENANT_A),
            json={"reason": DEFAULT_REASON},
        )

        assert r.status_code == 202
        body = r.json()
        assert body["success"] is False
        assert body["new_status"] == "pending"
        assert body["message_code"] == "replay_failed"
        assert body["attempt_count"] == 3  # 2 + 1 from increment_attempt
        assert body["entry_id"] == entry.id

        await session.refresh(entry)
        assert entry.replayed_at is None
        assert entry.abandoned_at is None
        assert entry.attempt_count == 3
        assert entry.last_error_code == "http_5xx"
        assert entry.last_status_code == 503

        # AuditLog records success=False and the bumped attempt_count.
        assert audit_emitter.call_count == 1
        call = audit_emitter.last()
        assert call["action"] == EVENT_DLQ_REPLAY
        details: dict[str, Any] = call["details"]
        assert details["success"] is False
        assert details["attempt_count"] == 3
        assert details["reason"] == DEFAULT_REASON
        assert details["entry_id"] == entry.id
        assert details["adapter_name"] == "slack"
        assert details["event_id"] == entry.event_id


# ===========================================================================
# Already-terminal short-circuit
# ===========================================================================


class TestReplayAlreadyTerminal:
    async def test_replay_409_already_replayed(
        self,
        api_client: AsyncClient,
        session: AsyncSession,
        audit_emitter: AuditEmitter,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        await seed_tenant(session, tenant_id=TENANT_A, name="alpha")
        entry = await enqueue_dlq_entry(
            session, tenant_id=TENANT_A, event_id="evt-already-replayed"
        )
        await force_terminal_replayed(session, entry_id=entry.id)
        adapter = _make_adapter_stub(
            _adapter_result(delivered=True, event_id=entry.event_id)
        )
        _patch_adapter(monkeypatch, adapter)

        r = await api_client.post(
            REPLAY_PATH.format(entry_id=entry.id),
            headers=headers_admin(TENANT_A),
            json={"reason": DEFAULT_REASON},
        )

        assert r.status_code == 409
        assert r.json()["detail"] == "already_replayed"
        adapter.send_with_retry.assert_not_awaited()
        audit_emitter.assert_not_called()

    async def test_replay_409_already_abandoned(
        self,
        api_client: AsyncClient,
        session: AsyncSession,
        audit_emitter: AuditEmitter,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        await seed_tenant(session, tenant_id=TENANT_A, name="alpha")
        entry = await enqueue_dlq_entry(
            session, tenant_id=TENANT_A, event_id="evt-already-abandoned"
        )
        await force_terminal_abandoned(session, entry_id=entry.id)
        adapter = _make_adapter_stub(
            _adapter_result(delivered=True, event_id=entry.event_id)
        )
        _patch_adapter(monkeypatch, adapter)

        r = await api_client.post(
            REPLAY_PATH.format(entry_id=entry.id),
            headers=headers_admin(TENANT_A),
            json={"reason": DEFAULT_REASON},
        )

        assert r.status_code == 409
        assert r.json()["detail"] == "already_abandoned"
        adapter.send_with_retry.assert_not_awaited()
        audit_emitter.assert_not_called()


# ===========================================================================
# Validation — body.reason
# ===========================================================================


class TestReplayValidation:
    async def test_replay_422_missing_reason(
        self,
        api_client: AsyncClient,
        session: AsyncSession,
        audit_emitter: AuditEmitter,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        await seed_tenant(session, tenant_id=TENANT_A, name="alpha")
        entry = await enqueue_dlq_entry(
            session, tenant_id=TENANT_A, event_id="evt-missing-reason"
        )
        adapter = _make_adapter_stub(
            _adapter_result(delivered=True, event_id=entry.event_id)
        )
        _patch_adapter(monkeypatch, adapter)

        r = await api_client.post(
            REPLAY_PATH.format(entry_id=entry.id),
            headers=headers_admin(TENANT_A),
            json={},
        )

        assert r.status_code == 422
        adapter.send_with_retry.assert_not_awaited()
        audit_emitter.assert_not_called()

    async def test_replay_422_reason_too_short(
        self,
        api_client: AsyncClient,
        session: AsyncSession,
        audit_emitter: AuditEmitter,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        await seed_tenant(session, tenant_id=TENANT_A, name="alpha")
        entry = await enqueue_dlq_entry(
            session, tenant_id=TENANT_A, event_id="evt-short-reason"
        )
        adapter = _make_adapter_stub(
            _adapter_result(delivered=True, event_id=entry.event_id)
        )
        _patch_adapter(monkeypatch, adapter)

        r = await api_client.post(
            REPLAY_PATH.format(entry_id=entry.id),
            headers=headers_admin(TENANT_A),
            json={"reason": "too short"},
        )

        assert r.status_code == 422
        adapter.send_with_retry.assert_not_awaited()
        audit_emitter.assert_not_called()

    async def test_replay_422_reason_too_long(
        self,
        api_client: AsyncClient,
        session: AsyncSession,
        audit_emitter: AuditEmitter,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        await seed_tenant(session, tenant_id=TENANT_A, name="alpha")
        entry = await enqueue_dlq_entry(
            session, tenant_id=TENANT_A, event_id="evt-long-reason"
        )
        adapter = _make_adapter_stub(
            _adapter_result(delivered=True, event_id=entry.event_id)
        )
        _patch_adapter(monkeypatch, adapter)

        r = await api_client.post(
            REPLAY_PATH.format(entry_id=entry.id),
            headers=headers_admin(TENANT_A),
            json={"reason": "x" * (WEBHOOK_DLQ_REASON_MAX_LEN + 1)},
        )

        assert r.status_code == 422
        adapter.send_with_retry.assert_not_awaited()
        audit_emitter.assert_not_called()


# ===========================================================================
# Edge cases — random non-existent id, audit-details schema completeness.
# ===========================================================================


class TestReplayEdgeCases:
    async def test_replay_404_random_unknown_entry_id(
        self,
        api_client: AsyncClient,
        session: AsyncSession,
        audit_emitter: AuditEmitter,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        await seed_tenant(session, tenant_id=TENANT_A, name="alpha")
        adapter = _make_adapter_stub(_adapter_result(delivered=True))
        _patch_adapter(monkeypatch, adapter)
        unknown_id = random_uuid()

        r = await api_client.post(
            REPLAY_PATH.format(entry_id=unknown_id),
            headers=headers_admin(TENANT_A),
            json={"reason": DEFAULT_REASON},
        )

        assert r.status_code == 404
        assert r.json()["detail"] == "dlq_entry_not_found"
        adapter.send_with_retry.assert_not_awaited()
        audit_emitter.assert_not_called()

    async def test_replay_audit_details_complete_shape(
        self,
        api_client: AsyncClient,
        session: AsyncSession,
        audit_emitter: AuditEmitter,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Verifies every field in the closed audit-details taxonomy is
        # present (entry_id, adapter_name, event_id, success,
        # attempt_count, reason — plus operator_user_id_hash injected by
        # `_emit_audit` itself).
        await seed_tenant(session, tenant_id=TENANT_A, name="alpha")
        entry = await enqueue_dlq_entry(
            session,
            tenant_id=TENANT_A,
            event_id="evt-audit-shape",
            adapter_name="jira",
            attempt_count=1,
        )
        adapter = _make_adapter_stub(
            _adapter_result(
                delivered=True,
                event_id=entry.event_id,
                adapter_name="jira",
            )
        )
        _patch_adapter(monkeypatch, adapter)

        custom_reason = "Quarantined override; manual replay after on-call"
        r = await api_client.post(
            REPLAY_PATH.format(entry_id=entry.id),
            headers=headers_admin(TENANT_A),
            json={"reason": custom_reason},
        )

        assert r.status_code == 202
        assert audit_emitter.call_count == 1
        call = audit_emitter.last()
        assert call["action"] == EVENT_DLQ_REPLAY
        assert call["tenant_id"] == TENANT_A

        details: dict[str, Any] = call["details"]
        required_keys = {
            "entry_id",
            "adapter_name",
            "event_id",
            "success",
            "attempt_count",
            "reason",
        }
        missing = required_keys - set(details.keys())
        assert not missing, (
            f"audit details missing required keys: {missing}; "
            f"details={details!r}"
        )
        assert details["entry_id"] == entry.id
        assert details["adapter_name"] == "jira"
        assert details["event_id"] == entry.event_id
        assert details["success"] is True
        assert details["attempt_count"] == 1
        assert details["reason"] == custom_reason
