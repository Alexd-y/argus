"""T39 acceptance — `GET /admin/webhooks/dlq` (Cycle 6 Batch 5, ARG-053).

Covers the LIST endpoint:

* RBAC matrix — operator / admin (own tenant + missing tenant) / super-admin
  (cross-tenant + tenant-scoped).
* Pagination contract — `limit` / `offset` / `total` arithmetic and bounds.
* Filters — `status` (terminal-vs-pending), `adapter_name`, `created_after`,
  `created_before`.
* Validation — `limit > 200` → 422; `offset < 0` → 422.
* Response shape — `target_url_hash` is the redacted hex prefix produced by
  `mcp.services.notifications._base.hash_target` (currently
  `TARGET_REDACTED_LEN`-char sha256 prefix). The raw webhook URL is NEVER
  present in the response body — see `WebhookDlqEntryItem` projection in
  `src.api.schemas`.
* Empty path — zero matching rows yields `items=[]` + `total=0`.

Plan: ai_docs/develop/plans/2026-04-22-argus-cycle6-b5.md (T39).
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from src.mcp.services.notifications._base import (
    TARGET_REDACTED_LEN,
    hash_target,
)
from tests.api.admin.conftest import (
    TENANT_A,
    TENANT_B,
    enqueue_dlq_entry,
    force_terminal_abandoned,
    force_terminal_replayed,
    headers_admin,
    headers_admin_no_tenant,
    headers_operator,
    headers_super_admin,
    seed_tenant,
)

LIST_PATH = "/admin/webhooks/dlq"

_HEX_REDACTED = re.compile(rf"^[0-9a-f]{{{TARGET_REDACTED_LEN}}}$")


# ---------------------------------------------------------------------------
# RBAC
# ---------------------------------------------------------------------------


class TestRbac:
    """Role-based access control matrix for the LIST endpoint."""

    async def test_list_403_for_operator(
        self, api_client: AsyncClient
    ) -> None:
        r = await api_client.get(LIST_PATH, headers=headers_operator())
        assert r.status_code == 403
        assert r.json()["detail"] == "forbidden"

    async def test_list_403_admin_without_tenant_header(
        self, api_client: AsyncClient
    ) -> None:
        r = await api_client.get(
            LIST_PATH, headers=headers_admin_no_tenant()
        )
        assert r.status_code == 403
        assert r.json()["detail"] == "tenant_required"

    async def test_list_200_admin_filters_to_own_tenant(
        self, api_client: AsyncClient, session: AsyncSession
    ) -> None:
        await seed_tenant(session, tenant_id=TENANT_A, name="alpha")
        await seed_tenant(session, tenant_id=TENANT_B, name="bravo")
        await enqueue_dlq_entry(
            session, tenant_id=TENANT_A, event_id="evt-a-001"
        )
        await enqueue_dlq_entry(
            session, tenant_id=TENANT_B, event_id="evt-b-001"
        )

        r = await api_client.get(LIST_PATH, headers=headers_admin(TENANT_A))

        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 1
        assert len(body["items"]) == 1
        assert body["items"][0]["tenant_id"] == TENANT_A
        assert body["items"][0]["event_id"] == "evt-a-001"

    async def test_list_200_super_admin_no_tenant_returns_all_tenants(
        self, api_client: AsyncClient, session: AsyncSession
    ) -> None:
        await seed_tenant(session, tenant_id=TENANT_A, name="alpha")
        await seed_tenant(session, tenant_id=TENANT_B, name="bravo")
        await enqueue_dlq_entry(
            session, tenant_id=TENANT_A, event_id="evt-a-100"
        )
        await enqueue_dlq_entry(
            session, tenant_id=TENANT_B, event_id="evt-b-100"
        )

        r = await api_client.get(LIST_PATH, headers=headers_super_admin())

        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 2
        tenants_in_response = {item["tenant_id"] for item in body["items"]}
        assert tenants_in_response == {TENANT_A, TENANT_B}

    async def test_list_200_super_admin_with_tenant_filters(
        self, api_client: AsyncClient, session: AsyncSession
    ) -> None:
        await seed_tenant(session, tenant_id=TENANT_A, name="alpha")
        await seed_tenant(session, tenant_id=TENANT_B, name="bravo")
        await enqueue_dlq_entry(
            session, tenant_id=TENANT_A, event_id="evt-a-200"
        )
        await enqueue_dlq_entry(
            session, tenant_id=TENANT_B, event_id="evt-b-200"
        )

        r = await api_client.get(
            LIST_PATH, headers=headers_super_admin(TENANT_B)
        )

        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 1
        assert body["items"][0]["tenant_id"] == TENANT_B
        assert body["items"][0]["event_id"] == "evt-b-200"


# ---------------------------------------------------------------------------
# Pagination + filters
# ---------------------------------------------------------------------------


class TestPaginationAndFilters:
    """Exercise `limit/offset/total`, `status`, `adapter_name`, date filters."""

    async def test_list_200_pagination_arithmetic(
        self, api_client: AsyncClient, session: AsyncSession
    ) -> None:
        await seed_tenant(session, tenant_id=TENANT_A, name="alpha")
        for i in range(5):
            await enqueue_dlq_entry(
                session, tenant_id=TENANT_A, event_id=f"evt-page-{i:03}"
            )

        first = await api_client.get(
            LIST_PATH,
            headers=headers_admin(TENANT_A),
            params={"limit": 2, "offset": 0},
        )
        second = await api_client.get(
            LIST_PATH,
            headers=headers_admin(TENANT_A),
            params={"limit": 2, "offset": 2},
        )
        third = await api_client.get(
            LIST_PATH,
            headers=headers_admin(TENANT_A),
            params={"limit": 2, "offset": 4},
        )

        for r in (first, second, third):
            assert r.status_code == 200
            assert r.json()["total"] == 5

        first_body = first.json()
        second_body = second.json()
        third_body = third.json()

        assert first_body["limit"] == 2
        assert first_body["offset"] == 0
        assert len(first_body["items"]) == 2
        assert len(second_body["items"]) == 2
        assert len(third_body["items"]) == 1

        ids_first = {item["event_id"] for item in first_body["items"]}
        ids_second = {item["event_id"] for item in second_body["items"]}
        ids_third = {item["event_id"] for item in third_body["items"]}
        assert ids_first.isdisjoint(ids_second)
        assert ids_first.isdisjoint(ids_third)
        assert ids_second.isdisjoint(ids_third)

    async def test_list_200_status_pending_excludes_terminal_rows(
        self, api_client: AsyncClient, session: AsyncSession
    ) -> None:
        await seed_tenant(session, tenant_id=TENANT_A, name="alpha")
        pending = await enqueue_dlq_entry(
            session, tenant_id=TENANT_A, event_id="evt-pending"
        )
        replayed = await enqueue_dlq_entry(
            session, tenant_id=TENANT_A, event_id="evt-replayed"
        )
        abandoned = await enqueue_dlq_entry(
            session, tenant_id=TENANT_A, event_id="evt-abandoned"
        )
        await force_terminal_replayed(session, entry_id=replayed.id)
        await force_terminal_abandoned(session, entry_id=abandoned.id)

        r = await api_client.get(
            LIST_PATH,
            headers=headers_admin(TENANT_A),
            params={"status": "pending"},
        )

        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 1
        assert body["items"][0]["id"] == pending.id
        assert body["items"][0]["triage_status"] == "pending"

    async def test_list_200_adapter_name_filter(
        self, api_client: AsyncClient, session: AsyncSession
    ) -> None:
        await seed_tenant(session, tenant_id=TENANT_A, name="alpha")
        await enqueue_dlq_entry(
            session,
            tenant_id=TENANT_A,
            adapter_name="slack",
            event_id="evt-slack-1",
        )
        await enqueue_dlq_entry(
            session,
            tenant_id=TENANT_A,
            adapter_name="linear",
            event_id="evt-linear-1",
        )
        await enqueue_dlq_entry(
            session,
            tenant_id=TENANT_A,
            adapter_name="jira",
            event_id="evt-jira-1",
        )

        r = await api_client.get(
            LIST_PATH,
            headers=headers_admin(TENANT_A),
            params={"adapter_name": "slack"},
        )

        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 1
        assert body["items"][0]["adapter_name"] == "slack"
        assert body["items"][0]["event_id"] == "evt-slack-1"

    async def test_list_200_created_after_before_filters(
        self, api_client: AsyncClient, session: AsyncSession
    ) -> None:
        await seed_tenant(session, tenant_id=TENANT_A, name="alpha")
        old = await enqueue_dlq_entry(
            session, tenant_id=TENANT_A, event_id="evt-old-0001"
        )
        recent = await enqueue_dlq_entry(
            session, tenant_id=TENANT_A, event_id="evt-recent-0002"
        )
        # Force `created_at` columns to known instants — server_default
        # sets `now()` so we backdate via raw SQL.
        old_when = datetime(2026, 1, 1, 12, 0, 0)
        recent_when = datetime(2026, 4, 22, 12, 0, 0)
        for entry_id, when in ((old.id, old_when), (recent.id, recent_when)):
            await session.execute(
                text(
                    "UPDATE webhook_dlq_entries SET created_at = :ts "
                    "WHERE id = :id"
                ),
                {"ts": when, "id": entry_id},
            )
        await session.commit()

        cutoff = (datetime(2026, 3, 1, tzinfo=UTC)).isoformat()
        r_after = await api_client.get(
            LIST_PATH,
            headers=headers_admin(TENANT_A),
            params={"created_after": cutoff},
        )

        cutoff_before = (datetime(2026, 3, 1, tzinfo=UTC)).isoformat()
        r_before = await api_client.get(
            LIST_PATH,
            headers=headers_admin(TENANT_A),
            params={"created_before": cutoff_before},
        )

        assert r_after.status_code == 200
        assert r_after.json()["total"] == 1
        assert r_after.json()["items"][0]["event_id"] == "evt-recent-0002"

        assert r_before.status_code == 200
        assert r_before.json()["total"] == 1
        assert r_before.json()["items"][0]["event_id"] == "evt-old-0001"

    async def test_list_200_combined_filters_intersect(
        self, api_client: AsyncClient, session: AsyncSession
    ) -> None:
        await seed_tenant(session, tenant_id=TENANT_A, name="alpha")
        await enqueue_dlq_entry(
            session,
            tenant_id=TENANT_A,
            adapter_name="slack",
            event_id="evt-slack-pending",
        )
        replayed = await enqueue_dlq_entry(
            session,
            tenant_id=TENANT_A,
            adapter_name="slack",
            event_id="evt-slack-replayed",
        )
        await force_terminal_replayed(session, entry_id=replayed.id)
        await enqueue_dlq_entry(
            session,
            tenant_id=TENANT_A,
            adapter_name="linear",
            event_id="evt-linear-pending",
        )

        r = await api_client.get(
            LIST_PATH,
            headers=headers_admin(TENANT_A),
            params={"adapter_name": "slack", "status": "pending"},
        )

        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 1
        assert body["items"][0]["event_id"] == "evt-slack-pending"


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


class TestValidation:
    """Pagination knob validation — pure FastAPI Query bound checks."""

    @pytest.mark.parametrize("limit", [201, 500, 100_000])
    async def test_list_422_limit_above_two_hundred(
        self, api_client: AsyncClient, limit: int
    ) -> None:
        r = await api_client.get(
            LIST_PATH,
            headers=headers_super_admin(),
            params={"limit": limit},
        )
        assert r.status_code == 422

    @pytest.mark.parametrize("offset", [-1, -100])
    async def test_list_422_offset_negative(
        self, api_client: AsyncClient, offset: int
    ) -> None:
        r = await api_client.get(
            LIST_PATH,
            headers=headers_super_admin(),
            params={"offset": offset},
        )
        assert r.status_code == 422

    async def test_list_422_limit_zero(
        self, api_client: AsyncClient
    ) -> None:
        r = await api_client.get(
            LIST_PATH,
            headers=headers_super_admin(),
            params={"limit": 0},
        )
        assert r.status_code == 422


# ---------------------------------------------------------------------------
# Empty path + response shape
# ---------------------------------------------------------------------------


class TestResponseShape:
    """Empty list path + redaction guarantees on `target_url_hash`."""

    async def test_list_200_empty_returns_empty_items_total_zero(
        self, api_client: AsyncClient, session: AsyncSession
    ) -> None:
        await seed_tenant(session, tenant_id=TENANT_A, name="alpha")

        r = await api_client.get(LIST_PATH, headers=headers_admin(TENANT_A))

        assert r.status_code == 200
        body = r.json()
        assert body["items"] == []
        assert body["total"] == 0
        assert body["limit"] == 50
        assert body["offset"] == 0

    async def test_list_200_target_url_hash_redacted_hex_no_raw_url(
        self, api_client: AsyncClient, session: AsyncSession
    ) -> None:
        await seed_tenant(session, tenant_id=TENANT_A, name="alpha")
        secret_url = "https://hooks.slack.example/T0/B0/super-secret-token-XYZ"
        await enqueue_dlq_entry(
            session,
            tenant_id=TENANT_A,
            event_id="evt-redaction",
            target_url=secret_url,
        )

        r = await api_client.get(LIST_PATH, headers=headers_admin(TENANT_A))

        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 1

        entry = body["items"][0]
        target_hash = entry["target_url_hash"]
        assert isinstance(target_hash, str)
        assert _HEX_REDACTED.match(target_hash), (
            "target_url_hash must be a "
            f"{TARGET_REDACTED_LEN}-char hex prefix of sha256(url), "
            f"got {target_hash!r}"
        )
        # Determinism: the value must be exactly the prefix produced by the
        # canonical helper used by the notification stack.
        assert target_hash == hash_target(secret_url)
        full_digest = hashlib.sha256(secret_url.encode("utf-8")).hexdigest()
        assert full_digest.startswith(target_hash)

        # Belt-and-braces: the raw URL token must NEVER leak into the body.
        raw = r.text
        assert "super-secret-token-XYZ" not in raw
        assert "hooks.slack.example" not in raw

    async def test_list_200_pagination_clamps_to_two_hundred(
        self, api_client: AsyncClient, session: AsyncSession
    ) -> None:
        # Edge of valid range: limit=200 must still succeed.
        await seed_tenant(session, tenant_id=TENANT_A, name="alpha")
        await enqueue_dlq_entry(
            session, tenant_id=TENANT_A, event_id="evt-clamp"
        )

        r = await api_client.get(
            LIST_PATH,
            headers=headers_admin(TENANT_A),
            params={"limit": 200},
        )

        assert r.status_code == 200
        assert r.json()["limit"] == 200

    async def test_list_no_audit_emit_on_read(
        self, api_client: AsyncClient, session: AsyncSession, audit_emitter
    ) -> None:
        # Reads must not emit audit rows — only state-changing actions
        # (replay/abandon) write to AuditLog.
        await seed_tenant(session, tenant_id=TENANT_A, name="alpha")
        await enqueue_dlq_entry(
            session, tenant_id=TENANT_A, event_id="evt-no-audit"
        )

        r = await api_client.get(LIST_PATH, headers=headers_admin(TENANT_A))

        assert r.status_code == 200
        audit_emitter.assert_not_called()


# ---------------------------------------------------------------------------
# Cross-tenant probe — admin scoped to A querying with no entries in A
# must NOT leak the existence of B's rows.
# ---------------------------------------------------------------------------


class TestCrossTenantProbe:
    async def test_list_200_admin_sees_zero_when_only_other_tenant_has_rows(
        self, api_client: AsyncClient, session: AsyncSession
    ) -> None:
        await seed_tenant(session, tenant_id=TENANT_A, name="alpha")
        await seed_tenant(session, tenant_id=TENANT_B, name="bravo")
        await enqueue_dlq_entry(
            session, tenant_id=TENANT_B, event_id="evt-tenant-b-only"
        )

        r = await api_client.get(LIST_PATH, headers=headers_admin(TENANT_A))

        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 0
        assert body["items"] == []
