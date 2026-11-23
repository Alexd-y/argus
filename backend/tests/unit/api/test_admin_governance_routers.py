"""WP D admin routers — engagements / approvals / rotation (no live DB).

The DAO logic itself is covered against real SQLite in
``tests/unit/governance/test_governance_stores.py``. These tests pin the *HTTP
layer*: the fail-closed admin gate, explicit tenant-id plumbing (there is no
session principal under the legacy ``X-Admin-Key`` shim, so tenant must travel
in the request), tenant-scoped 404s, response shaping, the mandatory-reason
gate, and that an approve/deny decision writes an immutable audit row.

Mirrors ``test_admin_bulk_ops.py``: the session factory and the ``stores``
helpers are patched, so no Postgres and no cross-event-loop aiosqlite handle.
"""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from src.core.config import settings
from src.llm.rotation import LLMRotation
from starlette.testclient import TestClient

ENGAGEMENTS = "/api/v1/admin/engagements"
ROTATION = "/api/v1/admin/rotation"
APPROVALS = "/api/v1/admin/approvals"

_ADMIN_KEY = "secret-admin-key"
_ADMIN_HEADERS = {"X-Admin-Key": _ADMIN_KEY}
_TENANT = str(uuid.uuid4())
_OTHER_TENANT = str(uuid.uuid4())


def _session_factory():
    """A mock async session whose context manager yields itself."""
    session = AsyncMock()
    session.add = MagicMock()
    session.commit = AsyncMock()
    session.flush = AsyncMock()

    @asynccontextmanager
    async def _cm():
        yield session

    return (lambda: _cm()), session


def _engagement_row(tenant_id: str = _TENANT, revoked: bool = False) -> SimpleNamespace:
    return SimpleNamespace(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        allowed_targets=["victim.example.com"],
        allowed_tenants=[tenant_id],
        allowed_actions=["recon"],
        window_start=None,
        window_end=None,
        max_rate_per_target=None,
        revoked=revoked,
    )


def _approval_row(tenant_id: str = _TENANT, status: str = "pending") -> SimpleNamespace:
    return SimpleNamespace(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        scan_id=None,
        action="secretsdump",
        target="dc01",
        status=status,
        reason="auto-enqueued",
        decided_by=None,
        decision_reason=None,
        decided_at=None,
    )


# --------------------------------------------------------------------- auth gate


class TestGovernanceAuthGate:
    def test_engagements_401_without_key(self, client: TestClient) -> None:
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.post(ENGAGEMENTS, json={"tenant_id": _TENANT})
        assert r.status_code == 401

    def test_rotation_get_401_without_key(self, client: TestClient) -> None:
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.get(f"{ROTATION}?tenant_id={_TENANT}")
        assert r.status_code == 401


# ------------------------------------------------------------------ engagements


class TestEngagements:
    def test_create_returns_mapped_row(self, client: TestClient) -> None:
        factory, _ = _session_factory()
        row = _engagement_row()
        with (
            patch.object(settings, "admin_api_key", _ADMIN_KEY),
            patch("src.api.routers.admin_engagements.async_session_factory", factory),
            patch(
                "src.api.routers.admin_engagements.stores.create_engagement",
                new=AsyncMock(return_value=row),
            ) as mock_create,
        ):
            r = client.post(
                ENGAGEMENTS,
                headers=_ADMIN_HEADERS,
                json={
                    "tenant_id": _TENANT,
                    "allowed_targets": ["victim.example.com"],
                    "allowed_tenants": [_TENANT],
                    "allowed_actions": ["recon"],
                },
            )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["id"] == row.id
        assert body["allowed_targets"] == ["victim.example.com"]
        # tenant travels from the request body into the store call (no principal).
        assert mock_create.await_args.kwargs["tenant_id"] == _TENANT

    def test_get_same_tenant_ok(self, client: TestClient) -> None:
        factory, _ = _session_factory()
        row = _engagement_row()
        with (
            patch.object(settings, "admin_api_key", _ADMIN_KEY),
            patch("src.api.routers.admin_engagements.async_session_factory", factory),
            patch(
                "src.api.routers.admin_engagements.stores.get_engagement",
                new=AsyncMock(return_value=row),
            ),
        ):
            r = client.get(f"{ENGAGEMENTS}/{row.id}?tenant_id={_TENANT}", headers=_ADMIN_HEADERS)
        assert r.status_code == 200
        assert r.json()["id"] == row.id

    def test_get_cross_tenant_404(self, client: TestClient) -> None:
        factory, _ = _session_factory()
        row = _engagement_row(tenant_id=_TENANT)
        with (
            patch.object(settings, "admin_api_key", _ADMIN_KEY),
            patch("src.api.routers.admin_engagements.async_session_factory", factory),
            patch(
                "src.api.routers.admin_engagements.stores.get_engagement",
                new=AsyncMock(return_value=row),
            ),
        ):
            r = client.get(
                f"{ENGAGEMENTS}/{row.id}?tenant_id={_OTHER_TENANT}", headers=_ADMIN_HEADERS
            )
        assert r.status_code == 404

    def test_revoke_sets_revoked(self, client: TestClient) -> None:
        factory, session = _session_factory()
        row = _engagement_row()
        revoked = _engagement_row(tenant_id=_TENANT, revoked=True)
        revoked.id = row.id
        with (
            patch.object(settings, "admin_api_key", _ADMIN_KEY),
            patch("src.api.routers.admin_engagements.async_session_factory", factory),
            patch(
                "src.api.routers.admin_engagements.stores.get_engagement",
                new=AsyncMock(return_value=row),
            ),
            patch(
                "src.api.routers.admin_engagements.stores.revoke_engagement",
                new=AsyncMock(return_value=revoked),
            ),
        ):
            r = client.post(
                f"{ENGAGEMENTS}/{row.id}/revoke?tenant_id={_TENANT}", headers=_ADMIN_HEADERS
            )
        assert r.status_code == 200
        assert r.json()["revoked"] is True
        session.commit.assert_awaited()


# --------------------------------------------------------------------- rotation


class TestRotation:
    def test_set_then_state_echo(self, client: TestClient) -> None:
        factory, session = _session_factory()
        with (
            patch.object(settings, "admin_api_key", _ADMIN_KEY),
            patch("src.api.routers.admin_rotation.async_session_factory", factory),
            patch(
                "src.api.routers.admin_rotation.stores.save_rotation",
                new=AsyncMock(return_value=None),
            ) as mock_save,
        ):
            r = client.post(
                ROTATION,
                headers=_ADMIN_HEADERS,
                json={"tenant_id": _TENANT, "role": "report", "profile_ids": ["A", "B"]},
            )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["profile_ids"] == ["A", "B"]
        assert body["cursor"] == 0
        assert mock_save.await_args.kwargs["tenant_id"] == _TENANT
        session.commit.assert_awaited()

    def test_get_loads_persisted(self, client: TestClient) -> None:
        factory, _ = _session_factory()
        with (
            patch.object(settings, "admin_api_key", _ADMIN_KEY),
            patch("src.api.routers.admin_rotation.async_session_factory", factory),
            patch(
                "src.api.routers.admin_rotation.stores.load_rotation",
                new=AsyncMock(return_value=LLMRotation(["A", "B"])),
            ),
        ):
            r = client.get(f"{ROTATION}?tenant_id={_TENANT}&role=report", headers=_ADMIN_HEADERS)
        assert r.status_code == 200
        assert r.json()["profile_ids"] == ["A", "B"]

    def test_get_absent_defaults_empty(self, client: TestClient) -> None:
        factory, _ = _session_factory()
        with (
            patch.object(settings, "admin_api_key", _ADMIN_KEY),
            patch("src.api.routers.admin_rotation.async_session_factory", factory),
            patch(
                "src.api.routers.admin_rotation.stores.load_rotation",
                new=AsyncMock(return_value=None),
            ),
        ):
            r = client.get(f"{ROTATION}?tenant_id={_TENANT}", headers=_ADMIN_HEADERS)
        assert r.status_code == 200
        body = r.json()
        assert body["profile_ids"] == []
        assert body["cursor"] == 0


# -------------------------------------------------------------------- approvals


class TestGovernanceRbac:
    """Tenant-scope RBAC: X-Admin-Key alone = super-admin (back-compat); an explicit
    ``X-Admin-Role: admin`` is bound to its ``X-Admin-Tenant`` and cannot cross."""

    def test_admin_role_cross_tenant_denied(self, client: TestClient) -> None:
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.post(
                ENGAGEMENTS,
                headers={**_ADMIN_HEADERS, "X-Admin-Role": "admin", "X-Admin-Tenant": _TENANT},
                json={
                    "tenant_id": _OTHER_TENANT,  # different tenant than X-Admin-Tenant
                    "allowed_targets": [],
                    "allowed_tenants": [],
                    "allowed_actions": [],
                },
            )
        assert r.status_code == 403

    def test_admin_role_own_tenant_allowed(self, client: TestClient) -> None:
        factory, _ = _session_factory()
        row = _engagement_row()
        with (
            patch.object(settings, "admin_api_key", _ADMIN_KEY),
            patch("src.api.routers.admin_engagements.async_session_factory", factory),
            patch(
                "src.api.routers.admin_engagements.stores.create_engagement",
                new=AsyncMock(return_value=row),
            ),
        ):
            r = client.post(
                ENGAGEMENTS,
                headers={**_ADMIN_HEADERS, "X-Admin-Role": "admin", "X-Admin-Tenant": _TENANT},
                json={
                    "tenant_id": _TENANT,
                    "allowed_targets": ["victim.example.com"],
                    "allowed_tenants": [_TENANT],
                    "allowed_actions": ["recon"],
                },
            )
        assert r.status_code == 200, r.text

    def test_unknown_role_denied(self, client: TestClient) -> None:
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.get(
                f"{APPROVALS}?tenant_id={_TENANT}",
                headers={**_ADMIN_HEADERS, "X-Admin-Role": "wizard"},
            )
        assert r.status_code == 403


class TestApprovals:
    def test_list_maps_rows(self, client: TestClient) -> None:
        factory, _ = _session_factory()
        rows = [_approval_row(), _approval_row()]
        with (
            patch.object(settings, "admin_api_key", _ADMIN_KEY),
            patch("src.api.routers.admin_approvals.async_session_factory", factory),
            patch(
                "src.api.routers.admin_approvals.stores.list_approvals",
                new=AsyncMock(return_value=rows),
            ) as mock_list,
        ):
            r = client.get(
                f"{APPROVALS}?tenant_id={_TENANT}&status=pending", headers=_ADMIN_HEADERS
            )
        assert r.status_code == 200
        assert len(r.json()) == 2
        assert mock_list.await_args.kwargs["tenant_id"] == _TENANT
        assert mock_list.await_args.kwargs["status"] == "pending"

    def test_decide_approve_writes_audit(self, client: TestClient) -> None:
        factory, session = _session_factory()
        row = _approval_row()
        decided = _approval_row(status="approved")
        decided.id = row.id
        decided.decided_by = "admin_api"
        decided.decision_reason = "in scope, authorized"
        with (
            patch.object(settings, "admin_api_key", _ADMIN_KEY),
            patch("src.api.routers.admin_approvals.async_session_factory", factory),
            patch(
                "src.api.routers.admin_approvals.stores.get_approval",
                new=AsyncMock(return_value=row),
            ),
            patch(
                "src.api.routers.admin_approvals.stores.decide_approval_if_pending",
                new=AsyncMock(return_value=decided),
            ) as mock_decide,
            patch(
                "src.api.routers.admin_approvals.record_decision_audit",
                new=AsyncMock(return_value=None),
            ) as mock_audit,
        ):
            r = client.post(
                f"{APPROVALS}/{row.id}/decide",
                headers=_ADMIN_HEADERS,
                json={"tenant_id": _TENANT, "approve": True, "reason": "in scope, authorized"},
            )
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "approved"
        mock_decide.assert_awaited_once()
        # Immutable-audit row written in the same transaction as the decision.
        mock_audit.assert_awaited_once()
        assert mock_audit.await_args.kwargs["action"] == "governance.approval.decided"
        assert mock_audit.await_args.kwargs["resource_id"] == row.id
        session.commit.assert_awaited()

    def test_decide_approve_exploitation_resumes_scan(self, client: TestClient) -> None:
        factory, session = _session_factory()
        row = _approval_row()
        decided = _approval_row(status="approved")
        decided.id = row.id
        decided.action = "exploitation"
        decided.scan_id = "scan-xyz"
        fake_scan = SimpleNamespace(
            id="scan-xyz",
            tenant_id=_TENANT,
            target_url="https://victim.example.com",
            options={"k": "v"},
            status="approved",
        )
        with (
            patch.object(settings, "admin_api_key", _ADMIN_KEY),
            patch("src.api.routers.admin_approvals.async_session_factory", factory),
            patch(
                "src.api.routers.admin_approvals.stores.get_approval",
                new=AsyncMock(return_value=row),
            ),
            patch(
                "src.api.routers.admin_approvals.stores.decide_approval_if_pending",
                new=AsyncMock(return_value=decided),
            ),
            patch(
                "src.api.routers.admin_approvals.stores.approve_scan_if_awaiting",
                new=AsyncMock(return_value=fake_scan),
            ) as mock_scan,
            patch(
                "src.api.routers.admin_approvals.record_decision_audit",
                new=AsyncMock(return_value=None),
            ),
            patch("src.policy.scan_queue._dispatch_scan_phase") as mock_dispatch,
        ):
            r = client.post(
                f"{APPROVALS}/{row.id}/decide",
                headers=_ADMIN_HEADERS,
                json={"tenant_id": _TENANT, "approve": True, "reason": "authorized in scope"},
            )
        assert r.status_code == 200, r.text
        # Drives the EXISTING gate: atomic scan transition won → re-dispatched.
        mock_scan.assert_awaited_once()
        mock_dispatch.assert_called_once()
        assert mock_dispatch.call_args.kwargs["scan_id"] == "scan-xyz"

    def test_decide_approve_non_exploitation_does_not_dispatch(self, client: TestClient) -> None:
        factory, session = _session_factory()
        row = _approval_row()  # action="secretsdump"
        decided = _approval_row(status="approved")
        decided.id = row.id
        decided.scan_id = "scan-xyz"
        with (
            patch.object(settings, "admin_api_key", _ADMIN_KEY),
            patch("src.api.routers.admin_approvals.async_session_factory", factory),
            patch(
                "src.api.routers.admin_approvals.stores.get_approval",
                new=AsyncMock(return_value=row),
            ),
            patch(
                "src.api.routers.admin_approvals.stores.decide_approval_if_pending",
                new=AsyncMock(return_value=decided),
            ),
            patch(
                "src.api.routers.admin_approvals.stores.approve_scan_if_awaiting",
                new=AsyncMock(return_value=None),
            ) as mock_scan,
            patch(
                "src.api.routers.admin_approvals.record_decision_audit",
                new=AsyncMock(return_value=None),
            ),
            patch("src.policy.scan_queue._dispatch_scan_phase") as mock_dispatch,
        ):
            r = client.post(
                f"{APPROVALS}/{row.id}/decide",
                headers=_ADMIN_HEADERS,
                json={"tenant_id": _TENANT, "approve": True, "reason": "ok"},
            )
        assert r.status_code == 200
        # Non-exploitation action: the scan-resume path is never consulted.
        mock_scan.assert_not_awaited()
        mock_dispatch.assert_not_called()

    def test_decide_deny_exploitation_does_not_dispatch(self, client: TestClient) -> None:
        factory, _ = _session_factory()
        row = _approval_row()
        decided = _approval_row(status="denied")
        decided.id = row.id
        decided.action = "exploitation"
        decided.scan_id = "scan-xyz"
        with (
            patch.object(settings, "admin_api_key", _ADMIN_KEY),
            patch("src.api.routers.admin_approvals.async_session_factory", factory),
            patch(
                "src.api.routers.admin_approvals.stores.get_approval",
                new=AsyncMock(return_value=row),
            ),
            patch(
                "src.api.routers.admin_approvals.stores.decide_approval_if_pending",
                new=AsyncMock(return_value=decided),
            ),
            patch(
                "src.api.routers.admin_approvals.record_decision_audit",
                new=AsyncMock(return_value=None),
            ),
            patch("src.policy.scan_queue._dispatch_scan_phase") as mock_dispatch,
        ):
            r = client.post(
                f"{APPROVALS}/{row.id}/decide",
                headers=_ADMIN_HEADERS,
                json={"tenant_id": _TENANT, "approve": False, "reason": "out of scope"},
            )
        assert r.status_code == 200
        mock_dispatch.assert_not_called()

    def test_decide_already_decided_returns_409(self, client: TestClient) -> None:
        factory, _ = _session_factory()
        row = _approval_row()  # exists (passes 404), but the atomic decide loses
        with (
            patch.object(settings, "admin_api_key", _ADMIN_KEY),
            patch("src.api.routers.admin_approvals.async_session_factory", factory),
            patch(
                "src.api.routers.admin_approvals.stores.get_approval",
                new=AsyncMock(return_value=row),
            ),
            patch(
                # Atomic conditional UPDATE matched no pending row → race/already decided.
                "src.api.routers.admin_approvals.stores.decide_approval_if_pending",
                new=AsyncMock(return_value=None),
            ),
            patch("src.policy.scan_queue._dispatch_scan_phase") as mock_dispatch,
        ):
            r = client.post(
                f"{APPROVALS}/{row.id}/decide",
                headers=_ADMIN_HEADERS,
                json={"tenant_id": _TENANT, "approve": True, "reason": "retry"},
            )
        assert r.status_code == 409
        mock_dispatch.assert_not_called()

    def test_decide_resume_only_when_awaiting_approval(self, client: TestClient) -> None:
        factory, session = _session_factory()
        row = _approval_row()
        decided = _approval_row(status="approved")
        decided.id = row.id
        decided.action = "exploitation"
        decided.scan_id = "scan-xyz"
        with (
            patch.object(settings, "admin_api_key", _ADMIN_KEY),
            patch("src.api.routers.admin_approvals.async_session_factory", factory),
            patch(
                "src.api.routers.admin_approvals.stores.get_approval",
                new=AsyncMock(return_value=row),
            ),
            patch(
                "src.api.routers.admin_approvals.stores.decide_approval_if_pending",
                new=AsyncMock(return_value=decided),
            ),
            patch(
                # Scan not in awaiting_approval → atomic transition matches nothing.
                "src.api.routers.admin_approvals.stores.approve_scan_if_awaiting",
                new=AsyncMock(return_value=None),
            ),
            patch(
                "src.api.routers.admin_approvals.record_decision_audit",
                new=AsyncMock(return_value=None),
            ),
            patch("src.policy.scan_queue._dispatch_scan_phase") as mock_dispatch,
        ):
            r = client.post(
                f"{APPROVALS}/{row.id}/decide",
                headers=_ADMIN_HEADERS,
                json={"tenant_id": _TENANT, "approve": True, "reason": "authorized"},
            )
        assert r.status_code == 200
        mock_dispatch.assert_not_called()

    def test_decide_requires_reason(self, client: TestClient) -> None:
        factory, _ = _session_factory()
        row = _approval_row()
        with (
            patch.object(settings, "admin_api_key", _ADMIN_KEY),
            patch("src.api.routers.admin_approvals.async_session_factory", factory),
            patch(
                "src.api.routers.admin_approvals.stores.get_approval",
                new=AsyncMock(return_value=row),
            ),
        ):
            r = client.post(
                f"{APPROVALS}/{row.id}/decide",
                headers=_ADMIN_HEADERS,
                json={"tenant_id": _TENANT, "approve": True, "reason": "   "},
            )
        assert r.status_code == 400

    def test_decide_cross_tenant_404(self, client: TestClient) -> None:
        factory, _ = _session_factory()
        row = _approval_row(tenant_id=_TENANT)
        with (
            patch.object(settings, "admin_api_key", _ADMIN_KEY),
            patch("src.api.routers.admin_approvals.async_session_factory", factory),
            patch(
                "src.api.routers.admin_approvals.stores.get_approval",
                new=AsyncMock(return_value=row),
            ),
        ):
            r = client.post(
                f"{APPROVALS}/{row.id}/decide",
                headers=_ADMIN_HEADERS,
                json={"tenant_id": _OTHER_TENANT, "approve": True, "reason": "x"},
            )
        assert r.status_code == 404
