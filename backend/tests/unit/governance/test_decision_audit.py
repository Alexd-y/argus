"""WP D — immutable-audit helper for governance decisions.

``audit_logs.details`` is a Postgres ``JSONB`` column (no SQLite variant), so this
exercises the helper against a mock session and inspects the row it stages — the
same no-live-DB approach used for the bulk-ops audit path.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

from src.db.models import AuditLog
from src.governance.audit import record_decision_audit


def _mock_session():
    session = MagicMock()
    session.add = MagicMock()
    session.flush = AsyncMock()
    return session


async def test_record_decision_audit_stages_immutable_row() -> None:
    session = _mock_session()
    await record_decision_audit(
        session,
        tenant_id="11111111-1111-1111-1111-111111111111",
        user_id="lead@firm",
        action="governance.approval.decided",
        resource_type="approval",
        resource_id="approval-123",
        details={"approve": True, "status": "approved"},
    )
    session.add.assert_called_once()
    row = session.add.call_args[0][0]
    assert isinstance(row, AuditLog)
    assert row.action == "governance.approval.decided"
    assert row.resource_type == "approval"
    assert row.resource_id == "approval-123"
    assert row.details == {"approve": True, "status": "approved"}
    session.flush.assert_awaited_once()


async def test_record_decision_audit_truncates_user_and_resource() -> None:
    session = _mock_session()
    await record_decision_audit(
        session,
        tenant_id="11111111-1111-1111-1111-111111111111",
        user_id="x" * 100,
        action="governance.approval.decided",
        resource_type="approval",
        resource_id="y" * 100,
        details=None,
    )
    row = session.add.call_args[0][0]
    assert len(row.user_id) == 36
    assert len(row.resource_id) == 36


async def test_record_decision_audit_user_id_none_stays_none() -> None:
    session = _mock_session()
    await record_decision_audit(
        session,
        tenant_id="11111111-1111-1111-1111-111111111111",
        user_id=None,
        action="governance.approval.decided",
        resource_type="approval",
        resource_id="r1",
        details=None,
    )
    row = session.add.call_args[0][0]
    assert row.user_id is None
