"""WP C/D — async DAOs for rotation / engagements / approvals (in-memory SQLite).

Offline (unit/): a self-contained async SQLite engine creates only the three new
tables (FKs stay unchecked without the PRAGMA), so the DAO logic is exercised without
Postgres.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool
from src.db.models import ApprovalRecord, Base, EngagementRecord, LLMRotationState
from src.governance import stores
from src.governance.engagement import ScopeViolation, assert_in_scope
from src.llm.rotation import LLMRotation

_TABLES = [LLMRotationState.__table__, EngagementRecord.__table__, ApprovalRecord.__table__]


@pytest.fixture
async def session():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(lambda c: Base.metadata.create_all(c, tables=_TABLES))
    sm = async_sessionmaker(engine, expire_on_commit=False)
    async with sm() as s:
        yield s
    await engine.dispose()


async def test_rotation_cursor_roundtrips(session) -> None:
    rot = LLMRotation(["A", "B", "C"])
    assert rot.advance() == "A"  # cursor now 1
    await stores.save_rotation(session, tenant_id="t1", role="report", rotation=rot)
    loaded = await stores.load_rotation(session, tenant_id="t1", role="report")
    assert loaded is not None
    assert loaded.advance() == "B"  # resumed from the persisted cursor


async def test_rotation_upsert_overwrites(session) -> None:
    rot = LLMRotation(["A", "B"])
    await stores.save_rotation(session, tenant_id="t1", role="report", rotation=rot)
    rot.advance()
    rot.advance()  # cursor 2
    await stores.save_rotation(session, tenant_id="t1", role="report", rotation=rot)
    loaded = await stores.load_rotation(session, tenant_id="t1", role="report")
    assert loaded.cursor == 2


async def test_rotation_absent_is_none(session) -> None:
    assert await stores.load_rotation(session, tenant_id="t1", role="nope") is None


async def test_engagement_create_feeds_fail_closed_gate(session) -> None:
    now = datetime.now(UTC)
    row = await stores.create_engagement(
        session,
        tenant_id="t1",
        allowed_targets=["victim.example.com"],
        allowed_tenants=["t1"],
        allowed_actions=["recon"],
        window_start=now - timedelta(hours=1),
        window_end=now + timedelta(hours=1),
    )
    eng = stores.engagement_row_to_dataclass(row)
    assert assert_in_scope("https://victim.example.com", "recon", eng, now=now) is None
    with pytest.raises(ScopeViolation):
        assert_in_scope("https://evil.example.net", "recon", eng, now=now)


async def test_engagement_revoke_is_denied_by_gate(session) -> None:
    now = datetime.now(UTC)
    row = await stores.create_engagement(
        session,
        tenant_id="t1",
        allowed_targets=["x.example.com"],
        allowed_tenants=["t1"],
        allowed_actions=["recon"],
    )
    await stores.revoke_engagement(session, row.id)
    eng = stores.engagement_row_to_dataclass(await stores.get_engagement(session, row.id))
    with pytest.raises(ScopeViolation):
        assert_in_scope("https://x.example.com", "recon", eng, now=now)


async def test_approval_enqueue_is_pending_then_approved(session) -> None:
    row = await stores.enqueue_approval(
        session, tenant_id="t1", action="secretsdump", target="dc01"
    )
    assert row.status == "pending"
    decided = await stores.decide_approval(
        session, approval_id=row.id, approve=True, decided_by="lead@firm", reason="in scope"
    )
    assert decided.status == "approved"
    assert await stores.list_approvals(session, tenant_id="t1", status="pending") == []


async def test_approval_decision_requires_reason(session) -> None:
    row = await stores.enqueue_approval(session, tenant_id="t1", action="delete", target="db")
    with pytest.raises(ValueError):
        await stores.decide_approval(
            session, approval_id=row.id, approve=True, decided_by="lead@firm", reason=""
        )


async def test_enqueue_approval_once_is_idempotent(session) -> None:
    first = await stores.enqueue_approval_once(
        session, tenant_id="t1", action="exploitation", target="h", scan_id="scan-1"
    )
    second = await stores.enqueue_approval_once(
        session, tenant_id="t1", action="exploitation", target="h", scan_id="scan-1"
    )
    assert first.id == second.id  # no duplicate pending row
    pending = await stores.list_approvals(session, tenant_id="t1", status="pending")
    assert len([r for r in pending if r.scan_id == "scan-1"]) == 1


async def test_enqueue_approval_once_requeues_after_decided(session) -> None:
    first = await stores.enqueue_approval_once(
        session, tenant_id="t1", action="exploitation", target="h", scan_id="scan-2"
    )
    await stores.decide_approval(
        session, approval_id=first.id, approve=False, decided_by="lead", reason="out of scope"
    )
    # The prior row is no longer pending → a new pending row may be enqueued.
    again = await stores.enqueue_approval_once(
        session, tenant_id="t1", action="exploitation", target="h", scan_id="scan-2"
    )
    assert again.id != first.id
    assert again.status == "pending"
