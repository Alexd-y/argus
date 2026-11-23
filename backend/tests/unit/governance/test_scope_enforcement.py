"""WP D — fail-closed governance scope enforcement for the scan pipeline.

The gate is **no-op when no governance engagement is attached** (so existing
scans — which only carry the unrelated recon-campaign ``engagement_id`` — are
unchanged) and **fail-closed when one is**: an unknown id, a cross-tenant id, a
revoked engagement, or an out-of-scope target/action all deny.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool
from src.db.models import ApprovalRecord, Base, EngagementRecord, LLMRotationState
from src.governance import stores
from src.governance.engagement import ScopeViolation
from src.governance.scope_enforcement import enforce_engagement_scope

_TABLES = [LLMRotationState.__table__, EngagementRecord.__table__, ApprovalRecord.__table__]
_T1 = "11111111-1111-1111-1111-111111111111"
_T2 = "22222222-2222-2222-2222-222222222222"


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


async def _make_engagement(session, *, tenant=_T1, revoked=False):
    now = datetime.now(UTC)
    row = await stores.create_engagement(
        session,
        tenant_id=tenant,
        allowed_targets=["victim.example.com"],
        allowed_tenants=[tenant],
        allowed_actions=["scan", "recon"],
        window_start=now - timedelta(hours=1),
        window_end=now + timedelta(hours=1),
    )
    if revoked:
        await stores.revoke_engagement(session, row.id)
    return row


async def test_no_governance_engagement_is_noop(session) -> None:
    # Absent id → unchanged behavior, even for a target no engagement would allow.
    assert (
        await enforce_engagement_scope(
            session,
            governance_engagement_id=None,
            tenant_id=_T1,
            target="https://anything.example.net",
            action="scan",
        )
        is None
    )
    assert (
        await enforce_engagement_scope(
            session,
            governance_engagement_id="",
            tenant_id=_T1,
            target="https://anything.example.net",
            action="scan",
        )
        is None
    )


async def test_in_scope_passes(session) -> None:
    row = await _make_engagement(session)
    assert (
        await enforce_engagement_scope(
            session,
            governance_engagement_id=row.id,
            tenant_id=_T1,
            target="https://victim.example.com/app",
            action="scan",
        )
        is None
    )


async def test_unknown_id_denies_fail_closed(session) -> None:
    with pytest.raises(ScopeViolation):
        await enforce_engagement_scope(
            session,
            governance_engagement_id="does-not-exist",
            tenant_id=_T1,
            target="https://victim.example.com",
            action="scan",
        )


async def test_cross_tenant_id_denies(session) -> None:
    row = await _make_engagement(session, tenant=_T1)
    with pytest.raises(ScopeViolation):
        await enforce_engagement_scope(
            session,
            governance_engagement_id=row.id,
            tenant_id=_T2,
            target="https://victim.example.com",
            action="scan",
        )


async def test_out_of_scope_target_denies(session) -> None:
    row = await _make_engagement(session)
    with pytest.raises(ScopeViolation):
        await enforce_engagement_scope(
            session,
            governance_engagement_id=row.id,
            tenant_id=_T1,
            target="https://evil.example.net",
            action="scan",
        )


async def test_out_of_scope_action_denies(session) -> None:
    row = await _make_engagement(session)
    with pytest.raises(ScopeViolation):
        await enforce_engagement_scope(
            session,
            governance_engagement_id=row.id,
            tenant_id=_T1,
            target="https://victim.example.com",
            action="exploit",
        )


async def test_revoked_denies(session) -> None:
    row = await _make_engagement(session, revoked=True)
    with pytest.raises(ScopeViolation):
        await enforce_engagement_scope(
            session,
            governance_engagement_id=row.id,
            tenant_id=_T1,
            target="https://victim.example.com",
            action="scan",
        )
