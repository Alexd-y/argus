"""WP D — the governance scope gate is wired into the scan entrypoint.

Validates the call site in ``run_scan_state_machine`` without running the
pipeline: an out-of-scope governance engagement denies *before* any subsystem is
initialized; an in-scope (or absent) engagement lets the scan proceed.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool
from src.db.models import ApprovalRecord, Base, EngagementRecord, LLMRotationState
from src.governance import stores
from src.governance.engagement import ScopeViolation
from src.orchestration import state_machine

_TABLES = [LLMRotationState.__table__, EngagementRecord.__table__, ApprovalRecord.__table__]
_TENANT = "11111111-1111-1111-1111-111111111111"


class _StopAfterGate(RuntimeError):
    """Sentinel raised by the patched subsystem init to prove the gate let us pass."""


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


async def _engagement(session):
    now = datetime.now(UTC)
    return await stores.create_engagement(
        session,
        tenant_id=_TENANT,
        allowed_targets=["victim.example.com"],
        allowed_tenants=[_TENANT],
        allowed_actions=["scan"],
        window_start=now - timedelta(hours=1),
        window_end=now + timedelta(hours=1),
    )


async def test_out_of_scope_denies_before_subsystem_init(session) -> None:
    row = await _engagement(session)
    init = AsyncMock(side_effect=_StopAfterGate)
    with (
        patch.object(state_machine, "_init_scan_subsystems", init),
        pytest.raises(ScopeViolation),
    ):
        await state_machine.run_scan_state_machine(
            session,
            "scan-1",
            _TENANT,
            "https://evil.example.net",  # out of scope
            {"governance_engagement_id": row.id},
        )
    init.assert_not_awaited()  # denied up front — the pipeline never started


async def test_in_scope_passes_gate_and_proceeds(session) -> None:
    row = await _engagement(session)
    init = AsyncMock(side_effect=_StopAfterGate)
    with (
        patch.object(state_machine, "_init_scan_subsystems", init),
        pytest.raises(_StopAfterGate),
    ):
        await state_machine.run_scan_state_machine(
            session,
            "scan-2",
            _TENANT,
            "https://victim.example.com/app",  # in scope
            {"governance_engagement_id": row.id},
        )
    init.assert_awaited_once()  # gate allowed → reached subsystem init


async def test_absent_governance_id_is_inert(session) -> None:
    init = AsyncMock(side_effect=_StopAfterGate)
    with (
        patch.object(state_machine, "_init_scan_subsystems", init),
        pytest.raises(_StopAfterGate),
    ):
        await state_machine.run_scan_state_machine(
            session,
            "scan-3",
            _TENANT,
            "https://anything.example.net",
            {},  # no governance engagement attached → gate inert
        )
    init.assert_awaited_once()


async def test_disabled_flag_skips_gate(session) -> None:
    row = await _engagement(session)
    init = AsyncMock(side_effect=_StopAfterGate)
    with (
        patch.object(state_machine.settings, "governance_scope_enforcement_enabled", False),
        patch.object(state_machine, "_init_scan_subsystems", init),
        pytest.raises(_StopAfterGate),
    ):
        await state_machine.run_scan_state_machine(
            session,
            "scan-4",
            _TENANT,
            "https://evil.example.net",  # would be denied, but gate is off
            {"governance_engagement_id": row.id},
        )
    init.assert_awaited_once()
