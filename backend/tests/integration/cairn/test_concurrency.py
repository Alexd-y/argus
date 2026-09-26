"""Phase 2 — concurrency invariants (requires_postgres, §4.3).

Cairn upstream relies on a single-writer dispatcher; ARGUS is distributed, so
these prove Postgres row locks + fence tokens keep the graph consistent:
  * N coroutines racing to claim one intent → exactly one wins, the rest get 409;
  * N coroutines racing for the reason-lease → exactly one wins;
  * a conclude carrying a stale fence token is rejected.
"""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from src.cairn import graph_service as gs
from src.cairn.errors import CairnConflictError
from src.db.session import set_session_tenant

from .conftest import skip_without_pg

pytestmark = [pytest.mark.requires_postgres, skip_without_pg]


async def _create_project_with_open_intent(
    sm: async_sessionmaker[AsyncSession], tenant_id: str
) -> tuple[str, str]:
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        detail = await gs.create_project(s, tenant_id, title="race", origin="o", goal="g")
        pid = detail.project.id
        intent = await gs.create_intent(
            s, tenant_id, pid, from_refs=["origin"], description="d", creator="w0"
        )
        return pid, intent.id


async def test_claim_race_single_winner(sm, tenant_id) -> None:
    pid, iid = await _create_project_with_open_intent(sm, tenant_id)

    async def _claim(worker: str) -> bool:
        try:
            async with sm() as s, s.begin():
                await set_session_tenant(s, tenant_id)
                await gs.claim_intent(s, tenant_id, pid, iid, worker)
            return True
        except CairnConflictError:
            return False

    results = await asyncio.gather(*[_claim(f"w{i}") for i in range(20)])
    assert sum(1 for ok in results if ok) == 1


async def test_reason_race_single_winner(sm, tenant_id) -> None:
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        detail = await gs.create_project(s, tenant_id, title="race", origin="o", goal="g")
        pid = detail.project.id

    async def _claim(worker: str) -> bool:
        try:
            async with sm() as s, s.begin():
                await set_session_tenant(s, tenant_id)
                await gs.claim_reason(s, tenant_id, pid, worker, "initial")
            return True
        except CairnConflictError:
            return False

    results = await asyncio.gather(*[_claim(f"w{i}") for i in range(20)])
    assert sum(1 for ok in results if ok) == 1


async def test_stale_fence_token_conclude_rejected(sm, tenant_id) -> None:
    pid, iid = await _create_project_with_open_intent(sm, tenant_id)
    # First worker claims — token becomes 1.
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        claimed = await gs.claim_intent(s, tenant_id, pid, iid, "w1")
        stale_token = claimed.fence_token - 1  # a token from before the claim
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        with pytest.raises(CairnConflictError, match="Stale fence token"):
            await gs.conclude_intent(s, tenant_id, pid, iid, "w1", "x", fence_token=stale_token)
