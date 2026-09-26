"""Phase 2 — graph service protocol invariants (requires_postgres).

One test per row of the invariant table in §4.2 of the integration prompt, ported
from ``_external/Cairn/cairn/tests/test_server_api.py``.
"""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from src.cairn import graph_service as gs
from src.cairn.errors import (
    CairnConflictError,
    CairnForbiddenError,
    CairnNotFoundError,
    CairnValidationError,
)
from src.db.session import set_session_tenant

from .conftest import skip_without_pg

pytestmark = [pytest.mark.requires_postgres, skip_without_pg]


async def _new_project(sm: async_sessionmaker[AsyncSession], tenant_id: str, **kwargs) -> str:
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        detail = await gs.create_project(
            s,
            tenant_id,
            title=kwargs.pop("title", "t"),
            origin=kwargs.pop("origin", "start here"),
            goal=kwargs.pop("goal", "reach goal"),
            **kwargs,
        )
        return detail.project.id


async def test_create_project_seeds_origin_and_goal(sm, tenant_id) -> None:
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        detail = await gs.create_project(
            s, tenant_id, title="p", origin="o", goal="g", hints=[("look here", "human")]
        )
        assert detail.project.ref == "proj_001"
        refs = {f.ref for f in detail.facts}
        assert refs == {"origin", "goal"}
        assert detail.project.origin_fact_id is not None
        assert detail.project.goal_fact_id is not None
        assert len(detail.hints) == 1
        assert detail.hints[0].ref == "h001"


async def test_fact_from_must_exist_404(sm, tenant_id) -> None:
    pid = await _new_project(sm, tenant_id)
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        with pytest.raises(CairnNotFoundError, match="Fact f999 not found"):
            await gs.create_intent(
                s, tenant_id, pid, from_refs=["f999"], description="d", creator="w1"
            )


async def test_goal_cannot_be_in_from_400(sm, tenant_id) -> None:
    pid = await _new_project(sm, tenant_id)
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        with pytest.raises(CairnValidationError, match="goal cannot be used in from"):
            await gs.create_intent(
                s, tenant_id, pid, from_refs=["goal"], description="d", creator="w1"
            )


async def test_intent_worker_must_equal_creator_400(sm, tenant_id) -> None:
    pid = await _new_project(sm, tenant_id)
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        with pytest.raises(CairnValidationError, match="worker must be null or equal"):
            await gs.create_intent(
                s,
                tenant_id,
                pid,
                from_refs=["origin"],
                description="d",
                creator="w1",
                worker="w2",
            )


async def test_claim_conflict_when_held_by_another_worker_409(sm, tenant_id) -> None:
    pid = await _new_project(sm, tenant_id)
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        intent = await gs.create_intent(
            s, tenant_id, pid, from_refs=["origin"], description="d", creator="w1"
        )
        iid = intent.id
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        await gs.claim_intent(s, tenant_id, pid, iid, "w1")
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        with pytest.raises(CairnConflictError, match="currently claimed by w1"):
            await gs.claim_intent(s, tenant_id, pid, iid, "w2")


async def test_conclude_closes_intent_and_makes_fact(sm, tenant_id) -> None:
    pid = await _new_project(sm, tenant_id)
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        intent = await gs.create_intent(
            s, tenant_id, pid, from_refs=["origin"], description="d", creator="w1", worker="w1"
        )
        iid = intent.id
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        result = await gs.conclude_intent(s, tenant_id, pid, iid, "w1", "found X")
        assert result.fact.ref == "f001"
        assert result.intent.to_fact_id == result.fact.id
        assert result.intent.concluded_at is not None
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        with pytest.raises(CairnConflictError, match="already concluded"):
            await gs.conclude_intent(s, tenant_id, pid, iid, "w1", "again")


async def test_release_is_idempotent_when_free(sm, tenant_id) -> None:
    pid = await _new_project(sm, tenant_id)
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        intent = await gs.create_intent(
            s, tenant_id, pid, from_refs=["origin"], description="d", creator="w1"
        )
        iid = intent.id
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        released = await gs.release_intent(s, tenant_id, pid, iid, "w1")
        assert released.worker is None


async def test_reason_lease_conflict_and_heartbeat(sm, tenant_id) -> None:
    pid = await _new_project(sm, tenant_id)
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        await gs.claim_reason(s, tenant_id, pid, "w1", "initial")
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        with pytest.raises(CairnConflictError, match="currently claimed by w1"):
            await gs.claim_reason(s, tenant_id, pid, "w2", "initial")
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        # idempotent re-claim by same worker
        proj = await gs.claim_reason(s, tenant_id, pid, "w1", "initial")
        assert proj.reason_worker == "w1"


async def test_reason_heartbeat_without_lease_409(sm, tenant_id) -> None:
    pid = await _new_project(sm, tenant_id)
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        with pytest.raises(CairnConflictError, match="not currently claimed"):
            await gs.heartbeat_reason(s, tenant_id, pid, "w1")


async def test_complete_sets_status_and_clears_reason(sm, tenant_id) -> None:
    pid = await _new_project(sm, tenant_id)
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        await gs.claim_reason(s, tenant_id, pid, "w1", "initial")
        intent = await gs.complete_project(
            s, tenant_id, pid, from_refs=["origin"], description="done", worker="w1"
        )
        assert intent.is_completion is True
        assert intent.concluded_at is not None
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        detail = await gs.get_project(s, tenant_id, pid)
        assert detail.project.status == "completed"
        assert detail.project.reason_worker is None


async def test_completed_cannot_change_status_409(sm, tenant_id) -> None:
    pid = await _new_project(sm, tenant_id)
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        await gs.complete_project(
            s, tenant_id, pid, from_refs=["origin"], description="done", worker="w1"
        )
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        with pytest.raises(CairnConflictError, match="Completed projects cannot"):
            await gs.update_project_status(s, tenant_id, pid, "active")


async def test_stopped_clears_workers_and_reason(sm, tenant_id) -> None:
    pid = await _new_project(sm, tenant_id)
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        intent = await gs.create_intent(
            s, tenant_id, pid, from_refs=["origin"], description="d", creator="w1", worker="w1"
        )
        iid = intent.id
        await gs.claim_reason(s, tenant_id, pid, "w1", "initial")
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        await gs.update_project_status(s, tenant_id, pid, "stopped")
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        detail = await gs.get_project(s, tenant_id, pid)
        assert detail.project.reason_worker is None
        matching = [i for i in detail.intents if i.id == iid]
        assert matching and matching[0].worker is None


async def test_hint_writable_in_completed_status(sm, tenant_id) -> None:
    pid = await _new_project(sm, tenant_id)
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        await gs.complete_project(
            s, tenant_id, pid, from_refs=["origin"], description="done", worker="w1"
        )
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        hint = await gs.create_hint(s, tenant_id, pid, content="new idea", creator="human")
        assert hint.ref == "h001"


async def test_create_intent_forbidden_when_not_active(sm, tenant_id) -> None:
    pid = await _new_project(sm, tenant_id)
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        await gs.update_project_status(s, tenant_id, pid, "stopped")
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        with pytest.raises(CairnForbiddenError, match="Project is stopped"):
            await gs.create_intent(
                s, tenant_id, pid, from_refs=["origin"], description="d", creator="w1"
            )


async def test_reopen_from_completed(sm, tenant_id) -> None:
    pid = await _new_project(sm, tenant_id)
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        await gs.complete_project(
            s, tenant_id, pid, from_refs=["origin"], description="done", worker="w1"
        )
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        result = await gs.reopen_project(
            s, tenant_id, pid, description="client says retest", creator="human"
        )
        assert result.project.status == "active"
        assert result.intent.description == "external_feedback"
        assert result.fact.description == "client says retest"


async def test_reopen_requires_completed_403(sm, tenant_id) -> None:
    pid = await _new_project(sm, tenant_id)
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        with pytest.raises(CairnForbiddenError):
            await gs.reopen_project(s, tenant_id, pid, description="x", creator="human")


async def test_settings_reject_timeout_below_5(sm, tenant_id) -> None:
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        with pytest.raises(CairnValidationError, match="intent_timeout must be >= 5"):
            await gs.update_settings(s, tenant_id, intent_timeout=1)
