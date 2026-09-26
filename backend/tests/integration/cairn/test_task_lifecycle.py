"""Phase 8 — worker-task lifecycle applied to the graph (requires_postgres).

Uses a mock driver (no LLM/Docker) to exercise run_worker_task end-to-end at the
graph level: reason→intents, explore→fact, bootstrap→complete, and the
conclude-fallback path when the first response is unparseable.
"""

from __future__ import annotations

import pytest
from src.cairn import graph_service as gs
from src.cairn.tasks import run_worker_task
from src.cairn.workers.base import CairnTaskContext, DriverResult
from src.cairn.workers.health import HealthResult
from src.db.session import set_session_tenant

from .conftest import skip_without_pg

pytestmark = [pytest.mark.requires_postgres, skip_without_pg]


class MockCairnDriver:
    """Deterministic driver: returns canned text for execute / conclude."""

    type_name = "mock"

    def __init__(self, execute_text: str, conclude_text: str = "") -> None:
        self._execute_text = execute_text
        self._conclude_text = conclude_text

    def supports_conclude(self) -> bool:
        return True

    def local_binary(self):
        return None

    async def prepare_session(self):
        return "mock-session"

    async def check_health(self, worker, *, timeout):
        return HealthResult(ok=True, status=200, detail="")

    def describe_health(self, worker):
        return "mock"

    async def execute(self, ctx, prompt, session):
        return DriverResult(text=self._execute_text, session=session or "mock-session")

    async def conclude(self, ctx, prompt, session):
        return DriverResult(text=self._conclude_text, session=session)

    def extract_session(self, session, stdout, stderr):
        return session

    def extract_response_text(self, stdout, stderr):
        return stdout


def _ctx(tenant_id: str, project_id: str, task_type: str) -> CairnTaskContext:
    return CairnTaskContext(tenant_id=tenant_id, project_id=project_id, task_type=task_type)


async def test_reason_creates_intents(sm, tenant_id) -> None:
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        detail = await gs.create_project(s, tenant_id, title="p", origin="o", goal="g")
        pid = detail.project.id

    driver = MockCairnDriver(
        '{"accepted": true, "data": {"intents": [{"from": ["origin"], "description": "probe port 8080"}]}}'
    )
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        outcome = await run_worker_task(
            s,
            tenant_id,
            pid,
            task_type="reason",
            worker="w1",
            driver=driver,
            ctx=_ctx(tenant_id, pid, "reason"),
            prompt="reason",
            conclude_prompt="conclude",
            open_intents_empty=True,
        )
    assert outcome == "success"
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        detail = await gs.get_project(s, tenant_id, pid)
        assert any(i.description == "probe port 8080" for i in detail.intents)


async def test_explore_concludes_intent(sm, tenant_id) -> None:
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        detail = await gs.create_project(s, tenant_id, title="p", origin="o", goal="g")
        pid = detail.project.id
        intent = await gs.create_intent(
            s,
            tenant_id,
            pid,
            from_refs=["origin"],
            description="explore",
            creator="w1",
            worker="w1",
        )
        iid = intent.id

    driver = MockCairnDriver('{"accepted": true, "data": {"description": "found tomcat 9"}}')
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        outcome = await run_worker_task(
            s,
            tenant_id,
            pid,
            task_type="explore",
            worker="w1",
            driver=driver,
            ctx=_ctx(tenant_id, pid, "explore"),
            prompt="explore",
            conclude_prompt="conclude",
            intent_id=iid,
        )
    assert outcome == "success"
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        detail = await gs.get_project(s, tenant_id, pid)
        concluded = [i for i in detail.intents if i.id == iid][0]
        assert concluded.concluded_at is not None
        assert any(f.description == "found tomcat 9" for f in detail.facts)


async def test_bootstrap_completes_project(sm, tenant_id) -> None:
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        detail = await gs.create_project(s, tenant_id, title="p", origin="o", goal="g")
        pid = detail.project.id
        boot = await gs.create_intent(
            s,
            tenant_id,
            pid,
            from_refs=["origin"],
            description="bootstrap",
            creator="dispatcher.bootstrap",
        )
        bid = boot.id

    driver = MockCairnDriver(
        '{"accepted": true, "data": {"fact": {"description": "got shell"}, "complete": {"description": "RCE proven"}}}'
    )
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        outcome = await run_worker_task(
            s,
            tenant_id,
            pid,
            task_type="bootstrap",
            worker="w1",
            driver=driver,
            ctx=_ctx(tenant_id, pid, "bootstrap"),
            prompt="bootstrap",
            conclude_prompt="conclude",
            bootstrap_intent_id=bid,
        )
    assert outcome == "success"
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        detail = await gs.get_project(s, tenant_id, pid)
        assert detail.project.status == "completed"


async def test_conclude_fallback_on_unparseable(sm, tenant_id) -> None:
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        detail = await gs.create_project(s, tenant_id, title="p", origin="o", goal="g")
        pid = detail.project.id
        intent = await gs.create_intent(
            s,
            tenant_id,
            pid,
            from_refs=["origin"],
            description="explore",
            creator="w1",
            worker="w1",
        )
        iid = intent.id

    # execute returns garbage; conclude salvages a fact.
    driver = MockCairnDriver(
        "the model rambled and produced no json at all",
        conclude_text='{"accepted": true, "data": {"description": "salvaged: port 4000 open"}}',
    )
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        outcome = await run_worker_task(
            s,
            tenant_id,
            pid,
            task_type="explore",
            worker="w1",
            driver=driver,
            ctx=_ctx(tenant_id, pid, "explore"),
            prompt="explore",
            conclude_prompt="conclude",
            intent_id=iid,
            session_id="s1",
        )
    assert outcome == "success"
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        detail = await gs.get_project(s, tenant_id, pid)
        assert any("salvaged" in f.description for f in detail.facts)


async def test_unhealthy_when_driver_raises(sm, tenant_id) -> None:
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        detail = await gs.create_project(s, tenant_id, title="p", origin="o", goal="g")
        pid = detail.project.id

    class _Raising(MockCairnDriver):
        async def execute(self, ctx, prompt, session):
            raise RuntimeError("WRB unavailable")

    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        outcome = await run_worker_task(
            s,
            tenant_id,
            pid,
            task_type="reason",
            worker="w1",
            driver=_Raising(""),
            ctx=_ctx(tenant_id, pid, "reason"),
            prompt="reason",
            conclude_prompt="conclude",
            open_intents_empty=True,
        )
    assert outcome == "unhealthy"
