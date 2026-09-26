"""Phase 12 — mock end-to-end cycle (requires_postgres, no network/Docker).

Drives a project through the real components — task-selection decisions + the
worker-task lifecycle + the graph service — using a deterministic mock driver, from
creation to ``completed``. This is the ARGUS analogue of upstream
``test_mock_end_to_end.py``.
"""

from __future__ import annotations

import pytest
from src.cairn import graph_service as gs
from src.cairn.scheduler.decisions import (
    IntentSnapshot,
    ProjectDispatchState,
    ReasonCheckpoint,
    select_task_for_project,
)
from src.cairn.tasks import run_worker_task
from src.cairn.workers.base import CairnTaskContext, DriverResult
from src.cairn.workers.health import HealthResult
from src.db.session import set_session_tenant

from .conftest import skip_without_pg

pytestmark = [pytest.mark.requires_postgres, skip_without_pg]


class _MockDriver:
    type_name = "mock"

    def __init__(self, text: str) -> None:
        self._text = text

    def supports_conclude(self) -> bool:
        return True

    def local_binary(self):
        return None

    async def prepare_session(self):
        return "s"

    async def check_health(self, worker, *, timeout):
        return HealthResult(ok=True, status=200, detail="")

    def describe_health(self, worker):
        return "mock"

    async def execute(self, ctx, prompt, session):
        return DriverResult(text=self._text, session=session or "s")

    async def conclude(self, ctx, prompt, session):
        return DriverResult(text=self._text, session=session)

    def extract_session(self, session, stdout, stderr):
        return session

    def extract_response_text(self, stdout, stderr):
        return stdout


def _ctx(t, p, task_type):
    return CairnTaskContext(tenant_id=t, project_id=p, task_type=task_type)


async def _snapshot(sm, tenant_id, pid) -> ProjectDispatchState:
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        detail = await gs.get_project(s, tenant_id, pid)
    fact_refs = [f.ref for f in detail.facts]
    open_intents = [
        IntentSnapshot(i.ref, i.worker, i.description == "bootstrap", i.created_at)
        for i in detail.intents
        if i.concluded_at is None
    ]
    return ProjectDispatchState(
        status=detail.project.status,
        fact_refs=fact_refs,
        open_intents=open_intents,
        bootstrap_enabled=detail.project.bootstrap_enabled,
        reason_worker=detail.project.reason_worker,
        hint_count=len(detail.hints),
        running_task_count=0,
        max_project_workers=4,
        fact_count=len(fact_refs),
        checkpoint=ReasonCheckpoint(len(fact_refs), len(detail.hints), len(open_intents)),
    )


async def test_reason_explore_complete_cycle(sm, tenant_id) -> None:
    # 1. create project
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        detail = await gs.create_project(
            s, tenant_id, title="e2e", origin="http://t", goal="prove RCE", bootstrap_enabled=False
        )
        pid = detail.project.id

    # 2. dispatcher sees an initial project with bootstrap disabled → reason
    state = await _snapshot(sm, tenant_id, pid)
    decision = select_task_for_project(state, worker_supports_bootstrap=False)
    assert decision.kind == "reason"

    # 3. reason proposes one intent
    reason_driver = _MockDriver(
        '{"accepted": true, "data": {"intents": [{"from": ["origin"], "description": "probe tomcat"}]}}'
    )
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        out = await run_worker_task(
            s,
            tenant_id,
            pid,
            task_type="reason",
            worker="w1",
            driver=reason_driver,
            ctx=_ctx(tenant_id, pid, "reason"),
            prompt="p",
            conclude_prompt="c",
            open_intents_empty=True,
        )
    assert out == "success"

    # 4. dispatcher now selects explore on the new intent
    state = await _snapshot(sm, tenant_id, pid)
    decision = select_task_for_project(state, worker_supports_bootstrap=False)
    assert decision.kind == "explore"
    intent_ref = decision.intent_ref
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        detail = await gs.get_project(s, tenant_id, pid)
        intent = next(i for i in detail.intents if i.ref == intent_ref)
        iid = intent.id

    # 5. explore concludes with a fact
    explore_driver = _MockDriver(
        '{"accepted": true, "data": {"description": "tomcat 9 CVE-2026-1 confirmed"}}'
    )
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        out = await run_worker_task(
            s,
            tenant_id,
            pid,
            task_type="explore",
            worker="w2",
            driver=explore_driver,
            ctx=_ctx(tenant_id, pid, "explore"),
            prompt="p",
            conclude_prompt="c",
            intent_id=iid,
        )
    assert out == "success"

    # 6. reason now sees the new fact and completes the project
    complete_driver = _MockDriver(
        '{"accepted": true, "data": {"complete": {"from": ["f001"], "description": "RCE proven via CVE"}}}'
    )
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        out = await run_worker_task(
            s,
            tenant_id,
            pid,
            task_type="reason",
            worker="w1",
            driver=complete_driver,
            ctx=_ctx(tenant_id, pid, "reason"),
            prompt="p",
            conclude_prompt="c",
            open_intents_empty=False,
        )
    assert out == "success"

    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        detail = await gs.get_project(s, tenant_id, pid)
    assert detail.project.status == "completed"
    assert any(i.is_completion for i in detail.intents)
