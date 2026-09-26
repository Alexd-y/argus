"""Phase 14 (generator) — LLM directive pipeline safety gates (requires_postgres)."""

from __future__ import annotations

import json

import pytest
from sqlalchemy import select
from src.cairn import graph_service as gs
from src.cairn.directives.generator import generate_directives
from src.cairn.directives.models import CairnDirective
from src.cairn.directives.schemas import DirectiveFocus, FocusType, Intrusiveness
from src.db.session import set_session_tenant

from .conftest import skip_without_pg

pytestmark = [pytest.mark.requires_postgres, skip_without_pg]

_BATCH = {
    "directives": [
        {
            "kind": "service_deep_dive",
            "title": "Zoom in on Tomcat",
            "directive_text": "Focus on Tomcat; validate CVEs with a working PoC. Take your time.",
            "focus": {"type": "service", "value": "Tomcat"},
            "success_criterion": "A working PoC executes a command on the target.",
            "proof_requirement": "command_execution",
            "intrusiveness": "active_intrusive",
            "priority_score": 0.9,
        },
        {
            "kind": "broad_recon_goal",
            "title": "Attack evil.test",
            "directive_text": "Pivot to evil.test and enumerate.",
            "focus": {"type": "host", "value": "evil.test"},
            "success_criterion": "Enumerate hosts.",
            "proof_requirement": "tool_output",
            "intrusiveness": "active_safe",
            "priority_score": 0.5,
        },
    ]
}


async def _make_project(sm, tenant_id) -> str:
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        detail = await gs.create_project(
            s, tenant_id, title="p", origin="http://ok.test", goal="rce"
        )
        return detail.project.id


async def test_generate_clamps_intrusiveness_and_drops_out_of_scope(sm, tenant_id) -> None:
    pid = await _make_project(sm, tenant_id)

    async def _llm(system, user):
        return json.dumps(_BATCH)

    def _scope_check(focus: DirectiveFocus) -> bool:
        return focus.value.strip().lower() in ("ok.test",)

    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        directives = await generate_directives(
            s,
            tenant_id,
            pid,
            context={"target": "ok.test"},
            execution_mode="production",  # caps at active_safe
            has_target_lease=False,
            llm_caller=_llm,
            scope_check=_scope_check,
        )
    # evil.test host directive dropped (out of scope); Tomcat service kept.
    assert len(directives) == 1
    kept = directives[0]
    assert kept.ref == "d001"
    assert kept.kind == "service_deep_dive"
    # active_intrusive requested in production -> clamped to active_safe
    assert kept.intrusiveness == Intrusiveness.ACTIVE_SAFE.value
    assert 0.0 <= kept.priority_score <= 1.0


async def test_generate_dedupes_same_focus(sm, tenant_id) -> None:
    pid = await _make_project(sm, tenant_id)
    dup = {
        "directives": [
            {
                "kind": "service_deep_dive",
                "title": "a",
                "directive_text": "x",
                "focus": {"type": "service", "value": "nginx"},
                "success_criterion": "poc",
                "proof_requirement": "tool_output",
                "intrusiveness": "active_safe",
                "priority_score": 0.5,
            },
            {
                "kind": "service_deep_dive",
                "title": "b",
                "directive_text": "y",
                "focus": {"type": "service", "value": "Nginx"},
                "success_criterion": "poc",
                "proof_requirement": "tool_output",
                "intrusiveness": "active_safe",
                "priority_score": 0.4,
            },
        ]
    }

    async def _llm(system, user):
        return json.dumps(dup)

    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        directives = await generate_directives(
            s,
            tenant_id,
            pid,
            context={},
            execution_mode="production",
            has_target_lease=False,
            llm_caller=_llm,
        )
    assert len(directives) == 1  # nginx == Nginx deduped

    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        rows = (
            (await s.execute(select(CairnDirective).where(CairnDirective.project_id == pid)))
            .scalars()
            .all()
        )
    assert len(rows) == 1
    assert rows[0].focus["type"] == FocusType.SERVICE.value
