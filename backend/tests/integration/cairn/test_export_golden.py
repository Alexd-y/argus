"""Phase 3 — export golden structure (requires_postgres).

Builds a small graph via the service and checks the YAML snapshot and timeline
render the expected structure (upstream form), independent of local timestamps.
"""

from __future__ import annotations

import pytest
import yaml
from src.cairn import graph_service as gs
from src.cairn.export import export_timeline, export_yaml
from src.db.session import set_session_tenant

from .conftest import skip_without_pg

pytestmark = [pytest.mark.requires_postgres, skip_without_pg]


async def _build_graph(sm, tenant_id: str) -> str:
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        detail = await gs.create_project(
            s,
            tenant_id,
            title="acme pentest",
            origin="http://acme.test",
            goal="prove RCE",
            hints=[("check tomcat", "human")],
        )
        pid = detail.project.id
        intent = await gs.create_intent(
            s,
            tenant_id,
            pid,
            from_refs=["origin"],
            description="enumerate",
            creator="w1",
            worker="w1",
        )
        await gs.conclude_intent(s, tenant_id, pid, intent.id, "w1", "found tomcat 9")
    return pid


async def test_export_yaml_structure(sm, tenant_id) -> None:
    pid = await _build_graph(sm, tenant_id)
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        detail = await gs.get_project(s, tenant_id, pid)
    text = export_yaml(detail)
    data = yaml.safe_load(text)

    assert data["project"]["title"] == "acme pentest"
    assert data["project"]["origin"] == "http://acme.test"
    assert data["project"]["goal"] == "prove RCE"
    assert data["project"]["bootstrap_enabled"] is True
    assert data["hints"][0]["content"] == "check tomcat"
    fact_ids = {f["id"] for f in data["facts"]}
    assert {"origin", "goal", "f001"} <= fact_ids
    assert data["intents"][0]["from"] == ["origin"]
    assert data["intents"][0]["to"] == "f001"


async def test_export_timeline_structure(sm, tenant_id) -> None:
    pid = await _build_graph(sm, tenant_id)
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        detail = await gs.get_project(s, tenant_id, pid)
    text = export_timeline(detail)

    assert "PROJECT CREATED" in text
    assert "HINT by human" in text
    assert "INTENT DECLARED i001 by w1" in text
    assert "INTENT CONCLUDED i001 by w1" in text
    assert "produced: f001" in text


async def test_export_timeline_completion(sm, tenant_id) -> None:
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        detail = await gs.create_project(s, tenant_id, title="p", origin="o", goal="g")
        pid = detail.project.id
        await gs.complete_project(
            s, tenant_id, pid, from_refs=["origin"], description="done", worker="w1"
        )
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        detail = await gs.get_project(s, tenant_id, pid)
    text = export_timeline(detail)
    assert "PROJECT COMPLETED by w1" in text
