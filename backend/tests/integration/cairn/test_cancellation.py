"""Phase 9 — scan cancellation stops the linked Cairn project (requires_postgres, §11.4)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from src.cairn import graph_service as gs
from src.db.session import set_session_tenant

from .conftest import skip_without_pg

pytestmark = [pytest.mark.requires_postgres, skip_without_pg]


async def _make_scan(sm, tenant_id: str) -> str:
    scan_id = uuid.uuid4().hex
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        await s.execute(
            text(
                "INSERT INTO scans (id, tenant_id, target_url, status) "
                "VALUES (:id, :tid, :url, 'running')"
            ),
            {"id": scan_id, "tid": tenant_id, "url": "http://target.test"},
        )
    return scan_id


async def test_cancel_stops_linked_cairn_project(sm, tenant_id) -> None:
    scan_id = await _make_scan(sm, tenant_id)
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        detail = await gs.create_project(
            s, tenant_id, title="p", origin="o", goal="g", scan_id=scan_id
        )
        pid = detail.project.id
        intent = await gs.create_intent(
            s, tenant_id, pid, from_refs=["origin"], description="d", creator="w1", worker="w1"
        )
        iid = intent.id
        await gs.claim_reason(s, tenant_id, pid, "w1", "initial")

    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        stopped = await gs.stop_projects_for_scan(s, tenant_id, scan_id)
    assert stopped == 1

    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        detail = await gs.get_project(s, tenant_id, pid)
    assert detail.project.status == "stopped"
    assert detail.project.reason_worker is None
    assert [i for i in detail.intents if i.id == iid][0].worker is None


async def test_cancel_ignores_projects_of_other_scans(sm, tenant_id) -> None:
    scan_a = await _make_scan(sm, tenant_id)
    scan_b = await _make_scan(sm, tenant_id)
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        a = await gs.create_project(s, tenant_id, title="a", origin="o", goal="g", scan_id=scan_a)
        await gs.create_project(s, tenant_id, title="b", origin="o", goal="g", scan_id=scan_b)
        pid_a = a.project.id

    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        stopped = await gs.stop_projects_for_scan(s, tenant_id, scan_a)
    assert stopped == 1

    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        detail_a = await gs.get_project(s, tenant_id, pid_a)
    assert detail_a.project.status == "stopped"
