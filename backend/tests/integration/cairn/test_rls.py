"""Phase 2 — RLS tenant isolation for Cairn tables (requires_postgres).

A raw, unfiltered ``SELECT count(*)`` under tenant B's session must see only tenant
B's rows — proving the FORCE RLS policy bites, not just the service's explicit
``tenant_id`` filter.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from src.cairn import graph_service as gs
from src.db.session import set_session_tenant

from .conftest import skip_without_pg

pytestmark = [pytest.mark.requires_postgres, skip_without_pg]


async def _make_project(sm: async_sessionmaker[AsyncSession], tenant_id: str, title: str) -> str:
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        detail = await gs.create_project(s, tenant_id, title=title, origin="o", goal="g")
        return detail.project.id


async def test_cross_tenant_projects_isolated(app_sm, seed_tenant) -> None:
    tenant_a = seed_tenant("cairn-rls-a")
    tenant_b = seed_tenant("cairn-rls-b")
    await _make_project(app_sm, tenant_a, "proj-a")
    await _make_project(app_sm, tenant_b, "proj-b")

    # tenant B sees only its own project via the service ...
    async with app_sm() as s, s.begin():
        await set_session_tenant(s, tenant_b)
        summaries = await gs.list_projects(s, tenant_b)
        assert len(summaries) == 1
        assert summaries[0].project.title == "proj-b"
        # ... and a raw count proves RLS, not just the tenant filter.
        raw = await s.execute(text("SELECT count(*) FROM cairn_projects"))
        assert raw.scalar_one() == 1
        raw_facts = await s.execute(text("SELECT count(*) FROM cairn_facts"))
        assert raw_facts.scalar_one() == 2  # origin + goal for B only

    # tenant A sees only its own row too (RLS scopes the raw count).
    async with app_sm() as s, s.begin():
        await set_session_tenant(s, tenant_a)
        raw = await s.execute(text("SELECT count(*) FROM cairn_projects WHERE title = 'proj-a'"))
        assert raw.scalar_one() == 1


async def test_cross_tenant_get_project_not_found(app_sm, seed_tenant) -> None:
    from src.cairn.errors import CairnNotFoundError

    tenant_a = seed_tenant("cairn-rls-a2")
    tenant_b = seed_tenant("cairn-rls-b2")
    pid_a = await _make_project(app_sm, tenant_a, "proj-a")

    async with app_sm() as s, s.begin():
        await set_session_tenant(s, tenant_b)
        with pytest.raises(CairnNotFoundError):
            await gs.get_project(s, tenant_b, pid_a)
