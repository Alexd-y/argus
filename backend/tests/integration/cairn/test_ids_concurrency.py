r"""Phase 1 — concurrent ref-id generation is race-free (requires_postgres).

AC: 1000 concurrent increments produce 1000 unique refs. The atomic
``INSERT ... ON CONFLICT DO UPDATE RETURNING`` in ``src/cairn/ids.py`` must give
every concurrent caller a distinct value, without a single-writer dispatcher.

Uses the shared ``migrated_db`` / ``async_engine`` fixtures (migrations run in a
sync fixture — never inside the running event loop of an async test).
"""

from __future__ import annotations

import asyncio
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker
from src.cairn.ids import next_fact_ref

from .conftest import skip_without_pg

pytestmark = [pytest.mark.requires_postgres, skip_without_pg]


async def _seed_tenant_and_project(engine: AsyncEngine) -> tuple[str, str]:
    tenant_id = uuid.uuid4().hex
    project_id = uuid.uuid4().hex
    async with engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO tenants (id, name) VALUES (:id, :name)"),
            {"id": tenant_id, "name": f"cairn-ids-{tenant_id[:8]}"},
        )
        await conn.execute(text(f"SET app.current_tenant_id = '{tenant_id}'"))
        await conn.execute(
            text("""
                INSERT INTO cairn_projects (id, ref, tenant_id, title, status)
                VALUES (:id, :ref, :tid, :title, 'active')
                """),
            {"id": project_id, "ref": "proj_001", "tid": tenant_id, "title": "ids-test"},
        )
    return tenant_id, project_id


async def test_1000_concurrent_fact_refs_are_unique(async_engine: AsyncEngine) -> None:
    tenant_id, project_id = await _seed_tenant_and_project(async_engine)
    session_factory = async_sessionmaker(async_engine, expire_on_commit=False)

    async def _one() -> str:
        async with session_factory() as session, session.begin():
            await session.execute(text(f"SET LOCAL app.current_tenant_id = '{tenant_id}'"))
            return await next_fact_ref(session, tenant_id, project_id)

    refs = await asyncio.gather(*[_one() for _ in range(1000)])
    assert len(refs) == 1000
    assert len(set(refs)) == 1000, "duplicate refs generated under concurrency"
    values = sorted(int(r[1:]) for r in refs)
    assert values == list(range(1, 1001))
