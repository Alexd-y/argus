r"""Phase 1 — concurrent ref-id generation is race-free (requires_postgres).

AC: 1000 concurrent increments produce 1000 unique refs. The atomic
``INSERT ... ON CONFLICT DO UPDATE RETURNING`` in ``src/cairn/ids.py`` must give
every concurrent caller a distinct value, without a single-writer dispatcher.

Run locally (PowerShell)::

    docker run --rm -d --name argus-pg -p 55432:5432 -e POSTGRES_PASSWORD=argus `
        -e POSTGRES_DB=argus_test postgres:15
    $env:ARGUS_TEST_PG_DSN = "postgresql+asyncpg://postgres:argus@localhost:55432/argus_test"
    $env:DATABASE_URL = $env:ARGUS_TEST_PG_DSN
    .\.venv\Scripts\python.exe -m pytest tests/integration/cairn/test_ids_concurrency.py -m requires_postgres
"""

from __future__ import annotations

import asyncio
import os
import uuid
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from src.cairn.ids import next_fact_ref

pytestmark = pytest.mark.requires_postgres

_DSN = os.environ.get("ARGUS_TEST_PG_DSN", "")
_BACKEND_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(scope="module", autouse=True)
def _require_dsn() -> None:
    if not _DSN:
        pytest.skip("ARGUS_TEST_PG_DSN not set")


def _alembic_config() -> Config:
    cfg = Config(str(_BACKEND_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_BACKEND_ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", _DSN)
    return cfg


async def _seed_tenant_and_project(engine) -> tuple[str, str]:
    tenant_id = uuid.uuid4().hex
    project_id = uuid.uuid4().hex
    async with engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO tenants (id, name) VALUES (:id, :name)"),
            {"id": tenant_id, "name": f"cairn-ids-{tenant_id[:8]}"},
        )
        await conn.execute(
            text("""
                INSERT INTO cairn_projects (id, ref, tenant_id, title, status)
                VALUES (:id, :ref, :tid, :title, 'active')
                """),
            {"id": project_id, "ref": "proj_001", "tid": tenant_id, "title": "ids-test"},
        )
    return tenant_id, project_id


@pytest.mark.requires_postgres
async def test_1000_concurrent_fact_refs_are_unique() -> None:
    command.upgrade(_alembic_config(), "head")
    engine = create_async_engine(_DSN, pool_size=20, max_overflow=40, pool_pre_ping=True)
    try:
        tenant_id, project_id = await _seed_tenant_and_project(engine)
        sessionmaker = async_sessionmaker(engine, expire_on_commit=False)

        async def _one() -> str:
            async with sessionmaker() as session:
                ref = await next_fact_ref(session, tenant_id, project_id)
                await session.commit()
                return ref

        refs = await asyncio.gather(*[_one() for _ in range(1000)])
        assert len(refs) == 1000
        assert len(set(refs)) == 1000, "duplicate refs generated under concurrency"
        # Values form the contiguous set f001..f1000 (order irrelevant).
        values = sorted(int(r[1:]) for r in refs)
        assert values == list(range(1, 1001))
    finally:
        await engine.dispose()
