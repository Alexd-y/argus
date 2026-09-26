"""Phase 10/11 — DB-backed Cairn worker config (requires_postgres)."""

from __future__ import annotations

import pytest
from sqlalchemy import select
from src.cairn.workers.models import CairnWorker
from src.db.session import set_session_tenant

from .conftest import skip_without_pg

pytestmark = [pytest.mark.requires_postgres, skip_without_pg]


async def test_worker_crud_roundtrip(sm, tenant_id) -> None:
    # create
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        s.add(
            CairnWorker(
                tenant_id=tenant_id,
                name="wrb-1",
                type="wrb",
                task_types=["reason", "explore", "bootstrap"],
                max_running=2,
                priority=10,
            )
        )
    # list + patch
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        worker = (
            await s.execute(select(CairnWorker).where(CairnWorker.tenant_id == tenant_id))
        ).scalar_one()
        assert worker.task_types == ["reason", "explore", "bootstrap"]
        worker.enabled = False
        worker.priority = 5
        wid = worker.id
    # verify patch + delete
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        worker = await s.get(CairnWorker, wid)
        assert worker.enabled is False
        assert worker.priority == 5
        await s.delete(worker)
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        remaining = (
            (await s.execute(select(CairnWorker).where(CairnWorker.tenant_id == tenant_id)))
            .scalars()
            .all()
        )
        assert remaining == []


async def test_worker_name_unique_per_tenant(sm, tenant_id) -> None:
    async with sm() as s, s.begin():
        await set_session_tenant(s, tenant_id)
        s.add(CairnWorker(tenant_id=tenant_id, name="dup", type="wrb", task_types=["reason"]))
    with pytest.raises(Exception):  # noqa: B017 - unique violation surfaces as IntegrityError
        async with sm() as s, s.begin():
            await set_session_tenant(s, tenant_id)
            s.add(CairnWorker(tenant_id=tenant_id, name="dup", type="wrb", task_types=["reason"]))
