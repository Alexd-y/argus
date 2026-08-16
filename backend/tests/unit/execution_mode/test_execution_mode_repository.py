"""Unit tests for execution mode repository persistence."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from src.api.routers import execution_mode as em_api
from src.execution_mode.lab_lease import LabLeaseService
from src.execution_mode.lab_scope import LabScopeManifest
from src.execution_mode.mode import (
    ExecutionMode,
    ExecutionModeImmutableError,
    assert_mode_immutable,
)
from src.execution_mode.repository import (
    InMemoryExecutionModeRepository,
    set_execution_mode_repository,
    strip_lease_storage_meta,
)


def _manifest(**overrides):
    base = {
        "tenant_id": "t-1",
        "engagement_id": "e-1",
        "cidrs": ("10.90.0.0/16",),
        "dns_suffixes": ("lab.argus",),
        "k8s_namespace": "argus-lab-42",
        "vm_network_ids": ("labnet-42",),
        "capture_full": True,
        "expires_at": datetime.now(tz=UTC) + timedelta(hours=4),
        "created_by": "u-1",
    }
    base.update(overrides)
    return LabScopeManifest(**base)


@pytest.fixture
def repo() -> InMemoryExecutionModeRepository:
    store = InMemoryExecutionModeRepository()
    set_execution_mode_repository(store)
    yield store
    set_execution_mode_repository(InMemoryExecutionModeRepository())


@pytest.mark.asyncio
async def test_repository_mode_round_trip(repo: InMemoryExecutionModeRepository):
    saved = await repo.upsert_execution_mode(
        tenant_id="t-1",
        engagement_id="e-1",
        mode=ExecutionMode.LAB_UNRESTRICTED.value,
    )
    assert saved["mode"] == "lab_unrestricted"
    assert saved["first_execution_at"] is None

    loaded = await repo.get_execution_mode(tenant_id="t-1", engagement_id="e-1")
    assert loaded == saved


@pytest.mark.asyncio
async def test_repository_manifest_and_lease_round_trip(repo: InMemoryExecutionModeRepository):
    manifest = _manifest()
    await repo.save_manifest(manifest)

    active = await repo.list_active_manifests(tenant_id="t-1", engagement_id="e-1")
    assert len(active) == 1
    assert active[0].manifest_id == manifest.manifest_id

    lease = LabLeaseService().issue(manifest, boundary_proof="proof-abc")
    payload = lease.to_storage_dict()
    await repo.save_lease("idem-42", payload)

    cached = await repo.get_lease_by_idempotency_key("idem-42")
    assert cached is not None
    assert cached["lease_id"] == lease.lease_id
    assert cached["_idempotency_key"] == "idem-42"
    assert strip_lease_storage_meta(cached)["lease_id"] == lease.lease_id


@pytest.mark.asyncio
async def test_mark_first_execution_sets_timestamp(repo: InMemoryExecutionModeRepository):
    await repo.upsert_execution_mode(
        tenant_id="t-1",
        engagement_id="e-1",
        mode=ExecutionMode.PRODUCTION.value,
    )
    marked = await repo.mark_first_execution(tenant_id="t-1", engagement_id="e-1")
    assert marked["first_execution_at"] is not None

    again = await repo.mark_first_execution(tenant_id="t-1", engagement_id="e-1")
    assert again["first_execution_at"] == marked["first_execution_at"]


@pytest.mark.asyncio
async def test_mode_immutable_after_mark_first_execution(repo: InMemoryExecutionModeRepository):
    await repo.upsert_execution_mode(
        tenant_id="t-1",
        engagement_id="e-1",
        mode=ExecutionMode.PRODUCTION.value,
    )
    marked = await repo.mark_first_execution(tenant_id="t-1", engagement_id="e-1")
    current = ExecutionMode(marked["mode"])

    with pytest.raises(ExecutionModeImmutableError):
        assert_mode_immutable(
            current,
            ExecutionMode.LAB_UNRESTRICTED,
            has_started_execution=True,
        )


def test_api_works_with_injected_repo(repo: InMemoryExecutionModeRepository):
    set_execution_mode_repository(repo)
    app = FastAPI()
    app.include_router(em_api.router, prefix="/api/v1")
    client = TestClient(app)
    headers = {"X-Tenant-Id": "t-1", "X-User-Id": "u-1"}

    r = client.post(
        "/api/v1/engagements/e-1/execution-mode",
        headers=headers,
        json={"mode": "lab_unrestricted"},
    )
    assert r.status_code == 200
    assert r.json()["mode"] == "lab_unrestricted"

    r = client.post(
        "/api/v1/engagements/e-1/lab-scope",
        headers=headers,
        json={
            "cidrs": ["10.90.0.0/16"],
            "dns_suffixes": ["lab.argus"],
            "k8s_namespace": "argus-lab-42",
            "vm_network_ids": ["labnet-42"],
            "capture_full": True,
        },
    )
    assert r.status_code == 201

    r = client.post(
        "/api/v1/engagements/e-1/lab-lease",
        headers={**headers, "Idempotency-Key": "idem-1"},
        json={
            "target": "https://victim.lab.argus/",
            "k8s_namespace": "argus-lab-42",
            "vm_network_id": "labnet-42",
        },
    )
    assert r.status_code == 201
    assert r.json()["policy"]["requires_approval"] is False


@pytest.mark.asyncio
async def test_api_mode_immutable_after_first_execution(repo: InMemoryExecutionModeRepository):
    set_execution_mode_repository(repo)
    app = FastAPI()
    app.include_router(em_api.router, prefix="/api/v1")
    client = TestClient(app)
    headers = {"X-Tenant-Id": "t-1"}

    r = client.post(
        "/api/v1/engagements/e-1/execution-mode",
        headers=headers,
        json={"mode": "production"},
    )
    assert r.status_code == 200

    await repo.mark_first_execution(tenant_id="t-1", engagement_id="e-1")

    r = client.post(
        "/api/v1/engagements/e-1/execution-mode",
        headers=headers,
        json={"mode": "lab_unrestricted"},
    )
    assert r.status_code == 409