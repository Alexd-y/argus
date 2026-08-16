"""Unit tests for LAB mode DB persistence via ExecutionModeRepository."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx import ASGITransport
from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool
from src.api.routers import execution_mode as em_api
from src.api.routers import unified_ai_lab as lab_api
from src.db.models import Tenant
from src.db.models_recon import Engagement
from src.execution_mode.lab_lease import LabLeaseService, LabLeaseStatus
from src.execution_mode.lab_scope import LabScopeManifest
from src.execution_mode.mode import ExecutionMode
from src.execution_mode.repository import (
    InMemoryExecutionModeRepository,
    SqlAlchemyExecutionModeRepository,
    set_execution_mode_repository,
    strip_lease_storage_meta,
)


def _manifest(**overrides: object) -> LabScopeManifest:
    base: dict = {
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
async def test_save_lease_indexes_idempotency_and_lease_id(
    repo: InMemoryExecutionModeRepository,
) -> None:
    manifest = _manifest()
    await repo.save_manifest(manifest)
    lease = LabLeaseService().issue(manifest, boundary_proof="proof-1")
    await repo.save_lease("idem-abc", lease.to_storage_dict())

    by_key = await repo.get_lease_by_idempotency_key("idem-abc")
    assert by_key is not None
    assert by_key["lease_id"] == lease.lease_id
    assert by_key["_idempotency_key"] == "idem-abc"

    by_lease_id = await repo.get_lease_by_idempotency_key(lease.lease_id)
    assert by_lease_id is not None
    assert by_lease_id["lease_id"] == lease.lease_id

    domain = strip_lease_storage_meta(by_key)
    assert "_idempotency_key" not in domain


@pytest.mark.asyncio
async def test_api_persists_mode_manifest_lease_via_repository(
    repo: InMemoryExecutionModeRepository,
) -> None:
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
    stored_mode = await repo.get_execution_mode(tenant_id="t-1", engagement_id="e-1")
    assert stored_mode is not None
    assert stored_mode["mode"] == ExecutionMode.LAB_UNRESTRICTED.value

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
    manifests = await repo.list_active_manifests(tenant_id="t-1", engagement_id="e-1")
    assert len(manifests) == 1

    r = client.post(
        "/api/v1/engagements/e-1/lab-lease",
        headers={**headers, "Idempotency-Key": "idem-persist-1"},
        json={
            "target": "https://victim.lab.argus/",
            "k8s_namespace": "argus-lab-42",
            "vm_network_id": "labnet-42",
        },
    )
    assert r.status_code == 201
    body = r.json()
    assert "_idempotency_key" not in body
    cached = await repo.get_lease_by_idempotency_key("idem-persist-1")
    assert cached is not None
    assert cached["lease_id"] == body["lease_id"]

    r2 = client.post(
        "/api/v1/engagements/e-1/lab-lease",
        headers={**headers, "Idempotency-Key": "idem-persist-1"},
        json={
            "target": "https://victim.lab.argus/",
            "k8s_namespace": "argus-lab-42",
            "vm_network_id": "labnet-42",
        },
    )
    assert r2.status_code == 201
    assert r2.json()["lease_id"] == body["lease_id"]


@pytest.mark.asyncio
async def test_persist_reload_across_api_sessions(
    repo: InMemoryExecutionModeRepository,
) -> None:
    """Same repo instance survives a new FastAPI/TestClient 'session' (no module stores)."""
    set_execution_mode_repository(repo)
    headers = {"X-Tenant-Id": "t-1", "X-User-Id": "u-1"}

    app_write = FastAPI()
    app_write.include_router(em_api.router, prefix="/api/v1")
    write_client = TestClient(app_write)

    r = write_client.post(
        "/api/v1/engagements/e-reload/execution-mode",
        headers=headers,
        json={"mode": "lab_unrestricted"},
    )
    assert r.status_code == 200

    r = write_client.post(
        "/api/v1/engagements/e-reload/lab-scope",
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
    manifest_id = r.json()["manifest_id"]

    r = write_client.post(
        "/api/v1/engagements/e-reload/lab-lease",
        headers={**headers, "Idempotency-Key": "idem-reload-1"},
        json={
            "target": "https://app.lab.argus/",
            "k8s_namespace": "argus-lab-42",
            "vm_network_id": "labnet-42",
        },
    )
    assert r.status_code == 201
    lease_id = r.json()["lease_id"]

    # New app + client — only shared repository keeps state.
    set_execution_mode_repository(repo)
    app_read = FastAPI()
    app_read.include_router(em_api.router, prefix="/api/v1")
    read_client = TestClient(app_read)

    mode = read_client.get("/api/v1/engagements/e-reload/execution-mode", headers=headers)
    assert mode.status_code == 200
    assert mode.json()["mode"] == ExecutionMode.LAB_UNRESTRICTED.value

    reloaded_mode = await repo.get_execution_mode(tenant_id="t-1", engagement_id="e-reload")
    assert reloaded_mode is not None
    assert reloaded_mode["mode"] == ExecutionMode.LAB_UNRESTRICTED.value

    manifests = await repo.list_active_manifests(tenant_id="t-1", engagement_id="e-reload")
    assert len(manifests) == 1
    assert manifests[0].manifest_id == manifest_id

    cached = await repo.get_lease_by_idempotency_key("idem-reload-1")
    assert cached is not None
    assert cached["lease_id"] == lease_id

    r_idem = read_client.post(
        "/api/v1/engagements/e-reload/lab-lease",
        headers={**headers, "Idempotency-Key": "idem-reload-1"},
        json={
            "target": "https://app.lab.argus/",
            "k8s_namespace": "argus-lab-42",
            "vm_network_id": "labnet-42",
        },
    )
    assert r_idem.status_code == 201
    assert r_idem.json()["lease_id"] == lease_id
    assert "_idempotency_key" not in r_idem.json()


@pytest.mark.asyncio
async def test_lab_script_execute_requires_persisted_usable_lease(
    repo: InMemoryExecutionModeRepository,
) -> None:
    set_execution_mode_repository(repo)
    manifest = _manifest()
    await repo.save_manifest(manifest)
    lease = LabLeaseService().issue(manifest, boundary_proof="proof-exec")
    await repo.save_lease(lease.lease_id, lease.to_storage_dict())

    app = FastAPI()
    app.include_router(lab_api.lab_router, prefix="/api/v1")
    client = TestClient(app)
    headers = {"X-Tenant-Id": "t-1"}

    created = client.post(
        "/api/v1/lab/scripts",
        headers=headers,
        json={
            "language": "python",
            "source": "print(1)",
            "lease_id": lease.lease_id,
        },
    )
    assert created.status_code == 201
    script_id = created.json()["script_id"]

    executed = client.post(f"/api/v1/lab/scripts/{script_id}/execute", headers=headers)
    assert executed.status_code == 200
    assert executed.json()["requires_approval"] is False
    assert executed.json()["status"] == "completed"
    assert "1" in executed.json()["stdout"]

    denied = client.post(
        "/api/v1/lab/scripts",
        headers=headers,
        json={
            "language": "python",
            "source": "print(1)",
            "lease_id": "missing-lease",
        },
    )
    assert denied.status_code == 403
    assert denied.json()["detail"] == "lab_lease_required"

    revoked = lease.revoke(reason=LabLeaseStatus.REVOKED)
    await repo.save_lease(revoked.lease_id, revoked.to_storage_dict())
    blocked = client.post(f"/api/v1/lab/scripts/{script_id}/execute", headers=headers)
    assert blocked.status_code == 403


@pytest.mark.asyncio
async def test_save_lease_strips_trace_id_before_domain_parse(
    repo: InMemoryExecutionModeRepository,
) -> None:
    manifest = _manifest()
    await repo.save_manifest(manifest)
    lease = LabLeaseService().issue(manifest, boundary_proof="proof-trace")
    payload = lease.to_storage_dict()
    payload["trace_id"] = "should-not-break-extra-forbid"
    await repo.save_lease("idem-trace", payload)
    stored = await repo.get_lease_by_idempotency_key("idem-trace")
    assert stored is not None
    assert stored["lease_id"] == lease.lease_id
    assert "trace_id" not in stored
    domain = strip_lease_storage_meta(stored)
    assert LabLeaseStatus(domain["status"]) is LabLeaseStatus.ACTIVE


@pytest.fixture
async def sqlite_mode_env() -> AsyncIterator[
    tuple[SqlAlchemyExecutionModeRepository, str, str, async_sessionmaker[AsyncSession]]
]:
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine.sync_engine, "connect")
    def _enable_sqlite_fks(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    async with engine.begin() as conn:
        await conn.execute(
            text(
                "CREATE TABLE tenants ("
                "id VARCHAR(36) PRIMARY KEY NOT NULL, "
                "name VARCHAR(255) NOT NULL)"
            )
        )
        await conn.execute(
            text(
                "CREATE TABLE engagements ("
                "id VARCHAR(36) PRIMARY KEY NOT NULL, "
                "tenant_id VARCHAR(36) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE, "
                "name VARCHAR(255) NOT NULL)"
            )
        )
        await conn.execute(
            text(
                "CREATE TABLE engagement_execution_modes ("
                "engagement_id VARCHAR(36) PRIMARY KEY NOT NULL "
                "REFERENCES engagements(id) ON DELETE CASCADE, "
                "tenant_id VARCHAR(36) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE, "
                "mode VARCHAR(32) NOT NULL DEFAULT 'production', "
                "first_execution_at DATETIME, "
                "created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL, "
                "updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL)"
            )
        )
        await conn.execute(
            text(
                "CREATE TABLE lab_scope_manifests ("
                "id VARCHAR(36) PRIMARY KEY NOT NULL, "
                "tenant_id VARCHAR(36) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE, "
                "engagement_id VARCHAR(36) NOT NULL REFERENCES engagements(id) ON DELETE CASCADE, "
                "mode VARCHAR(32) NOT NULL DEFAULT 'lab_unrestricted', "
                "payload JSON NOT NULL, "
                "signature VARCHAR(128), "
                "capture_full BOOLEAN NOT NULL DEFAULT 0, "
                "expires_at DATETIME NOT NULL, "
                "created_by VARCHAR(36) NOT NULL, "
                "created_at DATETIME DEFAULT CURRENT_TIMESTAMP, "
                "revoked_at DATETIME)"
            )
        )
        await conn.execute(
            text(
                "CREATE TABLE lab_execution_leases ("
                "id VARCHAR(36) PRIMARY KEY NOT NULL, "
                "tenant_id VARCHAR(36) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE, "
                "engagement_id VARCHAR(36) NOT NULL REFERENCES engagements(id) ON DELETE CASCADE, "
                "manifest_id VARCHAR(36) NOT NULL REFERENCES lab_scope_manifests(id) ON DELETE CASCADE, "
                "mode VARCHAR(32) NOT NULL DEFAULT 'lab_unrestricted', "
                "status VARCHAR(32) NOT NULL DEFAULT 'active', "
                "boundary_proof VARCHAR(128) NOT NULL, "
                "capture_full BOOLEAN NOT NULL DEFAULT 0, "
                "k8s_namespace VARCHAR(253), "
                "payload JSON, "
                "issued_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL, "
                "expires_at DATETIME NOT NULL, "
                "revoked_at DATETIME, "
                "revoke_reason TEXT)"
            )
        )
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    tenant_id = str(uuid4())
    engagement_id = str(uuid4())
    assert Tenant.__tablename__ == "tenants"
    assert Engagement.__tablename__ == "engagements"
    async with factory() as session:
        await session.execute(
            text("INSERT INTO tenants (id, name) VALUES (:id, :name)"),
            {"id": tenant_id, "name": "persist-mode-test"},
        )
        await session.execute(
            text(
                "INSERT INTO engagements (id, tenant_id, name) "
                "VALUES (:id, :tenant_id, :name)"
            ),
            {"id": engagement_id, "tenant_id": tenant_id, "name": "persist-eng"},
        )
        await session.commit()
    repo = SqlAlchemyExecutionModeRepository(session_factory=factory)
    set_execution_mode_repository(repo)
    try:
        yield repo, tenant_id, engagement_id, factory
    finally:
        set_execution_mode_repository(InMemoryExecutionModeRepository())
        await engine.dispose()


@pytest.mark.asyncio
async def test_sqlalchemy_mode_lease_survives_new_app_instance(
    sqlite_mode_env: tuple[
        SqlAlchemyExecutionModeRepository, str, str, async_sessionmaker[AsyncSession]
    ],
) -> None:
    _repo, tenant_id, engagement_id, factory = sqlite_mode_env
    headers = {"X-Tenant-Id": tenant_id, "X-User-Id": str(uuid4())}

    app_write = FastAPI()
    app_write.include_router(em_api.router, prefix="/api/v1")
    transport_write = ASGITransport(app=app_write)
    async with httpx.AsyncClient(transport=transport_write, base_url="http://test") as write_client:
        r = await write_client.post(
            f"/api/v1/engagements/{engagement_id}/execution-mode",
            headers=headers,
            json={"mode": "lab_unrestricted"},
        )
        assert r.status_code == 200, r.text
        assert r.json()["mode"] == ExecutionMode.LAB_UNRESTRICTED.value

        r = await write_client.post(
            f"/api/v1/engagements/{engagement_id}/lab-scope",
            headers=headers,
            json={
                "cidrs": ["10.90.0.0/16"],
                "dns_suffixes": ["lab.argus"],
                "k8s_namespace": "argus-lab-42",
                "vm_network_ids": ["labnet-42"],
                "capture_full": True,
            },
        )
        assert r.status_code == 201, r.text
        manifest_id = r.json()["manifest_id"]

        r = await write_client.post(
            f"/api/v1/engagements/{engagement_id}/lab-lease",
            headers={**headers, "Idempotency-Key": "idem-sqlite-restart"},
            json={
                "target": "https://app.lab.argus/",
                "k8s_namespace": "argus-lab-42",
                "vm_network_id": "labnet-42",
            },
        )
        assert r.status_code == 201, r.text
        lease_id = r.json()["lease_id"]
        assert r.json().get("trace_id")

    restarted = SqlAlchemyExecutionModeRepository(session_factory=factory)
    set_execution_mode_repository(restarted)
    app_read = FastAPI()
    app_read.include_router(em_api.router, prefix="/api/v1")
    transport_read = ASGITransport(app=app_read)
    async with httpx.AsyncClient(transport=transport_read, base_url="http://test") as read_client:
        mode = await read_client.get(
            f"/api/v1/engagements/{engagement_id}/execution-mode",
            headers=headers,
        )
        assert mode.status_code == 200
        assert mode.json()["mode"] == ExecutionMode.LAB_UNRESTRICTED.value

        r_idem = await read_client.post(
            f"/api/v1/engagements/{engagement_id}/lab-lease",
            headers={**headers, "Idempotency-Key": "idem-sqlite-restart"},
            json={
                "target": "https://app.lab.argus/",
                "k8s_namespace": "argus-lab-42",
                "vm_network_id": "labnet-42",
            },
        )
        assert r_idem.status_code == 201
        assert r_idem.json()["lease_id"] == lease_id
        assert "_idempotency_key" not in r_idem.json()

    reloaded = await restarted.get_execution_mode(
        tenant_id=tenant_id, engagement_id=engagement_id
    )
    assert reloaded is not None
    assert reloaded["mode"] == ExecutionMode.LAB_UNRESTRICTED.value

    manifests = await restarted.list_active_manifests(
        tenant_id=tenant_id, engagement_id=engagement_id
    )
    assert len(manifests) == 1
    assert manifests[0].manifest_id == manifest_id

    cached = await restarted.get_lease_by_idempotency_key("idem-sqlite-restart")
    assert cached is not None
    assert cached["lease_id"] == lease_id

    by_id = await restarted.get_lease_by_idempotency_key(lease_id)
    assert by_id is not None
    assert by_id["lease_id"] == lease_id

    usable = await em_api.lookup_usable_lease(lease_id)
    assert usable is not None
    assert usable.lease_id == lease_id


@pytest.mark.asyncio
async def test_sqlalchemy_missing_engagement_returns_404(
    sqlite_mode_env: tuple[
        SqlAlchemyExecutionModeRepository, str, str, async_sessionmaker[AsyncSession]
    ],
) -> None:
    _repo, tenant_id, _engagement_id, _factory = sqlite_mode_env
    missing_engagement = str(uuid4())
    app = FastAPI()
    app.include_router(em_api.router, prefix="/api/v1")
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            f"/api/v1/engagements/{missing_engagement}/execution-mode",
            headers={"X-Tenant-Id": tenant_id},
            json={"mode": "lab_unrestricted"},
        )
    assert r.status_code == 404
    assert r.json()["detail"] == "not_found"
    assert "Traceback" not in r.text
    assert "IntegrityError" not in r.text
