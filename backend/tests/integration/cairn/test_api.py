"""Phase 3 — Cairn REST API contract (requires_postgres).

Drives the mounted router through an ASGI transport with auth dependencies
overridden to a seeded tenant. Verifies the response shapes match the upstream
Cairn contract (field names / graph edges) and that auth is enforced.
"""

from __future__ import annotations

import uuid

import httpx
import pytest
import pytest_asyncio
from httpx import ASGITransport

from .conftest import skip_without_pg

pytestmark = [pytest.mark.requires_postgres, skip_without_pg]


@pytest_asyncio.fixture(autouse=True)
async def _fresh_engine_pool():
    """Reset the app engine's pool so connections bind to this test's event loop.

    The app uses a module-global engine; pytest-asyncio gives each test its own
    loop, and asyncpg connections cannot be reused across loops (Windows Proactor).
    """
    from src.db.session import engine

    await engine.dispose()
    yield
    await engine.dispose()


@pytest.fixture()
def app_and_tenant(migrated_db, seed_tenant):
    import main
    from src.core.auth import AuthContext, get_required_auth
    from src.core.tenant import get_current_tenant_id

    tenant_id = seed_tenant("cairn-api")

    async def _tenant() -> str:
        return tenant_id

    async def _auth() -> AuthContext:
        return AuthContext(user_id="u-test", tenant_id=tenant_id)

    main.app.dependency_overrides[get_current_tenant_id] = _tenant
    main.app.dependency_overrides[get_required_auth] = _auth
    try:
        yield main.app, tenant_id
    finally:
        main.app.dependency_overrides.pop(get_current_tenant_id, None)
        main.app.dependency_overrides.pop(get_required_auth, None)


def _client(app) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


async def test_full_project_lifecycle(app_and_tenant) -> None:
    app, _ = app_and_tenant
    async with _client(app) as client:
        # create project
        resp = await client.post(
            "/api/v1/cairn/projects",
            json={"title": "web pentest", "origin": "http://t", "goal": "get RCE"},
        )
        assert resp.status_code == 201
        detail = resp.json()
        assert detail["project"]["ref"] == "proj_001"
        assert detail["project"]["status"] == "active"
        fact_ids = {f["id"] for f in detail["facts"]}
        assert fact_ids == {"origin", "goal"}
        pid = detail["project"]["id"]

        # create intent (from origin)
        resp = await client.post(
            f"/api/v1/cairn/projects/{pid}/intents",
            json={"from": ["origin"], "description": "enumerate endpoints", "creator": "w1"},
        )
        assert resp.status_code == 201
        intent = resp.json()
        assert intent["id"] == "i001"
        assert intent["from"] == ["origin"]
        assert intent["to"] is None
        iid = intent["id"]

        # claim then conclude
        resp = await client.post(
            f"/api/v1/cairn/projects/{pid}/intents/{iid}/heartbeat", json={"worker": "w1"}
        )
        assert resp.status_code == 200
        resp = await client.post(
            f"/api/v1/cairn/projects/{pid}/intents/{iid}/conclude",
            json={"worker": "w1", "description": "found /admin"},
        )
        assert resp.status_code == 200
        conclude = resp.json()
        assert conclude["fact"]["id"] == "f001"
        assert conclude["intent"]["to"] == "f001"

        # list + get
        resp = await client.get("/api/v1/cairn/projects")
        assert resp.status_code == 200
        summaries = resp.json()
        assert len(summaries) == 1
        assert summaries[0]["fact_count"] == 3  # origin, goal, f001
        assert summaries[0]["intent_count"] == 1

        resp = await client.get(f"/api/v1/cairn/projects/{pid}")
        assert resp.status_code == 200

        # hint works
        resp = await client.post(
            f"/api/v1/cairn/projects/{pid}/hints",
            json={"content": "try default creds", "creator": "human"},
        )
        assert resp.status_code == 201
        assert resp.json()["id"] == "h001"


async def test_export_formats(app_and_tenant) -> None:
    app, _ = app_and_tenant
    async with _client(app) as client:
        resp = await client.post(
            "/api/v1/cairn/projects",
            json={"title": "p", "origin": "o", "goal": "g"},
        )
        pid = resp.json()["project"]["id"]

        resp = await client.get(f"/api/v1/cairn/projects/{pid}/export?format=yaml")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/plain")
        assert "title: p" in resp.text

        resp = await client.get(f"/api/v1/cairn/projects/{pid}/export?format=timeline")
        assert resp.status_code == 200
        assert "PROJECT CREATED" in resp.text

        resp = await client.get(f"/api/v1/cairn/projects/{pid}/export?format=bogus")
        assert resp.status_code == 400


async def test_settings_roundtrip(app_and_tenant) -> None:
    app, _ = app_and_tenant
    async with _client(app) as client:
        resp = await client.get("/api/v1/cairn/settings")
        assert resp.status_code == 200
        assert resp.json()["intent_timeout"] == 900

        resp = await client.put(
            "/api/v1/cairn/settings",
            json={"intent_timeout": 600, "reason_timeout": 600},
        )
        assert resp.status_code == 200
        assert resp.json()["intent_timeout"] == 600

        # below-minimum rejected by Pydantic (422)
        resp = await client.put(
            "/api/v1/cairn/settings", json={"intent_timeout": 1, "reason_timeout": 600}
        )
        assert resp.status_code == 422


async def test_validation_and_conflicts(app_and_tenant) -> None:
    app, _ = app_and_tenant
    async with _client(app) as client:
        # empty title -> 422
        resp = await client.post(
            "/api/v1/cairn/projects", json={"title": "  ", "origin": "o", "goal": "g"}
        )
        assert resp.status_code == 422

        resp = await client.post(
            "/api/v1/cairn/projects", json={"title": "p", "origin": "o", "goal": "g"}
        )
        pid = resp.json()["project"]["id"]

        # goal in from -> 400 (domain error translated)
        resp = await client.post(
            f"/api/v1/cairn/projects/{pid}/intents",
            json={"from": ["goal"], "description": "d", "creator": "w1"},
        )
        assert resp.status_code == 400

        # unknown fact -> 404
        resp = await client.post(
            f"/api/v1/cairn/projects/{pid}/intents",
            json={"from": ["f999"], "description": "d", "creator": "w1"},
        )
        assert resp.status_code == 404


async def test_cross_tenant_and_missing(app_and_tenant, seed_tenant) -> None:
    app, _ = app_and_tenant
    async with _client(app) as client:
        resp = await client.post(
            "/api/v1/cairn/projects", json={"title": "p", "origin": "o", "goal": "g"}
        )
        pid = resp.json()["project"]["id"]

    # switch the tenant override to a different tenant → project not visible (404)
    import main
    from src.core.tenant import get_current_tenant_id

    other = seed_tenant("cairn-api-other")

    async def _other() -> str:
        return other

    main.app.dependency_overrides[get_current_tenant_id] = _other
    try:
        async with _client(app) as client:
            resp = await client.get(f"/api/v1/cairn/projects/{pid}")
            assert resp.status_code == 404
            resp = await client.get(f"/api/v1/cairn/projects/{uuid.uuid4().hex}")
            assert resp.status_code == 404
    finally:
        # restore handled by outer fixture teardown
        pass


async def test_requires_auth() -> None:
    """Without the auth override, the tenant dependency yields 401."""
    import main

    async with _client(main.app) as client:
        resp = await client.get("/api/v1/cairn/settings")
        assert resp.status_code == 401
