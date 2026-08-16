"""QUICK-007 — POST /api/v1/scans execution_mode=quick flag and conflict contracts.

Mocks ``async_session_factory``. No live Postgres. Feature flag via settings.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

os.environ.setdefault("DEBUG", "true")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("JWT_SECRET", "test-secret-not-for-prod-but-required-by-settings")
os.environ.setdefault("ARGUS_TEST_MODE", "1")

import pytest  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

from src.api.routers import scans as scans_router  # noqa: E402
from src.core.auth import AuthContext, get_optional_auth, get_required_auth  # noqa: E402
from src.core.config import settings  # noqa: E402
from src.db.models import Scan  # noqa: E402

_TENANT_ID = "00000000-0000-0000-0000-000000000001"
_TARGET = "https://example.com"
_EMAIL = "user@example.com"


@pytest.fixture(autouse=True)
def override_auth() -> Iterator[None]:
    """Do not boot the full FastAPI ``app`` — this module uses a mini client."""
    yield


def _api_client() -> TestClient:
    app = FastAPI()
    app.include_router(scans_router.router, prefix="/api/v1")

    async def _mock_auth() -> AuthContext:
        return AuthContext(user_id="test-user", tenant_id=_TENANT_ID, is_api_key=False)

    app.dependency_overrides[get_required_auth] = _mock_auth
    app.dependency_overrides[get_optional_auth] = _mock_auth
    return TestClient(app)


def _detail_code(response) -> str | None:
    body = response.json()
    detail = body.get("detail")
    if isinstance(detail, dict):
        return detail.get("code")
    return body.get("code")


def _mock_db_session_create() -> tuple[object, AsyncMock]:
    tenant_result = MagicMock()
    tenant_result.scalar_one_or_none.return_value = None
    session = AsyncMock()
    session.add = MagicMock()
    session.commit = AsyncMock()
    session.flush = AsyncMock()
    session.execute = AsyncMock(return_value=tenant_result)

    @asynccontextmanager
    async def _cm():
        yield session

    def factory():
        return _cm()

    return factory, session


def _added_scans(session: AsyncMock) -> list[Scan]:
    rows: list[Scan] = []
    for call in session.add.call_args_list:
        obj = call.args[0]
        if isinstance(obj, Scan):
            rows.append(obj)
    return rows


def test_create_scan_quick_flag_off_returns_400_quick_mode_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "quick_mode_enabled", False)
    response = _api_client().post(
        "/api/v1/scans",
        json={
            "target": _TARGET,
            "email": _EMAIL,
            "execution_mode": "quick",
        },
    )
    assert response.status_code == 400
    assert _detail_code(response) == "quick_mode_disabled"
    detail = response.json()["detail"]
    assert isinstance(detail, dict)
    assert "error" in detail


def test_create_scan_quick_flag_on_creates_queued_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "quick_mode_enabled", True)
    factory, session = _mock_db_session_create()
    with (
        patch("src.api.routers.scans.async_session_factory", factory),
        patch("src.api.routers.scans.try_pick_queued_scan", new_callable=AsyncMock),
        patch("src.api.routers.scans.record_scan_started"),
    ):
        response = _api_client().post(
            "/api/v1/scans",
            json={
                "target": _TARGET,
                "email": _EMAIL,
                "execution_mode": "quick",
                "quick": {"profile": "balanced"},
            },
        )
    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "queued"
    uuid.UUID(body["scan_id"])
    created = _added_scans(session)
    assert len(created) == 1
    assert created[0].execution_mode == "quick"
    assert created[0].scan_mode == "quick"
    assert created[0].quick_profile == "balanced"
    assert created[0].deadline_at is not None


def test_create_scan_legacy_post_without_execution_mode_still_works(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "quick_mode_enabled", False)
    factory, session = _mock_db_session_create()
    with (
        patch("src.api.routers.scans.async_session_factory", factory),
        patch("src.api.routers.scans.try_pick_queued_scan", new_callable=AsyncMock),
        patch("src.api.routers.scans.record_scan_started"),
    ):
        response = _api_client().post(
            "/api/v1/scans",
            json={"target": _TARGET, "email": _EMAIL},
        )
    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "queued"
    uuid.UUID(body["scan_id"])
    created = _added_scans(session)
    assert len(created) == 1
    assert created[0].execution_mode == "production"


def test_create_scan_lab_plus_quick_payload_returns_400_conflicting_execution_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "quick_mode_enabled", True)
    response = _api_client().post(
        "/api/v1/scans",
        json={
            "target": _TARGET,
            "email": _EMAIL,
            "execution_mode": "lab_unrestricted",
            "quick": {"profile": "compact"},
        },
    )
    assert response.status_code == 400
    assert _detail_code(response) == "conflicting_execution_mode"
