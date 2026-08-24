"""POST /api/v1/scans canonical scan_profile contract (Requirements R1-R4).

Mocks ``async_session_factory`` — no live Postgres. Mirrors the style of
``test_scan_create_quick_flag.py``.
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

from src.api.errors import register_profile_error_handler  # noqa: E402
from src.api.routers import scans as scans_router  # noqa: E402
from src.core.auth import AuthContext, get_optional_auth, get_required_auth  # noqa: E402
from src.core.config import settings  # noqa: E402
from src.db.models import Scan  # noqa: E402

_TENANT_ID = "00000000-0000-0000-0000-000000000001"
_TARGET = "https://example.com"
_EMAIL = "user@example.com"


@pytest.fixture(autouse=True)
def override_auth() -> Iterator[None]:
    yield


@pytest.fixture(autouse=True)
def _quick_enabled(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(settings, "quick_mode_enabled", True)
    yield


def _api_client() -> TestClient:
    app = FastAPI()
    app.include_router(scans_router.router, prefix="/api/v1")
    register_profile_error_handler(app)

    async def _mock_auth() -> AuthContext:
        return AuthContext(user_id="test-user", tenant_id=_TENANT_ID, is_api_key=False)

    app.dependency_overrides[get_required_auth] = _mock_auth
    app.dependency_overrides[get_optional_auth] = _mock_auth
    return TestClient(app, raise_server_exceptions=False)


def _code(response) -> str | None:
    body = response.json()
    if isinstance(body.get("code"), str):
        return body["code"]
    detail = body.get("detail")
    if isinstance(detail, dict):
        return detail.get("code")
    return None


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
    return [c.args[0] for c in session.add.call_args_list if isinstance(c.args[0], Scan)]


def _post(json_body: dict):
    factory, session = _mock_db_session_create()
    with (
        patch("src.api.routers.scans.async_session_factory", factory),
        patch("src.api.routers.scans.try_pick_queued_scan", new_callable=AsyncMock),
        patch("src.api.routers.scans.record_scan_started"),
    ):
        response = _api_client().post("/api/v1/scans", json=json_body)
    return response, session


def test_scan_profile_quick_resolves_quick_quick_balanced():
    response, session = _post(
        {"target": _TARGET, "email": _EMAIL, "scan_profile": "quick"}
    )
    assert response.status_code == 201, response.text
    scan = _added_scans(session)[0]
    assert scan.scan_profile == "quick"
    assert scan.scan_mode == "quick"
    assert scan.execution_mode == "quick"
    assert scan.quick_profile == "balanced"
    assert scan.nuclei_profile == "quick-default"
    assert scan.profile_version == "v1"


def test_scan_profile_quick_honours_quick_profile_hint():
    response, session = _post(
        {
            "target": _TARGET,
            "email": _EMAIL,
            "scan_profile": "quick",
            "quick": {"profile": "extended"},
        }
    )
    assert response.status_code == 201, response.text
    scan = _added_scans(session)[0]
    assert scan.quick_profile == "extended"


def test_scan_profile_light_resolves_standard_production():
    response, session = _post(
        {"target": _TARGET, "email": _EMAIL, "scan_profile": "light"}
    )
    assert response.status_code == 201, response.text
    scan = _added_scans(session)[0]
    assert scan.scan_profile == "light"
    assert scan.scan_mode == "standard"
    assert scan.execution_mode == "production"
    assert scan.nuclei_profile == "vuln_default"


def test_scan_profile_deep_without_engagement_denied():
    response, _ = _post({"target": _TARGET, "email": _EMAIL, "scan_profile": "deep"})
    assert response.status_code == 422
    assert _code(response) == "lab_engagement_required"


def test_scan_profile_deep_without_lease_denied():
    response, _ = _post(
        {
            "target": _TARGET,
            "email": _EMAIL,
            "scan_profile": "deep",
            "engagement_id": "engagement-uuid",
        }
    )
    assert response.status_code == 422
    body = response.json()
    assert _code(response) == "lab_lease_required"
    assert body.get("details", {}).get("required_action") == "issue_or_select_lab_lease"


def test_scan_profile_invalid_returns_422():
    response, _ = _post(
        {"target": _TARGET, "email": _EMAIL, "scan_profile": "nuclear"}
    )
    # Pydantic Literal rejects it at validation time (422 validation_error) OR our
    # resolver rejects invalid values (invalid_scan_profile). Either is a 422.
    assert response.status_code == 422


def test_scan_profile_conflicts_with_legacy_scan_mode():
    response, _ = _post(
        {
            "target": _TARGET,
            "email": _EMAIL,
            "scan_profile": "deep",
            "scan_mode": "standard",
        }
    )
    assert response.status_code == 422
    assert _code(response) == "conflicting_profile_fields"


def test_scan_profile_deep_with_matching_legacy_scan_mode_reaches_lease_check():
    """Legacy scan_mode=lab matches deep resolution → no conflict, proceeds to lease gate."""
    response, _ = _post(
        {
            "target": _TARGET,
            "email": _EMAIL,
            "scan_profile": "deep",
            "scan_mode": "lab",
        }
    )
    # No conflict; deep still requires a lease → lab_engagement_required.
    assert response.status_code == 422
    assert _code(response) == "lab_engagement_required"


def test_legacy_path_still_works_without_scan_profile():
    response, session = _post({"target": _TARGET, "email": _EMAIL})
    assert response.status_code == 201, response.text
    scan = _added_scans(session)[0]
    assert scan.scan_profile is None
    assert scan.execution_mode == "production"
