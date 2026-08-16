"""QUICK-007 — GET /api/v1/quick/profiles catalog contract.

Mini FastAPI app + TestClient. No live Postgres. Auth is stubbed locally.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from unittest.mock import patch

os.environ.setdefault("DEBUG", "true")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("JWT_SECRET", "test-secret-not-for-prod-but-required-by-settings")
os.environ.setdefault("ARGUS_TEST_MODE", "1")

import pytest  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

from src.api.routers import quick as quick_router  # noqa: E402
from src.core.auth import AuthContext, get_optional_auth, get_required_auth  # noqa: E402
from src.quick.profiles import QuickProfileCatalogError  # noqa: E402

_TENANT_ID = "00000000-0000-0000-0000-000000000001"
_CATALOG_FIELDS = (
    "name",
    "wall_clock_budget_seconds",
    "ai_budget_seconds",
    "reserve_for_validation_percent",
    "max_targets",
    "max_urls_per_host",
    "crawl_depth",
    "severity_floor",
    "enable_ai",
    "enable_oast",
    "enable_headless_on_signal",
    "request_budget",
    "per_host_budget",
    "concurrency_budget",
)
_SECRET_KEYS = frozenset(
    {
        "password",
        "token",
        "secret",
        "api_key",
        "argv",
        "command",
        "cmdline",
        "authenticated_context_id",
    }
)


@pytest.fixture(autouse=True)
def override_auth() -> Iterator[None]:
    """Do not boot the full FastAPI ``app`` — this module uses a mini client."""
    yield


def _api_client() -> TestClient:
    app = FastAPI()
    app.include_router(quick_router.router, prefix="/api/v1")

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


def test_list_quick_profiles_returns_three_named_budgets() -> None:
    response = _api_client().get("/api/v1/quick/profiles")
    assert response.status_code == 200
    body = response.json()
    assert "profiles" in body
    names = [item["name"] for item in body["profiles"]]
    assert names == ["compact", "balanced", "extended"]
    by_name = {item["name"]: item for item in body["profiles"]}
    assert by_name["compact"]["wall_clock_budget_seconds"] == 300
    assert by_name["balanced"]["wall_clock_budget_seconds"] == 900
    assert by_name["extended"]["wall_clock_budget_seconds"] == 1800
    for item in body["profiles"]:
        for field in _CATALOG_FIELDS:
            assert field in item, f"missing catalog field {field}"
        leaked = _SECRET_KEYS.intersection(item)
        assert not leaked, f"catalog leaked secret-like keys: {leaked}"


def test_list_quick_profiles_catalog_unavailable_returns_503() -> None:
    with patch(
        "src.api.routers.quick.load_quick_profiles",
        side_effect=QuickProfileCatalogError("quick_profile_catalog_unreadable"),
    ):
        response = _api_client().get("/api/v1/quick/profiles")
    assert response.status_code == 503
    assert _detail_code(response) == "quick_profile_catalog_unavailable"
    detail = response.json().get("detail")
    assert isinstance(detail, dict)
    assert "error" in detail
