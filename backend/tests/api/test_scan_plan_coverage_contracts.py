"""QUICK-007 — GET /scans/{id}/plan and GET /scans/{id}/coverage contracts.

Plan is 404 ``plan_not_applicable`` for non-quick scans. Coverage results
carry additive ``reason_code``. DB is mocked; coverage store is in-memory.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

os.environ.setdefault("DEBUG", "true")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("JWT_SECRET", "test-secret-not-for-prod-but-required-by-settings")
os.environ.setdefault("ARGUS_TEST_MODE", "1")

import pytest  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

from src.api.routers import scans as scans_router  # noqa: E402
from src.api.routers import unified_ai_lab as lab_api  # noqa: E402
from src.core.auth import AuthContext, get_optional_auth, get_required_auth  # noqa: E402
from src.orchestration.coverage_phase_sink import (  # noqa: E402
    attach_phase_coverage,
    get_coverage_store,
    signals_for_quick_reason,
)

_TENANT_ID = "00000000-0000-0000-0000-000000000001"
_SCAN_ID = "abcdabcd-abcd-4000-8000-abcdabcdabcd"


@pytest.fixture(autouse=True)
def override_auth() -> Iterator[None]:
    """Do not boot the full FastAPI ``app`` — this module uses a mini client."""
    yield


def _auth_overrides(app: FastAPI) -> None:
    async def _mock_auth() -> AuthContext:
        return AuthContext(user_id="test-user", tenant_id=_TENANT_ID, is_api_key=False)

    app.dependency_overrides[get_required_auth] = _mock_auth
    app.dependency_overrides[get_optional_auth] = _mock_auth


def _scans_client() -> TestClient:
    app = FastAPI()
    app.include_router(scans_router.router, prefix="/api/v1")
    _auth_overrides(app)
    return TestClient(app)


def _coverage_client() -> TestClient:
    app = FastAPI()
    app.include_router(lab_api.coverage_router, prefix="/api/v1")
    _auth_overrides(app)
    return TestClient(app)


def _detail_code(response) -> str | None:
    body = response.json()
    detail = body.get("detail")
    if isinstance(detail, dict):
        return detail.get("code")
    return body.get("code")


def _session_factory_for_scan(scan: MagicMock | None) -> object:
    scan_result = MagicMock()
    scan_result.scalar_one_or_none.return_value = scan
    session = AsyncMock()
    session.execute = AsyncMock(return_value=scan_result)

    @asynccontextmanager
    async def _cm():
        yield session

    def factory():
        return _cm()

    return factory


def _session_factory_for_plan(scan: MagicMock, plan_row: MagicMock | None) -> object:
    session = AsyncMock()
    calls = {"n": 0}

    async def _execute(stmt, *args, **kwargs):
        calls["n"] += 1
        result = MagicMock()
        # 1st query is Scan; subsequent queries are plan/config rows.
        result.scalar_one_or_none.return_value = scan if calls["n"] == 1 else plan_row
        return result

    session.execute = AsyncMock(side_effect=_execute)

    @asynccontextmanager
    async def _cm():
        yield session

    def factory():
        return _cm()

    return factory


def _production_scan() -> MagicMock:
    mock_scan = MagicMock()
    mock_scan.id = _SCAN_ID
    mock_scan.tenant_id = _TENANT_ID
    mock_scan.execution_mode = "production"
    mock_scan.quick_profile = None
    mock_scan.options = {}
    mock_scan.deadline_at = None
    return mock_scan


def _quick_scan() -> MagicMock:
    mock_scan = MagicMock()
    mock_scan.id = _SCAN_ID
    mock_scan.tenant_id = _TENANT_ID
    mock_scan.execution_mode = "quick"
    mock_scan.quick_profile = "balanced"
    mock_scan.options = {
        "quick_budget": {
            "wall_clock_budget_seconds": 900,
            "ai_budget_seconds": 90,
        }
    }
    mock_scan.deadline_at = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
    return mock_scan


@pytest.mark.parametrize("mode", ["production", "lab_unrestricted"])
def test_get_scan_plan_non_quick_returns_404_plan_not_applicable(mode: str) -> None:
    scan = _production_scan()
    scan.execution_mode = mode
    factory = _session_factory_for_scan(scan)
    with (
        patch("src.api.routers.scans.async_session_factory", factory),
        patch("src.api.routers.scans.set_session_tenant", new_callable=AsyncMock),
    ):
        response = _scans_client().get(f"/api/v1/scans/{_SCAN_ID}/plan")
    assert response.status_code == 404
    assert _detail_code(response) == "plan_not_applicable"
    detail = response.json()["detail"]
    assert isinstance(detail, dict)
    assert "error" in detail


def test_get_scan_plan_missing_scan_returns_404() -> None:
    factory = _session_factory_for_scan(None)
    with (
        patch("src.api.routers.scans.async_session_factory", factory),
        patch("src.api.routers.scans.set_session_tenant", new_callable=AsyncMock),
    ):
        response = _scans_client().get(f"/api/v1/scans/{uuid4()}/plan")
    assert response.status_code == 404
    assert _detail_code(response) != "plan_not_applicable"


def test_get_scan_plan_quick_returns_typed_plan_without_raw_command() -> None:
    scan = _quick_scan()
    plan_row = MagicMock()
    plan_row.plan_version = 1
    plan_row.deadline_at = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
    plan_row.budget = {
        "wall_clock_budget_seconds": 900,
        "ai_budget_seconds": 90,
        "profile": "balanced",
    }
    plan_row.stages = ["discovery", "fingerprint", "test", "verify", "triage", "report"]
    plan_row.tasks = [{"tool_id": "nuclei", "capability_id": "web.application.api.rest"}]
    plan_row.fallbacks = ["deterministic_planner"]
    plan_row.coverage_intent = [
        {"capability_id": "web.application.api.rest", "reason_code": "executed"}
    ]
    plan_row.assumptions = ["awaiting_fingerprint"]
    plan_row.prompt_version = "pending"
    plan_row.model_route = "deterministic"
    plan_row.revision_reason = None
    factory = _session_factory_for_plan(scan, plan_row)
    with (
        patch("src.api.routers.scans.async_session_factory", factory),
        patch("src.api.routers.scans.set_session_tenant", new_callable=AsyncMock),
    ):
        response = _scans_client().get(f"/api/v1/scans/{_SCAN_ID}/plan")
    assert response.status_code == 200
    body = response.json()
    assert body["scan_id"] == _SCAN_ID
    assert body["mode"] == "quick"
    assert body["profile"] == "balanced"
    assert body["plan_version"] == 1
    assert "deadline_at" in body
    assert body["budget"]["wall_clock_budget_seconds"] == 900
    assert isinstance(body["tasks"], list)
    dumped = str(body).lower()
    assert "argv" not in dumped
    assert '"command"' not in dumped


def test_get_scan_coverage_results_include_reason_code() -> None:
    get_coverage_store().clear()
    scan_id = "scan-cov-quick-1"
    attach_phase_coverage(
        phase="vuln_analysis",
        tenant_id=_TENANT_ID,
        scan_id=scan_id,
        asset_id="asset-1",
        signals=signals_for_quick_reason(
            tool_id="nuclei",
            quick_reason="not_scheduled_by_quick_profile",
            capability_id="web.application.api.rest",
        ),
        scan_options={"execution_mode": "quick"},
    )
    response = _coverage_client().get(f"/api/v1/scans/{scan_id}/coverage")
    assert response.status_code == 200
    body = response.json()
    assert body["scan_id"] == scan_id
    assert body["results"]
    for item in body["results"]:
        assert "reason_code" in item
    codes = {item.get("reason_code") for item in body["results"]}
    assert "not_scheduled_by_quick_profile" in codes
