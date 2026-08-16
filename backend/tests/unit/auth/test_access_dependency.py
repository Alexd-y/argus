"""Tests for the opt-in ABAC authorization dependency (F-M05).

Covers the three operating modes (passthrough / advisory / enforce), role
resolution (JWT claim → default → viewer fallback), anonymous passthrough,
and the resource-id audit field.
"""

from __future__ import annotations

import logging
from types import SimpleNamespace

import pytest
from fastapi import Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient

from src.auth import access_dependency
from src.auth.abac import AccessAction, ResourceType, Role
from src.auth.access_dependency import require_access
from src.core.auth import AuthContext, get_optional_auth


def _request(path_params: dict[str, str] | None = None) -> SimpleNamespace:
    """Minimal stand-in for starlette.Request — only ``path_params`` is read."""
    return SimpleNamespace(path_params=path_params or {})


def _auth(role: str | None = None) -> AuthContext:
    return AuthContext(
        user_id="user-1",
        tenant_id="11111111-1111-1111-1111-111111111111",
        is_api_key=False,
        role=role,
    )


@pytest.fixture
def abac(monkeypatch: pytest.MonkeyPatch):
    """Helper to flip ABAC settings on the shared singleton per-test."""

    def _set(*, enabled: bool, enforce: bool = False, default_role: str = "org_admin") -> None:
        monkeypatch.setattr(access_dependency.settings, "abac_enabled", enabled)
        monkeypatch.setattr(access_dependency.settings, "abac_enforce", enforce)
        monkeypatch.setattr(access_dependency.settings, "abac_default_role", default_role)

    return _set


# ---------------------------------------------------------------------------
# Passthrough (master switch off)
# ---------------------------------------------------------------------------


async def test_passthrough_when_disabled_never_denies(abac):
    """Disabled ABAC returns auth unchanged even for a would-be denial."""
    abac(enabled=False)
    dep = access_dependency.require_access(AccessAction.WRITE, ResourceType.FINDING)

    # viewer WRITE on finding is denied by policy, but the switch is off.
    result = await dep(_request(), _auth(role="viewer"))

    assert result is not None
    assert result.user_id == "user-1"


async def test_anonymous_request_passthrough(abac):
    """No auth → nothing to authorize; return None without evaluating."""
    abac(enabled=True, enforce=True)
    dep = access_dependency.require_access(AccessAction.WRITE, ResourceType.FINDING)

    assert await dep(_request(), None) is None


# ---------------------------------------------------------------------------
# Advisory mode
# ---------------------------------------------------------------------------


async def test_advisory_logs_but_allows_on_deny(abac, caplog):
    abac(enabled=True, enforce=False)
    dep = access_dependency.require_access(AccessAction.WRITE, ResourceType.FINDING)

    with caplog.at_level(logging.WARNING, logger=access_dependency.logger.name):
        result = await dep(_request(), _auth(role="viewer"))

    # Advisory never blocks.
    assert result is not None
    assert any("abac_denied_advisory" in r.message for r in caplog.records)


async def test_advisory_allows_permitted_without_denial_log(abac, caplog):
    abac(enabled=True, enforce=False)
    dep = access_dependency.require_access(AccessAction.READ, ResourceType.FINDING)

    with caplog.at_level(logging.WARNING, logger=access_dependency.logger.name):
        result = await dep(_request(), _auth(role="viewer"))

    assert result is not None
    assert not any("abac_denied" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# Enforcing mode
# ---------------------------------------------------------------------------


async def test_enforce_raises_403_on_deny(abac):
    abac(enabled=True, enforce=True)
    dep = access_dependency.require_access(AccessAction.WRITE, ResourceType.FINDING)

    with pytest.raises(HTTPException) as exc:
        await dep(_request(), _auth(role="viewer"))

    assert exc.value.status_code == 403


async def test_enforce_allows_permitted(abac):
    abac(enabled=True, enforce=True)
    dep = access_dependency.require_access(AccessAction.WRITE, ResourceType.FINDING)

    result = await dep(_request(), _auth(role="developer"))

    assert result is not None
    assert result.user_id == "user-1"


# ---------------------------------------------------------------------------
# Role resolution
# ---------------------------------------------------------------------------


async def test_default_role_used_when_claim_absent(abac):
    """No role claim → settings.abac_default_role governs the decision."""
    abac(enabled=True, enforce=True, default_role="viewer")
    dep = access_dependency.require_access(AccessAction.WRITE, ResourceType.FINDING)

    # viewer default cannot WRITE.
    with pytest.raises(HTTPException):
        await dep(_request(), _auth(role=None))


async def test_default_org_admin_allows_broad_access(abac):
    abac(enabled=True, enforce=True, default_role="org_admin")
    dep = access_dependency.require_access(AccessAction.WRITE, ResourceType.SCAN)

    result = await dep(_request(), _auth(role=None))

    assert result is not None


async def test_unknown_role_falls_back_to_viewer(abac, caplog):
    """A bogus role string is treated as least-privileged viewer + logged."""
    abac(enabled=True, enforce=True)
    read_dep = access_dependency.require_access(AccessAction.READ, ResourceType.FINDING)
    write_dep = access_dependency.require_access(AccessAction.WRITE, ResourceType.FINDING)

    with caplog.at_level(logging.WARNING, logger=access_dependency.logger.name):
        # viewer can READ …
        assert await read_dep(_request(), _auth(role="wizard")) is not None
        # … but cannot WRITE.
        with pytest.raises(HTTPException):
            await write_dep(_request(), _auth(role="wizard"))

    assert any("abac_unknown_role_fallback_viewer" in r.message for r in caplog.records)


async def test_role_claim_case_insensitive(abac):
    abac(enabled=True, enforce=True)
    dep = access_dependency.require_access(AccessAction.WRITE, ResourceType.FINDING)

    # "DEVELOPER" (upper) normalizes to Role.DEVELOPER which may write findings.
    result = await dep(_request(), _auth(role="DEVELOPER"))

    assert result is not None


# ---------------------------------------------------------------------------
# Audit field
# ---------------------------------------------------------------------------


async def test_resource_id_param_recorded_in_denial_log(abac, caplog):
    abac(enabled=True, enforce=False)
    dep = access_dependency.require_access(
        AccessAction.WRITE,
        ResourceType.FINDING,
        resource_id_param="finding_id",
    )

    with caplog.at_level(logging.WARNING, logger=access_dependency.logger.name):
        await dep(_request({"finding_id": "abc-123"}), _auth(role="viewer"))

    denial = next(r for r in caplog.records if "abac_denied_advisory" in r.message)
    assert getattr(denial, "resource_id", "") == "abc-123"


def test_resolve_role_helper_direct():
    assert access_dependency._resolve_role(_auth(role="org_admin")) is Role.ORG_ADMIN


# ---------------------------------------------------------------------------
# FastAPI integration — proves the dependency is reachable through real DI
# (Request injection + nested Depends(get_optional_auth) chain).
# ---------------------------------------------------------------------------


def _build_app() -> FastAPI:
    app = FastAPI()

    @app.get("/finding/{finding_id}")
    async def _route(
        finding_id: str,
        _access: object = Depends(
            require_access(
                AccessAction.WRITE,
                ResourceType.FINDING,
                resource_id_param="finding_id",
            )
        ),
    ) -> dict[str, object]:
        return {"ok": True, "finding_id": finding_id}

    return app


def test_integration_enforce_blocks_low_privilege(abac):
    abac(enabled=True, enforce=True)
    app = _build_app()
    app.dependency_overrides[get_optional_auth] = lambda: _auth(role="viewer")

    resp = TestClient(app).get("/finding/f1")

    assert resp.status_code == 403


def test_integration_enforce_allows_privileged(abac):
    abac(enabled=True, enforce=True)
    app = _build_app()
    app.dependency_overrides[get_optional_auth] = lambda: _auth(role="developer")

    resp = TestClient(app).get("/finding/f1")

    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "finding_id": "f1"}


def test_integration_advisory_allows_low_privilege(abac):
    abac(enabled=True, enforce=False)
    app = _build_app()
    app.dependency_overrides[get_optional_auth] = lambda: _auth(role="viewer")

    resp = TestClient(app).get("/finding/f1")

    assert resp.status_code == 200


def test_integration_disabled_passthrough(abac):
    abac(enabled=False)
    app = _build_app()
    app.dependency_overrides[get_optional_auth] = lambda: _auth(role="viewer")

    resp = TestClient(app).get("/finding/f1")

    assert resp.status_code == 200
