"""SEC-001 enforcement on the WebSocket transport (``src.api.routers.ws``).

The WebSocket routes cannot use the ``get_current_tenant_id`` FastAPI dependency,
so ``_resolve_ws_tenant`` reproduces its decision table at handshake time. These
tests pin that contract:

* an unauthenticated handshake is always refused — previously the endpoints read
  ``X-Tenant-ID``/``?tenant_id`` and accepted the connection, which bypassed
  tenant isolation entirely even in production;
* the tenant always comes from the principal, and a disagreeing tenant hint is a
  cross-tenant pivot attempt (denied), whether it arrives as a header or as a
  query parameter (browsers can only use the latter).

Pure unit tests: no FastAPI app, no DB, no live socket.
"""

from __future__ import annotations

from typing import Any

import pytest

from src.api.routers.ws import (
    _WS_CLOSE_FORBIDDEN,
    _WS_CLOSE_UNAUTHORIZED,
    _resolve_ws_tenant,
)
from src.core.auth import create_access_token
from src.core.config import settings

_SCAN_ID = "scan-1234"
_DEFAULT_TENANT = "tenant-default"
_VICTIM_TENANT = "tenant-victim"


class _FakeWebSocket:
    """Minimal stand-in for the Starlette ``WebSocket`` handshake surface."""

    def __init__(
        self,
        headers: dict[str, str] | None = None,
        query_params: dict[str, str] | None = None,
    ) -> None:
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.query_params = dict(query_params or {})
        self.closed_with: tuple[int, str] | None = None
        self.accepted = False

    async def accept(self) -> None:
        self.accepted = True

    async def close(self, code: int = 1000, reason: str = "") -> None:
        self.closed_with = (code, reason)


@pytest.fixture(autouse=True)
def _tenant_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """Deterministic tenant configuration for every test in this module."""
    monkeypatch.setattr(settings, "default_tenant_id", _DEFAULT_TENANT)
    monkeypatch.setattr(settings, "api_keys", [])


class TestUnauthenticatedHandshake:
    """A credential-less handshake is refused unconditionally."""

    async def test_no_credentials_is_denied(self) -> None:
        ws = _FakeWebSocket()

        assert await _resolve_ws_tenant(ws, _SCAN_ID) is None
        assert ws.closed_with == (_WS_CLOSE_UNAUTHORIZED, "Authentication required")
        assert ws.accepted is False

    async def test_tenant_header_alone_cannot_select_a_tenant(self) -> None:
        """The core bypass: a bare ``X-Tenant-ID`` must not grant tenant access."""
        ws = _FakeWebSocket(headers={"X-Tenant-ID": _VICTIM_TENANT})

        assert await _resolve_ws_tenant(ws, _SCAN_ID) is None
        assert ws.closed_with == (_WS_CLOSE_UNAUTHORIZED, "Authentication required")

    async def test_tenant_query_param_alone_cannot_select_a_tenant(self) -> None:
        """Browsers cannot set headers, so the query-param path needs the same gate."""
        ws = _FakeWebSocket(query_params={"tenant_id": _VICTIM_TENANT})

        assert await _resolve_ws_tenant(ws, _SCAN_ID) is None
        assert ws.closed_with == (_WS_CLOSE_UNAUTHORIZED, "Authentication required")

    async def test_default_tenant_is_not_an_anonymous_fallback(self) -> None:
        """Asking for the default tenant is still anonymous access."""
        ws = _FakeWebSocket(headers={"X-Tenant-ID": _DEFAULT_TENANT})

        assert await _resolve_ws_tenant(ws, _SCAN_ID) is None
        assert ws.closed_with == (_WS_CLOSE_UNAUTHORIZED, "Authentication required")

    async def test_invalid_bearer_token_is_denied(self) -> None:
        ws = _FakeWebSocket(headers={"Authorization": "Bearer not-a-real-jwt"})

        assert await _resolve_ws_tenant(ws, _SCAN_ID) is None
        assert ws.closed_with == (_WS_CLOSE_UNAUTHORIZED, "Authentication required")

    async def test_unknown_api_key_is_denied(self) -> None:
        ws = _FakeWebSocket(headers={"X-API-Key": "not-a-configured-key"})

        assert await _resolve_ws_tenant(ws, _SCAN_ID) is None
        assert ws.closed_with == (_WS_CLOSE_UNAUTHORIZED, "Authentication required")


class TestAuthenticatedHandshake:
    """The principal's tenant is authoritative."""

    async def test_jwt_in_header_resolves_principal_tenant(self) -> None:
        token = create_access_token("operator-1", "tenant-a")
        ws = _FakeWebSocket(headers={"Authorization": f"Bearer {token}"})

        resolved = await _resolve_ws_tenant(ws, _SCAN_ID)

        assert resolved is not None
        tenant_id, auth = resolved
        assert tenant_id == "tenant-a"
        assert auth is not None
        assert auth.user_id == "operator-1"
        assert ws.closed_with is None

    async def test_jwt_in_query_param_is_accepted(self) -> None:
        """Browser WebSocket clients pass the token as ``?token=``."""
        token = create_access_token("operator-1", "tenant-a")
        ws = _FakeWebSocket(query_params={"token": token})

        resolved = await _resolve_ws_tenant(ws, _SCAN_ID)

        assert resolved is not None
        assert resolved[0] == "tenant-a"

    async def test_api_key_resolves_its_bound_tenant(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(settings, "api_keys", ["svc-key-1:tenant-b"])
        ws = _FakeWebSocket(headers={"X-API-Key": "svc-key-1"})

        resolved = await _resolve_ws_tenant(ws, _SCAN_ID)

        assert resolved is not None
        tenant_id, auth = resolved
        assert tenant_id == "tenant-b"
        assert auth is not None
        assert auth.is_api_key is True

    async def test_matching_tenant_hint_is_accepted(self) -> None:
        token = create_access_token("operator-1", "tenant-a")
        ws = _FakeWebSocket(
            headers={"Authorization": f"Bearer {token}", "X-Tenant-ID": "tenant-a"}
        )

        resolved = await _resolve_ws_tenant(ws, _SCAN_ID)

        assert resolved is not None
        assert resolved[0] == "tenant-a"
        assert ws.closed_with is None


class TestCrossTenantPivot:
    """A tenant hint that disagrees with the principal is refused."""

    @pytest.mark.parametrize(
        ("headers", "query_params"),
        [
            ({"X-Tenant-ID": _VICTIM_TENANT}, {}),
            ({}, {"tenant_id": _VICTIM_TENANT}),
        ],
        ids=["header", "query_param"],
    )
    async def test_conflicting_tenant_is_denied(
        self,
        headers: dict[str, str],
        query_params: dict[str, str],
    ) -> None:
        token = create_access_token("operator-1", "tenant-a")
        ws = _FakeWebSocket(
            headers={"Authorization": f"Bearer {token}", **headers},
            query_params=query_params,
        )

        assert await _resolve_ws_tenant(ws, _SCAN_ID) is None
        assert ws.closed_with == (_WS_CLOSE_FORBIDDEN, "Tenant mismatch")
        assert ws.accepted is False

    async def test_scoped_api_key_cannot_be_repointed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(settings, "api_keys", ["svc-key-1:tenant-b"])
        ws = _FakeWebSocket(
            headers={"X-API-Key": "svc-key-1", "X-Tenant-ID": _VICTIM_TENANT}
        )

        assert await _resolve_ws_tenant(ws, _SCAN_ID) is None
        assert ws.closed_with == (_WS_CLOSE_FORBIDDEN, "Tenant mismatch")


class TestNoOptOut:
    """There is no configuration that restores the anonymous path."""

    def test_require_tenant_auth_flag_is_gone(self) -> None:
        assert not hasattr(settings, "require_tenant_auth")


class TestCredentialExtraction:
    """Whitespace/prefix handling around the handshake credential."""

    @pytest.mark.parametrize("scheme", ["Bearer", "bearer", "BEARER"])
    async def test_bearer_scheme_is_case_insensitive(self, scheme: str) -> None:
        token = create_access_token("operator-1", "tenant-a")
        ws = _FakeWebSocket(headers={"Authorization": f"{scheme} {token}"})

        resolved = await _resolve_ws_tenant(ws, _SCAN_ID)

        assert resolved is not None
        assert resolved[0] == "tenant-a"

    async def test_blank_tenant_hint_is_ignored(self) -> None:
        token = create_access_token("operator-1", "tenant-a")
        ws = _FakeWebSocket(
            headers={"Authorization": f"Bearer {token}", "X-Tenant-ID": "   "}
        )

        resolved = await _resolve_ws_tenant(ws, _SCAN_ID)

        assert resolved is not None
        assert resolved[0] == "tenant-a"

    async def test_close_failure_does_not_propagate(self) -> None:
        """A client that vanished mid-handshake must not surface as a 500."""

        class _BrokenWebSocket(_FakeWebSocket):
            async def close(self, code: int = 1000, reason: str = "") -> None:
                raise RuntimeError("transport already gone")

        ws: Any = _BrokenWebSocket()

        assert await _resolve_ws_tenant(ws, _SCAN_ID) is None
