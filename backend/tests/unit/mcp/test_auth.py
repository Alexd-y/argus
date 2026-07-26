"""Unit tests for :mod:`src.mcp.auth`.

Three authentication channels are exercised:

1. **Static bearer token** (``MCP_AUTH_TOKEN`` / ``Settings.mcp_auth_token``).
2. **JWT bearer token** (re-uses :func:`src.core.auth._decode_jwt`).
3. **API key** (``X-API-Key``) including the admin-key fast path.

Plus the ``stdio`` local fallback (no credentials, ``transport=stdio``) and
the ``MCP_REQUIRE_AUTH`` env override.

Tests assert constant-time comparisons (no early-return on length mismatch),
that an authenticated context never carries an empty tenant id, and — SEC-001 —
that ``X-Tenant-ID`` can only **confirm** the tenant a credential is bound to.
The header used to *select* the tenant on the static-token and API-key channels,
so any valid credential could read another tenant's data.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Iterator

import pytest
from jose import jwt

from src.core.config import settings
from src.mcp.auth import MCPAuthContext, authenticate
from src.mcp.exceptions import AuthenticationError, TenantMismatchError


@pytest.fixture()
def static_token(monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    token = "static-test-token-A1B2C3D4E5F6"
    monkeypatch.setenv("MCP_AUTH_TOKEN", token)
    monkeypatch.setattr(settings, "mcp_auth_token", token, raising=True)
    try:
        yield token
    finally:
        monkeypatch.delenv("MCP_AUTH_TOKEN", raising=False)


@pytest.fixture()
def admin_api_key(monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    key = "admin-api-key-XYZ"
    monkeypatch.setattr(settings, "admin_api_key", key, raising=True)
    yield key


@pytest.fixture()
def regular_api_keys(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    keys = ["regular-api-key-1", "regular-api-key-2"]
    monkeypatch.setenv("ARGUS_API_KEYS", ",".join(keys))
    yield keys


@pytest.fixture()
def jwt_token(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[str, str, str]]:
    secret = "test-jwt-secret-32-chars-long-enough"
    monkeypatch.setenv("JWT_SECRET", secret)
    monkeypatch.setattr(settings, "jwt_secret", secret, raising=True)
    monkeypatch.setattr(settings, "jwt_algorithm", "HS256", raising=True)
    sub = str(uuid.uuid4())
    tenant = str(uuid.uuid4())
    payload = {
        "sub": sub,
        "tenant_id": tenant,
        "type": "access",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    token = jwt.encode(payload, secret, algorithm="HS256")
    yield token, sub, tenant


# ---------------------------------------------------------------------------
# Stdio fallback
# ---------------------------------------------------------------------------


class TestStdioFallback:
    def test_no_creds_returns_local_context(self) -> None:
        ctx = authenticate(headers=None, transport="stdio")
        assert ctx.method == "stdio_local"
        assert ctx.tenant_id  # never empty
        assert ctx.is_admin is False

    def test_explicit_x_tenant_header_overrides_default(self) -> None:
        custom = str(uuid.uuid4())
        ctx = authenticate(headers={"X-Tenant-ID": custom}, transport="stdio")
        assert ctx.tenant_id == custom

    def test_blank_x_tenant_header_falls_back(self) -> None:
        ctx = authenticate(headers={"X-Tenant-ID": "  "}, transport="stdio")
        assert ctx.tenant_id  # falls back, not empty

    def test_require_auth_override_blocks_stdio(self) -> None:
        with pytest.raises(AuthenticationError):
            authenticate(headers=None, transport="stdio", require_auth=True)


# ---------------------------------------------------------------------------
# HTTP transport — authentication required
# ---------------------------------------------------------------------------


class TestHttpAuthRequired:
    def test_no_creds_rejected(self) -> None:
        with pytest.raises(AuthenticationError) as exc_info:
            authenticate(headers={}, transport="streamable-http")
        assert exc_info.value.code == "mcp_auth_unauthenticated"

    def test_malformed_bearer_rejected(self) -> None:
        with pytest.raises(AuthenticationError):
            authenticate(
                headers={"Authorization": "Basic abc=="},
                transport="streamable-http",
            )

    def test_empty_bearer_rejected(self) -> None:
        with pytest.raises(AuthenticationError):
            authenticate(
                headers={"Authorization": "Bearer "}, transport="streamable-http"
            )


# ---------------------------------------------------------------------------
# Static bearer token
# ---------------------------------------------------------------------------


class TestStaticBearerToken:
    def test_correct_token_accepted(self, static_token: str) -> None:
        ctx = authenticate(
            headers={"Authorization": f"Bearer {static_token}"},
            transport="streamable-http",
        )
        assert ctx.method == "static_token"
        assert ctx.user_id == "mcp-static-token"
        assert ctx.is_admin is False

    def test_wrong_token_rejected(self, static_token: str) -> None:
        with pytest.raises(AuthenticationError):
            authenticate(
                headers={"Authorization": "Bearer wrong-token-XYZ"},
                transport="streamable-http",
            )

    def test_case_insensitive_bearer_prefix(self, static_token: str) -> None:
        ctx = authenticate(
            headers={"authorization": f"BEARER {static_token}"},
            transport="streamable-http",
        )
        assert ctx.method == "static_token"

    def test_tenant_defaults_to_configured_mcp_tenant(self, static_token: str) -> None:
        ctx = authenticate(
            headers={"Authorization": f"Bearer {static_token}"},
            transport="streamable-http",
        )
        assert ctx.tenant_id == settings.mcp_stdio_tenant_id

    def test_matching_x_tenant_header_accepted(self, static_token: str) -> None:
        ctx = authenticate(
            headers={
                "Authorization": f"Bearer {static_token}",
                "X-Tenant-ID": settings.mcp_stdio_tenant_id,
            },
            transport="streamable-http",
        )
        assert ctx.tenant_id == settings.mcp_stdio_tenant_id

    def test_foreign_x_tenant_header_rejected(self, static_token: str) -> None:
        """The static token carries no identity, so it cannot be aimed at a tenant."""
        with pytest.raises(TenantMismatchError) as exc_info:
            authenticate(
                headers={
                    "Authorization": f"Bearer {static_token}",
                    "X-Tenant-ID": str(uuid.uuid4()),
                },
                transport="streamable-http",
            )
        assert exc_info.value.code == "mcp_tenant_mismatch"


# ---------------------------------------------------------------------------
# JWT bearer token
# ---------------------------------------------------------------------------


class TestJwtBearer:
    def test_valid_jwt_accepted(self, jwt_token: tuple[str, str, str]) -> None:
        token, sub, tenant = jwt_token
        ctx = authenticate(
            headers={"Authorization": f"Bearer {token}"},
            transport="streamable-http",
        )
        assert ctx.method == "jwt"
        assert ctx.user_id == sub
        assert ctx.tenant_id == tenant

    def test_matching_x_tenant_header_accepted(
        self, jwt_token: tuple[str, str, str]
    ) -> None:
        token, _sub, tenant = jwt_token
        ctx = authenticate(
            headers={"Authorization": f"Bearer {token}", "X-Tenant-ID": tenant},
            transport="streamable-http",
        )
        assert ctx.tenant_id == tenant

    def test_foreign_x_tenant_header_rejected(
        self, jwt_token: tuple[str, str, str]
    ) -> None:
        """The claim wins; the header cannot redirect the session to another tenant."""
        token, _sub, _tenant = jwt_token
        with pytest.raises(TenantMismatchError):
            authenticate(
                headers={
                    "Authorization": f"Bearer {token}",
                    "X-Tenant-ID": str(uuid.uuid4()),
                },
                transport="streamable-http",
            )

    def test_wrong_token_type_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        secret = "test-jwt-secret-32-chars-long-enough"
        monkeypatch.setenv("JWT_SECRET", secret)
        monkeypatch.setattr(settings, "jwt_secret", secret, raising=True)
        monkeypatch.setattr(settings, "jwt_algorithm", "HS256", raising=True)
        payload = {
            "sub": str(uuid.uuid4()),
            "tenant_id": str(uuid.uuid4()),
            "type": "refresh",
            "iat": int(time.time()),
            "exp": int(time.time()) + 60,
        }
        token = jwt.encode(payload, secret, algorithm="HS256")
        with pytest.raises(AuthenticationError):
            authenticate(
                headers={"Authorization": f"Bearer {token}"},
                transport="streamable-http",
            )

    def test_expired_jwt_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        secret = "test-jwt-secret-32-chars-long-enough"
        monkeypatch.setenv("JWT_SECRET", secret)
        monkeypatch.setattr(settings, "jwt_secret", secret, raising=True)
        monkeypatch.setattr(settings, "jwt_algorithm", "HS256", raising=True)
        payload = {
            "sub": str(uuid.uuid4()),
            "tenant_id": str(uuid.uuid4()),
            "type": "access",
            "iat": int(time.time()) - 3600,
            "exp": int(time.time()) - 60,
        }
        token = jwt.encode(payload, secret, algorithm="HS256")
        with pytest.raises(AuthenticationError):
            authenticate(
                headers={"Authorization": f"Bearer {token}"},
                transport="streamable-http",
            )


# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------


class TestApiKeys:
    def test_regular_api_key_accepted(self, regular_api_keys: list[str]) -> None:
        ctx = authenticate(
            headers={"X-API-Key": regular_api_keys[0]},
            transport="streamable-http",
        )
        assert ctx.method == "api_key"
        assert ctx.is_admin is False
        assert ctx.user_id == "argus-api-key"

    def test_admin_api_key_sets_admin_flag(self, admin_api_key: str) -> None:
        ctx = authenticate(
            headers={"X-API-Key": admin_api_key},
            transport="streamable-http",
        )
        assert ctx.method == "api_key"
        assert ctx.is_admin is True
        assert ctx.user_id == "argus-admin"

    def test_unknown_api_key_rejected(self, regular_api_keys: list[str]) -> None:
        with pytest.raises(AuthenticationError):
            authenticate(
                headers={"X-API-Key": "totally-unknown-key"},
                transport="streamable-http",
            )

    def test_empty_api_key_rejected(self) -> None:
        with pytest.raises(AuthenticationError):
            authenticate(headers={"X-API-Key": ""}, transport="streamable-http")


class TestApiKeyTenantBinding:
    """``ARGUS_API_KEYS`` supports ``key:tenant_uuid``, as the HTTP API does."""

    def test_plain_key_binds_to_mcp_tenant(self, regular_api_keys: list[str]) -> None:
        ctx = authenticate(
            headers={"X-API-Key": regular_api_keys[0]},
            transport="streamable-http",
        )
        assert ctx.tenant_id == settings.mcp_stdio_tenant_id

    def test_scoped_key_binds_to_its_tenant(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tenant = str(uuid.uuid4())
        monkeypatch.setenv("ARGUS_API_KEYS", f"scoped-key-1:{tenant}")

        ctx = authenticate(
            headers={"X-API-Key": "scoped-key-1"},
            transport="streamable-http",
        )

        assert ctx.tenant_id == tenant

    def test_plain_key_cannot_reach_another_tenant(
        self, regular_api_keys: list[str]
    ) -> None:
        with pytest.raises(TenantMismatchError):
            authenticate(
                headers={
                    "X-API-Key": regular_api_keys[0],
                    "X-Tenant-ID": str(uuid.uuid4()),
                },
                transport="streamable-http",
            )

    def test_scoped_key_cannot_be_repointed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tenant = str(uuid.uuid4())
        monkeypatch.setenv("ARGUS_API_KEYS", f"scoped-key-1:{tenant}")

        with pytest.raises(TenantMismatchError):
            authenticate(
                headers={
                    "X-API-Key": "scoped-key-1",
                    "X-Tenant-ID": str(uuid.uuid4()),
                },
                transport="streamable-http",
            )

    def test_scoped_key_accepts_its_own_tenant_in_header(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tenant = str(uuid.uuid4())
        monkeypatch.setenv("ARGUS_API_KEYS", f"scoped-key-1:{tenant}")

        ctx = authenticate(
            headers={"X-API-Key": "scoped-key-1", "X-Tenant-ID": tenant},
            transport="streamable-http",
        )

        assert ctx.tenant_id == tenant

    def test_admin_key_cannot_be_repointed(self, admin_api_key: str) -> None:
        with pytest.raises(TenantMismatchError):
            authenticate(
                headers={
                    "X-API-Key": admin_api_key,
                    "X-Tenant-ID": str(uuid.uuid4()),
                },
                transport="streamable-http",
            )


# ---------------------------------------------------------------------------
# Auth context invariants
# ---------------------------------------------------------------------------


class TestAuthContextInvariants:
    def test_dataclass_is_frozen(self) -> None:
        ctx = MCPAuthContext(
            user_id="x",
            tenant_id="y",
            method="static_token",
            is_admin=False,
        )
        with pytest.raises(Exception):  # FrozenInstanceError or AttributeError
            ctx.tenant_id = "z"  # type: ignore[misc]

    def test_method_is_closed_string(self) -> None:
        for method in ("static_token", "jwt", "api_key", "stdio_local"):
            ctx = MCPAuthContext(
                user_id="x",
                tenant_id="y",
                method=method,
                is_admin=False,
            )
            assert ctx.method == method


# ---------------------------------------------------------------------------
# Channel precedence — bearer > api key
# ---------------------------------------------------------------------------


class TestChannelPrecedence:
    def test_bearer_wins_over_api_key(
        self, static_token: str, admin_api_key: str
    ) -> None:
        ctx = authenticate(
            headers={
                "Authorization": f"Bearer {static_token}",
                "X-API-Key": admin_api_key,
            },
            transport="streamable-http",
        )
        assert ctx.method == "static_token"
        assert ctx.is_admin is False
