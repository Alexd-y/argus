"""SEC-001 regression tests for credential resolution (src.core.auth).

Service clients (e2e harness, nginx gateway) are documented to present a
provisioned ``ARGUS_API_KEYS`` value. Both supported transports must resolve to
the same authenticated context:

* ``X-API-Key: <key>``
* ``Authorization: Bearer <key>``

A bearer credential is tried as a JWT first; only when that fails is it matched
against the API-key allowlist. Unknown credentials must never authenticate.
"""

import pytest
from fastapi.security import HTTPAuthorizationCredentials

from src.core.auth import create_access_token, get_optional_auth
from src.core.config import settings

_SERVICE_KEY = "service-key-not-for-production"
_ADMIN_KEY = "admin-key-not-for-production"
_JWT_SECRET = "unit-test-secret-min-32-chars-long-for-hs256"


def _bearer(token: str) -> HTTPAuthorizationCredentials:
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


@pytest.fixture(autouse=True)
def _configured_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "api_keys", [_SERVICE_KEY])
    monkeypatch.setattr(settings, "admin_api_key", _ADMIN_KEY)
    monkeypatch.delenv("ARGUS_API_KEYS", raising=False)


async def test_no_credentials_returns_none() -> None:
    assert await get_optional_auth(credentials=None, api_key=None) is None


async def test_api_key_header_authenticates() -> None:
    auth = await get_optional_auth(credentials=None, api_key=_SERVICE_KEY)
    assert auth is not None
    assert auth.is_api_key is True
    assert auth.user_id == "api-key"
    assert auth.tenant_id == settings.default_tenant_id


async def test_bearer_api_key_authenticates() -> None:
    """The gateway / e2e transport: the API key arrives in Authorization."""
    auth = await get_optional_auth(credentials=_bearer(_SERVICE_KEY), api_key=None)
    assert auth is not None
    assert auth.is_api_key is True
    assert auth.user_id == "api-key"


async def test_unknown_api_key_header_is_rejected() -> None:
    assert await get_optional_auth(credentials=None, api_key="wrong-key") is None


async def test_unknown_bearer_token_is_rejected() -> None:
    assert await get_optional_auth(credentials=_bearer("wrong-key"), api_key=None) is None


async def test_admin_key_authenticates_via_both_transports() -> None:
    via_header = await get_optional_auth(credentials=None, api_key=_ADMIN_KEY)
    via_bearer = await get_optional_auth(credentials=_bearer(_ADMIN_KEY), api_key=None)
    assert via_header is not None and via_header.user_id == "admin"
    assert via_bearer is not None and via_bearer.user_id == "admin"


async def test_unset_admin_key_does_not_authenticate_empty_credential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "admin_api_key", None)
    assert await get_optional_auth(credentials=None, api_key="") is None


async def test_env_fallback_used_when_settings_keys_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "api_keys", [])
    monkeypatch.setenv("ARGUS_API_KEYS", f"other-key, {_SERVICE_KEY} ")
    auth = await get_optional_auth(credentials=_bearer(_SERVICE_KEY), api_key=None)
    assert auth is not None and auth.is_api_key is True


async def test_valid_jwt_resolves_to_user_not_api_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "jwt_secret", _JWT_SECRET)
    token = create_access_token(user_id="u-1", tenant_id="tenant-1")
    auth = await get_optional_auth(credentials=_bearer(token), api_key=None)
    assert auth is not None
    assert auth.is_api_key is False
    assert auth.user_id == "u-1"
    assert auth.tenant_id == "tenant-1"
