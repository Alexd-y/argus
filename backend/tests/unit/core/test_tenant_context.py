"""SEC-001 regression tests for tenant resolution (src.core.tenant).

Tenant identity must come from the authenticated principal, and a mismatching
X-Tenant-ID header must be rejected. Unauthenticated behaviour is governed by
``require_tenant_auth``.
"""

import pytest
from fastapi import HTTPException

from src.core.auth import AuthContext
from src.core.config import settings
from src.core.tenant import get_current_tenant_id

_DEFAULT = settings.default_tenant_id
_TENANT_A = "11111111-1111-1111-1111-111111111111"
_TENANT_B = "22222222-2222-2222-2222-222222222222"


@pytest.fixture(autouse=True)
def _permissive(monkeypatch: pytest.MonkeyPatch) -> None:
    # Default posture: enforcement off (backward compatible). Individual tests
    # opt into enforcement explicitly.
    monkeypatch.setattr(settings, "require_tenant_auth", False)


async def test_authenticated_without_header_uses_identity() -> None:
    auth = AuthContext(user_id="u", tenant_id=_TENANT_A)
    assert await get_current_tenant_id(auth=auth, x_tenant_id=None) == _TENANT_A


async def test_authenticated_matching_header_is_accepted() -> None:
    auth = AuthContext(user_id="u", tenant_id=_TENANT_A)
    assert await get_current_tenant_id(auth=auth, x_tenant_id=_TENANT_A) == _TENANT_A


async def test_authenticated_mismatching_header_is_rejected() -> None:
    auth = AuthContext(user_id="u", tenant_id=_TENANT_A)
    with pytest.raises(HTTPException) as exc:
        await get_current_tenant_id(auth=auth, x_tenant_id=_TENANT_B)
    assert exc.value.status_code == 403


async def test_authenticated_ignores_blank_header() -> None:
    auth = AuthContext(user_id="u", tenant_id=_TENANT_A)
    assert await get_current_tenant_id(auth=auth, x_tenant_id="   ") == _TENANT_A


async def test_unauthenticated_no_header_returns_default() -> None:
    assert await get_current_tenant_id(auth=None, x_tenant_id=None) == _DEFAULT


async def test_unauthenticated_default_header_returns_default() -> None:
    assert await get_current_tenant_id(auth=None, x_tenant_id=_DEFAULT) == _DEFAULT


async def test_unauthenticated_foreign_header_permissive_legacy() -> None:
    # Enforcement off: legacy behaviour preserved (non-breaking) but logged.
    assert await get_current_tenant_id(auth=None, x_tenant_id=_TENANT_B) == _TENANT_B


async def test_unauthenticated_foreign_header_enforced_401(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "require_tenant_auth", True)
    with pytest.raises(HTTPException) as exc:
        await get_current_tenant_id(auth=None, x_tenant_id=_TENANT_B)
    assert exc.value.status_code == 401


async def test_unauthenticated_enforced_requires_auth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "require_tenant_auth", True)
    with pytest.raises(HTTPException) as exc:
        await get_current_tenant_id(auth=None, x_tenant_id=None)
    assert exc.value.status_code == 401


async def test_authenticated_mismatch_rejected_even_when_enforced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "require_tenant_auth", True)
    auth = AuthContext(user_id="u", tenant_id=_TENANT_A)
    with pytest.raises(HTTPException) as exc:
        await get_current_tenant_id(auth=auth, x_tenant_id=_TENANT_B)
    assert exc.value.status_code == 403
