"""SEC-001 regression tests for tenant resolution (src.core.tenant).

Tenant identity must come from the authenticated principal, a mismatching
X-Tenant-ID header must be rejected, and an anonymous caller must never reach a
tenant at all — there is no flag that re-enables the old header/default-tenant
fallback, so these tests double as a guard against re-introducing one.
"""

import pytest
from fastapi import HTTPException

from src.core.auth import AuthContext
from src.core.config import settings
from src.core.tenant import get_current_tenant_id

_DEFAULT = settings.default_tenant_id
_TENANT_A = "11111111-1111-1111-1111-111111111111"
_TENANT_B = "22222222-2222-2222-2222-222222222222"


class TestAuthenticated:
    async def test_without_header_uses_identity(self) -> None:
        auth = AuthContext(user_id="u", tenant_id=_TENANT_A)
        assert await get_current_tenant_id(auth=auth, x_tenant_id=None) == _TENANT_A

    async def test_matching_header_is_accepted(self) -> None:
        auth = AuthContext(user_id="u", tenant_id=_TENANT_A)
        assert (
            await get_current_tenant_id(auth=auth, x_tenant_id=_TENANT_A) == _TENANT_A
        )

    async def test_mismatching_header_is_rejected(self) -> None:
        auth = AuthContext(user_id="u", tenant_id=_TENANT_A)
        with pytest.raises(HTTPException) as exc:
            await get_current_tenant_id(auth=auth, x_tenant_id=_TENANT_B)
        assert exc.value.status_code == 403

    async def test_blank_header_is_ignored(self) -> None:
        auth = AuthContext(user_id="u", tenant_id=_TENANT_A)
        assert await get_current_tenant_id(auth=auth, x_tenant_id="   ") == _TENANT_A

    async def test_default_tenant_header_still_needs_to_match(self) -> None:
        """The default tenant id is not a magic value that bypasses the check."""
        auth = AuthContext(user_id="u", tenant_id=_TENANT_A)
        with pytest.raises(HTTPException) as exc:
            await get_current_tenant_id(auth=auth, x_tenant_id=_DEFAULT)
        assert exc.value.status_code == 403


class TestUnauthenticated:
    """No credential means no tenant — unconditionally."""

    @pytest.mark.parametrize(
        "header",
        [None, "   ", _DEFAULT, _TENANT_B],
        ids=["absent", "blank", "default_tenant", "foreign_tenant"],
    )
    async def test_always_401(self, header: str | None) -> None:
        with pytest.raises(HTTPException) as exc:
            await get_current_tenant_id(auth=None, x_tenant_id=header)
        assert exc.value.status_code == 401
        assert exc.value.headers is not None
        assert exc.value.headers.get("WWW-Authenticate") == "Bearer"

    async def test_no_opt_out_flag_exists(self) -> None:
        """``require_tenant_auth`` was removed; an insecure config is unrepresentable."""
        assert not hasattr(settings, "require_tenant_auth")
