"""Restore the repo-level auth override for the router tests in this package.

``tests/unit/conftest.py`` shadows the root ``override_auth`` fixture with a no-op
because most tests under ``tests/unit/**`` never build the FastAPI app. The tests
in *this* package do: they drive real routers through the ``client`` fixture, and
the tenant-data routers require an authenticated principal (SEC-001). Without the
override every request here would get 401.

Tests that want to assert real authentication behaviour keep opting out with the
``no_auth_override`` marker, exactly as they do against the root fixture.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from src.core.auth import AuthContext, get_optional_auth, get_required_auth


@pytest.fixture(autouse=True)
def override_auth(request: pytest.FixtureRequest, app) -> Iterator[None]:
    """Inject a stub authenticated principal for router tests in this package.

    ``get_optional_auth`` is stubbed alongside the required one because
    ``get_current_tenant_id`` resolves the tenant through it and rejects
    anonymous callers (SEC-001).
    """
    if "no_auth_override" in {m.name for m in request.node.iter_markers()}:
        yield
        return

    async def _mock_auth() -> AuthContext:
        return AuthContext(
            user_id="test-user",
            tenant_id="test-tenant",
            is_api_key=False,
        )

    app.dependency_overrides[get_required_auth] = _mock_auth
    app.dependency_overrides[get_optional_auth] = _mock_auth
    yield
    app.dependency_overrides.pop(get_required_auth, None)
    app.dependency_overrides.pop(get_optional_auth, None)
