"""Shared fixtures for ``backend/tests/scripts/`` (C7-T02).

The repo-level ``backend/tests/conftest.py::override_auth`` autouse fixture
pulls in ``main.app`` (FastAPI app + DB engine + Celery + OpenTelemetry)
just to install a JWT-bypass dependency override. None of that is needed
to test a stdlib XML parser, and forcing the import would also make the
suite refuse to run when ``DATABASE_URL`` / ``JWT_SECRET`` are unset in a
contributor's local shell.

Same pattern as ``backend/tests/auth/conftest.py`` and
``backend/tests/api/admin/conftest.py``: shadow the autouse fixture with a
no-op so the parent's heavy import chain never fires under this subtree.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest


@pytest.fixture(autouse=True)
def override_auth() -> Iterator[None]:
    """Neutralise the parent ``override_auth`` fixture for this subtree."""
    yield
