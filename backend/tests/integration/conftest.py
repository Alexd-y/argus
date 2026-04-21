"""Conftest for the ``backend/tests/integration`` subtree.

Integration tests under this directory exercise composed subsystems against
real on-disk artefacts (signed YAML tool catalog, OpenAPI snapshots, etc.).
They MUST NOT spin up the full FastAPI app, a DB engine, or any network I/O.

Two protections are layered here, mirroring ``backend/tests/unit/conftest.py``:

1.  Safe environment defaults are set BEFORE any ``src.*`` import so that the
    production-only ``Settings()`` validators do not blow up at collection
    time. ``os.environ.setdefault`` is used so an explicitly exported value
    in CI / dev is never overridden.

2.  The parent ``backend/tests/conftest.py`` declares an ``autouse=True``
    fixture ``override_auth(request, app)`` that pulls in the full FastAPI
    application (``main.app``) and, transitively, ``src.db.session``. The
    integration tests in this tree do not need it, so we shadow it with a
    no-op autouse fixture.

Hard requirements (do not relax):
  * Do NOT import ``src.*`` at the top of this module — env defaults must
    land in ``os.environ`` first.
  * Do NOT weaken the production-mode guards in ``Settings`` itself.
  * Keep this file tiny and side-effect free.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

# ---------------------------------------------------------------------------
# Safe environment defaults for integration-test collection.
# ---------------------------------------------------------------------------

os.environ.setdefault("DEBUG", "true")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault(
    "JWT_SECRET",
    "test-secret-not-for-prod-but-required-by-settings",
)
os.environ.setdefault("ARGUS_TEST_MODE", "1")


# ---------------------------------------------------------------------------
# Neutralise the parent autouse ``override_auth`` fixture.
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def override_auth() -> Iterator[None]:
    """Integration tests in this tree do not touch FastAPI auth."""
    yield
