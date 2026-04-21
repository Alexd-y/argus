"""Conftest for the ``backend/tests/unit`` subtree.

Pure unit tests under this directory MUST NOT depend on a real DEBUG=true /
DATABASE_URL / JWT_SECRET environment, nor on a live FastAPI application.  They
exercise contracts and pure-Python modules (``src.pipeline.contracts``,
``src.orchestrator.schemas``, etc.) that have zero runtime side effects.

Two protections are layered here:

1.  Safe environment defaults are set BEFORE any ``src.*`` import so that, if
    a unit test (or a future one) transitively imports ``src.core.config``,
    the production-only ``Settings()`` validators do not blow up at import
    time.  ``os.environ.setdefault`` is used so an explicitly exported value
    in CI / dev is never overridden.

2.  The parent ``backend/tests/conftest.py`` declares an ``autouse=True``
    fixture ``override_auth(request, app)`` that pulls in the full FastAPI
    application (``main.app``) and, transitively, ``src.db.session`` —
    requiring optional drivers like ``aiosqlite`` and a working DB engine.
    For pure unit tests this is unnecessary and creates spurious failures, so
    we shadow ``override_auth`` here with a no-op autouse fixture.  Pytest's
    fixture-resolution rule (closest definition wins) makes this transparent
    to test files in ``unit/**``.

Hard requirements (do not relax):
  * Do NOT import ``src.*`` at the top of this module — env defaults must
    land in ``os.environ`` first.
  * Do NOT weaken the production-mode guards in ``Settings`` itself; the
    ``JWT_SECRET must be set in production`` check stays intact upstream.
  * Keep this file tiny and side-effect free.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

# ---------------------------------------------------------------------------
# Layer 1 — safe environment defaults for unit-test collection.
#
# ``setdefault`` semantics: only writes when the key is unset, so any value
# already exported by the developer / CI runner takes precedence.
# ---------------------------------------------------------------------------

# DEBUG=true short-circuits the production validators in
# ``src.core.config.Settings`` (JWT_SECRET / DATABASE_URL / MINIO_SECRET_KEY
# requirement, CORS wildcard rejection, default-MinIO-creds warning, etc.).
os.environ.setdefault("DEBUG", "true")

# Minimal in-memory DSN — pure unit tests never touch a DB engine, but a
# non-empty value keeps any defensive ``Settings`` validator quiet.
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")

# Length-conformant placeholder for HS256 JWT signing; never used to issue
# real tokens during unit-test collection.  The string is intentionally
# self-describing so it can never be mistaken for a production secret.
os.environ.setdefault(
    "JWT_SECRET",
    "test-secret-not-for-prod-but-required-by-settings",
)

# Marker the rest of the codebase (and any future fixture) can read to detect
# unit-test mode without re-deriving it from DEBUG/DATABASE_URL combinations.
os.environ.setdefault("ARGUS_TEST_MODE", "1")


# ---------------------------------------------------------------------------
# Layer 2 — neutralize the parent autouse ``override_auth`` fixture.
#
# The same name in this conftest shadows the one in ``backend/tests/conftest.py``
# for every test collected under ``backend/tests/unit/**``.  No FastAPI app is
# instantiated, no DB engine is created, no optional driver is imported.
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def override_auth() -> Iterator[None]:
    """Pure unit tests do not touch FastAPI auth — skip the heavy parent fixture."""
    yield
