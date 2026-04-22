"""Shared fixtures for the ``backend/tests/auth`` suite (ISS-T20-003 Phase 1).

Test architecture
-----------------
Every test in this subtree exercises the new admin auth flow against an
in-memory SQLite engine that has Alembic revision ``028`` applied. We:

* spin up a per-test ``sqlite+aiosqlite:///:memory:`` engine with
  :class:`StaticPool` so every connection lands in the same in-memory DB;
* import the ``028_admin_sessions`` migration as a standalone module and
  apply ``upgrade()`` against the fresh engine (no full alembic chain
  required — the tables have no FK dependencies);
* monkey-patch the module-level ``async_session_factory`` references in
  ``src.auth.*`` and ``src.api.routers.admin*`` so all DB I/O — including
  the dual-mode ``require_admin`` resolver — points at the per-test engine;
* override the FastAPI ``get_db`` dependency on the running app so the
  admin auth router shares the same engine.

Cross-loop note
---------------
HTTP requests are issued via ``httpx.AsyncClient`` + ``ASGITransport`` so
the ASGI handler runs in the test's event loop, which keeps the
aiosqlite engine reachable from the route coroutines. The base URL is
``https://testserver`` because the new ``argus.admin.session`` cookie is
``Secure``-only and ``httpx`` will not echo it on plain-HTTP redirects.

Parent ``override_auth`` neutralisation
---------------------------------------
The repo-level ``backend/tests/conftest.py::override_auth`` autouse
fixture installs a JWT-bypass and *requires* ``main.app`` to be
importable. We don't need it on this surface (the admin auth router has
its own dependencies), so we shadow it with a no-op that yields
immediately — same trick as ``backend/tests/api/admin/conftest.py``.
"""

from __future__ import annotations

import importlib.util
import os
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Layer 1 — env defaults BEFORE any ``src.*`` import (mirrors api/admin).
# ---------------------------------------------------------------------------

os.environ.setdefault("DEBUG", "true")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault(
    "JWT_SECRET",
    "test-secret-not-for-prod-but-required-by-settings",
)
os.environ.setdefault("ARGUS_TEST_MODE", "1")
# Alembic 030 (ISS-T20-003 hardening) — server-side at-rest pepper. Stable
# value so per-test backfill expectations stay deterministic.
os.environ.setdefault(
    "ADMIN_SESSION_PEPPER",
    "test-pepper-iss-t20-003-not-for-prod-32chars-min",
)
# C7-T01 — never set ADMIN_MFA_KEYRING at import time. The Pydantic
# validator runs at Settings construction and would refuse a bad value
# before any test could intervene; tests that exercise MFA crypto pull
# the ``mfa_keyring`` fixture below, which generates fresh Fernet keys
# per-test and pins them via ``monkeypatch.setattr(settings, ...)``.


# ---------------------------------------------------------------------------
# Layer 2 — heavy ``src.*`` imports.
# ---------------------------------------------------------------------------

from alembic.migration import MigrationContext  # noqa: E402
from alembic.operations import Operations  # noqa: E402
from sqlalchemy import event  # noqa: E402
from sqlalchemy.ext.asyncio import (  # noqa: E402
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool  # noqa: E402

from src.core.config import settings  # noqa: E402


_BACKEND_ROOT: Path = Path(__file__).resolve().parents[2]
_VERSIONS_DIR: Path = _BACKEND_ROOT / "alembic" / "versions"
_REVISION: str = "028"
#: Alembic 030 hardens admin_sessions with at-rest hashing
#: (ISS-T20-003 follow-up). The ORM ``AdminSession`` model now declares
#: ``session_token_hash``; without applying 030 the SQLite schema lacks the
#: column and any ``create_session`` flush blows up. We chain 028 → 030
#: directly because 029 touches an unrelated ``tenants`` table that the
#: admin tests never reference.
_REVISION_030: str = "030"
#: Alembic 032 (C7-T01) adds the admin-MFA columns (``mfa_enabled``,
#: ``mfa_secret_encrypted``, ``mfa_backup_codes_hash``) to ``admin_users``
#: and ``mfa_passed_at`` to ``admin_sessions``. The ORM models declared
#: in :mod:`src.db.models` already reference these columns, so the
#: 028→030→032 chain is the *only* SQLite shape that keeps every
#: ``admin_users`` / ``admin_sessions`` flush legal during a test run.
#: (031 lands later in C7-T07 and rebases 032 to ``Revises: 031``.)
_REVISION_032: str = "032"


def _load_revision_module(revision: str = _REVISION) -> Any:
    """Import revision *revision* as a standalone module (no full chain run)."""
    matches = list(_VERSIONS_DIR.glob(f"{revision}_*.py"))
    assert matches, f"revision {revision} not found under {_VERSIONS_DIR}"
    spec = importlib.util.spec_from_file_location(
        f"_alembic_{revision}", matches[0]
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _apply_admin_sessions_schema_sync(conn: Any) -> None:
    """Apply 028 → 030 → 032 ``upgrade()`` — yields the post-032 admin schema.

    Skipping 029 is intentional: it only touches ``tenants.pdf_archival_format``
    and the auth tests never touch that table, so a partial chain keeps the
    fixture deterministic and Postgres-free.

    032 (C7-T01) adds the MFA columns required by the ORM
    (``mfa_enabled`` / ``mfa_secret_encrypted`` / ``mfa_backup_codes_hash``
    on ``admin_users`` and ``mfa_passed_at`` on ``admin_sessions``). Without
    this hop, every ``AdminUser`` / ``AdminSession`` flush hits
    ``OperationalError: no such column`` because the ORM model declares
    columns the 030 schema does not yet have.
    """
    ctx = MigrationContext.configure(conn)
    with Operations.context(ctx):
        _load_revision_module(_REVISION).upgrade()
        _load_revision_module(_REVISION_030).upgrade()
        _load_revision_module(_REVISION_032).upgrade()


@pytest.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    """Per-test in-memory async SQLite engine with revision 028 applied."""
    eng = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )

    @event.listens_for(eng.sync_engine, "connect")
    def _enable_sqlite_fk(dbapi_conn: Any, _conn_record: Any) -> None:
        cursor = dbapi_conn.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
        finally:
            cursor.close()

    async with eng.begin() as conn:
        await conn.run_sync(_apply_admin_sessions_schema_sync)

    try:
        yield eng
    finally:
        await eng.dispose()


@pytest.fixture
def session_factory(engine: AsyncEngine):
    """Return a callable matching ``async_session_factory()`` semantics."""
    sm = async_sessionmaker(engine, expire_on_commit=False)

    @asynccontextmanager
    async def _cm() -> AsyncIterator[AsyncSession]:
        async with sm() as s:
            yield s

    def _factory() -> Any:
        return _cm()

    return _factory


@pytest.fixture
async def session(engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    """Per-test ``AsyncSession`` for direct ORM assertions."""
    sm = async_sessionmaker(engine, expire_on_commit=False)
    async with sm() as s:
        try:
            yield s
        finally:
            await s.rollback()


@pytest.fixture
def patch_async_session_factory(
    session_factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Re-route every ``async_session_factory`` import site to the test engine.

    The new auth modules grab the factory by attribute (``from src.db.session
    import async_session_factory``); a single ``monkeypatch.setattr`` per
    import site is enough to keep the patch local to the test.

    C7-T03 note — ``require_admin`` and its session resolver moved from
    ``src.api.routers.admin`` to ``src.auth.admin_dependencies`` so the
    new ``require_admin_mfa_passed`` gate could depend on it without a
    circular import. The factory pointer follows the implementation.
    """
    for module_path in (
        "src.auth.admin_users.async_session_factory",
        "src.auth.admin_dependencies.async_session_factory",
    ):
        monkeypatch.setattr(module_path, session_factory)


@pytest.fixture(autouse=True)
def _reset_login_rate_limiter() -> Iterator[None]:
    """Drop the cached :class:`_LoginRateLimiter` between tests.

    The limiter is a module-level singleton so leaving residue from a
    previous test would skew ``test_login_rate_limit_*`` assertions.
    """
    from src.api.routers.admin_auth import _reset_login_rate_limiter_for_tests

    _reset_login_rate_limiter_for_tests()
    yield
    _reset_login_rate_limiter_for_tests()


@pytest.fixture(autouse=True)
def override_auth() -> Iterator[None]:
    """Neutralise the parent ``override_auth`` fixture for this subtree."""
    yield


@pytest.fixture
def settings_admin_mode_session(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin ``settings.admin_auth_mode`` to ``session`` for the test."""
    monkeypatch.setattr(settings, "admin_auth_mode", "session")


@pytest.fixture
def settings_admin_mode_cookie(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin ``settings.admin_auth_mode`` to ``cookie`` for the test."""
    monkeypatch.setattr(settings, "admin_auth_mode", "cookie")


@pytest.fixture
def settings_admin_mode_both(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin ``settings.admin_auth_mode`` to ``both`` for the test."""
    monkeypatch.setattr(settings, "admin_auth_mode", "both")


@pytest.fixture
def admin_api_key(monkeypatch: pytest.MonkeyPatch) -> str:
    """Pin ``settings.admin_api_key`` to a stable test value."""
    key = "test-admin-key-iss-t20-003"
    monkeypatch.setattr(settings, "admin_api_key", key)
    return key


# ---------------------------------------------------------------------------
# C7-T01 — admin MFA fixtures.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class MfaKeyring:
    """Per-test Fernet keyring snapshot.

    ``primary`` is the newest key (the one ``MultiFernet`` encrypts with);
    ``secondary`` is the older one used to verify decrypt-with-any-key
    semantics. ``csv`` is the newest-first CSV that
    :attr:`Settings.admin_mfa_keyring` expects.

    Tests that need to *rotate* (e.g. swap the primary mid-test) read
    these fields and call ``monkeypatch.setattr(settings,
    "admin_mfa_keyring", new_csv)`` directly — see
    ``test_mfa_crypto.test_current_key_id_changes_after_rotation``.
    """

    primary: str
    secondary: str
    csv: str


@pytest.fixture
def mfa_keyring(monkeypatch: pytest.MonkeyPatch) -> MfaKeyring:
    """Generate a fresh 2-key Fernet keyring and pin it onto ``settings``.

    Why ``monkeypatch.setattr(settings, ...)`` and not
    ``monkeypatch.setenv``: ``Settings`` is instantiated at module import
    time (``src.core.config.settings`` is the live singleton), and its
    Pydantic validator runs *exactly once* against the env value seen at
    construction. Mutating the env after import has no effect on the
    already-built object — the only safe seam is to overwrite the
    attribute on the live instance, which :func:`pytest.MonkeyPatch.setattr`
    handles with automatic teardown.

    The crypto layer (:func:`src.auth._mfa_crypto._build_multifernet`)
    re-reads ``settings.admin_mfa_keyring`` on *every* call, so this
    monkeypatch propagates immediately to the next ``encrypt`` /
    ``decrypt`` / ``current_key_id`` invocation without needing to
    reload :mod:`src.auth._mfa_crypto`.

    Generates *fresh* keys per test — never hardcoded — so a leak from a
    forgotten test fixture cannot ship a real key into the repo.
    """
    from cryptography.fernet import Fernet

    secondary = Fernet.generate_key().decode("ascii")
    primary = Fernet.generate_key().decode("ascii")
    csv = f"{primary},{secondary}"
    monkeypatch.setattr(settings, "admin_mfa_keyring", csv)
    return MfaKeyring(primary=primary, secondary=secondary, csv=csv)


@pytest.fixture
async def admin_app(
    session_factory, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[Any]:
    """Return a FastAPI app wired to the per-test SQLite engine.

    We override ``get_db`` so the ``admin_auth`` router shares the same
    engine the session resolver lives on. Any test that hits the HTTP
    surface should pull this fixture instead of building its own app.
    """
    monkeypatch.setattr(
        "src.auth.admin_users.async_session_factory", session_factory
    )
    monkeypatch.setattr(
        "src.auth.admin_dependencies.async_session_factory", session_factory
    )

    from fastapi import FastAPI

    from src.api.routers import admin_auth as admin_auth_router

    app = FastAPI()
    app.include_router(admin_auth_router.router, prefix="/api/v1")

    async def _override_get_db():
        async with session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    from src.db.session import get_db

    app.dependency_overrides[get_db] = _override_get_db
    try:
        yield app
    finally:
        app.dependency_overrides.pop(get_db, None)


@pytest.fixture
async def api_client(admin_app):
    """Async HTTPS client wired directly to the admin auth FastAPI app."""
    from httpx import ASGITransport, AsyncClient

    transport = ASGITransport(app=admin_app)
    async with AsyncClient(
        transport=transport, base_url="https://testserver"
    ) as ac:
        yield ac


# ---------------------------------------------------------------------------
# Shared constants — keep test bodies short.
# ---------------------------------------------------------------------------

#: Plaintext used by the bcrypt happy-path tests (never written to DB).
TEST_PLAINTEXT_PASSWORD: str = "Tr0ub4dor&3-not-the-real-one"

#: Canonical bootstrap subject used across the suite.
TEST_ADMIN_SUBJECT: str = "soc-team@argus.example"


__all__ = [
    "TEST_ADMIN_SUBJECT",
    "TEST_PLAINTEXT_PASSWORD",
    "MfaKeyring",
    "admin_api_key",
    "admin_app",
    "api_client",
    "engine",
    "mfa_keyring",
    "patch_async_session_factory",
    "session",
    "session_factory",
    "settings_admin_mode_both",
    "settings_admin_mode_cookie",
    "settings_admin_mode_session",
]
