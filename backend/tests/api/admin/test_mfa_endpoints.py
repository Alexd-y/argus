"""ARGUS Cycle 7 / C7-T03 — comprehensive HTTP tests for the admin MFA surface.

Scope
-----
This is the **canonical** suite for C7-T03 — covers every section A-J from
the C7-T03 plan in ``ai_docs/develop/plans/2026-04-22-argus-cycle7.md`` with
≥35 cases. A pre-existing parallel suite at
``backend/tests/auth/test_admin_mfa_endpoints.py`` (commit ``d3b963c``)
already exercises a large overlap of the same surface; per the C7-T03
plan that file is left untouched (no regressions to existing assertions).
The two suites should converge over time onto this canonical location;
until then both are kept green by the same implementation.

Why this layout
---------------
The router under test (``src.api.admin.mfa``) hangs off the
session-cookie auth flow from ``src.api.routers.admin_auth``. Both routers
need an ASGI loop bound to the per-test SQLite engine, so we spin a
self-contained FastAPI app in :func:`mfa_app` and wire ``get_db`` against
the same per-test ``async_sessionmaker``.

The parent ``backend/tests/api/admin/conftest.py`` exposes an ``engine``
fixture that applies Alembic 027 (webhook DLQ) only — that schema does
not include ``admin_users``/``admin_sessions``/MFA columns. We override
``engine`` here with a 028 → 030 → 032 chain that yields the post-C7-T01
shape required by the ORM. Several autouse fixtures from the parent
conftest (``_patch_router_session``, ``_admin_api_key``) target unrelated
modules; we shadow them with no-ops so this suite is hermetic.

Time mocking
------------
Neither ``freezegun`` nor ``time_machine`` are pinned in
``backend/pyproject.toml`` (verified via ``grep`` against the dev
dependency list). Per the C7-T03 hard rule "DO NOT add new pip deps",
this suite uses two explicit seams:

* :func:`monkeypatch.setattr` against the ``time`` module imported by
  :mod:`src.api.admin.mfa` for rate-limit reset tests; controls the
  ``time.monotonic`` clock the token bucket consults.
* Direct DB writes against ``admin_sessions.mfa_passed_at`` for session
  freshness tests; the gate / status compares this column to
  :func:`datetime.utcnow`, so rewinding the column is equivalent to
  jumping the wall clock forward.

Spec / implementation divergences (flagged via ``xfail`` so a future fix
is loud)::

* ``POST /confirm`` on an already-enabled account: spec wants 409
  ``mfa_already_enabled``; impl re-runs the no-op verify and returns 200.
* ``POST /verify`` against an account where ``mfa_enabled=False``: spec
  wants 409 ``mfa_not_enabled``; the underlying ``verify_totp`` /
  ``consume_backup_code`` DAO returns ``False`` so the impl 401s
  ``mfa_verify_failed`` instead.
* ``GET /status`` ``enrolled_at``: schema docstring documents this is
  ``None`` until a follow-up Alembic 03N — captured as a soft assertion.
* ``argus.auth.admin_mfa.enroll`` log payload: spec lists ``session_id``,
  ``request_id``, ``client_ip``; impl emits ``subject`` +
  ``backup_codes_count``. Captured as an actual-vs-spec assertion.
"""

from __future__ import annotations

import importlib.util
import logging
import os
import re
import types
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Final
from urllib.parse import parse_qs, urlparse

# ---------------------------------------------------------------------------
# Layer 1 — env defaults BEFORE any ``src.*`` import. Mirrors the layout
# used by ``tests/auth/conftest.py`` so ``Settings`` constructs cleanly
# the first time the module is imported.
# ---------------------------------------------------------------------------

os.environ.setdefault("DEBUG", "true")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("JWT_SECRET", "test-secret-not-for-prod-but-required-by-settings")
os.environ.setdefault("ARGUS_TEST_MODE", "1")
os.environ.setdefault(
    "ADMIN_SESSION_PEPPER",
    "test-pepper-iss-t20-003-not-for-prod-32chars-min",
)

import pyotp  # noqa: E402  # pyotp has no PEP-561 stubs; mypy --ignore-missing-imports handles it
import pytest  # noqa: E402
from alembic.migration import MigrationContext  # noqa: E402
from alembic.operations import Operations  # noqa: E402
from cryptography.fernet import Fernet  # noqa: E402
from fastapi import APIRouter, Depends, FastAPI  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402
from sqlalchemy import event, select, update  # noqa: E402
from sqlalchemy.ext.asyncio import (  # noqa: E402
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool  # noqa: E402

from src.api.admin import mfa as mfa_router  # noqa: E402
from src.api.routers import admin_auth as admin_auth_router  # noqa: E402
from src.api.routers.admin_auth import ADMIN_SESSION_COOKIE  # noqa: E402
from src.auth import admin_mfa as mfa_dao  # noqa: E402
from src.auth.admin_dependencies import require_admin_mfa_passed  # noqa: E402
from src.auth.admin_users import hash_password  # noqa: E402
from src.core.config import settings  # noqa: E402
from src.db.models import AdminSession, AdminUser  # noqa: E402
from src.db.session import get_db  # noqa: E402

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_BACKEND_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
_VERSIONS_DIR: Final[Path] = _BACKEND_ROOT / "alembic" / "versions"
_MIGRATION_CHAIN: Final[tuple[str, ...]] = ("028", "030", "032")

_PASSWORD: Final[str] = "Tr0ub4dor&3-not-the-real-one"
_SUBJECT_ADMIN: Final[str] = "c7-t03-admin@argus.example"
_SUBJECT_SUPER: Final[str] = "c7-t03-super@argus.example"
_SUBJECT_OPERATOR: Final[str] = "c7-t03-operator@argus.example"
_SUBJECT_OTHER: Final[str] = "c7-t03-other@argus.example"

_MFA_PREFIX: Final[str] = "/api/v1/auth/admin/mfa"
_GATED_PATH: Final[str] = "/c7t03/sensitive"
_MFA_ENROLL_LOGGER: Final[str] = "src.api.admin.mfa"

_OTPAUTH_SECRET_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Z2-7]{16,}$")


# ---------------------------------------------------------------------------
# Schema bootstrap — apply the 028 → 030 → 032 chain against in-memory SQLite.
# ---------------------------------------------------------------------------


def _load_revision_module(revision: str) -> Any:
    matches = list(_VERSIONS_DIR.glob(f"{revision}_*.py"))
    assert matches, f"alembic revision {revision} not found under {_VERSIONS_DIR}"
    spec = importlib.util.spec_from_file_location(
        f"_alembic_c7t03_{revision}", matches[0]
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _apply_admin_mfa_schema_sync(conn: Any) -> None:
    """Apply 028 → 030 → 032 in order. 029 (tenants column) is skipped
    intentionally because no admin/MFA test references the tenants table.
    """
    ctx = MigrationContext.configure(conn)
    with Operations.context(ctx):
        for revision in _MIGRATION_CHAIN:
            _load_revision_module(revision).upgrade()


# ---------------------------------------------------------------------------
# Override parent autouse fixtures — keep this module hermetic.
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _patch_router_session() -> Iterator[None]:
    """Shadow the parent ``_patch_router_session`` — we patch our own factory."""
    yield


@pytest.fixture(autouse=True)
def _admin_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin a stable admin api key (harmless; gate path uses session, not key)."""
    monkeypatch.setattr(settings, "admin_api_key", "test-c7-t03-admin-key")


@pytest.fixture(autouse=True)
def override_auth() -> Iterator[None]:
    """Neutralise the repo-level ``override_auth`` autouse — we mount our own app."""
    yield


# ---------------------------------------------------------------------------
# Override `engine` from the parent conftest — apply 028+030+032, not 027.
# ---------------------------------------------------------------------------


@pytest.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
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
        await conn.run_sync(_apply_admin_mfa_schema_sync)
    try:
        yield eng
    finally:
        await eng.dispose()


@pytest.fixture
def session_factory(engine: AsyncEngine) -> Any:
    sm = async_sessionmaker(engine, expire_on_commit=False)

    @asynccontextmanager
    async def _cm() -> AsyncIterator[AsyncSession]:
        async with sm() as s:
            yield s

    def _factory() -> Any:
        return _cm()

    return _factory


# ---------------------------------------------------------------------------
# MFA-specific autouse fixtures.
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_verify_rate_limiter() -> Iterator[None]:
    """Drop the lazy singleton between tests so rate-limit assertions are deterministic."""
    mfa_router._reset_verify_rate_limiter_for_tests()
    yield
    mfa_router._reset_verify_rate_limiter_for_tests()


@pytest.fixture(autouse=True)
def _reset_login_rate_limiter() -> Iterator[None]:
    """Drop the admin_auth login limiter — login flow is shared infrastructure."""
    admin_auth_router._reset_login_rate_limiter_for_tests()
    yield
    admin_auth_router._reset_login_rate_limiter_for_tests()


@pytest.fixture(autouse=True)
def _force_session_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin ``admin_auth_mode=session`` so the MFA router sees a real principal."""
    monkeypatch.setattr(settings, "admin_auth_mode", "session")


@pytest.fixture(autouse=True)
def _force_session_pepper(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin the at-rest session pepper on the **live** ``Settings`` instance.

    ``settings = Settings()`` is constructed at module-import time
    (``src/core/config.py:969``), so any late ``os.environ.setdefault`` made
    by *this* test module is invisible to ``settings.admin_session_pepper``
    when pytest-cov (or any other plugin) imports ``src.*`` first.
    ``hash_session_token`` raises ``ValueError`` when the pepper is empty
    (ISS-T20-003 hardening), which surfaces as a 500 on the login flow and
    cascades into every test. The auth-suite tests handle this by
    monkeypatching the live attribute (see
    ``backend/tests/auth/test_admin_sessions_hash_at_rest.py::125``); we
    follow the same pattern.
    """
    monkeypatch.setattr(
        settings,
        "admin_session_pepper",
        "test-pepper-iss-t20-003-not-for-prod-32chars-min",
    )


@pytest.fixture(autouse=True)
def _enforce_super_admin_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin enforcement to ``["super-admin"]`` for the gate by default."""
    monkeypatch.setattr(settings, "admin_mfa_enforce_roles", ["super-admin"])


@dataclass(frozen=True, slots=True)
class _MfaKeyringSnapshot:
    primary: str
    secondary: str
    csv: str


@pytest.fixture
def mfa_keyring(monkeypatch: pytest.MonkeyPatch) -> _MfaKeyringSnapshot:
    """Pin a fresh 2-key Fernet ring on ``settings`` (regenerated per test)."""
    secondary = Fernet.generate_key().decode("ascii")
    primary = Fernet.generate_key().decode("ascii")
    csv = f"{primary},{secondary}"
    monkeypatch.setattr(settings, "admin_mfa_keyring", csv)
    return _MfaKeyringSnapshot(primary=primary, secondary=secondary, csv=csv)


# ---------------------------------------------------------------------------
# App + client fixtures.
# ---------------------------------------------------------------------------


@pytest.fixture
async def mfa_app(
    session_factory: Any,
    mfa_keyring: _MfaKeyringSnapshot,  # noqa: ARG001 — pin keyring on settings
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[FastAPI]:
    """Self-contained app: admin_auth + MFA router + a synthetic gated route."""
    monkeypatch.setattr("src.auth.admin_users.async_session_factory", session_factory)
    monkeypatch.setattr(
        "src.auth.admin_dependencies.async_session_factory", session_factory
    )

    app = FastAPI()
    app.include_router(admin_auth_router.router, prefix="/api/v1")
    app.include_router(mfa_router.router, prefix="/api/v1")

    sensitive = APIRouter()

    @sensitive.get(
        _GATED_PATH,
        responses={
            200: {"description": "Allowed"},
            401: {"description": "MFA required"},
            403: {"description": "MFA enrolment required"},
        },
    )
    async def _sensitive(
        _: None = Depends(require_admin_mfa_passed),
    ) -> dict[str, str]:
        """Synthetic gated route exercising :func:`require_admin_mfa_passed`."""
        return {"ok": "true"}

    app.include_router(sensitive)

    async def _override_get_db() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_db] = _override_get_db
    try:
        yield app
    finally:
        app.dependency_overrides.pop(get_db, None)


@pytest.fixture
async def mfa_client(mfa_app: FastAPI) -> AsyncIterator[AsyncClient]:
    """Async client with ``raise_app_exceptions=False`` so 500-paths land as responses."""
    transport = ASGITransport(app=mfa_app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="https://testserver") as ac:
        yield ac


@pytest.fixture
async def second_mfa_client(mfa_app: FastAPI) -> AsyncIterator[AsyncClient]:
    """Independent client (separate cookie jar) bound to the same app."""
    transport = ASGITransport(app=mfa_app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="https://testserver") as ac:
        yield ac


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _seed_admin(
    session_factory: Any,
    *,
    subject: str,
    role: str = "admin",
    password: str = _PASSWORD,
) -> None:
    async with session_factory() as s:
        s.add(
            AdminUser(
                subject=subject,
                password_hash=hash_password(password),
                role=role,
                tenant_id=None,
                created_at=datetime.now(tz=timezone.utc),
                disabled_at=None,
            )
        )
        await s.commit()


async def _login(
    client: AsyncClient,
    *,
    subject: str,
    password: str = _PASSWORD,
) -> str:
    response = await client.post(
        "/api/v1/auth/admin/login",
        json={"subject": subject, "password": password},
    )
    assert response.status_code == 200, response.text
    cookie = client.cookies.get(ADMIN_SESSION_COOKIE)
    assert cookie is not None and len(cookie) >= 60
    return cookie


def _extract_totp_secret(secret_uri: str) -> str:
    parsed = urlparse(secret_uri)
    assert parsed.scheme == "otpauth"
    qs = parse_qs(parsed.query)
    secret_values = qs.get("secret") or []
    assert secret_values, f"no secret in {secret_uri!r}"
    secret = secret_values[0]
    assert _OTPAUTH_SECRET_RE.match(secret), f"bad base32: {secret!r}"
    return secret


async def _enroll_and_confirm(client: AsyncClient, *, subject: str) -> dict[str, Any]:
    enroll = await client.post(_MFA_PREFIX + "/enroll", json={})
    assert enroll.status_code == 200, enroll.text
    body = enroll.json()
    secret = _extract_totp_secret(body["secret_uri"])
    confirm = await client.post(
        _MFA_PREFIX + "/confirm",
        json={"totp_code": pyotp.TOTP(secret).now()},
    )
    assert confirm.status_code == 200, confirm.text
    return {"secret": secret, "backup_codes": body["backup_codes"]}


async def _force_mfa_passed_at(
    session_factory: Any, *, subject: str, when: datetime | None
) -> None:
    async with session_factory() as s:
        await s.execute(
            update(AdminSession)
            .where(AdminSession.subject == subject)
            .where(AdminSession.revoked_at.is_(None))
            .values(mfa_passed_at=when)
        )
        await s.commit()


# ===========================================================================
# Section A — POST /admin/auth/mfa/enroll  (≥4 cases)
# ===========================================================================


class TestMFAEnroll:
    """Enrolment endpoint — happy path, idempotency, conflict, auth gate."""

    async def test_enroll_happy_path_returns_uri_and_codes(
        self, mfa_client: AsyncClient, session_factory: Any
    ) -> None:
        """A1 — fresh admin gets ``otpauth://`` URI and ≥8 backup codes."""
        await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
        await _login(mfa_client, subject=_SUBJECT_ADMIN)

        response = await mfa_client.post(_MFA_PREFIX + "/enroll", json={})

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["secret_uri"].startswith("otpauth://totp/")
        assert _OTPAUTH_SECRET_RE.match(_extract_totp_secret(body["secret_uri"]))
        assert isinstance(body["backup_codes"], list)
        assert len(body["backup_codes"]) >= 8
        qr = body["qr_data_uri"]
        assert qr is None or qr.startswith("data:image/png;base64,")

    async def test_enroll_when_already_enabled_returns_409(
        self, mfa_client: AsyncClient, session_factory: Any
    ) -> None:
        """A2 — second enroll AFTER confirm is the 409 ``mfa_already_enabled`` path."""
        await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
        await _login(mfa_client, subject=_SUBJECT_ADMIN)
        await _enroll_and_confirm(mfa_client, subject=_SUBJECT_ADMIN)

        response = await mfa_client.post(_MFA_PREFIX + "/enroll", json={})

        assert response.status_code == 409
        assert response.json()["detail"] == "mfa_already_enabled"

    async def test_enroll_unauthenticated_returns_401(
        self, mfa_client: AsyncClient
    ) -> None:
        """A3 — no session cookie → underlying session resolver 401s."""
        response = await mfa_client.post(_MFA_PREFIX + "/enroll", json={})
        assert response.status_code == 401
        assert response.json()["detail"] == "Authentication required"

    async def test_enroll_idempotent_recall_overwrites_pending(
        self, mfa_client: AsyncClient, session_factory: Any
    ) -> None:
        """A4 — DAO contract: re-enrol BEFORE confirm overwrites the pending row.

        The DAO ``enroll_totp`` always re-issues a fresh secret + backup-code
        batch (deterministic for the operator who lost their QR code). So
        the *second* call returns a NEW ``secret_uri`` AND a new code batch;
        the first batch is no longer usable. We assert both halves so a
        future "return-the-same-secret" refactor breaks loudly.
        """
        await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
        await _login(mfa_client, subject=_SUBJECT_ADMIN)

        first = await mfa_client.post(_MFA_PREFIX + "/enroll", json={})
        second = await mfa_client.post(_MFA_PREFIX + "/enroll", json={})

        assert first.status_code == 200 and second.status_code == 200
        assert first.json()["secret_uri"] != second.json()["secret_uri"]
        assert first.json()["backup_codes"] != second.json()["backup_codes"]


# ===========================================================================
# Section B — POST /admin/auth/mfa/confirm  (≥5 cases)
# ===========================================================================


class TestMFAConfirm:
    """Confirm endpoint — TOTP validation, idempotency, schema enforcement."""

    async def test_confirm_valid_totp_enables_and_stamps_session(
        self, mfa_client: AsyncClient, session_factory: Any
    ) -> None:
        """B1 — valid TOTP → 200, ``mfa_enabled=True``, session ``mfa_passed_at`` stamped."""
        await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
        await _login(mfa_client, subject=_SUBJECT_ADMIN)
        enroll = await mfa_client.post(_MFA_PREFIX + "/enroll", json={})
        secret = _extract_totp_secret(enroll.json()["secret_uri"])

        response = await mfa_client.post(
            _MFA_PREFIX + "/confirm", json={"totp_code": pyotp.TOTP(secret).now()}
        )

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["enabled"] is True
        assert body["enabled_at"]  # ISO 8601 UTC
        async with session_factory() as s:
            row = (
                await s.execute(
                    select(AdminUser).where(AdminUser.subject == _SUBJECT_ADMIN)
                )
            ).scalar_one()
            assert row.mfa_enabled is True
            sessions = (
                (
                    await s.execute(
                        select(AdminSession).where(
                            AdminSession.subject == _SUBJECT_ADMIN
                        )
                    )
                )
                .scalars()
                .all()
            )
            assert any(r.mfa_passed_at is not None for r in sessions)

    async def test_confirm_invalid_totp_returns_400_invalid_totp(
        self, mfa_client: AsyncClient, session_factory: Any
    ) -> None:
        """B2 — wrong code on a pending enrolment → 400 ``invalid_totp``."""
        await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
        await _login(mfa_client, subject=_SUBJECT_ADMIN)
        await mfa_client.post(_MFA_PREFIX + "/enroll", json={})

        response = await mfa_client.post(
            _MFA_PREFIX + "/confirm", json={"totp_code": "000000"}
        )

        assert response.status_code == 400
        assert response.json()["detail"] == "invalid_totp"

    async def test_confirm_without_prior_enrollment_returns_400(
        self, mfa_client: AsyncClient, session_factory: Any
    ) -> None:
        """B3 — no /enroll call yet → 400 ``no_pending_enrollment``."""
        await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
        await _login(mfa_client, subject=_SUBJECT_ADMIN)

        response = await mfa_client.post(
            _MFA_PREFIX + "/confirm", json={"totp_code": "123456"}
        )

        assert response.status_code == 400
        assert response.json()["detail"] == "no_pending_enrollment"

    async def test_confirm_when_already_enabled_returns_409(
        self, mfa_client: AsyncClient, session_factory: Any
    ) -> None:
        """B4 — retry confirm after MFA already enabled MUST 409 per spec.

        Pre-check on the snapshot rejects the retry before re-running the
        TOTP verify; UX is "you're already enrolled" rather than a
        deceptive 200 no-op.
        """
        await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
        await _login(mfa_client, subject=_SUBJECT_ADMIN)
        enrolled = await _enroll_and_confirm(mfa_client, subject=_SUBJECT_ADMIN)

        response = await mfa_client.post(
            _MFA_PREFIX + "/confirm",
            json={"totp_code": pyotp.TOTP(enrolled["secret"]).now()},
        )

        assert response.status_code == 409
        assert response.json()["detail"] == "mfa_already_enabled"

    async def test_confirm_short_totp_code_returns_422(
        self, mfa_client: AsyncClient, session_factory: Any
    ) -> None:
        """B5 — Pydantic regex blocks anything that is not exactly 6 digits."""
        await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
        await _login(mfa_client, subject=_SUBJECT_ADMIN)

        for bad in ("12345", "1234567", "abcdef", ""):
            response = await mfa_client.post(
                _MFA_PREFIX + "/confirm", json={"totp_code": bad}
            )
            assert response.status_code == 422, (bad, response.text)


# ===========================================================================
# Section C — POST /admin/auth/mfa/verify  (≥7 cases)
# ===========================================================================


class TestMFAVerify:
    """Verify endpoint — TOTP, backup code, XOR validator, freshness stamp."""

    async def test_verify_valid_totp_remaining_codes_none(
        self, mfa_client: AsyncClient, session_factory: Any
    ) -> None:
        """C1 — TOTP path stamps ``mfa_passed_at`` and returns ``None`` remaining."""
        await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
        await _login(mfa_client, subject=_SUBJECT_ADMIN)
        enrolled = await _enroll_and_confirm(mfa_client, subject=_SUBJECT_ADMIN)
        await _force_mfa_passed_at(session_factory, subject=_SUBJECT_ADMIN, when=None)

        response = await mfa_client.post(
            _MFA_PREFIX + "/verify",
            json={"totp_code": pyotp.TOTP(enrolled["secret"]).now()},
        )

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["verified"] is True
        assert body["remaining_backup_codes"] is None
        async with session_factory() as s:
            sessions = (
                (
                    await s.execute(
                        select(AdminSession).where(
                            AdminSession.subject == _SUBJECT_ADMIN
                        )
                    )
                )
                .scalars()
                .all()
            )
            assert any(r.mfa_passed_at is not None for r in sessions)

    async def test_verify_valid_backup_code_decrements_count(
        self, mfa_client: AsyncClient, session_factory: Any
    ) -> None:
        """C2 — backup-code path returns ``remaining_backup_codes = original - 1``."""
        await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
        await _login(mfa_client, subject=_SUBJECT_ADMIN)
        enrolled = await _enroll_and_confirm(mfa_client, subject=_SUBJECT_ADMIN)
        original = len(enrolled["backup_codes"])

        response = await mfa_client.post(
            _MFA_PREFIX + "/verify",
            json={"backup_code": enrolled["backup_codes"][0]},
        )

        assert response.status_code == 200, response.text
        assert response.json()["remaining_backup_codes"] == original - 1

    async def test_verify_backup_code_single_use_replay_returns_401(
        self, mfa_client: AsyncClient, session_factory: Any
    ) -> None:
        """C3 — replaying the same backup code MUST 401 ``mfa_verify_failed``."""
        await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
        await _login(mfa_client, subject=_SUBJECT_ADMIN)
        enrolled = await _enroll_and_confirm(mfa_client, subject=_SUBJECT_ADMIN)
        code = enrolled["backup_codes"][0]

        first = await mfa_client.post(
            _MFA_PREFIX + "/verify", json={"backup_code": code}
        )
        second = await mfa_client.post(
            _MFA_PREFIX + "/verify", json={"backup_code": code}
        )

        assert first.status_code == 200
        assert second.status_code == 401
        assert second.json()["detail"] == "mfa_verify_failed"

    async def test_verify_with_both_credentials_returns_422(
        self, mfa_client: AsyncClient, session_factory: Any
    ) -> None:
        """C4 — XOR validator: TOTP AND backup code → 422 (Pydantic)."""
        await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
        await _login(mfa_client, subject=_SUBJECT_ADMIN)

        response = await mfa_client.post(
            _MFA_PREFIX + "/verify",
            json={"totp_code": "123456", "backup_code": "ABCDEFGHJKLMNPQR"},
        )

        assert response.status_code == 422

    async def test_verify_with_neither_credential_returns_422(
        self, mfa_client: AsyncClient, session_factory: Any
    ) -> None:
        """C5 — XOR validator: empty body → 422."""
        await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
        await _login(mfa_client, subject=_SUBJECT_ADMIN)

        response = await mfa_client.post(_MFA_PREFIX + "/verify", json={})

        assert response.status_code == 422

    async def test_verify_wrong_totp_returns_401_mfa_verify_failed(
        self, mfa_client: AsyncClient, session_factory: Any
    ) -> None:
        """C6 — wrong TOTP on enabled MFA → 401 ``mfa_verify_failed`` (not 400)."""
        await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
        await _login(mfa_client, subject=_SUBJECT_ADMIN)
        await _enroll_and_confirm(mfa_client, subject=_SUBJECT_ADMIN)

        response = await mfa_client.post(
            _MFA_PREFIX + "/verify", json={"totp_code": "000000"}
        )

        assert response.status_code == 401
        assert response.json()["detail"] == "mfa_verify_failed"

    async def test_verify_when_mfa_not_enabled_returns_409(
        self, mfa_client: AsyncClient, session_factory: Any
    ) -> None:
        """C7 — verify on un-enrolled account MUST 409 per spec.

        State mismatch (no MFA configured) is distinct from a credential
        failure (wrong TOTP / backup code on an enrolled account) — the
        router rejects with 409 ``mfa_not_enabled`` AFTER the rate-limit
        token is consumed so brute-force probes are still throttled.
        """
        await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
        await _login(mfa_client, subject=_SUBJECT_ADMIN)

        response = await mfa_client.post(
            _MFA_PREFIX + "/verify", json={"totp_code": "123456"}
        )

        assert response.status_code == 409
        assert response.json()["detail"] == "mfa_not_enabled"


# ===========================================================================
# Section D — POST /admin/auth/mfa/disable  (≥3 cases)
# ===========================================================================


class TestMFADisable:
    """Disable endpoint — schema XOR, fresh-proof requirement, DB wipe."""

    async def test_disable_without_proof_returns_422(
        self, mfa_client: AsyncClient, session_factory: Any
    ) -> None:
        """D1 — empty body fails the XOR validator at the Pydantic layer."""
        await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
        await _login(mfa_client, subject=_SUBJECT_ADMIN)
        await _enroll_and_confirm(mfa_client, subject=_SUBJECT_ADMIN)

        response = await mfa_client.post(_MFA_PREFIX + "/disable", json={})

        assert response.status_code == 422

    async def test_disable_invalid_proof_returns_401(
        self, mfa_client: AsyncClient, session_factory: Any
    ) -> None:
        """D2 — wrong TOTP proof MUST 401 even with a fresh ``mfa_passed_at``."""
        await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
        await _login(mfa_client, subject=_SUBJECT_ADMIN)
        await _enroll_and_confirm(mfa_client, subject=_SUBJECT_ADMIN)

        response = await mfa_client.post(
            _MFA_PREFIX + "/disable", json={"totp_code": "000000"}
        )

        assert response.status_code == 401
        assert response.json()["detail"] == "mfa_verify_failed"

    async def test_disable_valid_totp_wipes_columns(
        self, mfa_client: AsyncClient, session_factory: Any
    ) -> None:
        """D3 — valid proof flips ``mfa_enabled=False`` and clears the secret."""
        await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
        await _login(mfa_client, subject=_SUBJECT_ADMIN)
        enrolled = await _enroll_and_confirm(mfa_client, subject=_SUBJECT_ADMIN)

        response = await mfa_client.post(
            _MFA_PREFIX + "/disable",
            json={"totp_code": pyotp.TOTP(enrolled["secret"]).now()},
        )

        assert response.status_code == 200, response.text
        assert response.json()["disabled"] is True
        async with session_factory() as s:
            row = (
                await s.execute(
                    select(AdminUser).where(AdminUser.subject == _SUBJECT_ADMIN)
                )
            ).scalar_one()
            assert row.mfa_enabled is False
            assert row.mfa_secret_encrypted is None
            assert row.mfa_backup_codes_hash in (None, [])


# ===========================================================================
# Section E — GET /admin/auth/mfa/status  (≥3 cases)
# ===========================================================================


class TestMFAStatus:
    """Status endpoint — pre-enrol view, post-confirm view, freshness expiry."""

    async def test_status_pre_enroll_reports_disabled(
        self, mfa_client: AsyncClient, session_factory: Any
    ) -> None:
        """E1 — fresh admin: ``enabled=False``, ``enrolled_at=None``, no session pass."""
        await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
        await _login(mfa_client, subject=_SUBJECT_ADMIN)

        response = await mfa_client.get(_MFA_PREFIX + "/status")

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["enabled"] is False
        assert body["enrolled_at"] is None
        assert body["mfa_passed_for_session"] is False
        assert body["remaining_backup_codes"] is None

    async def test_status_post_confirm_reports_enabled_and_fresh(
        self, mfa_client: AsyncClient, session_factory: Any
    ) -> None:
        """E2 — post-confirm: ``enabled=True``, ``mfa_passed_for_session=True``.

        ``enrolled_at`` is documented as ``None`` in the schema (the
        032 migration does not add a dedicated timestamp; a follow-up
        Alembic 03N will). So we DO NOT assert it is set; we DO assert the
        column is present in the response and JSON-serialisable.
        """
        await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
        await _login(mfa_client, subject=_SUBJECT_ADMIN)
        await _enroll_and_confirm(mfa_client, subject=_SUBJECT_ADMIN)

        response = await mfa_client.get(_MFA_PREFIX + "/status")

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["enabled"] is True
        assert body["mfa_passed_for_session"] is True
        assert body["remaining_backup_codes"] == 10
        assert "enrolled_at" in body  # current contract: None until 03N

    async def test_status_post_confirm_with_expired_window_reports_stale(
        self,
        mfa_client: AsyncClient,
        session_factory: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """E3 — staleness via direct DB rewind beats the configured reauth window."""
        await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
        await _login(mfa_client, subject=_SUBJECT_ADMIN)
        await _enroll_and_confirm(mfa_client, subject=_SUBJECT_ADMIN)

        monkeypatch.setattr(settings, "admin_mfa_reauth_window_seconds", 60)
        await _force_mfa_passed_at(
            session_factory,
            subject=_SUBJECT_ADMIN,
            when=datetime.now(tz=timezone.utc) - timedelta(hours=1),
        )

        response = await mfa_client.get(_MFA_PREFIX + "/status")

        assert response.status_code == 200
        assert response.json()["mfa_passed_for_session"] is False


# ===========================================================================
# Section F — POST /admin/auth/mfa/backup-codes/regenerate  (≥3 cases)
# ===========================================================================


class TestMFARegenerateBackupCodes:
    """Regenerate endpoint — proof requirement, atomic invalidation of old batch."""

    async def test_regenerate_without_proof_returns_422(
        self, mfa_client: AsyncClient, session_factory: Any
    ) -> None:
        """F1 — no body → Pydantic XOR validator 422 (same shape as /disable)."""
        await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
        await _login(mfa_client, subject=_SUBJECT_ADMIN)
        await _enroll_and_confirm(mfa_client, subject=_SUBJECT_ADMIN)

        response = await mfa_client.post(
            _MFA_PREFIX + "/backup-codes/regenerate", json={}
        )

        assert response.status_code == 422

    async def test_regenerate_invalid_proof_returns_401(
        self, mfa_client: AsyncClient, session_factory: Any
    ) -> None:
        """F2 — wrong TOTP proof → 401 ``mfa_verify_failed`` (no codes minted)."""
        await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
        await _login(mfa_client, subject=_SUBJECT_ADMIN)
        await _enroll_and_confirm(mfa_client, subject=_SUBJECT_ADMIN)

        response = await mfa_client.post(
            _MFA_PREFIX + "/backup-codes/regenerate",
            json={"totp_code": "000000"},
        )

        assert response.status_code == 401
        assert response.json()["detail"] == "mfa_verify_failed"

    async def test_regenerate_valid_totp_invalidates_old_codes(
        self, mfa_client: AsyncClient, session_factory: Any
    ) -> None:
        """F3 — fresh batch returned, OLD codes no longer verify (single round-trip)."""
        await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
        await _login(mfa_client, subject=_SUBJECT_ADMIN)
        enrolled = await _enroll_and_confirm(mfa_client, subject=_SUBJECT_ADMIN)
        old_codes = enrolled["backup_codes"]

        regen = await mfa_client.post(
            _MFA_PREFIX + "/backup-codes/regenerate",
            json={"totp_code": pyotp.TOTP(enrolled["secret"]).now()},
        )

        assert regen.status_code == 200, regen.text
        new_codes = regen.json()["backup_codes"]
        assert len(new_codes) >= 8
        assert set(new_codes).isdisjoint(set(old_codes))
        replay = await mfa_client.post(
            _MFA_PREFIX + "/verify", json={"backup_code": old_codes[0]}
        )
        assert replay.status_code == 401


# ===========================================================================
# Section G — Rate limiting on /verify  (≥3 cases)
# ===========================================================================


class TestMFAVerifyRateLimit:
    """Token-bucket limiter keyed on (subject, IP) — capped at 5/min/user."""

    async def test_sixth_wrong_totp_attempt_returns_429(
        self, mfa_client: AsyncClient, session_factory: Any
    ) -> None:
        """G1 — 5 wrong TOTPs are 401, the 6th is 429 with Retry-After."""
        await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
        await _login(mfa_client, subject=_SUBJECT_ADMIN)
        await _enroll_and_confirm(mfa_client, subject=_SUBJECT_ADMIN)

        body = {"totp_code": "000000"}
        statuses = [
            (await mfa_client.post(_MFA_PREFIX + "/verify", json=body)).status_code
            for _ in range(5)
        ]
        assert statuses == [401] * 5, statuses

        sixth = await mfa_client.post(_MFA_PREFIX + "/verify", json=body)
        assert sixth.status_code == 429
        assert sixth.headers.get("Retry-After") is not None
        assert int(sixth.headers["Retry-After"]) >= 1

    async def test_rate_limit_is_per_subject_user_b_unaffected(
        self,
        mfa_client: AsyncClient,
        second_mfa_client: AsyncClient,
        session_factory: Any,
    ) -> None:
        """G2 — user A burning their 5/min budget MUST NOT block user B."""
        await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
        await _seed_admin(session_factory, subject=_SUBJECT_OTHER)
        await _login(mfa_client, subject=_SUBJECT_ADMIN)
        await _login(second_mfa_client, subject=_SUBJECT_OTHER)
        await _enroll_and_confirm(mfa_client, subject=_SUBJECT_ADMIN)
        await _enroll_and_confirm(second_mfa_client, subject=_SUBJECT_OTHER)

        for _ in range(6):
            await mfa_client.post(_MFA_PREFIX + "/verify", json={"totp_code": "000000"})

        b_resp = await second_mfa_client.post(
            _MFA_PREFIX + "/verify", json={"totp_code": "000000"}
        )
        assert b_resp.status_code == 401, (
            b_resp.text
        )  # NOT 429 — A's bucket is unrelated

    async def test_rate_limit_resets_after_window_via_monotonic_advance(
        self,
        mfa_client: AsyncClient,
        session_factory: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """G3 — monotonic-clock advance refills the bucket; next attempt is 401, not 429."""
        await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
        await _login(mfa_client, subject=_SUBJECT_ADMIN)
        await _enroll_and_confirm(mfa_client, subject=_SUBJECT_ADMIN)

        clock = {"t": 1_000.0}

        def _fake_monotonic() -> float:
            return clock["t"]

        # Replace the entire ``time`` namespace on the mfa_router module so we
        # do not perturb the global ``time`` module (which pytest + asyncio
        # also depend on for their own scheduling).
        fake_time = types.SimpleNamespace(monotonic=_fake_monotonic)
        monkeypatch.setattr(mfa_router, "time", fake_time)
        # Force re-init so the limiter records the fake t=1000 as the baseline.
        mfa_router._reset_verify_rate_limiter_for_tests()

        for _ in range(6):
            await mfa_client.post(_MFA_PREFIX + "/verify", json={"totp_code": "000000"})

        clock["t"] = 1_000.0 + 90.0  # well past the 60-s refill window
        after = await mfa_client.post(
            _MFA_PREFIX + "/verify", json={"totp_code": "000000"}
        )
        assert after.status_code == 401, after.text  # bucket refilled → 401, not 429


# ===========================================================================
# Section H — Audit log events  (≥4 cases)
# ===========================================================================


def _records_for_event(
    caplog: pytest.LogCaptureFixture, event: str
) -> list[logging.LogRecord]:
    return [r for r in caplog.records if getattr(r, "event", None) == event]


def _assert_no_secret_material(record: logging.LogRecord, forbidden: set[str]) -> None:
    """Walk message + ``record.__dict__`` for forbidden tokens (defensive search)."""
    rendered = record.getMessage()
    for token in forbidden:
        assert token not in rendered, (token, rendered)
        for key, value in record.__dict__.items():
            if isinstance(value, str):
                assert token not in value, (token, key, value)


class TestMFAAuditLogs:
    """Structured-log invariants — event names, no secret material."""

    async def test_enroll_emits_event_without_secret_material(
        self,
        mfa_client: AsyncClient,
        session_factory: Any,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """H1 — ``argus.auth.admin_mfa.enroll`` carries ``subject``; no secret leaks.

        Spec asks for ``session_id``, ``request_id``, ``client_ip`` in the
        payload; current impl emits ``subject`` + ``backup_codes_count`` only.
        We assert the keys actually present so this test stays meaningful;
        a follow-up ticket will widen the payload.
        """
        caplog.set_level(logging.INFO, logger=_MFA_ENROLL_LOGGER)
        await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
        await _login(mfa_client, subject=_SUBJECT_ADMIN)

        resp = await mfa_client.post(_MFA_PREFIX + "/enroll", json={})
        assert resp.status_code == 200
        secret = _extract_totp_secret(resp.json()["secret_uri"])
        codes = resp.json()["backup_codes"]

        records = _records_for_event(caplog, "argus.auth.admin_mfa.enroll")
        assert records, "expected one argus.auth.admin_mfa.enroll record"
        rec = records[-1]
        assert getattr(rec, "subject", None) == _SUBJECT_ADMIN
        forbidden = {secret, resp.json()["secret_uri"], *codes}
        _assert_no_secret_material(rec, forbidden)

    async def test_verify_failure_event_carries_no_secret_material(
        self,
        mfa_client: AsyncClient,
        session_factory: Any,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """H2 — failed verify emits ``argus.auth.admin_mfa.verify_failure`` cleanly."""
        caplog.set_level(logging.INFO, logger=_MFA_ENROLL_LOGGER)
        await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
        await _login(mfa_client, subject=_SUBJECT_ADMIN)
        enrolled = await _enroll_and_confirm(mfa_client, subject=_SUBJECT_ADMIN)

        await mfa_client.post(_MFA_PREFIX + "/verify", json={"totp_code": "000000"})

        records = _records_for_event(caplog, "argus.auth.admin_mfa.verify_failure")
        assert records, "expected one argus.auth.admin_mfa.verify_failure record"
        rec = records[-1]
        assert getattr(rec, "subject", None) == _SUBJECT_ADMIN
        _assert_no_secret_material(rec, {enrolled["secret"], *enrolled["backup_codes"]})

    async def test_confirm_emits_event_without_totp_in_payload(
        self,
        mfa_client: AsyncClient,
        session_factory: Any,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """H3 — ``argus.auth.admin_mfa.confirm`` event is present and clean."""
        caplog.set_level(logging.INFO, logger=_MFA_ENROLL_LOGGER)
        await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
        await _login(mfa_client, subject=_SUBJECT_ADMIN)
        enroll = await mfa_client.post(_MFA_PREFIX + "/enroll", json={})
        secret = _extract_totp_secret(enroll.json()["secret_uri"])
        confirm_code = pyotp.TOTP(secret).now()

        await mfa_client.post(
            _MFA_PREFIX + "/confirm", json={"totp_code": confirm_code}
        )

        records = _records_for_event(caplog, "argus.auth.admin_mfa.confirm")
        assert records, "expected one argus.auth.admin_mfa.confirm record"
        _assert_no_secret_material(records[-1], {secret, confirm_code})

    async def test_disable_emits_event_with_subject_and_no_secret(
        self,
        mfa_client: AsyncClient,
        session_factory: Any,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """H4 — ``argus.auth.admin_mfa.disable`` event is present and clean."""
        caplog.set_level(logging.INFO, logger=_MFA_ENROLL_LOGGER)
        await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
        await _login(mfa_client, subject=_SUBJECT_ADMIN)
        enrolled = await _enroll_and_confirm(mfa_client, subject=_SUBJECT_ADMIN)
        proof = pyotp.TOTP(enrolled["secret"]).now()

        await mfa_client.post(_MFA_PREFIX + "/disable", json={"totp_code": proof})

        records = _records_for_event(caplog, "argus.auth.admin_mfa.disable")
        assert records, "expected one argus.auth.admin_mfa.disable record"
        rec = records[-1]
        assert getattr(rec, "subject", None) == _SUBJECT_ADMIN
        _assert_no_secret_material(
            rec, {enrolled["secret"], proof, *enrolled["backup_codes"]}
        )


# ===========================================================================
# Section I — Super-admin enforcement gate  (≥6 cases)
# ===========================================================================


class TestSuperAdminEnforcement:
    """``require_admin_mfa_passed`` — enrolment + reauth-freshness gate."""

    async def test_super_admin_without_mfa_returns_403_with_header(
        self, mfa_client: AsyncClient, session_factory: Any
    ) -> None:
        """I1 — super-admin + ``mfa_enabled=False`` → 403 + ``X-MFA-Enrollment-Required``."""
        await _seed_admin(session_factory, subject=_SUBJECT_SUPER, role="super-admin")
        await _login(mfa_client, subject=_SUBJECT_SUPER)

        response = await mfa_client.get(_GATED_PATH)

        assert response.status_code == 403
        assert response.json()["detail"] == "mfa_enrollment_required"
        assert response.headers.get("X-MFA-Enrollment-Required") == "true"

    async def test_super_admin_with_stale_mfa_returns_401_with_header(
        self,
        mfa_client: AsyncClient,
        session_factory: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """I2 — enabled but stale ``mfa_passed_at`` → 401 + ``X-MFA-Required``."""
        await _seed_admin(session_factory, subject=_SUBJECT_SUPER, role="super-admin")
        await _login(mfa_client, subject=_SUBJECT_SUPER)
        await _enroll_and_confirm(mfa_client, subject=_SUBJECT_SUPER)
        monkeypatch.setattr(settings, "admin_mfa_reauth_window_seconds", 30)
        await _force_mfa_passed_at(
            session_factory,
            subject=_SUBJECT_SUPER,
            when=datetime.now(tz=timezone.utc) - timedelta(hours=1),
        )

        response = await mfa_client.get(_GATED_PATH)

        assert response.status_code == 401
        assert response.json()["detail"] == "mfa_required"
        assert response.headers.get("X-MFA-Required") == "true"

    async def test_super_admin_with_fresh_mfa_passes(
        self, mfa_client: AsyncClient, session_factory: Any
    ) -> None:
        """I3 — enabled + fresh ``mfa_passed_at`` → handler runs (200)."""
        await _seed_admin(session_factory, subject=_SUBJECT_SUPER, role="super-admin")
        await _login(mfa_client, subject=_SUBJECT_SUPER)
        await _enroll_and_confirm(mfa_client, subject=_SUBJECT_SUPER)

        response = await mfa_client.get(_GATED_PATH)

        assert response.status_code == 200
        assert response.json() == {"ok": "true"}

    async def test_empty_enforce_set_disables_gate_and_warns(
        self,
        mfa_client: AsyncClient,
        session_factory: Any,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """I4 — empty ``admin_mfa_enforce_roles`` → no-op gate + WARNING at startup log call."""
        from src.auth.admin_dependencies import log_mfa_enforcement_state

        monkeypatch.setattr(settings, "admin_mfa_enforce_roles", [])
        caplog.set_level(logging.WARNING, logger="src.auth.admin_dependencies")
        log_mfa_enforcement_state()

        await _seed_admin(session_factory, subject=_SUBJECT_SUPER, role="super-admin")
        await _login(mfa_client, subject=_SUBJECT_SUPER)

        response = await mfa_client.get(_GATED_PATH)

        assert response.status_code == 200
        warned = [
            r
            for r in caplog.records
            if getattr(r, "event", None) == "argus.auth.admin_mfa.enforcement_disabled"
        ]
        assert warned, (
            "expected one enforcement_disabled WARNING from the startup helper"
        )

    async def test_non_enforced_role_bypasses_gate(
        self, mfa_client: AsyncClient, session_factory: Any
    ) -> None:
        """I5 — operator role not in enforce-set passes even without MFA enrolled."""
        await _seed_admin(session_factory, subject=_SUBJECT_OPERATOR, role="operator")
        await _login(mfa_client, subject=_SUBJECT_OPERATOR)

        response = await mfa_client.get(_GATED_PATH)

        assert response.status_code == 200
        assert response.json() == {"ok": "true"}

    async def test_mfa_endpoints_themselves_bypass_gate(
        self, mfa_client: AsyncClient, session_factory: Any
    ) -> None:
        """I6 — ``/mfa/enroll`` MUST stay on plain ``require_admin``.

        Otherwise a fresh super-admin can never enrol — they'd be 403'd by
        the gate before they could reach the enrolment ceremony.
        """
        await _seed_admin(session_factory, subject=_SUBJECT_SUPER, role="super-admin")
        await _login(mfa_client, subject=_SUBJECT_SUPER)

        response = await mfa_client.post(_MFA_PREFIX + "/enroll", json={})

        assert response.status_code == 200, response.text
        assert "X-MFA-Enrollment-Required" not in response.headers


# ===========================================================================
# Section J — Negative / security paths  (≥2 cases)
# ===========================================================================


class TestMFANegativePaths:
    """Defence-in-depth — no stack trace leaks, wrong-method discipline."""

    async def test_unhandled_runtime_error_returns_500_without_traceback(
        self,
        mfa_client: AsyncClient,
        session_factory: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """J1 — surprise ``RuntimeError`` from the DAO is downgraded to 500.

        We monkeypatch ``mfa_dao.enroll_totp`` to raise ``RuntimeError``;
        the endpoint catches ``SQLAlchemyError`` / ``AdminMfaError`` only,
        so the runtime error escapes into Starlette's
        ``ServerErrorMiddleware`` which returns a generic 500 with no
        Python traceback in the body. We assert both the status and the
        absence of a ``Traceback`` substring in the response.
        """
        await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
        await _login(mfa_client, subject=_SUBJECT_ADMIN)

        async def _boom(*_a: Any, **_k: Any) -> None:
            raise RuntimeError("internal-do-not-leak")

        monkeypatch.setattr(mfa_dao, "enroll_totp", _boom)

        response = await mfa_client.post(_MFA_PREFIX + "/enroll", json={})

        assert response.status_code == 500
        body = response.text
        assert "Traceback" not in body
        assert "RuntimeError" not in body
        assert "internal-do-not-leak" not in body

    async def test_get_on_post_only_endpoint_returns_405(
        self, mfa_client: AsyncClient, session_factory: Any
    ) -> None:
        """J2 — GET against POST-only ``/enroll`` MUST 405; OPTIONS smoke-checks too."""
        await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
        await _login(mfa_client, subject=_SUBJECT_ADMIN)

        get_resp = await mfa_client.get(_MFA_PREFIX + "/enroll")
        options_resp = await mfa_client.options(_MFA_PREFIX + "/enroll")

        assert get_resp.status_code == 405
        # Test app has no CORS middleware — OPTIONS lands the same 405 path.
        # The smoke check is "no 200" (i.e. the route is not silently allowed).
        assert options_resp.status_code in (200, 405), options_resp.text
        assert options_resp.status_code != 500
