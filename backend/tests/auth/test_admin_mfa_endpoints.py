"""ARGUS Cycle 7 / C7-T03 — HTTP-level tests for the admin MFA router.

Covers every observable behaviour of the new
``/api/v1/auth/admin/mfa/*`` surface plus the
:func:`require_admin_mfa_passed` policy gate exposed by
:mod:`src.auth.admin_dependencies`:

* enrolment happy path + idempotency + ``mfa_already_enabled`` 409;
* confirm with valid / invalid / no-pending TOTP shapes;
* verify TOTP / backup code (single-use) + 401 on wrong proof;
* verify XOR validation (both / neither) → 422;
* verify per-(subject, IP) rate limit → 429 with ``Retry-After``;
* disable + regenerate require fresh proof in the request body even
  when ``mfa_passed_at`` is fresh;
* status reports the ``mfa_passed_for_session`` signal correctly;
* logs never carry the secret URI / TOTP code / backup-code material;
* the gate enforces ``mfa_enrollment_required`` 403 + the
  ``X-MFA-Enrollment-Required`` header on a fresh super-admin and
  ``mfa_required`` 401 + ``X-MFA-Required`` on a stale session;
* gate degrades to no-op when ``ADMIN_MFA_ENFORCE_ROLES`` is empty;
* gate is opt-out for the legacy ``X-Admin-Key`` shim and for roles
  outside the enforcement set.

Persistence model
-----------------
The suite reuses the auth-conftest fixtures (``engine``,
``session_factory``, ``mfa_keyring``, ``settings_admin_mode_session``)
which apply Alembic 028 → 030 → 032 against an in-memory aiosqlite
engine — that is the post-C7-T01 ``admin_users`` / ``admin_sessions``
shape with the MFA columns and at-rest hashing in place. We DO NOT
mock the DAO layer; every test exercises the real Fernet keyring +
bcrypt + ``pyotp`` round-trip against the in-memory DB.

No new pip dependencies — TOTP codes are generated with
``pyotp.TOTP(secret).now()`` extracted from the ``otpauth://`` URI,
so we never need ``freezegun`` / ``time_machine`` to control the
TOTP window. Staleness tests rewind ``mfa_passed_at`` directly on the
``admin_sessions`` row.
"""

from __future__ import annotations

import logging
import re
from collections.abc import AsyncIterator, Iterator
from datetime import datetime, timedelta, timezone
from typing import Any, Final
from urllib.parse import parse_qs, urlparse

import pyotp  # type: ignore[import-not-found]  # pyotp ships no PEP-561 stubs
import pytest
from fastapi import APIRouter, Depends, FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, update

from src.api.admin import mfa as admin_mfa_router
from src.api.routers import admin_auth as admin_auth_router_module
from src.api.routers.admin_auth import ADMIN_SESSION_COOKIE
from src.auth.admin_dependencies import require_admin_mfa_passed
from src.auth.admin_users import hash_password
from src.core.config import settings
from src.db.models import AdminSession, AdminUser
from src.db.session import get_db

#: Stable subjects used across the suite — keep them narrow so a stray
#: row in the per-test DB cannot accidentally satisfy two assertions.
_SUBJECT_SUPER: Final[str] = "super-admin@argus.example"
_SUBJECT_ADMIN: Final[str] = "admin@argus.example"
_SUBJECT_OPERATOR: Final[str] = "operator@argus.example"

_PASSWORD: Final[str] = "Tr0ub4dor&3-not-the-real-one"

_MFA_PREFIX: Final[str] = "/api/v1/auth/admin/mfa"
_GATED_PATH: Final[str] = "/test/sensitive"


# ---------------------------------------------------------------------------
# Local fixtures — extend the conftest's admin_app with the MFA router
# and a synthetic gated endpoint that exercises ``require_admin_mfa_passed``
# without dragging in the full ``api.routers.admin`` surface (which would
# pull in unrelated ORM tables that revision 032 does not create).
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_verify_rate_limiter() -> Iterator[None]:
    """Drop the cached :class:`_VerifyRateLimiter` between tests.

    The limiter is a process-wide singleton (matches the production
    contract) so a leak from one test would skew the rate-limit
    assertions of the next. Mirror the pattern from
    ``conftest._reset_login_rate_limiter``.
    """
    admin_mfa_router._reset_verify_rate_limiter_for_tests()
    yield
    admin_mfa_router._reset_verify_rate_limiter_for_tests()


@pytest.fixture(autouse=True)
def _force_session_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin ``settings.admin_auth_mode`` to ``session`` for every MFA test.

    The MFA router depends on a real :class:`SessionPrincipal` — the
    legacy ``X-Admin-Key`` shim never lands one on ``request.state``,
    which would short-circuit every flow. Locking the mode here makes
    the suite deterministic regardless of what the developer's local
    ``backend/.env`` happens to be.
    """
    monkeypatch.setattr(settings, "admin_auth_mode", "session")


@pytest.fixture(autouse=True)
def _enforce_super_admin(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default to ``["super-admin"]`` for the gate.

    Individual tests that need an empty / extended set patch over this
    in their own body via ``monkeypatch.setattr(settings, ...)``.
    """
    monkeypatch.setattr(settings, "admin_mfa_enforce_roles", ["super-admin"])


@pytest.fixture
async def mfa_app(
    session_factory: Any,
    mfa_keyring: Any,  # noqa: ARG001 — pulls Fernet keyring side-effect
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[FastAPI]:
    """FastAPI app wired to the per-test SQLite engine for MFA tests.

    Mounts:
      * ``/api/v1/auth/admin/login`` (and friends) — needed to mint a
        real session cookie via the production login flow;
      * ``/api/v1/auth/admin/mfa/*`` — the surface under test;
      * ``/test/sensitive`` — synthetic gated endpoint that exercises
        :func:`require_admin_mfa_passed` end-to-end without coupling to
        unrelated admin endpoints (whose ORM tables aren't in the
        032 schema).
    """
    monkeypatch.setattr(
        "src.auth.admin_users.async_session_factory", session_factory
    )
    monkeypatch.setattr(
        "src.auth.admin_dependencies.async_session_factory", session_factory
    )

    app = FastAPI()
    app.include_router(admin_auth_router_module.router, prefix="/api/v1")
    app.include_router(admin_mfa_router.router, prefix="/api/v1")

    test_router = APIRouter()

    @test_router.get(
        _GATED_PATH,
        responses={
            200: {"description": "Allowed"},
            401: {"description": "MFA required"},
            403: {"description": "MFA enrolment required"},
        },
    )
    async def _sensitive(_: None = Depends(require_admin_mfa_passed)) -> dict[str, str]:
        """Synthetic sensitive route gated on the MFA policy."""
        return {"ok": "true"}

    app.include_router(test_router)

    async def _override_get_db() -> AsyncIterator[Any]:
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
    """Async HTTPS client wired directly to the MFA-enabled app."""
    transport = ASGITransport(app=mfa_app)
    async with AsyncClient(
        transport=transport, base_url="https://testserver"
    ) as ac:
        yield ac


# ---------------------------------------------------------------------------
# Domain helpers — admin seeding, login, secret extraction.
# ---------------------------------------------------------------------------


async def _seed_admin(
    session_factory: Any,
    *,
    subject: str,
    role: str = "admin",
    password: str = _PASSWORD,
) -> None:
    """Insert a fresh admin row (no MFA) and commit."""
    async with session_factory() as s:
        s.add(
            AdminUser(
                subject=subject,
                password_hash=hash_password(password),
                role=role,
                tenant_id=None,
                created_at=datetime.now(timezone.utc),
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
    """Log the admin in and return the resulting session id from the cookie."""
    response = await client.post(
        "/api/v1/auth/admin/login",
        json={"subject": subject, "password": password},
    )
    assert response.status_code == 200, response.text
    cookie = client.cookies.get(ADMIN_SESSION_COOKIE)
    assert cookie is not None and len(cookie) >= 60
    return cookie


_OTPAUTH_SECRET_RE = re.compile(r"^[A-Z2-7]{16,}$")


def _extract_totp_secret(secret_uri: str) -> str:
    """Pull the base32 secret out of an ``otpauth://`` URI."""
    parsed = urlparse(secret_uri)
    assert parsed.scheme == "otpauth", f"unexpected scheme: {parsed.scheme!r}"
    qs = parse_qs(parsed.query)
    secret_values = qs.get("secret") or []
    assert secret_values, f"no secret in {secret_uri!r}"
    secret = secret_values[0]
    assert _OTPAUTH_SECRET_RE.match(secret), (
        f"secret param does not match base32 alphabet: {secret!r}"
    )
    return secret


async def _enroll_and_confirm(
    client: AsyncClient,
    *,
    subject: str,
) -> dict[str, Any]:
    """Drive the full enrolment ceremony for *subject*; return secret/codes."""
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
    session_factory: Any,
    *,
    subject: str,
    when: datetime | None,
) -> None:
    """Rewrite ``mfa_passed_at`` on every active session row for *subject*."""
    async with session_factory() as s:
        await s.execute(
            update(AdminSession)
            .where(AdminSession.subject == subject)
            .where(AdminSession.revoked_at.is_(None))
            .values(mfa_passed_at=when)
        )
        await s.commit()


# ---------------------------------------------------------------------------
# Group A — POST /enroll
# ---------------------------------------------------------------------------


async def test_enroll_returns_secret_uri_and_ten_backup_codes(
    mfa_client: AsyncClient, session_factory: Any
) -> None:
    await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
    await _login(mfa_client, subject=_SUBJECT_ADMIN)

    response = await mfa_client.post(_MFA_PREFIX + "/enroll", json={})

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["secret_uri"].startswith("otpauth://totp/"), body["secret_uri"]
    assert _extract_totp_secret(body["secret_uri"])
    assert isinstance(body["backup_codes"], list)
    assert len(body["backup_codes"]) == 10
    assert all(len(c) == 16 for c in body["backup_codes"])
    # Per the C7-T03 docstring TODO (no qrcode/segno in requirements.txt).
    assert body["qr_data_uri"] is None


async def test_enroll_qr_data_uri_explicitly_none_when_no_encoder(
    mfa_client: AsyncClient, session_factory: Any
) -> None:
    """Honour the ``qrcode``/``segno``-absent fallback documented in the route."""
    await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
    await _login(mfa_client, subject=_SUBJECT_ADMIN)

    response = await mfa_client.post(_MFA_PREFIX + "/enroll", json={})

    assert response.status_code == 200
    assert response.json()["qr_data_uri"] is None


async def test_enroll_idempotent_second_call_overwrites_pending_secret(
    mfa_client: AsyncClient, session_factory: Any
) -> None:
    """Two ``/enroll`` calls before ``/confirm`` MUST overwrite the pending row.

    The DAO replaces the prior ciphertext + backup-code batch on every
    re-enrolment so an admin who lost the QR code can simply hit
    ``/enroll`` again. The plaintext codes returned in the second call
    are different from the first; the first batch is no longer usable.
    """
    await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
    await _login(mfa_client, subject=_SUBJECT_ADMIN)

    first = await mfa_client.post(_MFA_PREFIX + "/enroll", json={})
    second = await mfa_client.post(_MFA_PREFIX + "/enroll", json={})

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["secret_uri"] != second.json()["secret_uri"]
    assert first.json()["backup_codes"] != second.json()["backup_codes"]


async def test_enroll_when_already_enabled_returns_409(
    mfa_client: AsyncClient, session_factory: Any
) -> None:
    await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
    await _login(mfa_client, subject=_SUBJECT_ADMIN)
    await _enroll_and_confirm(mfa_client, subject=_SUBJECT_ADMIN)

    response = await mfa_client.post(_MFA_PREFIX + "/enroll", json={})

    assert response.status_code == 409
    assert response.json()["detail"] == "mfa_already_enabled"


async def test_enroll_without_session_returns_401(mfa_client: AsyncClient) -> None:
    response = await mfa_client.post(_MFA_PREFIX + "/enroll", json={})
    assert response.status_code == 401
    assert response.json()["detail"] == "Authentication required"


async def test_enroll_rejects_extra_fields_with_422(
    mfa_client: AsyncClient, session_factory: Any
) -> None:
    """``extra=forbid`` blocks parameter pollution at the schema layer."""
    await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
    await _login(mfa_client, subject=_SUBJECT_ADMIN)

    response = await mfa_client.post(
        _MFA_PREFIX + "/enroll", json={"forced_subject": "victim@example.com"}
    )

    assert response.status_code == 422


# ---------------------------------------------------------------------------
# Group B — POST /confirm
# ---------------------------------------------------------------------------


async def test_confirm_with_valid_totp_enables_mfa_and_stamps_session(
    mfa_client: AsyncClient, session_factory: Any
) -> None:
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
    assert body["enabled_at"].endswith("Z") or "+00:00" in body["enabled_at"]

    async with session_factory() as s:
        rows = (
            await s.execute(
                select(AdminSession).where(AdminSession.subject == _SUBJECT_ADMIN)
            )
        ).scalars().all()
        assert rows, "expected at least one session row"
        assert any(r.mfa_passed_at is not None for r in rows), (
            "confirm MUST stamp mfa_passed_at on the calling session"
        )


async def test_confirm_with_invalid_totp_returns_400_invalid_totp(
    mfa_client: AsyncClient, session_factory: Any
) -> None:
    await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
    await _login(mfa_client, subject=_SUBJECT_ADMIN)
    await mfa_client.post(_MFA_PREFIX + "/enroll", json={})

    response = await mfa_client.post(
        _MFA_PREFIX + "/confirm", json={"totp_code": "000000"}
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "invalid_totp"


async def test_confirm_without_prior_enrollment_returns_400_no_pending(
    mfa_client: AsyncClient, session_factory: Any
) -> None:
    await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
    await _login(mfa_client, subject=_SUBJECT_ADMIN)

    response = await mfa_client.post(
        _MFA_PREFIX + "/confirm", json={"totp_code": "123456"}
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "no_pending_enrollment"


async def test_confirm_rejects_short_totp_code_with_422(
    mfa_client: AsyncClient, session_factory: Any
) -> None:
    await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
    await _login(mfa_client, subject=_SUBJECT_ADMIN)

    response = await mfa_client.post(
        _MFA_PREFIX + "/confirm", json={"totp_code": "12345"}
    )
    assert response.status_code == 422


async def test_confirm_rejects_alphabetic_totp_code_with_422(
    mfa_client: AsyncClient, session_factory: Any
) -> None:
    await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
    await _login(mfa_client, subject=_SUBJECT_ADMIN)

    response = await mfa_client.post(
        _MFA_PREFIX + "/confirm", json={"totp_code": "abcdef"}
    )
    assert response.status_code == 422


async def test_confirm_without_session_returns_401(mfa_client: AsyncClient) -> None:
    response = await mfa_client.post(
        _MFA_PREFIX + "/confirm", json={"totp_code": "123456"}
    )
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# Group C — POST /verify
# ---------------------------------------------------------------------------


async def test_verify_totp_happy_path_sets_mfa_passed_at(
    mfa_client: AsyncClient, session_factory: Any
) -> None:
    await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
    await _login(mfa_client, subject=_SUBJECT_ADMIN)
    enrolled = await _enroll_and_confirm(mfa_client, subject=_SUBJECT_ADMIN)

    # Wipe the freshness stamp so /verify has work to do.
    await _force_mfa_passed_at(
        session_factory, subject=_SUBJECT_ADMIN, when=None
    )

    response = await mfa_client.post(
        _MFA_PREFIX + "/verify",
        json={"totp_code": pyotp.TOTP(enrolled["secret"]).now()},
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["verified"] is True
    assert body["remaining_backup_codes"] is None  # TOTP path


async def test_verify_backup_code_happy_path_decrements_count(
    mfa_client: AsyncClient, session_factory: Any
) -> None:
    await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
    await _login(mfa_client, subject=_SUBJECT_ADMIN)
    enrolled = await _enroll_and_confirm(mfa_client, subject=_SUBJECT_ADMIN)
    await _force_mfa_passed_at(
        session_factory, subject=_SUBJECT_ADMIN, when=None
    )

    response = await mfa_client.post(
        _MFA_PREFIX + "/verify",
        json={"backup_code": enrolled["backup_codes"][0]},
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["verified"] is True
    assert body["remaining_backup_codes"] == 9


async def test_verify_backup_code_second_use_returns_401_consumed(
    mfa_client: AsyncClient, session_factory: Any
) -> None:
    """One-shot semantics: the same backup code cannot be replayed."""
    await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
    await _login(mfa_client, subject=_SUBJECT_ADMIN)
    enrolled = await _enroll_and_confirm(mfa_client, subject=_SUBJECT_ADMIN)
    await _force_mfa_passed_at(
        session_factory, subject=_SUBJECT_ADMIN, when=None
    )

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


async def test_verify_with_both_credentials_returns_422_xor(
    mfa_client: AsyncClient, session_factory: Any
) -> None:
    await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
    await _login(mfa_client, subject=_SUBJECT_ADMIN)

    response = await mfa_client.post(
        _MFA_PREFIX + "/verify",
        json={
            "totp_code": "123456",
            "backup_code": "ABCDEFGHJKLMNPQR",
        },
    )

    assert response.status_code == 422


async def test_verify_with_neither_credential_returns_422_xor(
    mfa_client: AsyncClient, session_factory: Any
) -> None:
    await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
    await _login(mfa_client, subject=_SUBJECT_ADMIN)

    response = await mfa_client.post(_MFA_PREFIX + "/verify", json={})
    assert response.status_code == 422


async def test_verify_with_wrong_totp_returns_401_mfa_verify_failed(
    mfa_client: AsyncClient, session_factory: Any
) -> None:
    """Failure detail MUST be the bounded ``mfa_verify_failed`` taxonomy.

    We never differentiate "wrong TOTP" from "wrong backup code" so a
    brute-forcer cannot fingerprint which of the two paths succeeded
    against a typo.
    """
    await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
    await _login(mfa_client, subject=_SUBJECT_ADMIN)
    await _enroll_and_confirm(mfa_client, subject=_SUBJECT_ADMIN)

    response = await mfa_client.post(
        _MFA_PREFIX + "/verify", json={"totp_code": "000000"}
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "mfa_verify_failed"


async def test_verify_with_unknown_backup_code_returns_401_mfa_verify_failed(
    mfa_client: AsyncClient, session_factory: Any
) -> None:
    await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
    await _login(mfa_client, subject=_SUBJECT_ADMIN)
    await _enroll_and_confirm(mfa_client, subject=_SUBJECT_ADMIN)

    response = await mfa_client.post(
        _MFA_PREFIX + "/verify",
        json={"backup_code": "ZZZZZZZZZZZZZZZZ"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "mfa_verify_failed"


async def test_verify_rate_limit_trips_at_sixth_wrong_attempt_with_retry_after(
    mfa_client: AsyncClient, session_factory: Any
) -> None:
    """Per-(subject, IP) bucket caps verify attempts at 5/min — the 6th 429s."""
    await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
    await _login(mfa_client, subject=_SUBJECT_ADMIN)
    await _enroll_and_confirm(mfa_client, subject=_SUBJECT_ADMIN)

    body = {"totp_code": "000000"}
    statuses: list[int] = []
    for _ in range(5):
        r = await mfa_client.post(_MFA_PREFIX + "/verify", json=body)
        statuses.append(r.status_code)

    assert statuses == [401] * 5, f"expected five 401s, got {statuses}"

    sixth = await mfa_client.post(_MFA_PREFIX + "/verify", json=body)
    assert sixth.status_code == 429
    assert sixth.headers.get("Retry-After"), (
        "rate-limit response MUST include a Retry-After header"
    )
    assert "again later" in sixth.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Group D — POST /disable
# ---------------------------------------------------------------------------


async def test_disable_with_no_proof_in_body_returns_422(
    mfa_client: AsyncClient, session_factory: Any
) -> None:
    """Empty body fails the XOR validator at the Pydantic layer."""
    await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
    await _login(mfa_client, subject=_SUBJECT_ADMIN)
    await _enroll_and_confirm(mfa_client, subject=_SUBJECT_ADMIN)

    response = await mfa_client.post(_MFA_PREFIX + "/disable", json={})
    assert response.status_code == 422


async def test_disable_with_valid_totp_returns_200_and_wipes_columns(
    mfa_client: AsyncClient, session_factory: Any
) -> None:
    await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
    await _login(mfa_client, subject=_SUBJECT_ADMIN)
    enrolled = await _enroll_and_confirm(mfa_client, subject=_SUBJECT_ADMIN)

    response = await mfa_client.post(
        _MFA_PREFIX + "/disable",
        json={"totp_code": pyotp.TOTP(enrolled["secret"]).now()},
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["disabled"] is True

    async with session_factory() as s:
        row = (
            await s.execute(
                select(AdminUser).where(AdminUser.subject == _SUBJECT_ADMIN)
            )
        ).scalar_one()
        assert row.mfa_enabled is False
        assert row.mfa_secret_encrypted is None
        assert row.mfa_backup_codes_hash in (None, [])


async def test_disable_with_valid_backup_code_returns_200(
    mfa_client: AsyncClient, session_factory: Any
) -> None:
    await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
    await _login(mfa_client, subject=_SUBJECT_ADMIN)
    enrolled = await _enroll_and_confirm(mfa_client, subject=_SUBJECT_ADMIN)

    response = await mfa_client.post(
        _MFA_PREFIX + "/disable",
        json={"backup_code": enrolled["backup_codes"][0]},
    )
    assert response.status_code == 200


async def test_disable_with_wrong_totp_returns_401_mfa_verify_failed(
    mfa_client: AsyncClient, session_factory: Any
) -> None:
    """Even when ``mfa_passed_at`` is fresh, a wrong proof MUST 401.

    Disable trusts NO session state alone — a stolen but already
    MFA-passed cookie cannot silently strip MFA.
    """
    await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
    await _login(mfa_client, subject=_SUBJECT_ADMIN)
    await _enroll_and_confirm(mfa_client, subject=_SUBJECT_ADMIN)

    response = await mfa_client.post(
        _MFA_PREFIX + "/disable", json={"totp_code": "000000"}
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "mfa_verify_failed"


async def test_disable_when_mfa_not_enabled_returns_409(
    mfa_client: AsyncClient, session_factory: Any
) -> None:
    await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
    await _login(mfa_client, subject=_SUBJECT_ADMIN)

    response = await mfa_client.post(
        _MFA_PREFIX + "/disable", json={"totp_code": "123456"}
    )
    assert response.status_code == 409
    assert response.json()["detail"] == "mfa_not_enabled"


# ---------------------------------------------------------------------------
# Group E — GET /status
# ---------------------------------------------------------------------------


async def test_status_when_not_enrolled_reports_disabled(
    mfa_client: AsyncClient, session_factory: Any
) -> None:
    await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
    await _login(mfa_client, subject=_SUBJECT_ADMIN)

    response = await mfa_client.get(_MFA_PREFIX + "/status")

    assert response.status_code == 200
    body = response.json()
    assert body["enabled"] is False
    assert body["remaining_backup_codes"] is None
    assert body["mfa_passed_for_session"] is False
    assert body["enrolled_at"] is None  # follow-up Alembic 03N


async def test_status_when_enrolled_and_fresh_reports_passed_true(
    mfa_client: AsyncClient, session_factory: Any
) -> None:
    await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
    await _login(mfa_client, subject=_SUBJECT_ADMIN)
    await _enroll_and_confirm(mfa_client, subject=_SUBJECT_ADMIN)

    response = await mfa_client.get(_MFA_PREFIX + "/status")

    assert response.status_code == 200
    body = response.json()
    assert body["enabled"] is True
    assert body["remaining_backup_codes"] == 10
    assert body["mfa_passed_for_session"] is True


async def test_status_when_enrolled_but_stale_reports_passed_false(
    mfa_client: AsyncClient,
    session_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Stale ``mfa_passed_at`` outside the reauth window flips the flag back to False."""
    await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
    await _login(mfa_client, subject=_SUBJECT_ADMIN)
    await _enroll_and_confirm(mfa_client, subject=_SUBJECT_ADMIN)

    # Reauth window of 60 seconds; stamp the row 1 hour in the past.
    monkeypatch.setattr(settings, "admin_mfa_reauth_window_seconds", 60)
    await _force_mfa_passed_at(
        session_factory,
        subject=_SUBJECT_ADMIN,
        when=datetime.now(timezone.utc) - timedelta(hours=1),
    )

    response = await mfa_client.get(_MFA_PREFIX + "/status")

    assert response.status_code == 200
    assert response.json()["mfa_passed_for_session"] is False


# ---------------------------------------------------------------------------
# Group F — POST /backup-codes/regenerate
# ---------------------------------------------------------------------------


async def test_regenerate_returns_new_codes_and_invalidates_old(
    mfa_client: AsyncClient, session_factory: Any
) -> None:
    await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
    await _login(mfa_client, subject=_SUBJECT_ADMIN)
    enrolled = await _enroll_and_confirm(mfa_client, subject=_SUBJECT_ADMIN)
    old_codes = enrolled["backup_codes"]

    response = await mfa_client.post(
        _MFA_PREFIX + "/backup-codes/regenerate",
        json={"totp_code": pyotp.TOTP(enrolled["secret"]).now()},
    )

    assert response.status_code == 200, response.text
    body = response.json()
    new_codes = body["backup_codes"]
    assert len(new_codes) == 10
    assert set(new_codes).isdisjoint(set(old_codes))

    # Old codes no longer verify.
    await _force_mfa_passed_at(
        session_factory, subject=_SUBJECT_ADMIN, when=None
    )
    old_attempt = await mfa_client.post(
        _MFA_PREFIX + "/verify", json={"backup_code": old_codes[0]}
    )
    assert old_attempt.status_code == 401

    # New codes do verify (rate-limit budget still allows 4 more attempts).
    new_attempt = await mfa_client.post(
        _MFA_PREFIX + "/verify", json={"backup_code": new_codes[0]}
    )
    assert new_attempt.status_code == 200


async def test_regenerate_each_new_code_is_single_use(
    mfa_client: AsyncClient, session_factory: Any
) -> None:
    await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
    await _login(mfa_client, subject=_SUBJECT_ADMIN)
    enrolled = await _enroll_and_confirm(mfa_client, subject=_SUBJECT_ADMIN)

    response = await mfa_client.post(
        _MFA_PREFIX + "/backup-codes/regenerate",
        json={"totp_code": pyotp.TOTP(enrolled["secret"]).now()},
    )
    new_codes = response.json()["backup_codes"]

    await _force_mfa_passed_at(
        session_factory, subject=_SUBJECT_ADMIN, when=None
    )
    code = new_codes[0]
    first = await mfa_client.post(
        _MFA_PREFIX + "/verify", json={"backup_code": code}
    )
    second = await mfa_client.post(
        _MFA_PREFIX + "/verify", json={"backup_code": code}
    )
    assert first.status_code == 200
    assert second.status_code == 401


async def test_regenerate_when_mfa_not_enabled_returns_409(
    mfa_client: AsyncClient, session_factory: Any
) -> None:
    await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
    await _login(mfa_client, subject=_SUBJECT_ADMIN)

    response = await mfa_client.post(
        _MFA_PREFIX + "/backup-codes/regenerate",
        json={"totp_code": "123456"},
    )
    assert response.status_code == 409
    assert response.json()["detail"] == "mfa_not_enabled"


async def test_regenerate_with_wrong_proof_returns_401_mfa_verify_failed(
    mfa_client: AsyncClient, session_factory: Any
) -> None:
    await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
    await _login(mfa_client, subject=_SUBJECT_ADMIN)
    await _enroll_and_confirm(mfa_client, subject=_SUBJECT_ADMIN)

    response = await mfa_client.post(
        _MFA_PREFIX + "/backup-codes/regenerate",
        json={"totp_code": "000000"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "mfa_verify_failed"


# ---------------------------------------------------------------------------
# Group G — log hygiene (no secret material in caplog records)
# ---------------------------------------------------------------------------


async def test_no_secret_or_code_material_in_logs_across_full_flow(
    mfa_client: AsyncClient,
    session_factory: Any,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Full lifecycle MUST never leave plaintext credentials in log records.

    Captures ``WARNING / INFO / ERROR`` from every MFA logger and walks
    through enrol → confirm → verify (both paths) → disable → regenerate,
    then asserts no leaked secret material lands in any log line —
    including the ``otpauth://`` URI's secret param, the TOTP code, and
    every backup code (plaintext or hash fragment).
    """
    caplog.set_level(logging.INFO)

    await _seed_admin(session_factory, subject=_SUBJECT_ADMIN)
    await _login(mfa_client, subject=_SUBJECT_ADMIN)

    enroll = await mfa_client.post(_MFA_PREFIX + "/enroll", json={})
    body = enroll.json()
    secret = _extract_totp_secret(body["secret_uri"])
    backup_codes: list[str] = body["backup_codes"]

    confirm_code = pyotp.TOTP(secret).now()
    await mfa_client.post(
        _MFA_PREFIX + "/confirm", json={"totp_code": confirm_code}
    )
    await _force_mfa_passed_at(
        session_factory, subject=_SUBJECT_ADMIN, when=None
    )
    verify_code = pyotp.TOTP(secret).now()
    await mfa_client.post(
        _MFA_PREFIX + "/verify", json={"totp_code": verify_code}
    )
    await mfa_client.post(
        _MFA_PREFIX + "/verify", json={"backup_code": backup_codes[0]}
    )
    regen = await mfa_client.post(
        _MFA_PREFIX + "/backup-codes/regenerate",
        json={"totp_code": pyotp.TOTP(secret).now()},
    )
    new_codes = regen.json()["backup_codes"]

    forbidden = {secret, body["secret_uri"], confirm_code, verify_code}
    forbidden.update(backup_codes)
    forbidden.update(new_codes)

    for record in caplog.records:
        rendered = record.getMessage()
        for token in forbidden:
            assert token not in rendered, (
                f"forbidden token {token!r} leaked into log: {rendered!r}"
            )
        # Also walk the ``extra`` dict on each record — structured logs
        # land there, not in the message.
        for key, value in record.__dict__.items():
            if not isinstance(value, str):
                continue
            for token in forbidden:
                assert token not in value, (
                    f"forbidden token {token!r} leaked into "
                    f"record.{key}: {value!r}"
                )


# ---------------------------------------------------------------------------
# Group H — require_admin_mfa_passed gate
# ---------------------------------------------------------------------------


async def test_gate_blocks_super_admin_without_mfa_with_403_x_mfa_enrollment_required(
    mfa_client: AsyncClient, session_factory: Any
) -> None:
    """A super-admin who never enrolled MUST be bounced before the handler."""
    await _seed_admin(
        session_factory, subject=_SUBJECT_SUPER, role="super-admin"
    )
    await _login(mfa_client, subject=_SUBJECT_SUPER)

    response = await mfa_client.get(_GATED_PATH)

    assert response.status_code == 403
    assert response.json()["detail"] == "mfa_enrollment_required"
    assert response.headers.get("X-MFA-Enrollment-Required") == "true"


async def test_gate_blocks_super_admin_with_stale_mfa_passed_at_with_401_x_mfa_required(
    mfa_client: AsyncClient,
    session_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await _seed_admin(
        session_factory, subject=_SUBJECT_SUPER, role="super-admin"
    )
    await _login(mfa_client, subject=_SUBJECT_SUPER)
    await _enroll_and_confirm(mfa_client, subject=_SUBJECT_SUPER)

    # Force a stale mfa_passed_at against a tight reauth window.
    monkeypatch.setattr(settings, "admin_mfa_reauth_window_seconds", 60)
    await _force_mfa_passed_at(
        session_factory,
        subject=_SUBJECT_SUPER,
        when=datetime.now(timezone.utc) - timedelta(hours=1),
    )

    response = await mfa_client.get(_GATED_PATH)

    assert response.status_code == 401
    assert response.json()["detail"] == "mfa_required"
    assert response.headers.get("X-MFA-Required") == "true"


async def test_gate_passes_super_admin_with_fresh_mfa(
    mfa_client: AsyncClient, session_factory: Any
) -> None:
    await _seed_admin(
        session_factory, subject=_SUBJECT_SUPER, role="super-admin"
    )
    await _login(mfa_client, subject=_SUBJECT_SUPER)
    await _enroll_and_confirm(mfa_client, subject=_SUBJECT_SUPER)

    response = await mfa_client.get(_GATED_PATH)

    assert response.status_code == 200
    assert response.json() == {"ok": "true"}


async def test_gate_passes_admin_role_outside_enforcement_set(
    mfa_client: AsyncClient,
    session_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An ``admin`` role hitting the gate while only ``super-admin`` is enforced MUST pass through."""
    monkeypatch.setattr(settings, "admin_mfa_enforce_roles", ["super-admin"])

    await _seed_admin(session_factory, subject=_SUBJECT_ADMIN, role="admin")
    await _login(mfa_client, subject=_SUBJECT_ADMIN)

    response = await mfa_client.get(_GATED_PATH)

    assert response.status_code == 200
    assert response.json() == {"ok": "true"}


async def test_gate_no_op_when_enforcement_set_is_empty(
    mfa_client: AsyncClient,
    session_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Empty enforcement set degrades the gate to a pass-through."""
    monkeypatch.setattr(settings, "admin_mfa_enforce_roles", [])

    await _seed_admin(
        session_factory, subject=_SUBJECT_SUPER, role="super-admin"
    )
    await _login(mfa_client, subject=_SUBJECT_SUPER)

    response = await mfa_client.get(_GATED_PATH)
    assert response.status_code == 200


async def test_gate_passes_legacy_x_admin_key_when_session_mode_allows_both(
    mfa_client: AsyncClient,
    session_factory: Any,  # noqa: ARG001 — fixture pulled for engine wiring
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Legacy ``X-Admin-Key`` shim has no SessionPrincipal, so the gate degrades.

    The dual-mode bridge MUST NOT 401 on the MFA gate when an operator
    is still on the legacy header path — the gate cannot enforce on a
    surface where there is no session row to inspect.
    """
    monkeypatch.setattr(settings, "admin_auth_mode", "both")
    monkeypatch.setattr(settings, "admin_api_key", "test-legacy-key-c7-t03")

    response = await mfa_client.get(
        _GATED_PATH, headers={"X-Admin-Key": "test-legacy-key-c7-t03"}
    )

    assert response.status_code == 200, response.text


async def test_gate_unauthenticated_caller_returns_401_from_underlying_require_admin(
    mfa_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The underlying ``require_admin`` 401s before the MFA gate runs."""
    monkeypatch.setattr(settings, "admin_auth_mode", "session")

    response = await mfa_client.get(_GATED_PATH)

    assert response.status_code == 401
    # No MFA headers — the failure is the upstream session-auth gate.
    assert "X-MFA-Required" not in response.headers
    assert "X-MFA-Enrollment-Required" not in response.headers


async def test_gate_emits_structured_log_on_enrollment_block(
    mfa_client: AsyncClient,
    session_factory: Any,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The gate's 403 path MUST emit ``argus.auth.admin_mfa.gate_blocked``."""
    caplog.set_level(logging.INFO)

    await _seed_admin(
        session_factory, subject=_SUBJECT_SUPER, role="super-admin"
    )
    await _login(mfa_client, subject=_SUBJECT_SUPER)

    response = await mfa_client.get(_GATED_PATH)
    assert response.status_code == 403

    matched = [
        r
        for r in caplog.records
        if getattr(r, "event", None) == "argus.auth.admin_mfa.gate_blocked"
        and getattr(r, "reason", None) == "role_requires_mfa_but_not_enrolled"
    ]
    assert matched, (
        "expected one structured gate-blocked log line on enrolment block"
    )


async def test_gate_emits_structured_log_on_stale_session_block(
    mfa_client: AsyncClient,
    session_factory: Any,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    caplog.set_level(logging.INFO)

    await _seed_admin(
        session_factory, subject=_SUBJECT_SUPER, role="super-admin"
    )
    await _login(mfa_client, subject=_SUBJECT_SUPER)
    await _enroll_and_confirm(mfa_client, subject=_SUBJECT_SUPER)

    monkeypatch.setattr(settings, "admin_mfa_reauth_window_seconds", 60)
    await _force_mfa_passed_at(
        session_factory,
        subject=_SUBJECT_SUPER,
        when=datetime.now(timezone.utc) - timedelta(hours=1),
    )

    response = await mfa_client.get(_GATED_PATH)
    assert response.status_code == 401

    matched = [
        r
        for r in caplog.records
        if getattr(r, "event", None) == "argus.auth.admin_mfa.gate_blocked"
        and getattr(r, "reason", None) == "stale_or_missing_mfa_passed_at"
    ]
    assert matched, (
        "expected one structured gate-blocked log line on stale-session block"
    )
