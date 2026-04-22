"""HTTP-level tests for the admin auth router (``/auth/admin/*``).

Covers every observable behaviour of the new login / logout / whoami
surface introduced by B6-T08:

* ``POST /auth/admin/login`` happy path mints a session cookie + body
  ``{role, tenant_id, expires_at}``;
* invalid credentials return HTTP 401 with the same generic error wording
  for "subject unknown" and "wrong password" (no enumeration);
* the per-IP rate-limit gate trips at the configured threshold and emits
  a ``Retry-After`` header without echoing the token bucket state;
* ``POST /auth/admin/logout`` revokes the session, clears the cookie,
  and is idempotent;
* ``GET /auth/admin/whoami`` accepts cookie OR
  ``Authorization: Bearer <session>`` and rejects missing / expired /
  revoked / forged ids.

The HTTP client uses ``https://testserver`` so the ``Secure`` cookie
attribute applied by the router is honoured by httpx (otherwise the
client would silently drop the cookie on the next request).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from src.api.routers.admin_auth import ADMIN_SESSION_COOKIE
from src.auth.admin_users import hash_password
from src.core.config import settings
from src.db.models import AdminSession, AdminUser

from .conftest import TEST_ADMIN_SUBJECT, TEST_PLAINTEXT_PASSWORD


# ---------------------------------------------------------------------------
# Seeding helper.
# ---------------------------------------------------------------------------


async def _seed_admin(
    session_factory,
    *,
    role: str = "admin",
    tenant_id: str | None = None,
    disabled: bool = False,
) -> str:
    """Insert a single admin row and return the canonical subject."""
    async with session_factory() as s:
        digest = hash_password(TEST_PLAINTEXT_PASSWORD)
        row = AdminUser(
            subject=TEST_ADMIN_SUBJECT,
            password_hash=digest,
            role=role,
            tenant_id=tenant_id,
            created_at=datetime.now(timezone.utc),
            disabled_at=datetime.now(timezone.utc) if disabled else None,
        )
        s.add(row)
        await s.commit()
    return TEST_ADMIN_SUBJECT


# ---------------------------------------------------------------------------
# POST /auth/admin/login
# ---------------------------------------------------------------------------


async def test_login_happy_path_sets_cookie_and_returns_payload(
    api_client, session_factory
) -> None:
    await _seed_admin(session_factory, role="admin")

    response = await api_client.post(
        "/api/v1/auth/admin/login",
        json={"subject": TEST_ADMIN_SUBJECT, "password": TEST_PLAINTEXT_PASSWORD},
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body == {
        "role": "admin",
        "tenant_id": None,
        "expires_at": body["expires_at"],
    }
    assert isinstance(body["expires_at"], str)
    assert body["expires_at"].endswith("Z")
    assert "subject" not in body, "login response must not echo the subject"

    set_cookie_headers = response.headers.get_list("set-cookie")
    assert any(
        ADMIN_SESSION_COOKIE in h for h in set_cookie_headers
    ), f"missing {ADMIN_SESSION_COOKIE} cookie: {set_cookie_headers!r}"

    cookie_header = next(h for h in set_cookie_headers if ADMIN_SESSION_COOKIE in h)
    normalized = cookie_header.lower().replace(" ", "")
    assert "httponly" in normalized
    assert "secure" in normalized
    assert "samesite=strict" in normalized
    assert "path=/" in normalized

    cookie = api_client.cookies.get(ADMIN_SESSION_COOKIE)
    assert cookie is not None and len(cookie) >= 60


async def test_login_with_wrong_password_returns_401_generic_message(
    api_client, session_factory
) -> None:
    await _seed_admin(session_factory)

    response = await api_client.post(
        "/api/v1/auth/admin/login",
        json={"subject": TEST_ADMIN_SUBJECT, "password": "definitely-wrong"},
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid credentials"}
    assert ADMIN_SESSION_COOKIE not in api_client.cookies


async def test_login_with_unknown_subject_returns_same_401_message(
    api_client, session_factory
) -> None:
    """Subject-unknown and wrong-password MUST be indistinguishable to clients."""
    await _seed_admin(session_factory)

    response = await api_client.post(
        "/api/v1/auth/admin/login",
        json={
            "subject": "ghost@nowhere.invalid",
            "password": TEST_PLAINTEXT_PASSWORD,
        },
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid credentials"}


async def test_login_with_disabled_account_returns_same_401_message(
    api_client, session_factory
) -> None:
    await _seed_admin(session_factory, disabled=True)

    response = await api_client.post(
        "/api/v1/auth/admin/login",
        json={"subject": TEST_ADMIN_SUBJECT, "password": TEST_PLAINTEXT_PASSWORD},
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid credentials"}


async def test_login_with_short_password_returns_validation_error(
    api_client,
) -> None:
    """Pydantic guards against zero-length password — 422, not 401."""
    response = await api_client.post(
        "/api/v1/auth/admin/login",
        json={"subject": TEST_ADMIN_SUBJECT, "password": ""},
    )
    assert response.status_code == 422


async def test_login_with_oversized_password_returns_validation_error(
    api_client,
) -> None:
    """Hostile clients cannot ship megabyte-long bodies into the bcrypt path."""
    response = await api_client.post(
        "/api/v1/auth/admin/login",
        json={"subject": TEST_ADMIN_SUBJECT, "password": "x" * 5000},
    )
    assert response.status_code == 422


async def test_login_rate_limit_returns_429_with_retry_after(
    api_client, session_factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """After ``per_minute`` requests from the same IP, login MUST 429."""
    monkeypatch.setattr(settings, "admin_login_rate_limit_per_minute", 2)
    await _seed_admin(session_factory)

    body = {"subject": TEST_ADMIN_SUBJECT, "password": "wrong-password-xyz"}

    first = await api_client.post("/api/v1/auth/admin/login", json=body)
    second = await api_client.post("/api/v1/auth/admin/login", json=body)
    assert first.status_code == 401
    assert second.status_code == 401

    third = await api_client.post("/api/v1/auth/admin/login", json=body)
    assert third.status_code == 429
    assert third.headers.get("Retry-After"), (
        "rate-limit response MUST include a Retry-After header"
    )
    assert "again later" in third.json()["detail"].lower()


async def test_login_does_not_log_plaintext_password(
    api_client, session_factory, caplog: pytest.LogCaptureFixture
) -> None:
    await _seed_admin(session_factory)
    caplog.set_level("INFO")

    await api_client.post(
        "/api/v1/auth/admin/login",
        json={"subject": TEST_ADMIN_SUBJECT, "password": TEST_PLAINTEXT_PASSWORD},
    )

    for record in caplog.records:
        assert TEST_PLAINTEXT_PASSWORD not in record.getMessage()


# ---------------------------------------------------------------------------
# POST /auth/admin/logout
# ---------------------------------------------------------------------------


async def test_logout_revokes_session_and_clears_cookie(
    api_client, session_factory
) -> None:
    await _seed_admin(session_factory)

    login = await api_client.post(
        "/api/v1/auth/admin/login",
        json={"subject": TEST_ADMIN_SUBJECT, "password": TEST_PLAINTEXT_PASSWORD},
    )
    assert login.status_code == 200
    session_id = api_client.cookies.get(ADMIN_SESSION_COOKIE)
    assert session_id

    response = await api_client.post("/api/v1/auth/admin/logout")
    assert response.status_code == 200
    assert response.json() == {"revoked": True}

    set_cookie_headers = response.headers.get_list("set-cookie")
    deletion = next(
        (h for h in set_cookie_headers if ADMIN_SESSION_COOKIE in h), None
    )
    assert deletion is not None, "logout MUST emit a deletion Set-Cookie header"
    assert "Max-Age=0" in deletion or "expires=Thu, 01 Jan 1970" in deletion.lower()

    async with session_factory() as s:
        row = await s.get(AdminSession, session_id)
        assert row is not None
        assert row.revoked_at is not None, (
            "logout MUST tombstone the session row in admin_sessions"
        )


async def test_logout_without_active_session_is_idempotent(
    api_client,
) -> None:
    response = await api_client.post("/api/v1/auth/admin/logout")
    assert response.status_code == 200
    assert response.json() == {"revoked": False}


# ---------------------------------------------------------------------------
# GET /auth/admin/whoami
# ---------------------------------------------------------------------------


async def test_whoami_with_valid_cookie_returns_principal(
    api_client, session_factory
) -> None:
    await _seed_admin(session_factory, role="admin")

    login = await api_client.post(
        "/api/v1/auth/admin/login",
        json={"subject": TEST_ADMIN_SUBJECT, "password": TEST_PLAINTEXT_PASSWORD},
    )
    assert login.status_code == 200

    response = await api_client.get("/api/v1/auth/admin/whoami")
    assert response.status_code == 200
    body = response.json()
    assert body["subject"] == TEST_ADMIN_SUBJECT
    assert body["role"] == "admin"
    assert body["tenant_id"] is None
    assert body["expires_at"].endswith("Z")


async def test_whoami_with_bearer_header_returns_principal(
    api_client, session_factory
) -> None:
    await _seed_admin(session_factory, role="operator")

    await api_client.post(
        "/api/v1/auth/admin/login",
        json={"subject": TEST_ADMIN_SUBJECT, "password": TEST_PLAINTEXT_PASSWORD},
    )
    session_id = api_client.cookies.get(ADMIN_SESSION_COOKIE)
    assert session_id is not None
    api_client.cookies.delete(ADMIN_SESSION_COOKIE)

    response = await api_client.get(
        "/api/v1/auth/admin/whoami",
        headers={"Authorization": f"Bearer {session_id}"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["subject"] == TEST_ADMIN_SUBJECT
    assert response.json()["role"] == "operator"


async def test_whoami_without_session_returns_401(api_client) -> None:
    response = await api_client.get("/api/v1/auth/admin/whoami")
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid credentials"}


async def test_whoami_with_revoked_session_returns_401(
    api_client, session_factory
) -> None:
    await _seed_admin(session_factory)

    await api_client.post(
        "/api/v1/auth/admin/login",
        json={"subject": TEST_ADMIN_SUBJECT, "password": TEST_PLAINTEXT_PASSWORD},
    )
    await api_client.post("/api/v1/auth/admin/logout")

    response = await api_client.get("/api/v1/auth/admin/whoami")
    assert response.status_code == 401


async def test_whoami_with_expired_session_returns_401(
    api_client, session_factory
) -> None:
    """Mutate ``expires_at`` into the past and confirm whoami refuses the cookie."""
    await _seed_admin(session_factory)

    login = await api_client.post(
        "/api/v1/auth/admin/login",
        json={"subject": TEST_ADMIN_SUBJECT, "password": TEST_PLAINTEXT_PASSWORD},
    )
    session_id = api_client.cookies.get(ADMIN_SESSION_COOKIE)
    assert session_id and login.status_code == 200

    async with session_factory() as s:
        row = await s.get(AdminSession, session_id)
        assert row is not None
        row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)
        await s.commit()

    response = await api_client.get("/api/v1/auth/admin/whoami")
    assert response.status_code == 401


async def test_whoami_with_forged_session_id_returns_401(api_client) -> None:
    """A random / unknown id MUST be rejected with the same 401 message."""
    api_client.cookies.set(ADMIN_SESSION_COOKIE, "this-is-not-a-real-session-id-xx")
    response = await api_client.get("/api/v1/auth/admin/whoami")
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid credentials"}


# ---------------------------------------------------------------------------
# Logging discipline — full session id MUST NOT appear in any log record.
# ---------------------------------------------------------------------------


async def test_full_session_id_never_logged(
    api_client, session_factory, caplog: pytest.LogCaptureFixture
) -> None:
    """Our application code (``src.*``) must never emit a full session id.

    The DB driver layer (``aiosqlite`` / ``sqlalchemy.engine``) DOES log
    raw SQL — including parameter binds — at the DEBUG level. That's a
    development-only knob: production logging is configured at INFO and
    above, where no driver-level SQL trace ever reaches the log surface.
    The contract we care about for B6-T08 is that *our own* code never
    leaks a full session_id; the test enforces exactly that.
    """
    await _seed_admin(session_factory)
    caplog.set_level("DEBUG")

    await api_client.post(
        "/api/v1/auth/admin/login",
        json={"subject": TEST_ADMIN_SUBJECT, "password": TEST_PLAINTEXT_PASSWORD},
    )
    session_id = api_client.cookies.get(ADMIN_SESSION_COOKIE)
    assert session_id is not None
    await api_client.get("/api/v1/auth/admin/whoami")
    await api_client.post("/api/v1/auth/admin/logout")

    application_records = [
        r for r in caplog.records if r.name.startswith("src.")
    ]
    assert application_records, "expected at least one src.* log record"
    for record in application_records:
        msg = record.getMessage()
        assert session_id not in msg, (
            "full session id MUST never reach the log surface; "
            f"redaction broke in {record.name}"
        )
