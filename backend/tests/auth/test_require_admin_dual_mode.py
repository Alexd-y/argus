"""Dual-mode ``require_admin`` tests (B6-T08).

Three :data:`settings.admin_auth_mode` values produce three observable
behaviours; this module asserts each one against a tiny FastAPI app
mounting a single test endpoint that depends on
:func:`src.api.routers.admin.require_admin`.

Mode matrix
-----------
+-----------+-------------------+-------------------+-----------------------------+
| mode      | session cookie    | X-Admin-Key       | expected status / state     |
+===========+===================+===================+=============================+
| cookie    | ignored           | valid             | 200 + no ``admin_session``  |
| cookie    | valid             | absent            | 401 ``Invalid X-Admin-Key`` |
| cookie    | absent            | absent / invalid  | 401 ``Invalid X-Admin-Key`` |
+-----------+-------------------+-------------------+-----------------------------+
| session   | valid             | absent            | 200 + ``admin_session`` set |
| session   | absent            | valid             | 401 ``Authentication ...``  |
| session   | revoked           | valid             | 401 ``Authentication ...``  |
+-----------+-------------------+-------------------+-----------------------------+
| both      | valid             | absent            | 200 (session wins)          |
| both      | absent            | valid             | 200 (legacy fallback)       |
| both      | absent            | absent            | 401 ``Invalid X-Admin-Key`` |
| both      | valid bearer hdr  | absent            | 200 (session wins)          |
+-----------+-------------------+-------------------+-----------------------------+
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import datetime, timezone
from typing import Any

import pytest
from fastapi import Depends, FastAPI, Request

from src.api.routers.admin import require_admin
from src.api.routers.admin_auth import ADMIN_SESSION_COOKIE
from src.auth.admin_sessions import SessionPrincipal, create_session, revoke_session


# ---------------------------------------------------------------------------
# Local app fixture — single endpoint guarded by ``require_admin``.
# ---------------------------------------------------------------------------


@pytest.fixture
async def gated_app(
    session_factory, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[FastAPI]:
    """Tiny FastAPI app exposing one route protected by ``require_admin``.

    The route returns the request-state ``admin_session`` snapshot so each
    test can assert that a successful session resolve populated the
    principal exactly once (and that the legacy fallback path leaves the
    state untouched).
    """
    monkeypatch.setattr(
        "src.api.routers.admin.async_session_factory", session_factory
    )

    app = FastAPI()

    @app.get("/_t/protected")
    async def protected(
        request: Request, _: None = Depends(require_admin)
    ) -> dict[str, Any]:
        principal = getattr(request.state, "admin_session", None)
        if isinstance(principal, SessionPrincipal):
            return {
                "ok": True,
                "principal": {
                    "subject": principal.subject,
                    "role": principal.role,
                },
            }
        return {"ok": True, "principal": None}

    yield app


@pytest.fixture
async def gated_client(gated_app):
    from httpx import ASGITransport, AsyncClient

    transport = ASGITransport(app=gated_app)
    async with AsyncClient(
        transport=transport, base_url="https://testserver"
    ) as ac:
        yield ac


# ---------------------------------------------------------------------------
# Helpers — provision a real session row in the per-test DB.
# ---------------------------------------------------------------------------


async def _provision_session(
    session_factory,
    *,
    role: str = "admin",
    tenant_id: str | None = None,
    revoked: bool = False,
) -> str:
    """Persist a single ``admin_sessions`` row and return its id."""
    async with session_factory() as s:
        sid, _ = await create_session(
            s,
            subject="test-operator@example.com",
            role=role,
            tenant_id=tenant_id,
            ip="203.0.113.1",
            user_agent="argus-tests/dual-mode",
        )
        if revoked:
            await revoke_session(s, session_id=sid)
        await s.commit()
    return sid


# ---------------------------------------------------------------------------
# mode = cookie — legacy ``X-Admin-Key`` only.
# ---------------------------------------------------------------------------


async def test_mode_cookie_accepts_valid_admin_key(
    gated_client,
    settings_admin_mode_cookie,
    admin_api_key: str,
) -> None:
    response = await gated_client.get(
        "/_t/protected", headers={"X-Admin-Key": admin_api_key}
    )
    assert response.status_code == 200
    assert response.json() == {"ok": True, "principal": None}


async def test_mode_cookie_rejects_session_cookie_without_admin_key(
    gated_client,
    session_factory,
    settings_admin_mode_cookie,
    admin_api_key: str,
) -> None:
    """The legacy mode MUST ignore the new cookie even when it is valid."""
    sid = await _provision_session(session_factory)
    gated_client.cookies.set(ADMIN_SESSION_COOKIE, sid)

    response = await gated_client.get("/_t/protected")
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid X-Admin-Key"}


async def test_mode_cookie_rejects_when_neither_credential_present(
    gated_client,
    settings_admin_mode_cookie,
    admin_api_key: str,
) -> None:
    response = await gated_client.get("/_t/protected")
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# mode = session — new cookie / bearer only.
# ---------------------------------------------------------------------------


async def test_mode_session_accepts_valid_session_cookie(
    gated_client,
    session_factory,
    settings_admin_mode_session,
) -> None:
    sid = await _provision_session(session_factory, role="super-admin")
    gated_client.cookies.set(ADMIN_SESSION_COOKIE, sid)

    response = await gated_client.get("/_t/protected")
    assert response.status_code == 200
    body = response.json()
    assert body["principal"]["subject"] == "test-operator@example.com"
    assert body["principal"]["role"] == "super-admin"


async def test_mode_session_accepts_bearer_authorization_header(
    gated_client,
    session_factory,
    settings_admin_mode_session,
) -> None:
    sid = await _provision_session(session_factory)
    response = await gated_client.get(
        "/_t/protected", headers={"Authorization": f"Bearer {sid}"}
    )
    assert response.status_code == 200
    assert response.json()["principal"]["subject"] == "test-operator@example.com"


async def test_mode_session_rejects_legacy_admin_key(
    gated_client,
    settings_admin_mode_session,
    admin_api_key: str,
) -> None:
    """Pure session mode MUST refuse the legacy header even when valid."""
    response = await gated_client.get(
        "/_t/protected", headers={"X-Admin-Key": admin_api_key}
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication required"}


async def test_mode_session_rejects_revoked_session(
    gated_client,
    session_factory,
    settings_admin_mode_session,
) -> None:
    sid = await _provision_session(session_factory, revoked=True)
    gated_client.cookies.set(ADMIN_SESSION_COOKIE, sid)

    response = await gated_client.get("/_t/protected")
    assert response.status_code == 401


async def test_mode_session_rejects_unknown_session(
    gated_client,
    settings_admin_mode_session,
) -> None:
    gated_client.cookies.set(ADMIN_SESSION_COOKIE, "forged-session-not-in-db" * 2)
    response = await gated_client.get("/_t/protected")
    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication required"}


# ---------------------------------------------------------------------------
# mode = both — session wins, legacy fallback.
# ---------------------------------------------------------------------------


async def test_mode_both_session_cookie_wins_over_admin_key(
    gated_client,
    session_factory,
    settings_admin_mode_both,
    admin_api_key: str,
) -> None:
    sid = await _provision_session(session_factory, role="admin")
    gated_client.cookies.set(ADMIN_SESSION_COOKIE, sid)

    response = await gated_client.get(
        "/_t/protected", headers={"X-Admin-Key": admin_api_key}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["principal"] is not None, (
        "session resolve populated request.state.admin_session"
    )
    assert body["principal"]["subject"] == "test-operator@example.com"


async def test_mode_both_falls_back_to_admin_key_when_no_session(
    gated_client,
    settings_admin_mode_both,
    admin_api_key: str,
) -> None:
    response = await gated_client.get(
        "/_t/protected", headers={"X-Admin-Key": admin_api_key}
    )
    assert response.status_code == 200
    assert response.json() == {"ok": True, "principal": None}


async def test_mode_both_rejects_when_neither_credential_present(
    gated_client,
    settings_admin_mode_both,
    admin_api_key: str,
) -> None:
    response = await gated_client.get("/_t/protected")
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid X-Admin-Key"}


async def test_mode_both_rejects_revoked_session_then_legacy_fallback(
    gated_client,
    session_factory,
    settings_admin_mode_both,
    admin_api_key: str,
) -> None:
    """Revoked cookie + valid X-Admin-Key MUST still pass via the fallback."""
    sid = await _provision_session(session_factory, revoked=True)
    gated_client.cookies.set(ADMIN_SESSION_COOKIE, sid)

    response = await gated_client.get(
        "/_t/protected", headers={"X-Admin-Key": admin_api_key}
    )
    assert response.status_code == 200
    assert response.json()["principal"] is None, (
        "fallback path MUST NOT populate request.state.admin_session"
    )


async def test_mode_both_session_resolve_slides_window(
    gated_client,
    session_factory,
    settings_admin_mode_both,
) -> None:
    """Successful session resolution updates ``last_used_at`` (sliding window)."""
    sid = await _provision_session(session_factory)

    async with session_factory() as s:
        from src.db.models import AdminSession

        row = await s.get(AdminSession, sid)
        assert row is not None
        before = row.last_used_at

    gated_client.cookies.set(ADMIN_SESSION_COOKIE, sid)
    response = await gated_client.get("/_t/protected")
    assert response.status_code == 200

    async with session_factory() as s:
        from src.db.models import AdminSession

        row = await s.get(AdminSession, sid)
        assert row is not None
        after = row.last_used_at

    assert _aware(after) >= _aware(before), (
        "require_admin's resolver MUST commit the sliding-window UPDATE"
    )


# ---------------------------------------------------------------------------
# Bearer parsing edge-cases on the legacy gate.
# ---------------------------------------------------------------------------


async def test_mode_session_parses_authorization_case_insensitively(
    gated_client,
    session_factory,
    settings_admin_mode_session,
) -> None:
    sid = await _provision_session(session_factory)
    response = await gated_client.get(
        "/_t/protected", headers={"Authorization": f"bEaReR    {sid}"}
    )
    assert response.status_code == 200


def _aware(dt: datetime) -> datetime:
    """Promote naive datetimes (SQLite quirk) to UTC for safe comparisons."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)
