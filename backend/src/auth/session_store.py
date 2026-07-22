"""Per-principal session storage with strict isolation (P3-AUTH-003, G-7).

A :class:`SessionStore` holds one :class:`PrincipalSession` per ``principal_id``.
Each session owns an **isolated** cookie jar, an optional Playwright
``storageState`` blob, and a header bag (Bearer / API-key / CSRF). Cookie jars
of different principals are never shared or merged — that isolation is what lets
authorization / IDOR / cross-tenant tests reason about "who did what" (G-2).

Split-plane secrets (SI-3): configs and plans carry only opaque ``secret_ref``
handles. The real values are resolved **here**, on the execution layer, via
:meth:`SessionStore.resolve_secret`, and are never logged or placed in evidence.
Any serialisation of a session for logging routes through
:mod:`src.auth.redaction` first (see :meth:`PrincipalSession.to_redacted_dict`).
"""

from __future__ import annotations

import os
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from src.auth.redaction import (
    redact_cookie_map,
    redact_headers,
    redact_storage_state,
)
from src.orchestration.auth_config import PrincipalConfig, PrincipalRole

_DEFAULT_TTL_SECONDS = 3600


class SecretResolutionError(KeyError):
    """Raised when a ``secret_ref`` cannot be resolved on the execution layer.

    The message includes only the *handle* (never a secret value).
    """


class SessionNotFoundError(KeyError):
    """Raised when an operation targets an unknown ``principal_id``."""


@dataclass(repr=False)
class PrincipalSession:
    """An isolated, authenticated (or anonymous) session for one principal.

    The cookie jar (:attr:`_cookies`) and header bag (:attr:`_headers`) are
    per-instance, so two principals held by the same store never see each
    other's credentials.
    """

    principal_id: str
    role: PrincipalRole
    tenant_id: str | None = None
    storage_state: dict[str, Any] | None = None
    created_at: float = field(default_factory=time.time)
    last_refreshed_at: float = field(default_factory=time.time)
    expires_at: float | None = None
    # name -> full cookie record (Playwright-compatible). Isolated per session.
    _cookies: dict[str, dict[str, Any]] = field(default_factory=dict)
    # header name -> value (values may be secrets; never logged unredacted).
    _headers: dict[str, str] = field(default_factory=dict)

    # -- cookies ----------------------------------------------------------
    def set_cookie(
        self,
        name: str,
        value: str,
        *,
        domain: str | None = None,
        path: str = "/",
        secure: bool = True,
        http_only: bool = True,
        same_site: str | None = None,
    ) -> None:
        """Add or replace a cookie in this session's isolated jar."""
        record: dict[str, Any] = {
            "name": name,
            "value": value,
            "path": path,
            "secure": secure,
            "httpOnly": http_only,
        }
        if domain is not None:
            record["domain"] = domain
        if same_site is not None:
            record["sameSite"] = same_site
        self._cookies[name] = record

    def set_cookies_from_playwright(self, cookies: list[Mapping[str, Any]] | None) -> None:
        """Merge Playwright ``context.cookies()`` records into the jar."""
        if not cookies:
            return
        for cookie in cookies:
            name = cookie.get("name")
            if not name:
                continue
            self._cookies[str(name)] = dict(cookie)

    def get_cookie(self, name: str) -> str | None:
        record = self._cookies.get(name)
        return None if record is None else record.get("value")

    def has_cookie(self, name: str) -> bool:
        return name in self._cookies

    def cookies_as_map(self) -> dict[str, str]:
        """Return ``name -> value`` for all cookies (secret values included)."""
        return {name: str(rec.get("value", "")) for name, rec in self._cookies.items()}

    def cookies_as_list(self) -> list[dict[str, Any]]:
        """Return copies of the full cookie records (Playwright shape)."""
        return [dict(rec) for rec in self._cookies.values()]

    def cookie_header(self) -> str:
        """Render the jar as an HTTP ``Cookie`` header value."""
        return "; ".join(f"{name}={rec.get('value', '')}" for name, rec in self._cookies.items())

    # -- headers ----------------------------------------------------------
    def set_header(self, name: str, value: str) -> None:
        self._headers[name] = value

    def set_bearer(self, token: str) -> None:
        self._headers["Authorization"] = f"Bearer {token}"

    def set_api_key(self, value: str, *, header: str = "X-API-Key") -> None:
        self._headers[header] = value

    def set_csrf(self, token: str, *, header: str = "X-CSRF-Token") -> None:
        self._headers[header] = token

    def headers(self) -> dict[str, str]:
        """Return a copy of the header bag (secret values included)."""
        return dict(self._headers)

    # -- lifecycle --------------------------------------------------------
    @property
    def is_expired(self) -> bool:
        return self.expires_at is not None and time.time() >= self.expires_at

    def clear(self) -> None:
        """Drop all cookies, headers, and storage state (used by logout)."""
        self._cookies.clear()
        self._headers.clear()
        self.storage_state = None

    # -- execution-layer export ------------------------------------------
    def as_exploitation_auth(self) -> dict[str, Any]:
        """Return the auth context passed to sandbox tools (execution layer).

        This is the ONE place secret values legitimately leave the session, to
        be turned into tool argv (``-H "Cookie: ..."`` etc.). The returned dict
        must never be logged unredacted.
        """
        return {
            "principal_id": self.principal_id,
            "cookies": self.cookies_as_map(),
            "cookie_header": self.cookie_header(),
            "headers": self.headers(),
        }

    # -- redacted views ---------------------------------------------------
    def to_redacted_dict(self) -> dict[str, Any]:
        """Return a log/evidence-safe view with every secret value redacted."""
        redacted_headers, _ = redact_headers(self._headers)
        return {
            "principal_id": self.principal_id,
            "role": self.role.value,
            "tenant_id": self.tenant_id,
            "cookies": redact_cookie_map(self.cookies_as_map()),
            "headers": redacted_headers,
            "storage_state": (
                redact_storage_state(self.storage_state) if self.storage_state else None
            ),
            "created_at": self.created_at,
            "last_refreshed_at": self.last_refreshed_at,
            "expires_at": self.expires_at,
            "expired": self.is_expired,
        }

    def __repr__(self) -> str:
        # Only names/metadata — never cookie or header *values*.
        return (
            f"PrincipalSession(principal_id={self.principal_id!r}, role={self.role.value!r}, "
            f"tenant_id={self.tenant_id!r}, cookies={sorted(self._cookies)!r}, "
            f"headers={sorted(self._headers)!r}, expires_at={self.expires_at!r})"
        )


class SessionStore:
    """Registry of isolated per-principal sessions + secret resolution.

    Parameters
    ----------
    secrets:
        Optional ``secret_ref -> value`` map (e.g. injected from a vault client
        or the engagement payload). Checked first by :meth:`resolve_secret`.
    allow_env:
        When ``True`` (default), unresolved refs fall back to ``os.environ``.
    default_ttl_seconds:
        TTL applied to newly created / refreshed sessions.
    """

    def __init__(
        self,
        *,
        secrets: Mapping[str, str] | None = None,
        allow_env: bool = True,
        default_ttl_seconds: int = _DEFAULT_TTL_SECONDS,
    ) -> None:
        self._sessions: dict[str, PrincipalSession] = {}
        self._secrets: dict[str, str] = dict(secrets) if secrets else {}
        self._allow_env = allow_env
        self._default_ttl = default_ttl_seconds

    # -- registry ---------------------------------------------------------
    def get_session(self, principal_id: str) -> PrincipalSession | None:
        return self._sessions.get(principal_id)

    def set_session(self, session: PrincipalSession) -> None:
        self._sessions[session.principal_id] = session

    def has_session(self, principal_id: str) -> bool:
        return principal_id in self._sessions

    def __contains__(self, principal_id: object) -> bool:
        return principal_id in self._sessions

    def __len__(self) -> int:
        return len(self._sessions)

    def create_session(
        self,
        principal_id: str,
        role: PrincipalRole,
        *,
        tenant_id: str | None = None,
        ttl_seconds: int | None = None,
    ) -> PrincipalSession:
        """Create, register, and return a fresh isolated session."""
        now = time.time()
        ttl = self._default_ttl if ttl_seconds is None else ttl_seconds
        session = PrincipalSession(
            principal_id=principal_id,
            role=role,
            tenant_id=tenant_id,
            created_at=now,
            last_refreshed_at=now,
            expires_at=now + ttl if ttl > 0 else None,
        )
        self._sessions[principal_id] = session
        return session

    def create_session_for_principal(
        self,
        principal: PrincipalConfig,
        *,
        ttl_seconds: int | None = None,
    ) -> PrincipalSession:
        """Create a session for a :class:`PrincipalConfig`, resolving secret refs.

        Bearer / API-key handles are resolved to real values **here** and placed
        into the session header bag (execution layer). Missing refs raise
        :class:`SecretResolutionError` so misconfiguration fails loudly rather
        than silently running unauthenticated.
        """
        session = self.create_session(
            principal.principal_id,
            principal.role,
            tenant_id=principal.tenant_id,
            ttl_seconds=ttl_seconds,
        )
        if principal.bearer_token_ref is not None:
            session.set_bearer(self.resolve_secret(principal.bearer_token_ref))
        if principal.api_key_ref is not None:
            session.set_api_key(self.resolve_secret(principal.api_key_ref))
        return session

    def refresh(self, principal_id: str, *, ttl_seconds: int | None = None) -> PrincipalSession:
        """Extend a session's TTL. Raises if the principal is unknown."""
        session = self._sessions.get(principal_id)
        if session is None:
            raise SessionNotFoundError(f"no session for principal_id={principal_id!r}")
        now = time.time()
        ttl = self._default_ttl if ttl_seconds is None else ttl_seconds
        session.last_refreshed_at = now
        session.expires_at = now + ttl if ttl > 0 else None
        return session

    def invalidate(self, principal_id: str) -> bool:
        """Remove a session from the store. Returns ``True`` if one existed."""
        return self._sessions.pop(principal_id, None) is not None

    def logout(self, principal_id: str) -> bool:
        """Clear a session's credentials and remove it from the store."""
        session = self._sessions.get(principal_id)
        if session is None:
            return False
        session.clear()
        return self.invalidate(principal_id)

    # -- secret resolution (execution layer only) -------------------------
    def resolve_secret(self, secret_ref: str) -> str:
        """Resolve an opaque ``secret_ref`` handle to its real value.

        Never logs the value. Resolution order: injected map, then environment.
        """
        if secret_ref in self._secrets:
            return self._secrets[secret_ref]
        if self._allow_env:
            env_value = os.environ.get(secret_ref)
            if env_value is not None:
                return env_value
        raise SecretResolutionError(f"secret_ref not resolvable: {secret_ref!r}")

    def to_redacted_dict(self) -> dict[str, Any]:
        """Return a log-safe snapshot of all sessions (values redacted)."""
        return {pid: session.to_redacted_dict() for pid, session in self._sessions.items()}

    def __repr__(self) -> str:
        # secret_refs count only — never the secret map contents.
        return (
            f"SessionStore(sessions={sorted(self._sessions)!r}, secret_refs={len(self._secrets)})"
        )


__all__ = [
    "PrincipalSession",
    "SecretResolutionError",
    "SessionNotFoundError",
    "SessionStore",
]
