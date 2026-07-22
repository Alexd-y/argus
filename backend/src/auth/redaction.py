"""Secret redaction helpers for the multi-principal auth layer (P3-AUTH-003).

This module is deliberately thin: the structural secret-key/header/body
redaction primitives already exist in :mod:`src.playbooks.evidence` (created in
P2) and are reused verbatim here — there is no second copy of that logic.

What is added on top is the *session-shaped* redaction the auth layer needs:

* cookie jars (Playwright / HTTP), where the secret lives in the ``value`` of
  each cookie record (a plain ``name``/``value`` pair is not caught by the
  generic secret-*key* heuristics), and
* Playwright ``storageState`` blobs (``cookies`` + ``origins[].localStorage``).

Every helper is pure and side-effect free, and returns a redacted **copy** so
callers can never accidentally mutate live session state.

SI-3 (split-plane): secrets must never reach prompts, logs, or evidence. Any
code path that serialises a :class:`~src.auth.session_store.PrincipalSession`
for logging/evidence MUST route through here first.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from src.playbooks.evidence import (
    REDACTED,
    redact,
    redact_body,
    redact_headers,
)

# Cookie-record fields that carry the secret material itself.
_COOKIE_VALUE_KEYS: frozenset[str] = frozenset({"value", "token"})


def redact_secret(_value: object) -> str:
    """Always return the redaction marker for a known-secret value.

    Used for values (Bearer tokens, resolved passwords, cookie values) whose
    key/context already proves they are secret, so no heuristic is needed.
    """
    return REDACTED


def redact_cookie(cookie: Mapping[str, Any]) -> dict[str, Any]:
    """Redact the value of a single cookie record, keeping its metadata.

    The cookie name, domain, path, and flags are safe to keep (they are useful
    for debugging); only the value is a secret.
    """
    out: dict[str, Any] = {}
    for key, val in cookie.items():
        out[key] = REDACTED if str(key).lower() in _COOKIE_VALUE_KEYS else val
    return out


def redact_cookies(cookies: list[Mapping[str, Any]] | None) -> list[dict[str, Any]]:
    """Redact the values of every cookie in a jar (list of cookie records)."""
    if not cookies:
        return []
    return [redact_cookie(cookie) for cookie in cookies]


def redact_cookie_map(cookies: Mapping[str, str] | None) -> dict[str, str]:
    """Redact a ``name -> value`` cookie mapping (values are secrets)."""
    if not cookies:
        return {}
    return {name: REDACTED for name in cookies}


def redact_storage_state(storage_state: Mapping[str, Any] | None) -> dict[str, Any]:
    """Redact a Playwright ``storageState`` blob.

    Structure (Playwright): ``{"cookies": [...], "origins": [{"origin": str,
    "localStorage": [{"name": str, "value": str}, ...]}, ...]}``. Cookie values
    and every localStorage value are treated as secrets.
    """
    if not storage_state:
        return {}
    out: dict[str, Any] = dict(storage_state)
    if isinstance(storage_state.get("cookies"), list):
        out["cookies"] = redact_cookies(storage_state["cookies"])
    origins = storage_state.get("origins")
    if isinstance(origins, list):
        redacted_origins: list[dict[str, Any]] = []
        for origin in origins:
            if not isinstance(origin, Mapping):
                continue
            new_origin = dict(origin)
            local = origin.get("localStorage")
            if isinstance(local, list):
                new_origin["localStorage"] = [
                    (
                        {**item, "value": REDACTED}
                        if isinstance(item, Mapping) and "value" in item
                        else item
                    )
                    for item in local
                ]
            redacted_origins.append(new_origin)
        out["origins"] = redacted_origins
    return out


__all__ = [
    "REDACTED",
    "redact",
    "redact_body",
    "redact_cookie",
    "redact_cookie_map",
    "redact_cookies",
    "redact_headers",
    "redact_secret",
    "redact_storage_state",
]
