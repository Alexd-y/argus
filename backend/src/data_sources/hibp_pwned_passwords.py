"""
Have I Been Pwned — Pwned Passwords range API (k-anonymity).

Uses SHA-1 of the UTF-8 password: only the first 5 hex chars of the hash are sent
in the URL path; the remainder is matched client-side against the response.
See: https://haveibeenpwned.com/API/v3#PwnedPasswords

Security / compliance:
- Call only when ``settings.hibp_password_check_opt_in`` is True (explicit operator consent).
- Never log the plaintext password or full hash — at most the 5-char prefix for diagnostics.
- Passwords extracted from scan outputs are not persisted by this module.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

import httpx

from src.core.config import settings

logger = logging.getLogger(__name__)

_PWNED_RANGE_URL = "https://api.pwnedpasswords.com/range"


def sha1_hex_upper(password: str) -> str:
    """Full SHA-1 hex digest (uppercase); do not log return value."""
    return hashlib.sha1((password or "").encode("utf-8"), usedforsecurity=False).hexdigest().upper()


async def pwned_password_usage_count(password: str) -> int | None:
    """
    Return breach occurrence count for ``password`` via k-anonymity range API, or None on error.

    Requires ``settings.hibp_password_check_opt_in``. Does not log ``password``.
    """
    if not settings.hibp_password_check_opt_in:
        return None
    if not isinstance(password, str) or not password:
        return None
    digest = sha1_hex_upper(password)
    prefix = digest[:5]
    suffix = digest[5:]
    url = f"{_PWNED_RANGE_URL}/{prefix}"
    headers = {"Add-Padding": "true"}
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
    except Exception:
        logger.warning(
            "hibp_pwned_range_request_failed",
            extra={"sha1_prefix": prefix},
        )
        return None

    for line in (resp.text or "").splitlines():
        part, _, cnt_s = line.partition(":")
        if not part or not cnt_s:
            continue
        if part.upper() == suffix:
            try:
                return int(cnt_s.strip())
            except ValueError:
                return None
    return 0


def collect_password_candidates_from_structure(
    obj: Any,
    *,
    max_values: int = 5,
    max_depth: int = 6,
) -> list[str]:
    """
    Best-effort extraction of password-like strings from nested dict/list structures.

    Keys considered: ``password``, ``passwd``, ``pwd``, ``user_password`` (case-insensitive).
    Values truncated to 256 chars; empty skipped.
    """
    out: list[str] = []
    seen: set[str] = set()

    def walk(node: Any, depth: int) -> None:
        if len(out) >= max_values or depth > max_depth:
            return
        if isinstance(node, dict):
            for k, v in node.items():
                if len(out) >= max_values:
                    return
                lk = str(k).lower()
                if lk in {"password", "passwd", "pwd", "user_password", "credential_password"}:
                    if isinstance(v, str) and v.strip():
                        s = v.strip()[:256]
                        if s not in seen:
                            seen.add(s)
                            out.append(s)
                else:
                    walk(v, depth + 1)
        elif isinstance(node, list):
            for it in node:
                if len(out) >= max_values:
                    return
                walk(it, depth + 1)

    walk(obj, 0)
    return out


async def summarize_pwned_passwords_for_report(
    exploitation_dump: dict[str, Any] | None,
    *,
    max_checks: int = 5,
) -> dict[str, Any] | None:
    """
    Aggregate-only summary safe to embed in reporting context (no passwords, no full hashes).

    Returns None if opt-in disabled or nothing to check.
    """
    if not settings.hibp_password_check_opt_in:
        return None
    if not isinstance(exploitation_dump, dict):
        return None

    candidates = collect_password_candidates_from_structure(
        {k: exploitation_dump.get(k) for k in ("exploits", "evidence")},
        max_values=max_checks,
    )

    if not candidates:
        return {
            "opt_in": True,
            "checks_run": 0,
            "pwned_count": 0,
            "note": "no_password_fields_found",
        }

    pwned = 0
    checked = 0
    for pwd in candidates[:max_checks]:
        checked += 1
        cnt = await pwned_password_usage_count(pwd)
        if cnt is None:
            continue
        if cnt > 0:
            pwned += 1

    return {
        "opt_in": True,
        "checks_run": checked,
        "pwned_count": pwned,
        "note": (
            "k-anonymity Pwned Passwords API; plaintext passwords are not logged "
            "or stored by this hook."
        ),
    }
