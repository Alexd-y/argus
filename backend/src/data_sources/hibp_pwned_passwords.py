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


def finalize_hibp_pwned_password_summary(summary: dict[str, Any]) -> dict[str, Any]:
    """
    Canonical shape for ``hibp_pwned_password_summary`` everywhere (orchestration, report pipeline,
    Valhalla AI payload, Jinja, JSON). Aggregate-only; no secrets.

    ``checks_run`` counts **completed** HIBP API responses (definitive int, including 0 occurrences).
    Optional ``checks_attempted`` counts lookups tried; if omitted, treated equal to ``checks_run``
    (backward compatible with callers that only pass completed counts).

    Ensures integer counts, derived exposure flags, and a single narrative note so LLM/templates
    do not contradict raw scan counts.
    """
    out = dict(summary)
    try:
        checks = max(0, int(out.get("checks_run") or 0))
        pwned_n = max(0, int(out.get("pwned_count") or 0))
        if "checks_attempted" in out and out["checks_attempted"] is not None:
            attempted = max(0, int(out["checks_attempted"]))
        else:
            attempted = checks
    except (TypeError, ValueError):
        logger.warning(
            "hibp_pwned_summary_coerce_failed",
            extra={"event": "hibp_pwned_summary_coerce_failed"},
        )
        checks, pwned_n, attempted = 0, 0, 0
    if attempted < checks:
        logger.warning(
            "hibp_pwned_summary_inconsistent",
            extra={
                "event": "hibp_pwned_summary_attempted_lt_completed",
                "checks_run": checks,
                "checks_attempted": attempted,
            },
        )
        attempted = checks
    if pwned_n > checks:
        logger.warning(
            "hibp_pwned_summary_inconsistent",
            extra={
                "event": "hibp_pwned_summary_inconsistent",
                "pwned_count": pwned_n,
                "checks_run": checks,
            },
        )
        pwned_n = min(pwned_n, checks)
    out["checks_run"] = checks
    out["pwned_count"] = pwned_n
    if attempted != checks:
        out["checks_attempted"] = attempted
    else:
        out.pop("checks_attempted", None)

    incomplete = attempted > checks
    all_failed = attempted > 0 and checks == 0

    if pwned_n > 0:
        exposure = "yes"
    elif checks > 0 and not incomplete:
        exposure = "no"
    elif attempted > 0 and (all_failed or incomplete):
        exposure = "unknown"
    else:
        exposure = "no"

    out["data_breach_password_exposure"] = exposure

    if pwned_n > 0:
        note = (
            "At least one sampled credential string matched HIBP Pwned Passwords corpus."
        )
    elif all_failed:
        note = (
            "HIBP Pwned Passwords checks did not complete (network, HTTP, or parse error); "
            "credential exposure relative to the Pwned Passwords corpus is unknown."
        )
    elif incomplete and checks > 0:
        note = (
            f"Partial HIBP Pwned Passwords results: {checks} of {attempted} sampled checks "
            "returned a response; none of the completed checks matched the corpus."
        )
    elif checks > 0:
        note = (
            "No sampled credential strings matched Pwned Passwords corpus (or no candidates checked)."
        )
    else:
        note = "No password-like fields sampled from exploitation output for HIBP check."
    out["breach_signal_note"] = note
    return out


_HIBP_SUMMARY_CONTRACT_KEYS = frozenset(
    {
        "checks_run",
        "pwned_count",
        "data_breach_password_exposure",
        "breach_signal_note",
    },
)


def validate_hibp_pwned_password_summary_light(summary: dict[str, Any] | None) -> None:
    """
    Log-only guard when a non-empty summary bypasses ``finalize_hibp_pwned_password_summary``.
    Full schema checks belong in report pipeline validation (separate task).
    """
    if summary is None:
        return
    if not isinstance(summary, dict):
        logger.warning(
            "hibp_pwned_summary_contract_type_mismatch",
            extra={"event": "hibp_pwned_summary_contract_type_mismatch"},
        )
        return
    if not summary.get("opt_in"):
        return
    missing = sorted(k for k in _HIBP_SUMMARY_CONTRACT_KEYS if k not in summary)
    if missing:
        logger.warning(
            "hibp_pwned_summary_contract_incomplete",
            extra={
                "event": "hibp_pwned_summary_contract_incomplete",
                "missing_keys": missing,
            },
        )


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
        return finalize_hibp_pwned_password_summary(
            {
                "opt_in": True,
                "checks_run": 0,
                "pwned_count": 0,
                "note": "no_password_fields_found",
            }
        )

    pwned = 0
    attempted = 0
    completed = 0
    for pwd in candidates[:max_checks]:
        attempted += 1
        cnt = await pwned_password_usage_count(pwd)
        if cnt is None:
            continue
        completed += 1
        if cnt > 0:
            pwned += 1

    return finalize_hibp_pwned_password_summary(
        {
            "opt_in": True,
            "checks_run": completed,
            "checks_attempted": attempted,
            "pwned_count": pwned,
            "note": (
                "k-anonymity Pwned Passwords API; plaintext passwords are not logged "
                "or stored by this hook."
            ),
        }
    )
