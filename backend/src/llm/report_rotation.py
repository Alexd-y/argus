"""In-process report-role LLM rotation for the facade dispatch (WP C).

This is the *live-path* application of the configured multi-LLM rotation chain
(:class:`src.llm.rotation.LLMRotation` is the persisted/admin side). It rotates
the ``preferred_alias`` across successive **report/cloud-eligible** calls within a
scan — A,B,A,B — so report generation spreads across the configured cloud
providers for cost/resilience.

Hard rule (WRB-001): rotation is applied ONLY when the caller says the task is
report/cloud-eligible. Pentest *analysis* tasks are never rotated onto a cloud
alias here — the facade passes ``eligible=False`` for them.

The cursor is in-process and keyed by ``(scan_id, role)``: it survives across the
many facade calls of one scan inside a worker process, and two scans rotate
independently. It is deliberately not persisted per-call (the facade carries no DB
session); the DB/admin side persists the *chain*, this advances the *position*.
"""

from __future__ import annotations

from typing import Any

__all__ = ["pick_report_rotation_alias", "reset_report_rotation"]

#: (scan_id, role) -> next cursor position. Bounded in practice by live scans.
_cursors: dict[tuple[str, str], int] = {}

_REPORT_ROLE = "report"


def _read(opts: Any, key: str, default: Any) -> Any:
    if opts is None:
        return default
    if isinstance(opts, dict):
        return opts.get(key, default)
    return getattr(opts, key, default)


def pick_report_rotation_alias(
    llm_opts: Any,
    *,
    scan_id: str | None,
    eligible: bool,
    role: str = _REPORT_ROLE,
) -> str | None:
    """Return the next rotation alias, or ``None`` when rotation does not apply.

    ``llm_opts`` is the ``ScanOptions.llm`` payload (dict or object) carrying
    ``llm_rotate`` + ``llm_profile_ids``. Returns ``None`` unless *eligible* is
    True, rotation is enabled, and a non-empty chain is configured.
    """
    if not eligible:
        return None
    if not bool(_read(llm_opts, "llm_rotate", False)):
        return None
    profile_ids = list(_read(llm_opts, "llm_profile_ids", []) or [])
    if not profile_ids:
        return None
    key = (scan_id or "", role)
    cursor = _cursors.get(key, 0)
    alias = profile_ids[cursor % len(profile_ids)]
    _cursors[key] = cursor + 1
    return alias


def reset_report_rotation(scan_id: str | None = None) -> None:
    """Clear rotation cursors (all, or for one scan). Used by tests and cleanup."""
    if scan_id is None:
        _cursors.clear()
        return
    for key in [k for k in _cursors if k[0] == scan_id]:
        _cursors.pop(key, None)
