"""Shared report truncation limits + an overflow-aware slice helper (RC-14).

The limits themselves are reasonable; the defect they caused was *silence* — a
collection was cut to N with no trace of the ``M - N`` dropped items. ``cap_with_overflow``
returns the slice *and* the number dropped so callers can print an explicit "showing N
of M" note (``overflow_note``) and point the reader at the full list (Evidence Register
/ JSON), instead of a bare ellipsis or nothing at all.
"""

from __future__ import annotations

#: Evidence ids shown per OWASP category in the compliance rollup (generators.py).
EVIDENCE_PER_CATEGORY_PREVIEW = 4
#: Evidence ids shown per OWASP category row in the final output (generators.py).
EVIDENCE_IDS_PREVIEW = 8
#: Evidence refs shown inline in a finding's evidence cell (finding_metadata.py).
EVIDENCE_REFS_PREVIEW = 8
#: Evidence refs retained on a pre-pipeline finding row (data_collector.py).
EVIDENCE_REFS_MAX = 64
#: Max characters retained per evidence ref string (data_collector.py).
EVIDENCE_SNIPPET_MAXLEN = 500

def cap_with_overflow[T](seq: list[T], limit: int) -> tuple[list[T], int]:
    """Return ``(seq[:limit], dropped)`` where ``dropped`` is the count beyond ``limit``.

    ``limit`` < 0 is treated as 0. The input is never mutated.
    """
    limit = max(0, limit)
    items = list(seq)
    if len(items) <= limit:
        return items, 0
    return items[:limit], len(items) - limit


def overflow_note(*, shown: int, total: int, where: str = "Evidence Register / JSON") -> str:
    """Human note for a truncated collection, or ``""`` when nothing was dropped.

    ``"showing 4 of 11 — full list in Evidence Register / JSON"``.
    """
    if total <= shown:
        return ""
    return f"showing {shown} of {total} — full list in {where}"


__all__ = [
    "EVIDENCE_IDS_PREVIEW",
    "EVIDENCE_PER_CATEGORY_PREVIEW",
    "EVIDENCE_REFS_MAX",
    "EVIDENCE_REFS_PREVIEW",
    "EVIDENCE_SNIPPET_MAXLEN",
    "cap_with_overflow",
    "overflow_note",
]
