"""Shared low-level helpers for the Valhalla report sections (Wave 4 / Stage 6).

Pure, dependency-free helpers lifted out of ``valhalla_report_context`` so section
submodules can share them without importing the monolith (which would create an import
cycle). The monolith re-imports these names, so its own call sites are unchanged.
"""

from __future__ import annotations

from typing import Any


def _truncate(text: str, max_len: int) -> str:
    """Trim ``text`` to ``max_len`` chars, appending an ellipsis when it overflows."""
    t = (text or "").strip()
    if len(t) <= max_len:
        return t
    return t[: max_len - 1].rstrip() + "…"


def _finding_id_for_risk(f: dict[str, Any], fallback_idx: int) -> str:
    """Stable id for a finding dict: ``finding_id`` / ``id``, else a positional fallback."""
    for key in ("finding_id", "id"):
        v = f.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return f"finding-{fallback_idx}"


__all__ = ["_finding_id_for_risk", "_truncate"]
