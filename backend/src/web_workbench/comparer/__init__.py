"""Web Workbench — Comparer: deterministic diffs (WB-P3a).

Byte / word / line / JSON / DOM diff modes returning structured, JSON-safe
results for frontend rendering. Pure and offline.
"""

from src.web_workbench.comparer.engine import (
    ComparerError,
    DiffKind,
    DiffOp,
    DiffResult,
    DiffSegment,
    compare,
    result_to_dict,
)

__all__ = [
    "ComparerError",
    "DiffKind",
    "DiffOp",
    "DiffResult",
    "DiffSegment",
    "compare",
    "result_to_dict",
]
