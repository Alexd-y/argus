"""Quick observability helpers (QUICK-009).

Domain code MUST emit through these ``record_*`` functions. They delegate to
``src.core.unified_ai_metrics`` so Quick does not register a 10th family in
``observability.py``. Every path is fail-open — metrics never break a scan.
"""

from __future__ import annotations

import logging
from collections.abc import Collection, Mapping, Sequence
from typing import Any, Final

from src.core import unified_ai_metrics as _metrics
from src.core.unified_ai_metrics import QUICK_TOOL_WHITELIST
from src.quick.disallowed import DISALLOWED_TOOL_IDS

logger = logging.getLogger(__name__)

_CATALOG_TOOLS: Final[frozenset[str]] = frozenset(QUICK_TOOL_WHITELIST) - {"_other"}


def _fail_open(event: str, **extra: Any) -> None:
    logger.warning(event, extra={"event": event, **extra})


def record_scan_duration(seconds: float) -> None:
    try:
        _metrics.record_quick_scan_duration(seconds)
    except Exception:  # noqa: BLE001 — metrics must never break scans
        _fail_open("quick_metrics.scan_duration_failed")


def record_deadline_overrun(*, amount: int = 1) -> int:
    try:
        return _metrics.record_quick_deadline_overrun(amount=amount)
    except Exception:  # noqa: BLE001
        _fail_open("quick_metrics.deadline_overrun_failed")
        return 0


def record_budget_used_ratio(ratio: float) -> None:
    try:
        _metrics.record_quick_budget_used_ratio(ratio)
    except Exception:  # noqa: BLE001
        _fail_open("quick_metrics.budget_ratio_failed")


def record_task(*, stage: str, status: str, tool: str, amount: int = 1) -> int:
    try:
        return _metrics.record_quick_task(stage=stage, status=status, tool=tool, amount=amount)
    except Exception:  # noqa: BLE001
        _fail_open("quick_metrics.task_failed")
        return 0


def record_assets_discovered(*, amount: int = 1) -> int:
    try:
        return _metrics.record_quick_assets_discovered(amount=amount)
    except Exception:  # noqa: BLE001
        _fail_open("quick_metrics.assets_failed")
        return 0


def record_templates_selected(*, amount: int = 1) -> int:
    try:
        return _metrics.record_quick_templates_selected(amount=amount)
    except Exception:  # noqa: BLE001
        _fail_open("quick_metrics.templates_failed")
        return 0


def record_finding(*, severity: str, verdict: str, amount: int = 1) -> int:
    try:
        return _metrics.record_quick_finding(severity=severity, verdict=verdict, amount=amount)
    except Exception:  # noqa: BLE001
        _fail_open("quick_metrics.finding_failed")
        return 0


def record_validation_rate(ratio: float) -> None:
    try:
        _metrics.record_quick_validation_rate(ratio)
    except Exception:  # noqa: BLE001
        _fail_open("quick_metrics.validation_rate_failed")


def record_false_positive_rate(ratio: float) -> None:
    try:
        _metrics.record_quick_false_positive_rate(ratio)
    except Exception:  # noqa: BLE001
        _fail_open("quick_metrics.fp_rate_failed")


def record_coverage_ratio(ratio: float) -> None:
    try:
        _metrics.record_quick_coverage_ratio(ratio)
    except Exception:  # noqa: BLE001
        _fail_open("quick_metrics.coverage_ratio_failed")


def record_plan_revision(*, amount: int = 1) -> int:
    try:
        return _metrics.record_quick_plan_revision(amount=amount)
    except Exception:  # noqa: BLE001
        _fail_open("quick_metrics.plan_revision_failed")
        return 0


def record_llm_call(
    *,
    model: str,
    prompt: str,
    status: str,
    latency_seconds: float = 0.0,
) -> int:
    try:
        return _metrics.record_quick_llm_call(
            model=model,
            prompt=prompt,
            status=status,
            latency_seconds=latency_seconds,
        )
    except Exception:  # noqa: BLE001
        _fail_open("quick_metrics.llm_call_failed")
        return 0


def record_rag_latency(seconds: float) -> None:
    try:
        _metrics.record_quick_rag_latency(seconds)
    except Exception:  # noqa: BLE001
        _fail_open("quick_metrics.rag_latency_failed")


def record_tool_failure(*, tool: str, reason: str, amount: int = 1) -> int:
    try:
        return _metrics.record_quick_tool_failure(tool=tool, reason=reason, amount=amount)
    except Exception:  # noqa: BLE001
        _fail_open("quick_metrics.tool_failure_failed")
        return 0


def admit_tracked_tool(
    tool_id: str,
    *,
    catalog_ids: Collection[str] | None = None,
    planned_ids: Collection[str] | None = None,
) -> bool:
    """Return True iff *tool_id* may execute. Untracked tools never run.

    Fail-open on metric errors, fail-closed on the execution decision.
    """
    normalized = (tool_id or "").strip().lower()
    allowed = {item.strip().lower() for item in (catalog_ids or _CATALOG_TOOLS) if item}
    planned = {item.strip().lower() for item in (planned_ids or ()) if item}
    tracked = bool(normalized) and normalized in allowed and normalized not in DISALLOWED_TOOL_IDS
    if planned:
        tracked = tracked and normalized in planned
    if tracked:
        return True
    record_tool_failure(tool=normalized or "_other", reason="untracked")
    return False


def record_findings_from_rows(rows: Sequence[Mapping[str, Any]]) -> None:
    """Emit finding + FP/validation ratios from report/triage rows. Never raises."""
    if not rows:
        record_false_positive_rate(0.0)
        record_validation_rate(0.0)
        return
    fp = 0
    verified = 0
    for row in rows:
        severity = str(row.get("severity") or "medium")
        verdict = str(row.get("verdict") or "hypothesis")
        record_finding(severity=severity, verdict=verdict)
        lowered = verdict.strip().lower()
        if lowered == "false_positive_candidate":
            fp += 1
        if lowered in {"confirmed", "likely"}:
            verified += 1
    total = len(rows)
    record_false_positive_rate(fp / total)
    record_validation_rate(verified / total)


__all__ = [
    "admit_tracked_tool",
    "record_assets_discovered",
    "record_budget_used_ratio",
    "record_coverage_ratio",
    "record_deadline_overrun",
    "record_false_positive_rate",
    "record_finding",
    "record_findings_from_rows",
    "record_llm_call",
    "record_plan_revision",
    "record_rag_latency",
    "record_scan_duration",
    "record_task",
    "record_templates_selected",
    "record_tool_failure",
    "record_validation_rate",
]
