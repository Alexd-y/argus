"""Phase coverage collaborator — emit CoverageResult from tool execution facts.

Handlers call this module; they must not contain coverage SQL. Status is derived
from execution evidence via ``src.capabilities.coverage`` invariants:
``not_tested`` never becomes ``covered_no_finding`` without execution evidence.

LAB clears only ``policy_blocked``; ``tool_error`` and ``target_unreachable`` stay honest.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Mapping, Sequence
from threading import Lock
from typing import Any, Final
from uuid import uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictStr,
    ValidationError,
)

from src.capabilities.coverage import (
    CoverageAccountingError,
    build_coverage_result,
    infer_status_from_execution,
)
from src.capabilities.graph import CapabilityGraph, default_capability_graph
from src.capabilities.schemas import (
    COVERED_STATUSES,
    CoverageRequirement,
    CoverageResult,
    CoverageStatus,
)
from src.execution_mode.mode import ExecutionMode, parse_execution_mode

logger = logging.getLogger(__name__)

_ID_MAX: Final[int] = 36
_VA_PRIMARY_TOOL: Final[str] = "nuclei"
_RECON_NON_TOOL_KEYS: Final[frozenset[str]] = frozenset(
    {
        "recon_pipeline_summary",
        "http_crawl",
        "subdomain_passive_inventory",
    }
)
_POLICY_BLOCK_REASONS: Final[frozenset[str]] = frozenset(
    {
        "policy_blocked",
        "lab_tool_policy_denied",
        "approval_denied",
    }
)
_UNREACHABLE_MARKERS: Final[tuple[str, ...]] = (
    "unreachable",
    "timed out",
    "timeout",
    "connection refused",
    "no route to host",
)
_QUICK_REASON_STATUS: Final[dict[str, CoverageStatus]] = {
    "not_scheduled_by_quick_profile": CoverageStatus.NOT_TESTED,
    "deadline_reached": CoverageStatus.BLOCKED,
    "fingerprint_mismatch": CoverageStatus.NOT_APPLICABLE,
    "budget_partial": CoverageStatus.PARTIAL,
    "circuit_open": CoverageStatus.BLOCKED,
    "tool_error": CoverageStatus.BLOCKED,
}


class ToolRunSignal(BaseModel):
    """Raw execution facts for one tool (or explicit capability) in a phase."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_id: StrictStr = Field(min_length=1, max_length=128)
    capability_id: StrictStr | None = Field(default=None, min_length=3, max_length=256)
    skipped: StrictBool = False
    tool_executed: StrictBool = False
    tool_error: StrictBool = False
    target_unreachable: StrictBool = False
    policy_blocked: StrictBool = False
    not_applicable: StrictBool = False
    blocked_reason: StrictStr | None = None
    execution_evidence_id: StrictStr | None = None
    finding_id: StrictStr | None = None
    quick_reason: StrictStr | None = Field(default=None, max_length=128)
    template_ids: tuple[StrictStr, ...] = Field(default_factory=tuple)
    evidence_ids: tuple[StrictStr, ...] = Field(default_factory=tuple)


class InMemoryCoverageStore:
    """Process-local CoverageResult store keyed by scan_id (no DB migration)."""

    def __init__(self) -> None:
        self._by_scan: dict[str, list[CoverageResult]] = {}
        self._lock = Lock()

    def append(self, scan_id: str, results: Sequence[CoverageResult]) -> None:
        key = (scan_id or "").strip()
        if not key or not results:
            return
        with self._lock:
            bucket = self._by_scan.setdefault(key, [])
            bucket.extend(results)

    def get(self, scan_id: str) -> list[CoverageResult]:
        key = (scan_id or "").strip()
        if not key:
            return []
        with self._lock:
            return list(self._by_scan.get(key, ()))

    def clear(self, scan_id: str | None = None) -> None:
        with self._lock:
            if scan_id is None:
                self._by_scan.clear()
                return
            key = scan_id.strip()
            self._by_scan.pop(key, None)


_DEFAULT_STORE = InMemoryCoverageStore()


def get_coverage_store() -> InMemoryCoverageStore:
    """Return the process-wide in-memory coverage store."""
    return _DEFAULT_STORE


def _bounded_id(raw: str | None, *, fallback: str) -> str:
    text = (raw or "").strip() or fallback
    if len(text) <= _ID_MAX:
        return text
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:_ID_MAX]


def _requirement_id() -> str:
    return str(uuid4())


def serialize_coverage_results(results: Sequence[CoverageResult]) -> list[dict[str, Any]]:
    return [item.model_dump(mode="json") for item in results]


def _is_lab_mode(execution_mode: str | ExecutionMode) -> bool:
    return parse_execution_mode(execution_mode) is ExecutionMode.LAB_UNRESTRICTED


def _lab_adjust_block(
    *,
    is_lab: bool,
    policy_blocked: bool,
    tool_error: bool,
    target_unreachable: bool,
    blocked_reason: str | None,
) -> tuple[bool, str | None]:
    """LAB drops policy-blocked only; tool_error / unreachable stay blocked."""
    if not is_lab:
        return policy_blocked, blocked_reason
    if tool_error:
        reason = blocked_reason if blocked_reason and blocked_reason != "policy_blocked" else "tool_error"
        return False, reason
    if target_unreachable:
        reason = (
            blocked_reason
            if blocked_reason and blocked_reason != "policy_blocked"
            else "target_unreachable"
        )
        return False, reason
    if policy_blocked or blocked_reason == "policy_blocked":
        return False, None
    return False, blocked_reason


def _status_for_quick_reason(
    quick_reason: str | None,
    *,
    inferred: CoverageStatus,
    tool_executed: bool,
    evidence_id: str | None,
    finding_id: str | None,
) -> CoverageStatus:
    """Override inferred status for Quick profile / deadline signals."""
    if not quick_reason:
        return inferred
    if quick_reason == "executed":
        return inferred
    mapped = _QUICK_REASON_STATUS.get(quick_reason)
    if mapped is None:
        return inferred
    if mapped is CoverageStatus.PARTIAL and not (tool_executed or evidence_id):
        return CoverageStatus.NOT_TESTED
    if mapped in COVERED_STATUSES and not (tool_executed or evidence_id):
        return CoverageStatus.NOT_TESTED
    if mapped is CoverageStatus.COVERED_WITH_FINDING and not finding_id:
        return CoverageStatus.COVERED_NO_FINDING if evidence_id else CoverageStatus.NOT_TESTED
    return mapped


def _blocked_reason_for_status(
    status: CoverageStatus,
    *,
    tool_error: bool,
    target_unreachable: bool,
    policy_blocked: bool,
    blocked_reason: str | None,
) -> str | None:
    if status is not CoverageStatus.BLOCKED:
        return None
    if blocked_reason:
        return blocked_reason
    if tool_error:
        return "tool_error"
    if target_unreachable:
        return "target_unreachable"
    if policy_blocked:
        return "policy_blocked"
    return "not_executed"


def _mint_evidence_id(phase: str, tool_id: str, scan_id: str) -> str:
    return f"{phase}:{tool_id}:{scan_id}"


class CoveragePhaseSink:
    """Map phase tool-run signals to validated CoverageResult rows and store them."""

    def __init__(
        self,
        *,
        store: InMemoryCoverageStore | None = None,
        graph: CapabilityGraph | None = None,
    ) -> None:
        self._store = store if store is not None else get_coverage_store()
        self._graph = graph if graph is not None else default_capability_graph()

    def results_for_scan(self, scan_id: str) -> list[CoverageResult]:
        return self._store.get(scan_id)

    def snapshot_for_scan(self, scan_id: str) -> list[CoverageResult]:
        """Read-only view of stored results (reporting / API)."""
        return self._store.get(scan_id)

    def emit_phase(
        self,
        *,
        phase: str,
        tenant_id: str,
        scan_id: str,
        asset_id: str,
        signals: Sequence[ToolRunSignal],
        execution_mode: str = "production",
        lab_lease_active: bool = False,
    ) -> list[CoverageResult]:
        """Emit one CoverageResult per capability resolved from ``signals``."""
        tid = _bounded_id(tenant_id, fallback="unknown")
        sid = _bounded_id(scan_id, fallback="unknown")
        aid = _bounded_id(asset_id, fallback="unknown")
        is_lab = _is_lab_mode(execution_mode) or bool(lab_lease_active)
        emitted: list[CoverageResult] = []
        for signal in signals:
            emitted.extend(
                self._emit_signal(
                    signal,
                    phase=phase,
                    tenant_id=tid,
                    scan_id=sid,
                    asset_id=aid,
                    execution_mode=execution_mode,
                    is_lab=is_lab,
                )
            )
        self._store.append(sid, emitted)
        logger.info(
            "coverage_phase_emitted",
            extra={
                "event": "coverage_phase_emitted",
                "scan_id": sid,
                "phase": phase,
                "results_n": len(emitted),
            },
        )
        return emitted

    def _capability_ids(self, signal: ToolRunSignal, phase: str) -> tuple[str, ...]:
        if signal.capability_id:
            return (signal.capability_id,)
        tool = signal.tool_id.strip().lower()
        matched: list[str] = []
        for node in self._graph.nodes:
            tools = {item.lower() for item in node.tools}
            if tool not in tools:
                continue
            if node.allowed_phases and phase not in node.allowed_phases:
                continue
            matched.append(node.id)
        if matched:
            return tuple(matched)
        return (f"tool.{tool}",)

    def _emit_signal(
        self,
        signal: ToolRunSignal,
        *,
        phase: str,
        tenant_id: str,
        scan_id: str,
        asset_id: str,
        execution_mode: str,
        is_lab: bool,
    ) -> list[CoverageResult]:
        skipped = bool(signal.skipped)
        tool_executed = bool(signal.tool_executed) and not skipped
        tool_error = bool(signal.tool_error) and not skipped
        target_unreachable = bool(signal.target_unreachable) and not skipped
        policy_blocked, blocked_reason = _lab_adjust_block(
            is_lab=is_lab,
            policy_blocked=bool(signal.policy_blocked),
            tool_error=tool_error,
            target_unreachable=target_unreachable,
            blocked_reason=signal.blocked_reason,
        )
        evidence_id = signal.execution_evidence_id
        if tool_executed and not tool_error and not target_unreachable and not evidence_id:
            evidence_id = _mint_evidence_id(phase, signal.tool_id, scan_id)
        if not tool_executed:
            evidence_id = None

        finding_id = signal.finding_id if tool_executed else None
        proposed = infer_status_from_execution(
            tool_executed=tool_executed,
            tool_error=tool_error,
            target_unreachable=target_unreachable,
            finding_id=finding_id,
            execution_evidence_id=evidence_id,
            policy_blocked=policy_blocked,
            not_applicable=bool(signal.not_applicable),
        )
        proposed = _status_for_quick_reason(
            signal.quick_reason,
            inferred=proposed,
            tool_executed=tool_executed,
            evidence_id=evidence_id,
            finding_id=finding_id,
        )
        if proposed in COVERED_STATUSES and not evidence_id:
            proposed = CoverageStatus.NOT_TESTED
            finding_id = None
        if proposed is CoverageStatus.BLOCKED and signal.quick_reason and not blocked_reason:
            blocked_reason = signal.quick_reason
        reason = _blocked_reason_for_status(
            proposed,
            tool_error=tool_error,
            target_unreachable=target_unreachable,
            policy_blocked=policy_blocked,
            blocked_reason=blocked_reason,
        )
        reason_code = signal.quick_reason or reason
        extra_evidence_ids = signal.evidence_ids
        if evidence_id and evidence_id not in extra_evidence_ids:
            extra_evidence_ids = (evidence_id, *extra_evidence_ids)
        results: list[CoverageResult] = []
        for capability_id in self._capability_ids(signal, phase):
            built = self._build_one(
                capability_id=capability_id,
                tenant_id=tenant_id,
                scan_id=scan_id,
                asset_id=asset_id,
                status=proposed,
                execution_evidence_id=evidence_id,
                finding_id=finding_id if proposed is CoverageStatus.COVERED_WITH_FINDING else None,
                blocked_reason=reason,
                tool_executed=tool_executed,
                execution_mode=execution_mode,
                reason_code=reason_code,
                template_ids=signal.template_ids,
                evidence_ids=extra_evidence_ids,
            )
            if built is not None:
                results.append(built)
        return results

    def _build_one(
        self,
        *,
        capability_id: str,
        tenant_id: str,
        scan_id: str,
        asset_id: str,
        status: CoverageStatus,
        execution_evidence_id: str | None,
        finding_id: str | None,
        blocked_reason: str | None,
        tool_executed: bool,
        execution_mode: str,
        reason_code: str | None = None,
        template_ids: tuple[str, ...] = (),
        evidence_ids: tuple[str, ...] = (),
    ) -> CoverageResult | None:
        requirement = CoverageRequirement(
            id=_requirement_id(),
            tenant_id=tenant_id,
            scan_id=scan_id,
            asset_id=asset_id,
            capability_id=capability_id,
        )
        current = (
            CoverageStatus.PLANNED
            if status is CoverageStatus.NOT_TESTED
            else CoverageStatus.NOT_TESTED
        )
        try:
            return build_coverage_result(
                requirement,
                status=status,
                execution_evidence_id=execution_evidence_id,
                blocked_reason=blocked_reason,
                finding_id=finding_id,
                current=current,
                tool_executed=tool_executed,
                mode=execution_mode,
                reason_code=reason_code,
                template_ids=template_ids,
                evidence_ids=evidence_ids,
            )
        except CoverageAccountingError:
            logger.warning(
                "coverage_accounting_rejected",
                extra={
                    "event": "coverage_accounting_rejected",
                    "scan_id": scan_id,
                    "capability_id": capability_id,
                    "proposed": status.value,
                },
            )
            if status in COVERED_STATUSES:
                return self._not_tested_fallback(requirement, execution_mode)
            return None

    def _not_tested_fallback(
        self,
        requirement: CoverageRequirement,
        execution_mode: str,
    ) -> CoverageResult | None:
        try:
            return build_coverage_result(
                requirement,
                status=CoverageStatus.NOT_TESTED,
                execution_evidence_id=None,
                blocked_reason=None,
                finding_id=None,
                current=CoverageStatus.PLANNED,
                tool_executed=False,
                mode=execution_mode,
            )
        except CoverageAccountingError:
            return None


_DEFAULT_SINK = CoveragePhaseSink()


def get_coverage_phase_sink() -> CoveragePhaseSink:
    return _DEFAULT_SINK


def signals_from_tool_results(
    tool_results: Mapping[str, Any] | None,
    *,
    phase: str = "recon",
) -> list[ToolRunSignal]:
    """Build signals from recon-style ``{tool: {success, stdout, stderr}}`` maps."""
    if not tool_results:
        return []
    signals: list[ToolRunSignal] = []
    for raw_name, payload in tool_results.items():
        name = str(raw_name).strip()
        if not name or name in _RECON_NON_TOOL_KEYS or name.startswith("__"):
            continue
        if not isinstance(payload, dict):
            signals.append(ToolRunSignal(tool_id=name, skipped=True))
            continue
        success = bool(payload.get("success"))
        stderr = str(payload.get("stderr") or "").lower()
        unreachable = (not success) and any(marker in stderr for marker in _UNREACHABLE_MARKERS)
        signals.append(
            ToolRunSignal(
                tool_id=name,
                skipped=False,
                tool_executed=success,
                tool_error=(not success) and (not unreachable),
                target_unreachable=unreachable,
                blocked_reason=(
                    "target_unreachable" if unreachable else ("tool_error" if not success else None)
                ),
                execution_evidence_id=f"{phase}:{name}" if success else None,
            )
        )
    return signals


def signals_for_vuln_analysis(
    *,
    skipped: bool,
    skip_reason: str | None = None,
    tool_executed: bool = False,
    tool_error: bool = False,
    findings: Sequence[Mapping[str, Any]] | None = None,
    scan_id: str = "unknown",
    tool_id: str = _VA_PRIMARY_TOOL,
) -> list[ToolRunSignal]:
    """Single nuclei-centric signal for the vuln_analysis active-scan path."""
    policy_blocked = (skip_reason or "") in _POLICY_BLOCK_REASONS
    finding_id = _first_finding_id(findings) if tool_executed and not skipped else None
    evidence_id = None
    if tool_executed and not skipped and not tool_error:
        evidence_id = _mint_evidence_id("vuln_analysis", tool_id, scan_id)
    return [
        ToolRunSignal(
            tool_id=tool_id,
            skipped=skipped and not tool_executed,
            tool_executed=tool_executed and not skipped,
            tool_error=tool_error and not skipped,
            policy_blocked=policy_blocked,
            blocked_reason=_vuln_blocked_reason(
                skipped=skipped,
                skip_reason=skip_reason,
                tool_error=tool_error,
                policy_blocked=policy_blocked,
            ),
            execution_evidence_id=evidence_id,
            finding_id=finding_id,
        )
    ]


def signals_for_quick_reason(
    *,
    tool_id: str,
    quick_reason: str,
    capability_id: str | None = None,
    template_ids: tuple[str, ...] = (),
    evidence_ids: tuple[str, ...] = (),
    finding_id: str | None = None,
) -> list[ToolRunSignal]:
    """Quick profile / deadline / circuit signals for the coverage sink."""
    not_scheduled = quick_reason == "not_scheduled_by_quick_profile"
    not_applicable = quick_reason == "fingerprint_mismatch"
    failed = quick_reason in {"tool_error", "circuit_open"}
    timed_out = quick_reason == "deadline_reached"
    executed = quick_reason in {"executed", "budget_partial"}
    evidence_id = evidence_ids[0] if evidence_ids else None
    return [
        ToolRunSignal(
            tool_id=tool_id,
            capability_id=capability_id,
            skipped=not_scheduled or not_applicable,
            tool_executed=executed and bool(evidence_id),
            tool_error=failed,
            not_applicable=not_applicable,
            blocked_reason=quick_reason if (failed or timed_out) else None,
            execution_evidence_id=evidence_id if executed else None,
            finding_id=finding_id if executed else None,
            quick_reason=quick_reason,
            template_ids=template_ids,
            evidence_ids=evidence_ids,
        )
    ]


def _vuln_blocked_reason(
    *,
    skipped: bool,
    skip_reason: str | None,
    tool_error: bool,
    policy_blocked: bool,
) -> str | None:
    if tool_error:
        return "tool_error"
    if policy_blocked:
        return "policy_blocked"
    if skipped and skip_reason:
        return skip_reason
    return None


def _first_finding_id(findings: Sequence[Mapping[str, Any]] | None) -> str | None:
    if not findings:
        return None
    for item in findings:
        for key in ("finding_id", "id", "stable_id"):
            raw = item.get(key)
            if raw is None:
                continue
            text = str(raw).strip()
            if text:
                return text
    return None


def _mode_and_lab_from_options(opts: Mapping[str, Any]) -> tuple[str, bool]:
    ctx = opts.get("execution_mode_context")
    ctx_dict = ctx if isinstance(ctx, dict) else {}
    mode_raw = opts.get("execution_mode")
    if mode_raw is None:
        mode_raw = ctx_dict.get("mode")
    return str(mode_raw or "production"), bool(ctx_dict.get("lab_lease_active"))


def snapshot_coverage_dicts(
    scan_id: str | None,
    *,
    sink: CoveragePhaseSink | None = None,
) -> list[dict[str, Any]]:
    """Serialize stored results for reporting / phase output (no new SQL)."""
    try:
        active = sink if sink is not None else get_coverage_phase_sink()
        return serialize_coverage_results(active.snapshot_for_scan(scan_id or ""))
    except (CoverageAccountingError, ValidationError, ValueError, TypeError, KeyError):
        logger.warning(
            "coverage_snapshot_failed",
            extra={"event": "coverage_snapshot_failed", "scan_id": scan_id or ""},
        )
        return []


def attach_phase_coverage(
    *,
    phase: str,
    tenant_id: str | None,
    scan_id: str | None,
    asset_id: str,
    signals: Sequence[ToolRunSignal],
    scan_options: Mapping[str, Any] | None,
    sink: CoveragePhaseSink | None = None,
) -> list[dict[str, Any]]:
    """Thin handler helper: emit via sink and return JSON-serialisable rows."""
    try:
        opts = dict(scan_options) if isinstance(scan_options, dict) else {}
        mode, lab_active = _mode_and_lab_from_options(opts)
        active = sink if sink is not None else get_coverage_phase_sink()
        results = active.emit_phase(
            phase=phase,
            tenant_id=tenant_id or str(opts.get("tenant_id") or "unknown"),
            scan_id=scan_id or str(opts.get("scan_id") or "unknown"),
            asset_id=asset_id,
            signals=signals,
            execution_mode=mode,
            lab_lease_active=lab_active,
        )
        return serialize_coverage_results(results)
    except (CoverageAccountingError, ValidationError, ValueError, TypeError, KeyError):
        logger.warning(
            "coverage_phase_emit_failed",
            extra={
                "event": "coverage_phase_emit_failed",
                "phase": phase,
                "scan_id": scan_id or "",
            },
        )
        return []


__all__ = [
    "CoveragePhaseSink",
    "InMemoryCoverageStore",
    "ToolRunSignal",
    "attach_phase_coverage",
    "get_coverage_phase_sink",
    "get_coverage_store",
    "serialize_coverage_results",
    "signals_for_quick_reason",
    "signals_for_vuln_analysis",
    "signals_from_tool_results",
    "snapshot_coverage_dicts",
]
