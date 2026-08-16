"""Resolve execution mode + LAB lease for orchestration / policy preflight.

Collaborator (SRP): extract mode/lease from scan options and produce a single
tool-policy decision. LAB + usable lease → allow-all without approval; production
and Quick keep existing approval gates (Quick never sets lab_lease_active).
Boundary / missing-lease denies stay fail-closed.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from pydantic import BaseModel, ConfigDict, StrictBool, StrictStr, ValidationError

from src.execution_mode.lab_lease import LabExecutionLease, PolicyDecisionLab
from src.execution_mode.lab_scope import LabScopeManifest
from src.execution_mode.mode import (
    ExecutionMode,
    ModeContext,
    coerce_legacy_mode_field,
    parse_execution_mode,
)
from src.execution_mode.policy_bridge import evaluate_with_execution_mode
from src.execution_mode.runtime_context import bind_phase_execution_mode
from src.recon.mcp.policy import evaluate_tool_approval_policy

logger = logging.getLogger(__name__)

_DENY_OUTSIDE_LAB = "DENY_OUTSIDE_LAB"

# Optional DB/API lease resolver: (options, tenant_id, engagement_id) -> LabExecutionLease | None
LeaseLookupFn = Callable[
    [dict[str, Any], str | None, str | None],
    LabExecutionLease | None,
]


class ToolPolicyDecision(BaseModel):
    """Small DTO for orchestration / MCP / VA preflight."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed: StrictBool
    requires_approval: StrictBool
    reason: StrictStr
    deny_code: StrictStr | None = None
    lab_lease_active: StrictBool = False
    policy_id: StrictStr | None = None


class PhaseExecutionModePreflight(BaseModel):
    """Resolved execution-mode snapshot attached to phase inputs at phase start."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    mode: StrictStr
    lab_lease_active: StrictBool = False
    lab_lease_id: StrictStr | None = None
    deny_code: StrictStr | None = None
    reason: StrictStr = "production_default"


def _as_dict(options: dict[str, Any] | None) -> dict[str, Any]:
    return options if isinstance(options, dict) else {}


def _str_opt(raw: Any) -> str | None:
    if raw is None:
        return None
    text = str(raw).strip()
    return text or None


def resolve_lab_lease_from_options(options: dict[str, Any] | None) -> LabExecutionLease | None:
    """Parse ``lab_lease`` / ``lab_execution_lease`` payload from scan options."""
    opts = _as_dict(options)
    raw = opts.get("lab_lease")
    if raw is None:
        raw = opts.get("lab_execution_lease")
    if isinstance(raw, LabExecutionLease):
        return raw
    if isinstance(raw, dict):
        try:
            return LabExecutionLease.from_storage_dict(raw)
        except (ValidationError, TypeError, ValueError):
            logger.info(
                "lab_lease_parse_failed",
                extra={"event": "lab_lease_parse_failed"},
            )
            return None
    return None


def resolve_lease_for_options(
    options: dict[str, Any] | None,
    *,
    tenant_id: str | None = None,
    engagement_id: str | None = None,
    lease_lookup: LeaseLookupFn | None = None,
) -> LabExecutionLease | None:
    """Resolve lease from options, with optional injected lookup (DB/API)."""
    opts = _as_dict(options)
    embedded = resolve_lab_lease_from_options(opts)
    if lease_lookup is None:
        return embedded
    looked_up = lease_lookup(opts, tenant_id, engagement_id)
    return looked_up if looked_up is not None else embedded


def extract_execution_mode(options: dict[str, Any] | None) -> ExecutionMode:
    """Return execution mode from scan options (defaults to production).

    ``execution_mode`` is canonical. The ambiguous ``mode`` key is only accepted
    for legacy production / lab_unrestricted values — scan-depth ``quick`` is ignored.
    """
    opts = _as_dict(options)
    mode_raw = opts.get("execution_mode")
    if mode_raw is not None and str(mode_raw).strip() != "":
        return parse_execution_mode(mode_raw)
    fallback = coerce_legacy_mode_field(opts.get("mode"))
    return fallback if fallback is not None else ExecutionMode.PRODUCTION


def extract_lab_lease_id(options: dict[str, Any] | None) -> str | None:
    """Return lab lease id from options or embedded lease payload."""
    opts = _as_dict(options)
    lease_id = _str_opt(opts.get("lab_lease_id"))
    if lease_id is not None:
        return lease_id
    lease = resolve_lab_lease_from_options(opts)
    return lease.lease_id if lease is not None else None


def extract_lab_scope_manifest(options: dict[str, Any] | None) -> LabScopeManifest | None:
    """Return parsed lab scope manifest from options."""
    return resolve_lab_manifest_from_options(options)


def _scan_options_from_row(scan_row: Any | None) -> dict[str, Any]:
    if scan_row is None:
        return {}
    raw_opts = getattr(scan_row, "options", None)
    if isinstance(raw_opts, dict):
        return dict(raw_opts)
    return {}


def resolve_mode_context(
    scan_options: dict[str, Any] | None = None,
    scan_row: Any | None = None,
    *,
    tenant_id: str | None = None,
    engagement_id: str | None = None,
    scan_id: str | None = None,
) -> ModeContext:
    """Unified resolver: merge scan row options with explicit scan_options."""
    merged = _scan_options_from_row(scan_row)
    if scan_options:
        merged.update(scan_options)
    row_tid = _str_opt(getattr(scan_row, "tenant_id", None))
    row_sid = _str_opt(getattr(scan_row, "id", None))
    effective_scan_id = scan_id or _str_opt(merged.get("scan_id")) or row_sid
    return resolve_mode_context_from_options(
        merged,
        tenant_id=tenant_id or row_tid,
        engagement_id=engagement_id,
        scan_id=effective_scan_id,
    )


def resolve_lab_manifest_from_options(options: dict[str, Any] | None) -> LabScopeManifest | None:
    """Parse ``lab_scope`` / ``lab_scope_manifest`` from scan options."""
    opts = _as_dict(options)
    raw = opts.get("lab_scope")
    if raw is None:
        raw = opts.get("lab_scope_manifest")
    if isinstance(raw, LabScopeManifest):
        return raw
    if isinstance(raw, dict):
        try:
            return LabScopeManifest.from_storage_dict(raw)
        except (ValidationError, TypeError, ValueError):
            logger.info(
                "lab_manifest_parse_failed",
                extra={"event": "lab_manifest_parse_failed"},
            )
            return None
    return None


def resolve_mode_context_from_options(
    options: dict[str, Any] | None,
    *,
    tenant_id: str | None = None,
    engagement_id: str | None = None,
    scan_id: str | None = None,
) -> ModeContext:
    """Build ``ModeContext`` from scan/engagement options (defaults → production)."""
    opts = _as_dict(options)
    tid = _str_opt(tenant_id) or _str_opt(opts.get("tenant_id")) or "00000000-0000-0000-0000-000000000000"
    eid = (
        _str_opt(engagement_id)
        or _str_opt(opts.get("engagement_id"))
        or "00000000-0000-0000-0000-000000000000"
    )
    sid = _str_opt(scan_id) or _str_opt(opts.get("scan_id"))
    mode_raw = opts.get("execution_mode")
    if mode_raw is not None and str(mode_raw).strip() != "":
        mode = parse_execution_mode(mode_raw)
    else:
        mode = coerce_legacy_mode_field(opts.get("mode")) or ExecutionMode.PRODUCTION
    lease_id = _str_opt(opts.get("lab_lease_id"))
    if lease_id is None:
        lease = resolve_lab_lease_from_options(opts)
        if lease is not None:
            lease_id = lease.lease_id
    first_exec = _str_opt(opts.get("first_execution_at"))
    return ModeContext(
        tenant_id=tid,
        engagement_id=eid,
        scan_id=sid,
        mode=mode,
        lab_lease_id=lease_id,
        first_execution_at=first_exec,
    )


def is_lab_lease_active_from_options(
    options: dict[str, Any] | None,
    *,
    lease: LabExecutionLease | None = None,
    tenant_id: str | None = None,
    engagement_id: str | None = None,
) -> bool:
    """True when mode is LAB and a usable lease is present in options."""
    ctx = resolve_mode_context_from_options(
        options,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
    )
    if not ctx.is_lab:
        return False
    resolved = lease if lease is not None else resolve_lab_lease_from_options(options)
    if resolved is None or not resolved.is_usable():
        return False
    return not (tenant_id and resolved.tenant_id != tenant_id)


def preflight_phase_execution_mode(
    options: dict[str, Any] | None,
    *,
    tenant_id: str | None = None,
    engagement_id: str | None = None,
    scan_id: str | None = None,
    lease_lookup: LeaseLookupFn | None = None,
) -> PhaseExecutionModePreflight:
    """Phase-start helper: resolve mode + lease for orchestration preflight."""
    ctx = resolve_mode_context_from_options(
        options,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        scan_id=scan_id,
    )
    lease = resolve_lease_for_options(
        options,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        lease_lookup=lease_lookup,
    )
    lab_active = is_lab_lease_active_from_options(
        options,
        lease=lease,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
    )
    if ctx.is_production:
        return PhaseExecutionModePreflight(
            mode=ctx.mode.value,
            lab_lease_active=False,
            lab_lease_id=None,
            reason="production_default",
        )
    if ctx.is_quick:
        return PhaseExecutionModePreflight(
            mode=ctx.mode.value,
            lab_lease_active=False,
            lab_lease_id=None,
            reason="quick_production_like",
        )
    if lab_active:
        lease_id = lease.lease_id if lease is not None else ctx.lab_lease_id
        return PhaseExecutionModePreflight(
            mode=ctx.mode.value,
            lab_lease_active=True,
            lab_lease_id=lease_id,
            reason="verified_lab_unrestricted",
        )
    return PhaseExecutionModePreflight(
        mode=ctx.mode.value,
        lab_lease_active=False,
        lab_lease_id=ctx.lab_lease_id,
        deny_code=_DENY_OUTSIDE_LAB,
        reason="lab_lease_required",
    )


def inject_phase_execution_mode_preflight(
    input_data: dict[str, Any],
    preflight: PhaseExecutionModePreflight,
) -> dict[str, Any]:
    """Attach execution-mode preflight snapshot to phase input payload."""
    input_data["execution_mode_context"] = preflight.model_dump()
    return input_data


def attach_execution_mode_to_input(
    input_data: dict[str, Any],
    options: dict[str, Any] | None,
    *,
    tenant_id: str | None = None,
    engagement_id: str | None = None,
    scan_id: str | None = None,
    lease_lookup: LeaseLookupFn | None = None,
) -> PhaseExecutionModePreflight:
    """Phase-start helper: resolve preflight and stamp it onto input + options."""
    opts = _as_dict(options)
    preflight = preflight_phase_execution_mode(
        opts,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        scan_id=scan_id,
        lease_lookup=lease_lookup,
    )
    inject_phase_execution_mode_preflight(input_data, preflight)
    if isinstance(options, dict):
        options["execution_mode_context"] = preflight.model_dump()
    bind_phase_execution_mode(preflight.mode, options if isinstance(options, dict) else input_data)
    return preflight


def _approval_requires_flag(reason: str) -> bool:
    return reason in {
        "requires_approval",
        "requires_lab_mode",
        "requires_kill_switch_clearance",
        "active_injection_quick_blocks_destructive",
    }


def resolve_tool_policy(
    tool_name: str,
    *,
    mode: ExecutionMode | str | None = None,
    lease: LabExecutionLease | None = None,
    manifest: LabScopeManifest | None = None,
    target: str = "",
    scan_approval_flags: dict[str, bool] | None = None,
    tenant_id: str | None = None,
    engagement_id: str | None = None,
    asset_id: str | None = None,
    k8s_namespace: str | None = None,
    vm_network_id: str | None = None,
    policy_settings: Any | None = None,
) -> ToolPolicyDecision:
    """Mode-aware tool gate wrapping bridge + MCP approval policy.

    LAB + usable lease → allow without ``requires_approval``.
    Missing / unusable lease or outside boundary → deny ``DENY_OUTSIDE_LAB``.
    Production and Quick → existing ``evaluate_tool_approval_policy`` path
    with ``lab_lease_active=False`` (Quick never inherits LAB allow-all).
    """
    resolved_mode = parse_execution_mode(mode)

    if resolved_mode is ExecutionMode.LAB_UNRESTRICTED:
        lease_usable = lease is not None and lease.is_usable()
        if lease_usable and tenant_id and lease is not None and lease.tenant_id != tenant_id:
            return ToolPolicyDecision(
                allowed=False,
                requires_approval=True,
                reason="lab_lease_tenant_mismatch",
                deny_code=_DENY_OUTSIDE_LAB,
                lab_lease_active=False,
                policy_id="lab_unrestricted_lease_v1",
            )

        if not lease_usable:
            # Boundary deny when we can evaluate; otherwise missing lease → DENY_OUTSIDE_LAB.
            if manifest is not None and (target or asset_id):
                bridge = evaluate_with_execution_mode(
                    mode=resolved_mode,
                    target=target or "",
                    manifest=manifest,
                    lease=None,
                    tenant_id=tenant_id,
                    engagement_id=engagement_id,
                    asset_id=asset_id,
                    k8s_namespace=k8s_namespace,
                    vm_network_id=vm_network_id,
                )
                if not getattr(bridge, "allowed", False):
                    return ToolPolicyDecision(
                        allowed=False,
                        requires_approval=True,
                        reason=str(getattr(bridge, "reason", "lab_boundary_denied") or "lab_boundary_denied"),
                        deny_code=str(
                            getattr(bridge, "deny_code", None) or _DENY_OUTSIDE_LAB
                        ),
                        lab_lease_active=False,
                        policy_id="lab_unrestricted_lease_v1",
                    )
            return ToolPolicyDecision(
                allowed=False,
                requires_approval=True,
                reason="lab_lease_required",
                deny_code=_DENY_OUTSIDE_LAB,
                lab_lease_active=False,
                policy_id="lab_unrestricted_lease_v1",
            )

        bridge = evaluate_with_execution_mode(
            mode=resolved_mode,
            target=target or "",
            manifest=manifest,
            lease=lease,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            asset_id=asset_id,
            k8s_namespace=k8s_namespace,
            vm_network_id=vm_network_id,
        )
        if not getattr(bridge, "allowed", False):
            return ToolPolicyDecision(
                allowed=False,
                requires_approval=True,
                reason=str(getattr(bridge, "reason", "lab_policy_denied") or "lab_policy_denied"),
                deny_code=str(getattr(bridge, "deny_code", None) or _DENY_OUTSIDE_LAB),
                lab_lease_active=False,
                policy_id="lab_unrestricted_lease_v1",
            )

        mcp = evaluate_tool_approval_policy(
            tool_name,
            scan_approval_flags=scan_approval_flags,
            policy_settings=policy_settings,
            lab_lease_active=True,
        )
        return ToolPolicyDecision(
            allowed=bool(mcp.allowed),
            requires_approval=False,
            reason=str(mcp.reason or "verified_lab_unrestricted"),
            deny_code=None,
            lab_lease_active=True,
            policy_id=str(mcp.policy_id or "lab_unrestricted_lease_v1"),
        )

    if resolved_mode not in (ExecutionMode.PRODUCTION, ExecutionMode.QUICK):
        raise ValueError(f"unsupported_execution_mode:{resolved_mode}")

    mcp = evaluate_tool_approval_policy(
        tool_name,
        scan_approval_flags=scan_approval_flags,
        policy_settings=policy_settings,
        lab_lease_active=False,
    )
    reason = str(mcp.reason or "denied")
    return ToolPolicyDecision(
        allowed=bool(mcp.allowed),
        requires_approval=(not mcp.allowed) and _approval_requires_flag(reason),
        reason=reason,
        deny_code=None,
        lab_lease_active=False,
        policy_id=str(mcp.policy_id) if mcp.policy_id else None,
    )


def tool_policy_as_dict(decision: ToolPolicyDecision) -> dict[str, Any]:
    """Serialize ``ToolPolicyDecision`` for worker/sandbox kwargs."""
    return {
        "allowed": decision.allowed,
        "requires_approval": decision.requires_approval,
        "reason": decision.reason,
        "deny_code": decision.deny_code,
        "lab_lease_active": decision.lab_lease_active,
        "policy_id": decision.policy_id,
    }


def tool_policy_to_lab(decision: ToolPolicyDecision) -> PolicyDecisionLab:
    """Map orchestration decision into ``PolicyDecisionLab`` for policy bridge consumers."""
    if decision.allowed and not decision.requires_approval and decision.lab_lease_active:
        return PolicyDecisionLab(
            outcome="allow",
            requires_approval=False,
            reason=decision.reason,
        )
    return PolicyDecisionLab(
        outcome="deny",
        requires_approval=True,
        allowed_tools=(),
        allowed_actions=(),
        allowed_protocols=(),
        allowed_payloads=(),
        budget={},
        reason=decision.reason,
        deny_code=decision.deny_code or _DENY_OUTSIDE_LAB,
    )


def resolve_tool_policy_from_options(
    tool_name: str,
    options: dict[str, Any] | None,
    *,
    target: str = "",
    scan_approval_flags: dict[str, bool] | None = None,
    tenant_id: str | None = None,
    engagement_id: str | None = None,
    asset_id: str | None = None,
    k8s_namespace: str | None = None,
    vm_network_id: str | None = None,
    policy_settings: Any | None = None,
    lease_lookup: LeaseLookupFn | None = None,
    as_dict: bool = False,
) -> ToolPolicyDecision | dict[str, Any]:
    """Convenience: resolve mode/lease/manifest from options then ``resolve_tool_policy``."""
    opts = _as_dict(options)
    ctx = resolve_mode_context_from_options(
        opts,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
    )
    lease = resolve_lease_for_options(
        opts,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        lease_lookup=lease_lookup,
    )
    manifest = resolve_lab_manifest_from_options(opts)
    flags = scan_approval_flags
    if flags is None:
        raw_flags = opts.get("scan_approval_flags")
        if isinstance(raw_flags, dict):
            flags = {
                str(k).strip().lower(): bool(v)
                for k, v in raw_flags.items()
                if str(k).strip()
            }
    ns = k8s_namespace or _str_opt(opts.get("k8s_namespace"))
    vm = vm_network_id or _str_opt(opts.get("vm_network_id"))
    aid = asset_id or _str_opt(opts.get("asset_id"))
    decision = resolve_tool_policy(
        tool_name,
        mode=ctx.mode,
        lease=lease,
        manifest=manifest,
        target=target,
        scan_approval_flags=flags,
        tenant_id=tenant_id or ctx.tenant_id,
        engagement_id=engagement_id or ctx.engagement_id,
        asset_id=aid,
        k8s_namespace=ns,
        vm_network_id=vm,
        policy_settings=policy_settings,
    )
    if as_dict:
        return tool_policy_as_dict(decision)
    return decision


# Alias used by handlers / MCP callers (same as resolve_tool_policy_from_options).
resolve_tool_policy_for_scan = resolve_tool_policy_from_options