"""Runtime boundary gate for mutating tool execution under LAB lease."""

from __future__ import annotations

from typing import Any

from src.execution_mode.mode import ExecutionMode
from src.orchestration.execution_mode_context import (
    LeaseLookupFn,
    extract_execution_mode,
    resolve_tool_policy_from_options,
)


def assert_execution_allowed(
    tool_name: str,
    target: str,
    scan_options: dict[str, Any] | None,
    *,
    tenant_id: str | None = None,
    engagement_id: str | None = None,
    lease_lookup: LeaseLookupFn | None = None,
) -> None:
    """Fail-closed gate before mutating sandbox tool execution.

    Production mode is a no-op (existing approval/policy gates apply downstream).
    LAB paths go through ``resolve_tool_policy_from_options``:
    missing/unusable lease or outside boundary → ``PermissionError``.
    """
    opts = dict(scan_options) if isinstance(scan_options, dict) else {}
    mode = extract_execution_mode(opts)
    if mode is ExecutionMode.PRODUCTION:
        return

    decision = resolve_tool_policy_from_options(
        tool_name,
        opts,
        target=target or "",
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        lease_lookup=lease_lookup,
    )
    if decision.allowed and decision.lab_lease_active:
        return

    deny_code = decision.deny_code or "DENY_OUTSIDE_LAB"
    reason = decision.reason or "lab_boundary_denied"
    # Preserve compact "lab_lease_required" for missing-lease call sites.
    if reason == "lab_lease_required" and deny_code == "DENY_OUTSIDE_LAB":
        raise PermissionError("lab_lease_required")
    raise PermissionError(f"{deny_code}:{reason}")
