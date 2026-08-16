"""Bridge LAB lease → policy allow-all without hidden gates."""

from __future__ import annotations

import logging
from typing import Any

from src.execution_mode.boundary_verifier import LabBoundaryVerifier
from src.execution_mode.lab_lease import (
    LAB_ALLOW_ALL,
    LabExecutionLease,
    LabLeaseService,
    PolicyDecisionLab,
)
from src.execution_mode.lab_scope import LabScopeManifest
from src.execution_mode.metrics import (
    increment_lab_boundary_denial,
    increment_lab_execution,
)
from src.execution_mode.mode import ExecutionMode, parse_execution_mode

logger = logging.getLogger(__name__)


def evaluate_with_execution_mode(
    *,
    mode: ExecutionMode | str,
    target: str,
    manifest: LabScopeManifest | None = None,
    lease: LabExecutionLease | None = None,
    tenant_id: str | None = None,
    engagement_id: str | None = None,
    asset_id: str | None = None,
    k8s_namespace: str | None = None,
    vm_network_id: str | None = None,
    production_evaluator: Any | None = None,
    production_context: Any | None = None,
) -> PolicyDecisionLab | Any:
    """Mode-aware policy entry.

    LAB path (master prompt §2.5):
      - verify boundary once (or reuse valid lease)
      - return allow-all / no approval
      - never add hidden technique gates here

    Production and Quick paths delegate to ``production_evaluator``.
    Unknown modes raise ``ValueError`` — they must never fall through to LAB.
    """
    resolved = parse_execution_mode(mode)

    match resolved:
        case ExecutionMode.PRODUCTION | ExecutionMode.QUICK:
            if production_evaluator is None:
                raise ValueError("production_evaluator_required")
            if production_context is None:
                raise ValueError("production_context_required")
            return production_evaluator(production_context)
        case ExecutionMode.LAB_UNRESTRICTED:
            return _evaluate_lab_unrestricted(
                target=target,
                manifest=manifest,
                lease=lease,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                asset_id=asset_id,
                k8s_namespace=k8s_namespace,
                vm_network_id=vm_network_id,
            )
        case _:
            raise ValueError(f"unsupported_execution_mode:{resolved}")


def _evaluate_lab_unrestricted(
    *,
    target: str,
    manifest: LabScopeManifest | None,
    lease: LabExecutionLease | None,
    tenant_id: str | None,
    engagement_id: str | None,
    asset_id: str | None,
    k8s_namespace: str | None,
    vm_network_id: str | None,
) -> PolicyDecisionLab:
    if lease is not None and lease.is_usable():
        if tenant_id and lease.tenant_id != tenant_id:
            increment_lab_boundary_denial()
            return PolicyDecisionLab(
                outcome="deny",
                requires_approval=True,
                allowed_tools=(),
                allowed_actions=(),
                allowed_protocols=(),
                allowed_payloads=(),
                budget={},
                reason="lab_lease_tenant_mismatch",
                deny_code="DENY_OUTSIDE_LAB",
            )
        increment_lab_execution()
        return LAB_ALLOW_ALL

    if manifest is None:
        increment_lab_boundary_denial()
        return PolicyDecisionLab(
            outcome="deny",
            requires_approval=True,
            allowed_tools=(),
            allowed_actions=(),
            allowed_protocols=(),
            allowed_payloads=(),
            budget={},
            reason="lab_manifest_required",
            deny_code="DENY_OUTSIDE_LAB",
        )

    verdict = LabBoundaryVerifier().verify(
        target,
        manifest,
        tenant_id=tenant_id or manifest.tenant_id,
        engagement_id=engagement_id or manifest.engagement_id,
        asset_id=asset_id,
        k8s_namespace=k8s_namespace or manifest.k8s_namespace,
        vm_network_id=vm_network_id,
    )
    if not verdict.allowed:
        logger.info(
            "lab_policy_deny_outside",
            extra={
                "event": "lab_boundary_denial",
                "deny_code": verdict.deny_code,
                "reason": verdict.reason,
            },
        )
        increment_lab_boundary_denial()
        return PolicyDecisionLab(
            outcome="deny",
            requires_approval=True,
            allowed_tools=(),
            allowed_actions=(),
            allowed_protocols=(),
            allowed_payloads=(),
            budget={},
            reason=verdict.reason,
            deny_code=verdict.deny_code or "DENY_OUTSIDE_LAB",
        )

    # Boundary OK — issue ephemeral decision (caller should persist lease separately).
    _ = LabLeaseService()  # explicit dependency surface for callers/tests
    increment_lab_execution()
    return LAB_ALLOW_ALL
