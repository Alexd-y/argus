"""Guardrails — IPValidator, DomainValidator, RateLimiter (Phase 5)."""

from src.tools.guardrails.domain_validator import DomainValidator
from src.tools.guardrails.ip_validator import IPValidator
from src.tools.guardrails.rate_limiter import RateLimiter

__all__ = ["DomainValidator", "IPValidator", "RateLimiter", "validate_target_for_tool"]


def validate_target_for_tool(
    target: str,
    tool_name: str,  # noqa: ARG001 - retained for signature/API compatibility
    *,
    lab_authorized: bool = False,
) -> dict:
    """
    Validate target (IP or domain) before tool execution.
    Handles comma/space-separated targets.
    Returns {"allowed": bool, "reason": str}.

    ``lab_authorized`` MUST be passed ``True`` only by a caller that has verified,
    for THIS target, the full lab gate: execution mode is ``lab_unrestricted`` AND
    the target lies inside the operator's authorized lab scope
    (``argus_lab_allowed_targets`` / ``LabScopeManifest``). Compute it via
    :func:`src.orchestration.execution_mode_context.lab_authorized_target`, never by
    hand. When ``True`` the private/loopback/link-local (incl. cloud-metadata) and
    blocked-domain guards are lifted so an *authorized* internal-network engagement
    can run. Default ``False`` keeps production and quick fully guarded (fail-closed):
    the bypass is bound to the authorized scope, never global.
    """
    if not target or not target.strip():
        return {"allowed": False, "reason": "Target is empty"}

    if lab_authorized:
        return {"allowed": True, "reason": "lab_unrestricted_authorized_scope"}

    parts = [p.strip() for p in target.replace(",", " ").split() if p.strip()]
    for t in parts:
        if IPValidator.is_private_or_loopback(t):
            return {
                "allowed": False,
                "reason": "Private or loopback IP addresses are not allowed",
            }
        if DomainValidator.is_blocked(t):
            return {"allowed": False, "reason": "Blocked domain (localhost, .local)"}

    return {"allowed": True, "reason": ""}
