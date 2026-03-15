"""Guardrails — IPValidator, DomainValidator, RateLimiter (Phase 5)."""

from src.tools.guardrails.domain_validator import DomainValidator
from src.tools.guardrails.ip_validator import IPValidator
from src.tools.guardrails.rate_limiter import RateLimiter

__all__ = ["IPValidator", "DomainValidator", "RateLimiter", "validate_target_for_tool"]


def validate_target_for_tool(target: str, tool_name: str) -> dict:
    """
    Validate target (IP or domain) before tool execution.
    Handles comma/space-separated targets.
    Returns {"allowed": bool, "reason": str}.
    """
    if not target or not target.strip():
        return {"allowed": False, "reason": "Target is empty"}

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
