"""Human-in-the-loop approval gate (legitimate, FAIL-CLOSED).

A destructive or sensitive action is enqueued as an :class:`ApprovalRequest` and is
**not executable until a human approves it** (:func:`can_execute` is True only for an
``APPROVED`` request). Both approve and deny require a recorded reason so the decision
lands in the immutable audit.

This is the correct governance posture: destructive actions are *blocked pending
approval*, the opposite of the ARTEX "mark but always allow" inversion, which is not
implemented. Pure module: no DB/LLM/network; the ``approvals`` table + DAO + the admin
router wrap this logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

__all__ = [
    "ACTIONS_REQUIRING_APPROVAL",
    "ApprovalRequest",
    "ApprovalStatus",
    "can_execute",
    "decide",
    "requires_approval",
]


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"


#: Destructive / high-impact actions that must not run without human approval.
#: Substring match keeps it robust to tool-specific action names
#: (``ad.secretsdump``, ``exploit.delete_rows`` …).
ACTIONS_REQUIRING_APPROVAL: frozenset[str] = frozenset(
    {
        "secretsdump",
        "dcsync",
        "krbtgt",
        "delete",
        "drop",
        "encrypt",
        "wipe",
        "destroy",
        "exfil",
        "ransom",
        "mass_write",
        "persistence",
    }
)


def requires_approval(action: str) -> bool:
    """True when ``action`` names a destructive/sensitive operation needing approval."""
    a = str(action).strip().lower()
    return any(token in a for token in ACTIONS_REQUIRING_APPROVAL)


@dataclass
class ApprovalRequest:
    """One pending/decided human-in-the-loop approval item."""

    request_id: str
    action: str
    target: str
    tenant_id: str
    reason: str = ""  # why the action was requested
    status: ApprovalStatus = ApprovalStatus.PENDING
    decided_by: str | None = None
    decision_reason: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    decided_at: datetime | None = None


def can_execute(request: ApprovalRequest) -> bool:
    """Fail-closed: an action may run only when its request is APPROVED."""
    return request.status is ApprovalStatus.APPROVED


def decide(
    request: ApprovalRequest,
    *,
    approve: bool,
    decided_by: str,
    reason: str,
    now: datetime | None = None,
) -> ApprovalRequest:
    """Record an approve/deny decision (reason mandatory) and return the updated request.

    A blank reason is rejected so every decision is auditable — no silent approvals.
    """
    if not str(reason).strip():
        raise ValueError("an approval/denial decision requires a non-empty reason")
    request.status = ApprovalStatus.APPROVED if approve else ApprovalStatus.DENIED
    request.decided_by = decided_by
    request.decision_reason = reason
    request.decided_at = now or datetime.now(UTC)
    return request
