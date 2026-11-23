"""WP D (legitimate, FAIL-CLOSED) — human-in-the-loop approval gate.

Pure/offline. A destructive/sensitive action is NOT executable until a human
approves it (the opposite of the ARTEX "mark but never block" inversion). Approve
and deny both require a recorded reason for the immutable audit.
"""

from __future__ import annotations

import pytest
from src.governance.approvals import (
    ApprovalRequest,
    ApprovalStatus,
    can_execute,
    decide,
    requires_approval,
)


def test_destructive_action_requires_approval() -> None:
    assert requires_approval("secretsdump") is True
    assert requires_approval("krbtgt_dump") is True
    assert requires_approval("delete") is True


def test_benign_action_does_not_require_approval() -> None:
    assert requires_approval("recon") is False
    assert requires_approval("http_get") is False


def test_fresh_request_is_pending_and_not_executable() -> None:
    req = ApprovalRequest(request_id="A-1", action="secretsdump", target="dc01", tenant_id="t1")
    assert req.status is ApprovalStatus.PENDING
    assert can_execute(req) is False


def test_approved_request_is_executable() -> None:
    req = ApprovalRequest(request_id="A-1", action="secretsdump", target="dc01", tenant_id="t1")
    approved = decide(req, approve=True, decided_by="lead@firm", reason="in scope per RoE §4")
    assert approved.status is ApprovalStatus.APPROVED
    assert can_execute(approved) is True


def test_denied_request_is_not_executable() -> None:
    req = ApprovalRequest(request_id="A-1", action="delete", target="db", tenant_id="t1")
    denied = decide(req, approve=False, decided_by="lead@firm", reason="out of scope")
    assert denied.status is ApprovalStatus.DENIED
    assert can_execute(denied) is False


def test_decision_requires_a_reason() -> None:
    req = ApprovalRequest(request_id="A-1", action="delete", target="db", tenant_id="t1")
    with pytest.raises(ValueError):
        decide(req, approve=True, decided_by="lead@firm", reason="")
