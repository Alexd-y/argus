"""Backward-compatibility shim for the approval workflow (Backlog/dev1_md §8, §16).

Historically this module bundled both the approval *DTOs* and the
*service* that verifies them. That mix produced a latent cyclic-import
chain whenever the policy plane was imported cold:

    src.policy.__init__
      -> src.policy.approval (start; pulls in src.sandbox.signing)
        -> ... -> src.payloads.builder
          -> src.policy.preflight
            -> src.policy.approval (PARTIAL — kaboom)

T02 split the module into two layers:

* :mod:`src.policy.approval_dto` — pure pydantic DTOs and the closed
  failure taxonomy (no signing / audit / sandbox dependencies). Safe to
  import from anywhere.
* :mod:`src.policy.approval_service` — :class:`ApprovalService`, with
  the heavyweight crypto + audit dependencies kept in one place.

This file remains as a *thin re-export shim* so every existing call site
(``from src.policy.approval import ApprovalService`` etc.) keeps working
without churn. New code SHOULD prefer importing directly from
:mod:`src.policy.approval_dto` (DTO contract) or
:mod:`src.policy.approval_service` (verification engine) so the layering
stays visible at the import line.
"""

from __future__ import annotations

from src.policy.approval_dto import (
    APPROVAL_FAILURE_REASONS,
    ApprovalAction,
    ApprovalError,
    ApprovalRequest,
    ApprovalSignature,
    ApprovalStatus,
)
from src.policy.approval_service import ApprovalService


__all__ = [
    "APPROVAL_FAILURE_REASONS",
    "ApprovalAction",
    "ApprovalError",
    "ApprovalRequest",
    "ApprovalService",
    "ApprovalSignature",
    "ApprovalStatus",
]
