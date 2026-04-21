"""Shared primitives for MCP tool / resource schemas."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr


class ToolResultStatus(StrEnum):
    """Closed taxonomy for tool result status flags.

    Used by tools that return a small acknowledgement payload (e.g.
    ``scan.cancel``, ``findings.mark_false_positive``). Avoid free-form
    strings so callers can switch on the value without a string-compare.
    """

    OK = "ok"
    SUCCESS = "success"
    UNCHANGED = "unchanged"
    NOOP = "noop"
    QUEUED = "queued"
    DENIED = "denied"


class PaginationInput(BaseModel):
    """Common pagination parameters.

    The MCP server enforces an explicit upper bound (``limit <= 200``) so a
    client cannot accidentally drain the entire findings table in a single
    call. Larger result sets must paginate.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    limit: StrictInt = Field(default=50, ge=1, le=200)
    offset: StrictInt = Field(default=0, ge=0, le=100_000)


class FailureSummary(BaseModel):
    """Closed-taxonomy failure summary echoed back to the caller.

    Mirrors the policy-plane convention from :mod:`src.policy` — never
    include free-form text or internal identifiers.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: StrictStr = Field(min_length=1, max_length=64)
    detail: StrictStr | None = Field(default=None, max_length=200)


class AcknowledgementResult(BaseModel):
    """Generic ack payload for tools that mutate state.

    Tools that need a richer response should declare their own typed result
    schema instead of overloading this one.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: ToolResultStatus
    message: StrictStr | None = Field(default=None, max_length=200)
    audit_event_id: StrictStr | None = Field(default=None, max_length=64)
    actionable: StrictBool = True


__all__ = [
    "AcknowledgementResult",
    "FailureSummary",
    "PaginationInput",
    "ToolResultStatus",
]
