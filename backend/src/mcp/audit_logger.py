"""MCP-specific audit wrapper around :class:`src.policy.audit.AuditLogger`.

Every MCP tool / resource / prompt invocation MUST emit an audit event:

* ``actor=mcp_client`` — the LLM / human session is identified by its
  authenticated user id (when available) plus the constant tag ``mcp_client``
  so post-mortem audits can filter MCP traffic separately from HTTP API
  traffic.
* ``arguments_hash`` — SHA-256 hex of the *canonical* JSON serialisation of
  the input payload. We never persist the raw arguments because clients may
  pass tokens / secrets in free-text fields (we still validate, but the
  audit row stays size-bounded and PII-free).
* ``failure_summary`` — closed-taxonomy short string when the call denies /
  raises; never a free-form exception message.

The logger relies on :class:`src.policy.audit.AuditLogger` for the actual
hash chain and persistence. This module only knows how to safely hash
arguments and pick the right :class:`AuditEventType`.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Mapping
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import UUID

from src.policy.audit import (  # noqa: I001 — direct module import to avoid policy package init cycles
    AuditEvent,
    AuditEventType,
    AuditLogger,
    InMemoryAuditSink,
)

_logger = logging.getLogger(__name__)

_MCP_ACTOR_TAG = "mcp_client"


class MCPCallOutcome(StrEnum):
    """Closed taxonomy of MCP-call outcomes recorded by the audit logger."""

    ALLOWED = "allowed"
    DENIED = "denied"
    ERROR = "error"


_DEFAULT_MAX_HASH_INPUT_BYTES: int = 64 * 1024


def _to_jsonable(value: Any) -> Any:
    """Convert ``value`` to a JSON-serialisable structure.

    Used purely for hashing — we never persist this output. Falls back to
    ``str(...)`` for unknown types so a malformed argument still produces a
    deterministic hash and the call is still audited.
    """
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, list | tuple):
        return [_to_jsonable(item) for item in value]
    if isinstance(value, Mapping):
        return {str(k): _to_jsonable(v) for k, v in value.items()}
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        try:
            return _to_jsonable(dump(mode="json"))
        except TypeError:
            return _to_jsonable(dump())
    return str(value)


def _hash_arguments(arguments: Mapping[str, object] | None) -> str:
    """Return SHA-256 hex of the canonical JSON of ``arguments``.

    Empty / ``None`` arguments hash to a fixed sentinel so an absent payload
    is still distinguishable from any structured payload.
    """
    if arguments is None or len(arguments) == 0:
        canonical = b"{}"
    else:
        try:
            jsonable = _to_jsonable(arguments)
            canonical = json.dumps(
                jsonable,
                sort_keys=True,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:  # pragma: no cover — defensive
            _logger.warning(
                "mcp.audit.arguments_hash.encode_failed",
                extra={"error_class": type(exc).__name__},
            )
            canonical = repr(arguments).encode("utf-8", errors="replace")
    if len(canonical) > _DEFAULT_MAX_HASH_INPUT_BYTES:
        canonical = canonical[:_DEFAULT_MAX_HASH_INPUT_BYTES]
    return hashlib.sha256(canonical).hexdigest()


def _coerce_uuid(value: str | UUID) -> UUID:
    if isinstance(value, UUID):
        return value
    return UUID(str(value))


def _outcome_to_event_type(outcome: MCPCallOutcome) -> AuditEventType:
    if outcome is MCPCallOutcome.ALLOWED:
        return AuditEventType.PREFLIGHT_PASS
    return AuditEventType.PREFLIGHT_DENY


class MCPAuditLogger:
    """Front door for emitting MCP-specific audit events.

    Wraps a shared :class:`AuditLogger` (the same instance used by the
    policy plane) so the resulting hash chain is unified across HTTP API,
    sandbox, and MCP traffic.
    """

    def __init__(self, audit_logger: AuditLogger) -> None:
        self._audit_logger = audit_logger

    @property
    def audit_logger(self) -> AuditLogger:
        return self._audit_logger

    def record_tool_call(
        self,
        *,
        tool_name: str,
        tenant_id: str | UUID,
        outcome: MCPCallOutcome,
        actor_id: str | UUID | None = None,
        scan_id: str | UUID | None = None,
        arguments: Mapping[str, object] | None = None,
        failure_summary: str | None = None,
        extra_payload: Mapping[str, object] | None = None,
    ) -> AuditEvent:
        """Emit an audit event for an MCP tool / resource / prompt call.

        Returns the materialised :class:`AuditEvent` so the caller can echo
        the event id back to the MCP client (handy for post-mortem audits).
        """
        if not tool_name:
            raise ValueError("tool_name must be a non-empty string")
        if outcome is MCPCallOutcome.ERROR and failure_summary is None:
            failure_summary = "mcp_internal_error"

        payload: dict[str, object] = {
            "actor": _MCP_ACTOR_TAG,
            "tool_name": tool_name,
            "arguments_hash": _hash_arguments(arguments),
            "outcome": outcome.value,
        }
        if extra_payload:
            for key, value in extra_payload.items():
                if not isinstance(key, str):
                    continue
                if key in {"actor", "tool_name", "arguments_hash", "outcome"}:
                    continue
                payload[key] = value

        event = self._audit_logger.emit(
            event_type=_outcome_to_event_type(outcome),
            tenant_id=_coerce_uuid(tenant_id),
            scan_id=_coerce_uuid(scan_id) if scan_id is not None else None,
            actor_id=_coerce_uuid(actor_id) if actor_id is not None else None,
            decision_allowed=outcome is MCPCallOutcome.ALLOWED,
            failure_summary=failure_summary,
            payload=payload,
        )
        _logger.info(
            "mcp.audit.tool_call",
            extra={
                "tool_name": tool_name,
                "outcome": outcome.value,
                "tenant_id": str(tenant_id),
                "audit_event_id": str(event.event_id),
            },
        )
        return event


def make_default_audit_logger() -> MCPAuditLogger:
    """Construct an in-memory audit logger for stdio mode / tests.

    Production deployments should swap in a Postgres-backed
    :class:`~src.policy.audit.AuditSink` via dependency injection (the MCP
    server's startup hook accepts a custom logger).
    """
    return MCPAuditLogger(AuditLogger(InMemoryAuditSink()))


__all__ = [
    "MCPAuditLogger",
    "MCPCallOutcome",
    "make_default_audit_logger",
]
