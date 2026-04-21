"""Unit tests for :mod:`src.mcp.audit_logger`.

The MCP audit logger is the single source of truth for the trail every
MCP tool / resource invocation leaves. The tests below assert:

* Every call records an ``actor=mcp_client`` payload field.
* ``arguments_hash`` is deterministic, canonical JSON SHA-256, never the raw
  arguments themselves (so secrets passed in free-text fields stay out of
  the audit row).
* Allowed / denied / errored outcomes route to the right
  :class:`AuditEventType` (``preflight.pass`` vs ``preflight.deny``).
* The wrapper's ``record_tool_call`` is idempotent in the sense that two
  identical payloads hash identically — important so audit-chain replay
  can deduplicate without re-running the code path.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from src.mcp.audit_logger import (
    MCPAuditLogger,
    MCPCallOutcome,
    _hash_arguments,
    _to_jsonable,
    make_default_audit_logger,
)
from src.policy.audit import AuditEventType


def _canonical_sha256(payload: dict[str, object]) -> str:
    canonical = json.dumps(
        payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


# ---------------------------------------------------------------------------
# _to_jsonable
# ---------------------------------------------------------------------------


class TestToJsonable:
    def test_primitives_pass_through(self) -> None:
        assert _to_jsonable(None) is None
        assert _to_jsonable(True) is True
        assert _to_jsonable(42) == 42
        assert _to_jsonable("text") == "text"
        assert _to_jsonable(1.5) == 1.5

    def test_uuid_to_str(self) -> None:
        identifier = uuid4()
        assert _to_jsonable(identifier) == str(identifier)

    def test_datetime_normalised_to_utc_iso(self) -> None:
        moment = datetime(2026, 4, 19, 12, 0, 0, tzinfo=timezone.utc)
        result = _to_jsonable(moment)
        assert isinstance(result, str)
        assert result.endswith("+00:00")

    def test_nested_mapping(self) -> None:
        nested = {"outer": {"inner": uuid4(), "list": [1, 2, 3]}}
        result = _to_jsonable(nested)
        assert isinstance(result, dict)
        assert isinstance(result["outer"]["inner"], str)
        assert result["outer"]["list"] == [1, 2, 3]

    def test_unknown_type_falls_back_to_repr(self) -> None:
        class Custom:
            def __repr__(self) -> str:
                return "<Custom>"

        assert _to_jsonable(Custom()) == "<Custom>"


# ---------------------------------------------------------------------------
# _hash_arguments
# ---------------------------------------------------------------------------


class TestHashArguments:
    def test_empty_args_stable_sentinel(self) -> None:
        empty_hash = _hash_arguments({})
        none_hash = _hash_arguments(None)
        assert empty_hash == none_hash
        assert empty_hash == hashlib.sha256(b"{}").hexdigest()

    def test_canonical_order(self) -> None:
        a = _hash_arguments({"a": 1, "b": 2})
        b = _hash_arguments({"b": 2, "a": 1})
        assert a == b

    def test_sensitive_values_never_in_hash_input_metadata(self) -> None:
        token = "super-secret-token-XYZ"
        result_hash = _hash_arguments({"token": token})
        assert token not in result_hash
        assert len(result_hash) == 64

    def test_oversized_payload_truncated_but_hashable(self) -> None:
        big = {"k": "x" * 200_000}
        digest = _hash_arguments(big)
        assert len(digest) == 64

    def test_uuid_argument_normalised(self) -> None:
        sub_id = uuid4()
        a = _hash_arguments({"id": sub_id})
        b = _hash_arguments({"id": str(sub_id)})
        assert a == b


# ---------------------------------------------------------------------------
# MCPAuditLogger
# ---------------------------------------------------------------------------


class TestMCPAuditLogger:
    def test_make_default_returns_logger(self) -> None:
        logger = make_default_audit_logger()
        assert isinstance(logger, MCPAuditLogger)
        assert logger.audit_logger is not None

    def test_record_tool_call_emits_allowed_event(
        self, audit_logger: MCPAuditLogger, tenant_id: str
    ) -> None:
        event = audit_logger.record_tool_call(
            tool_name="scan.create",
            tenant_id=tenant_id,
            outcome=MCPCallOutcome.ALLOWED,
            arguments={"target": "example.com"},
        )
        assert event.event_type == AuditEventType.PREFLIGHT_PASS
        assert event.decision_allowed is True
        assert event.payload["actor"] == "mcp_client"
        assert event.payload["tool_name"] == "scan.create"
        assert event.payload["outcome"] == "allowed"
        assert event.payload["arguments_hash"] == _hash_arguments(
            {"target": "example.com"}
        )

    def test_record_tool_call_emits_denied_event(
        self, audit_logger: MCPAuditLogger, tenant_id: str
    ) -> None:
        event = audit_logger.record_tool_call(
            tool_name="scan.create",
            tenant_id=tenant_id,
            outcome=MCPCallOutcome.DENIED,
            failure_summary="mcp_scope_violation",
        )
        assert event.event_type == AuditEventType.PREFLIGHT_DENY
        assert event.decision_allowed is False
        assert event.failure_summary == "mcp_scope_violation"

    def test_record_tool_call_emits_error_event(
        self, audit_logger: MCPAuditLogger, tenant_id: str
    ) -> None:
        event = audit_logger.record_tool_call(
            tool_name="scan.create",
            tenant_id=tenant_id,
            outcome=MCPCallOutcome.ERROR,
        )
        assert event.event_type == AuditEventType.PREFLIGHT_DENY
        assert event.failure_summary == "mcp_internal_error"

    def test_empty_tool_name_rejected(
        self, audit_logger: MCPAuditLogger, tenant_id: str
    ) -> None:
        with pytest.raises(ValueError, match="non-empty"):
            audit_logger.record_tool_call(
                tool_name="",
                tenant_id=tenant_id,
                outcome=MCPCallOutcome.ALLOWED,
            )

    def test_extra_payload_does_not_overwrite_canonical_keys(
        self, audit_logger: MCPAuditLogger, tenant_id: str
    ) -> None:
        event = audit_logger.record_tool_call(
            tool_name="scan.status",
            tenant_id=tenant_id,
            outcome=MCPCallOutcome.ALLOWED,
            arguments={"scan_id": "abc"},
            extra_payload={
                "actor": "EVIL",
                "tool_name": "EVIL",
                "outcome": "EVIL",
                "arguments_hash": "EVIL",
                "scan_id": "abc",
            },
        )
        assert event.payload["actor"] == "mcp_client"
        assert event.payload["tool_name"] == "scan.status"
        assert event.payload["outcome"] == "allowed"
        assert event.payload["arguments_hash"] != "EVIL"
        assert event.payload["scan_id"] == "abc"

    def test_uuid_strings_accepted_for_tenant(
        self, audit_logger: MCPAuditLogger
    ) -> None:
        tenant_uuid = uuid4()
        event = audit_logger.record_tool_call(
            tool_name="scan.status",
            tenant_id=str(tenant_uuid),
            outcome=MCPCallOutcome.ALLOWED,
        )
        assert event.tenant_id == tenant_uuid

    def test_invalid_tenant_uuid_raises(self, audit_logger: MCPAuditLogger) -> None:
        with pytest.raises(ValueError):
            audit_logger.record_tool_call(
                tool_name="scan.status",
                tenant_id="not-a-uuid",
                outcome=MCPCallOutcome.ALLOWED,
            )

    def test_audit_chain_grows_monotonically(
        self, audit_logger: MCPAuditLogger, tenant_id: str
    ) -> None:
        e1 = audit_logger.record_tool_call(
            tool_name="scan.status",
            tenant_id=tenant_id,
            outcome=MCPCallOutcome.ALLOWED,
        )
        e2 = audit_logger.record_tool_call(
            tool_name="scan.status",
            tenant_id=tenant_id,
            outcome=MCPCallOutcome.ALLOWED,
        )
        assert e1.event_id != e2.event_id
        assert e2.prev_event_hash == e1.event_hash


class TestOutcomeTaxonomy:
    def test_outcome_values(self) -> None:
        assert {o.value for o in MCPCallOutcome} == {
            "allowed",
            "denied",
            "error",
        }
