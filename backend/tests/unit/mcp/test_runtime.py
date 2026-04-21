"""Unit tests for :mod:`src.mcp.tools._runtime`.

The ``run_tool`` wrapper is the only place where MCP tools talk to the
audit logger and convert internal exceptions into the closed-taxonomy
:class:`MCPError` hierarchy. These tests assert:

* Allowed calls emit ``preflight.pass`` and the result carries the audit
  event id.
* MCP errors raised by the body propagate untouched but produce a
  ``preflight.deny`` audit row with a closed-taxonomy failure summary.
* Unknown exceptions are wrapped in :class:`UpstreamServiceError` and emit
  an ``error`` audit row — never a raw stack trace.
* Pydantic validation errors map to ``mcp_validation_error``.
* Internal status codes feed the metric whitelist via the
  ``_INTERNAL_TO_METRIC_STATUS`` mapping table.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from pydantic import BaseModel, ConfigDict, Field, StrictStr

from src.core.observability import _MCP_STATUSES  # type: ignore[attr-defined]
from src.mcp.audit_logger import MCPAuditLogger
from src.mcp.auth import MCPAuthContext
from src.mcp.context import MCPCallContext, set_audit_logger, set_auth_override
from src.mcp.exceptions import (
    AuthenticationError,
    ResourceNotFoundError,
    UpstreamServiceError,
    ValidationError,
)
from src.mcp.tools._runtime import (
    _INTERNAL_TO_METRIC_STATUS,
    _classify_mcp_client,
    run_tool,
)
from src.policy.audit import AuditEventType


class _Payload(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    target: StrictStr = Field(min_length=1, max_length=64)


class _Result(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    target: StrictStr
    audit_event_id: StrictStr | None = None


def _drain(audit_logger: MCPAuditLogger) -> list[Any]:
    sink = audit_logger.audit_logger.sink
    events: list[Any] = []
    for tenant_events in sink._events.values():  # type: ignore[attr-defined]
        events.extend(tenant_events)
    events.sort(key=lambda e: e.occurred_at)
    return events


@pytest.fixture()
def call_payload() -> _Payload:
    return _Payload(target="example.com")


class TestRunToolHappyPath:
    def test_allowed_returns_result_with_audit_id(
        self,
        auth_ctx: MCPAuthContext,
        audit_logger: MCPAuditLogger,
        call_payload: _Payload,
    ) -> None:
        set_auth_override(auth_ctx)
        set_audit_logger(audit_logger)

        async def body(call: MCPCallContext) -> _Result:
            return _Result(target=call_payload.target)

        result = asyncio.run(
            run_tool(
                tool_name="test.echo",
                payload=call_payload,
                ctx=None,
                body=body,
            )
        )
        assert result.target == "example.com"
        assert result.audit_event_id is not None
        events = _drain(audit_logger)
        assert len(events) == 1
        assert events[0].event_type == AuditEventType.PREFLIGHT_PASS
        assert events[0].payload["tool_name"] == "test.echo"
        assert events[0].payload["outcome"] == "allowed"

    def test_extra_audit_payload_attached(
        self,
        auth_ctx: MCPAuthContext,
        audit_logger: MCPAuditLogger,
        call_payload: _Payload,
    ) -> None:
        set_auth_override(auth_ctx)
        set_audit_logger(audit_logger)

        async def body(call: MCPCallContext) -> _Result:
            return _Result(target="x")

        asyncio.run(
            run_tool(
                tool_name="test.echo",
                payload=call_payload,
                ctx=None,
                body=body,
                extra_audit_payload={"scan_id": "scan-1234"},
            )
        )
        events = _drain(audit_logger)
        assert events[-1].payload["scan_id"] == "scan-1234"


class TestRunToolMCPError:
    def test_mcp_error_propagates_with_deny_audit(
        self,
        auth_ctx: MCPAuthContext,
        audit_logger: MCPAuditLogger,
        call_payload: _Payload,
    ) -> None:
        set_auth_override(auth_ctx)
        set_audit_logger(audit_logger)

        async def body(call: MCPCallContext) -> _Result:
            raise ResourceNotFoundError("scan abc not found")

        with pytest.raises(ResourceNotFoundError) as exc_info:
            asyncio.run(
                run_tool(
                    tool_name="test.lookup",
                    payload=call_payload,
                    ctx=None,
                    body=body,
                )
            )
        assert exc_info.value.code == "mcp_resource_not_found"
        events = _drain(audit_logger)
        assert events[-1].event_type == AuditEventType.PREFLIGHT_DENY
        assert events[-1].failure_summary == "mcp_resource_not_found"

    def test_authentication_error_skips_body_and_audit(
        self,
        audit_logger: MCPAuditLogger,
        call_payload: _Payload,
    ) -> None:
        set_auth_override(None)
        set_audit_logger(audit_logger)

        async def body(call: MCPCallContext) -> _Result:  # pragma: no cover
            raise AssertionError("body should not run")

        # Force HTTP transport so stdio fallback is disabled
        import os

        os.environ["MCP_REQUIRE_AUTH"] = "true"
        try:
            with pytest.raises(AuthenticationError):
                asyncio.run(
                    run_tool(
                        tool_name="test.lookup",
                        payload=call_payload,
                        ctx=None,
                        body=body,
                    )
                )
        finally:
            os.environ.pop("MCP_REQUIRE_AUTH", None)
        # No event recorded because we never made it past auth
        assert _drain(audit_logger) == []


class TestRunToolPydanticValidationError:
    def test_validation_error_maps_and_audits(
        self,
        auth_ctx: MCPAuthContext,
        audit_logger: MCPAuditLogger,
        call_payload: _Payload,
    ) -> None:
        set_auth_override(auth_ctx)
        set_audit_logger(audit_logger)

        async def body(call: MCPCallContext) -> _Result:
            _Payload(target="")  # raises PydValid
            raise AssertionError("unreachable")

        with pytest.raises(ValidationError) as exc_info:
            asyncio.run(
                run_tool(
                    tool_name="test.lookup",
                    payload=call_payload,
                    ctx=None,
                    body=body,
                )
            )
        assert exc_info.value.code == "mcp_validation_error"
        events = _drain(audit_logger)
        assert events[-1].failure_summary == "mcp_validation_error"


class TestRunToolUnknownException:
    def test_random_exception_wrapped_in_upstream_error(
        self,
        auth_ctx: MCPAuthContext,
        audit_logger: MCPAuditLogger,
        call_payload: _Payload,
    ) -> None:
        set_auth_override(auth_ctx)
        set_audit_logger(audit_logger)

        async def body(call: MCPCallContext) -> _Result:
            raise RuntimeError("internal: secret SQL = 'SELECT * FROM users'")

        with pytest.raises(UpstreamServiceError) as exc_info:
            asyncio.run(
                run_tool(
                    tool_name="test.lookup",
                    payload=call_payload,
                    ctx=None,
                    body=body,
                )
            )
        # The leaked SQL never reaches the LLM client
        assert "secret SQL" not in exc_info.value.message
        assert "SELECT" not in exc_info.value.message
        assert exc_info.value.code == "mcp_upstream_error"

        events = _drain(audit_logger)
        assert events[-1].event_type == AuditEventType.PREFLIGHT_DENY
        assert events[-1].failure_summary == "mcp_internal_error"


class TestRunToolArgumentsHashing:
    def test_arguments_hash_is_recorded(
        self,
        auth_ctx: MCPAuthContext,
        audit_logger: MCPAuditLogger,
        call_payload: _Payload,
    ) -> None:
        set_auth_override(auth_ctx)
        set_audit_logger(audit_logger)

        async def body(call: MCPCallContext) -> _Result:
            return _Result(target="ok")

        asyncio.run(
            run_tool(
                tool_name="test.echo",
                payload=call_payload,
                ctx=None,
                body=body,
            )
        )
        events = _drain(audit_logger)
        # Hash present and 64-char hex
        h = events[-1].payload["arguments_hash"]
        assert isinstance(h, str)
        assert len(h) == 64

    def test_secret_in_arg_not_in_audit(
        self,
        auth_ctx: MCPAuthContext,
        audit_logger: MCPAuditLogger,
    ) -> None:
        set_auth_override(auth_ctx)
        set_audit_logger(audit_logger)
        secret_payload = _Payload(target="reallysecretX")

        async def body(call: MCPCallContext) -> _Result:
            return _Result(target="ok")

        asyncio.run(
            run_tool(
                tool_name="test.echo",
                payload=secret_payload,
                ctx=None,
                body=body,
            )
        )
        # The audit row only carries the SHA-256 of the canonical args
        events = _drain(audit_logger)
        assert "reallysecretX" not in events[-1].model_dump_json()


class TestRunToolMetricMapping:
    """Lock the contract between ``run_tool`` internal status codes and the
    Prometheus metric whitelist (:data:`src.core.observability._MCP_STATUSES`).

    Drift between these tables silently degrades metric labels to ``_other``
    which destroys per-status dashboards, so we assert it from both sides.
    """

    def test_every_mapping_target_is_in_metric_whitelist(self) -> None:
        for internal, metric in _INTERNAL_TO_METRIC_STATUS.items():
            assert metric in _MCP_STATUSES, (
                f"internal status {internal!r} maps to {metric!r} "
                f"which is NOT in _MCP_STATUSES whitelist"
            )

    @pytest.mark.parametrize(
        "internal,expected_metric",
        [
            ("ok", "success"),
            ("denied", "forbidden"),
            ("unauthorized", "unauthorized"),
            ("forbidden", "forbidden"),
            ("rate_limited", "rate_limited"),
            ("validation_error", "validation_error"),
            ("error", "error"),
        ],
    )
    def test_known_internal_statuses_map_to_whitelisted_metric(
        self, internal: str, expected_metric: str
    ) -> None:
        assert _INTERNAL_TO_METRIC_STATUS[internal] == expected_metric

    @pytest.mark.parametrize(
        "client_id,expected",
        [
            (None, "generic"),
            ("", "generic"),
            ("anthropic-claude-3.5", "anthropic"),
            ("Claude/Sonnet", "anthropic"),
            ("openai-python-1.42", "openai"),
            ("gpt-4o-mini", "openai"),
            ("custom-llm-client/0.1", "generic"),
        ],
    )
    def test_classify_mcp_client_buckets_to_whitelist(
        self, client_id: str | None, expected: str
    ) -> None:
        assert _classify_mcp_client(client_id) == expected
