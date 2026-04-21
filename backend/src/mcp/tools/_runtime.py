"""Common runtime plumbing shared by every MCP tool.

Wraps each tool body in:

* Authentication / tenant context resolution.
* Pre-call audit log entry (``decision_allowed=True``).
* Error mapping — every internal exception is converted to a closed-taxonomy
  :class:`src.mcp.exceptions.MCPError` and a matching DENY audit event so
  the LLM client never sees a raw stack trace.

Usage::

    @mcp.tool()
    async def my_tool(payload: MyInput, ctx: Context) -> MyOutput:
        async def body(call: MCPCallContext) -> MyOutput:
            return await do_work(payload)

        return await run_tool(
            tool_name="my.tool",
            payload=payload,
            ctx=ctx,
            body=body,
        )
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Mapping
from typing import Final, TypeVar

from pydantic import BaseModel, ValidationError as PydanticValidationError

from src.core.observability import (
    get_tracer,
    record_mcp_call,
    safe_set_span_attribute,
    tenant_hash,
)
from src.mcp.audit_logger import MCPCallOutcome
from src.mcp.context import (
    MCPCallContext,
    MCPContext,
    build_call_context,
    get_rate_limiter,
)
from src.mcp.exceptions import (
    AuthenticationError,
    AuthorizationError,
    MCPError,
    RateLimitedError,
    UpstreamServiceError,
    ValidationError,
)

_logger = logging.getLogger(__name__)
_tracer = get_tracer("argus.mcp")

T = TypeVar("T")


def _classify_mcp_client(client_id: str | None) -> str:
    """Bucket free-form ``client_id`` into the metric whitelist.

    The MCP metric whitelist (``_MCP_CLIENT_CLASSES`` in observability) only
    admits ``anthropic`` / ``openai`` / ``generic``. Any other classification
    (``google``, etc.) gets coerced to ``_other`` by the label guard, so
    bucketing into ``generic`` here keeps dashboards usable.
    """
    if not client_id:
        return "generic"
    cid = client_id.lower()
    if "anthropic" in cid or "claude" in cid:
        return "anthropic"
    if "openai" in cid or "gpt" in cid:
        return "openai"
    return "generic"


#: Map ``run_tool`` internal status terminology onto the MCP metric whitelist
#: (``_MCP_STATUSES`` in :mod:`src.core.observability`). Anything we forget
#: to map degrades to ``_other`` — that's intentional but the catalogue here
#: should stay exhaustive.
_INTERNAL_TO_METRIC_STATUS: Final[Mapping[str, str]] = {
    "ok": "success",
    "denied": "forbidden",  # legacy fallback; current code paths emit explicit values
    "unauthorized": "unauthorized",
    "forbidden": "forbidden",
    "rate_limited": "rate_limited",
    "validation_error": "validation_error",
    "error": "error",
}


def _emit_mcp_metric(
    *, tool_name: str, status: str, client_id: str | None
) -> None:
    """Emit ``argus_mcp_calls_total`` defensively (never raises)."""
    metric_status = _INTERNAL_TO_METRIC_STATUS.get(status, status)
    try:
        record_mcp_call(
            tool=tool_name,
            status=metric_status,
            client_class=_classify_mcp_client(client_id),
        )
    except Exception:  # pragma: no cover — defensive
        _logger.debug("mcp.runtime.metrics_emit_failed", exc_info=True)


def _serialise_for_audit(payload: object) -> Mapping[str, object]:
    if payload is None:
        return {}
    if isinstance(payload, BaseModel):
        try:
            dumped = payload.model_dump(mode="json")
        except (TypeError, AttributeError):
            dumped = payload.model_dump()
        return dumped if isinstance(dumped, dict) else {"value": dumped}
    if isinstance(payload, Mapping):
        return {str(k): v for k, v in payload.items()}
    return {"value": str(payload)}


def _classify_failure(exc: Exception) -> tuple[str, str]:
    """Return (audit_failure_summary, mcp_error_message)."""
    if isinstance(exc, AuthenticationError):
        return "mcp_auth_unauthenticated", str(exc.message)
    if isinstance(exc, AuthorizationError):
        return "mcp_auth_forbidden", str(exc.message)
    if isinstance(exc, MCPError):
        return exc.code, str(exc.message)
    if isinstance(exc, PydanticValidationError):
        return "mcp_validation_error", "Invalid arguments for the requested tool."
    return "mcp_internal_error", "Internal MCP error; see server logs."


async def run_tool(
    *,
    tool_name: str,
    payload: BaseModel,
    ctx: MCPContext | None,
    body: Callable[[MCPCallContext], Awaitable[T]],
    extra_audit_payload: Mapping[str, object] | None = None,
) -> T:
    """Wrap a tool body with auth / audit / error mapping.

    Args:
        tool_name: Stable MCP tool identifier (e.g. ``scan.create``). Used
            for the audit row's ``tool_name`` field.
        payload: Validated input model — hashed (not stored) into the audit
            row's ``arguments_hash`` field.
        ctx: FastMCP per-call context (may be ``None`` in unit tests).
        body: Async callable that performs the actual work; it receives the
            resolved :class:`MCPCallContext`.
        extra_audit_payload: Optional structured payload merged into the
            audit row (e.g. ``{"scan_id": ...}``). Subject to the audit
            payload shape guard in :mod:`src.policy.audit`.
    """
    arguments = _serialise_for_audit(payload)
    extras = dict(extra_audit_payload or {})

    try:
        call = build_call_context(ctx)
    except AuthenticationError as exc:
        _emit_mcp_metric(tool_name=tool_name, status="unauthorized", client_id=None)
        _logger.warning(
            "mcp.tool.auth_failed",
            extra={"tool_name": tool_name, "code": exc.code},
        )
        raise

    client_id_str = (
        str(call.auth.user_id) if call.auth.user_id else "anonymous"
    )

    span_ctx = _tracer.start_as_current_span("mcp.tool")
    span = span_ctx.__enter__()
    safe_set_span_attribute(span, "argus.tool", tool_name)
    safe_set_span_attribute(span, "tenant.hash", tenant_hash(call.auth.tenant_id))
    final_status: str = "error"
    try:
        limiter = get_rate_limiter()
        if limiter is not None:
            try:
                await limiter.acquire(  # type: ignore[attr-defined]
                    client_id=client_id_str,
                    tenant_id=str(call.auth.tenant_id),
                    tokens=1,
                )
            except RateLimitedError as exc:
                final_status = "rate_limited"
                try:
                    call.audit.record_tool_call(
                        tool_name=tool_name,
                        tenant_id=call.auth.tenant_id,
                        actor_id=None,
                        outcome=MCPCallOutcome.DENIED,
                        arguments=arguments,
                        failure_summary=exc.code,
                        extra_payload=extras,
                    )
                except Exception:  # pragma: no cover — audit must never propagate
                    _logger.exception("mcp.audit.rate_limited_emit_failed")
                _logger.info(
                    "mcp.tool.rate_limited",
                    extra={
                        "tool_name": tool_name,
                        "tenant_id": call.auth.tenant_id,
                        "code": exc.code,
                    },
                )
                raise

        try:
            result = await body(call)
        except MCPError as exc:
            final_status = (
                "unauthorized"
                if isinstance(exc, AuthenticationError)
                else "forbidden"
                if isinstance(exc, AuthorizationError)
                else "error"
            )
            failure_summary, _ = _classify_failure(exc)
            try:
                call.audit.record_tool_call(
                    tool_name=tool_name,
                    tenant_id=call.auth.tenant_id,
                    actor_id=None,
                    outcome=MCPCallOutcome.DENIED,
                    arguments=arguments,
                    failure_summary=failure_summary,
                    extra_payload=extras,
                )
            except Exception:  # pragma: no cover — audit must never propagate
                _logger.exception("mcp.audit.deny_emit_failed")
            _logger.info(
                "mcp.tool.denied",
                extra={
                    "tool_name": tool_name,
                    "code": exc.code,
                    "tenant_id": call.auth.tenant_id,
                },
            )
            raise
        except PydanticValidationError as exc:
            final_status = "validation_error"
            try:
                call.audit.record_tool_call(
                    tool_name=tool_name,
                    tenant_id=call.auth.tenant_id,
                    actor_id=None,
                    outcome=MCPCallOutcome.DENIED,
                    arguments=arguments,
                    failure_summary="mcp_validation_error",
                    extra_payload=extras,
                )
            except Exception:  # pragma: no cover
                _logger.exception("mcp.audit.validation_emit_failed")
            _logger.info(
                "mcp.tool.validation_failed",
                extra={"tool_name": tool_name, "tenant_id": call.auth.tenant_id},
            )
            raise ValidationError(
                "Invalid arguments for the requested tool."
            ) from exc
        except Exception as exc:
            final_status = "error"
            try:
                call.audit.record_tool_call(
                    tool_name=tool_name,
                    tenant_id=call.auth.tenant_id,
                    actor_id=None,
                    outcome=MCPCallOutcome.ERROR,
                    arguments=arguments,
                    failure_summary="mcp_internal_error",
                    extra_payload=extras,
                )
            except Exception:  # pragma: no cover
                _logger.exception("mcp.audit.error_emit_failed")
            _logger.exception(
                "mcp.tool.unhandled_error",
                extra={"tool_name": tool_name, "tenant_id": call.auth.tenant_id},
            )
            raise UpstreamServiceError(
                "An internal error occurred while executing the tool."
            ) from exc

        final_status = "ok"
        try:
            event = call.audit.record_tool_call(
                tool_name=tool_name,
                tenant_id=call.auth.tenant_id,
                actor_id=None,
                outcome=MCPCallOutcome.ALLOWED,
                arguments=arguments,
                failure_summary=None,
                extra_payload=extras,
            )
            if (
                isinstance(result, BaseModel)
                and "audit_event_id" in type(result).model_fields
            ):
                try:
                    result = result.model_copy(
                        update={"audit_event_id": str(event.event_id)}
                    )
                except Exception:  # pragma: no cover — defensive
                    _logger.debug(
                        "mcp.tool.cannot_attach_audit_event", exc_info=True
                    )
        except Exception:  # pragma: no cover
            _logger.exception("mcp.audit.allow_emit_failed")
        return result
    finally:
        safe_set_span_attribute(span, "argus.status", final_status)
        _emit_mcp_metric(
            tool_name=tool_name, status=final_status, client_id=client_id_str
        )
        try:
            span_ctx.__exit__(None, None, None)
        except Exception:  # pragma: no cover — defensive
            _logger.debug("mcp.runtime.span_exit_failed", exc_info=True)


__all__ = ["run_tool"]
