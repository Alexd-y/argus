"""Request-scoped execution mode for LLM / tool callers that omit the argument.

Handlers stamp mode onto scan options and this contextvar so nested
``call_llm_unified`` sites inherit LAB vs production without guessing.
"""

from __future__ import annotations

from contextvars import ContextVar, Token
from typing import Any

from src.execution_mode.mode import (
    ExecutionMode,
    coerce_legacy_mode_field,
    parse_execution_mode,
)

_execution_mode_var: ContextVar[ExecutionMode | None] = ContextVar(
    "argus_execution_mode",
    default=None,
)
_scan_options_var: ContextVar[dict[str, Any] | None] = ContextVar(
    "argus_scan_options",
    default=None,
)

_VALID_MODE_VALUES: frozenset[str] = frozenset(m.value for m in ExecutionMode)


def get_runtime_execution_mode() -> ExecutionMode | None:
    """Return the bound execution mode, or None if nothing was stamped."""
    return _execution_mode_var.get()


def get_runtime_scan_options() -> dict[str, Any] | None:
    """Return the bound scan options dict, or None."""
    return _scan_options_var.get()


def set_runtime_execution_mode(mode: ExecutionMode | str | None) -> Token:
    """Bind execution mode for the current task/request context."""
    resolved: ExecutionMode | None
    if mode is None or mode == "":
        resolved = None
    elif isinstance(mode, ExecutionMode):
        resolved = mode
    else:
        raw = str(getattr(mode, "value", mode)).strip().lower()
        resolved = ExecutionMode(raw) if raw in _VALID_MODE_VALUES else None
    return _execution_mode_var.set(resolved)


def set_runtime_scan_options(options: dict[str, Any] | None) -> Token:
    """Bind scan options for nested LLM callers that forgot execution_mode."""
    return _scan_options_var.set(options if isinstance(options, dict) else None)


def reset_runtime_execution_mode(token: Token) -> None:
    _execution_mode_var.reset(token)


def reset_runtime_scan_options(token: Token) -> None:
    _scan_options_var.reset(token)


def clear_runtime_execution_context() -> None:
    """Drop bound mode/options — tests and task teardown only."""
    _execution_mode_var.set(None)
    _scan_options_var.set(None)


def peek_execution_mode_from_options(options: dict[str, Any] | None) -> ExecutionMode | None:
    """Return a valid ExecutionMode from scan/phase options, or None if absent.

    Ignores scan-depth aliases such as ``quick`` / ``deep`` stored under ``mode``.
    ``ExecutionMode.QUICK`` is accepted only from ``execution_mode`` or
    ``execution_mode_context.mode``.
    """
    if not isinstance(options, dict):
        return None
    candidates: list[Any] = [options.get("execution_mode")]
    ctx = options.get("execution_mode_context")
    if isinstance(ctx, dict):
        candidates.append(ctx.get("mode"))
    for raw in candidates:
        coerced = _coerce_domain_mode(raw)
        if coerced is not None:
            return coerced
    return coerce_legacy_mode_field(options.get("mode"))


def bind_phase_execution_mode(
    mode: ExecutionMode | str | None,
    options: dict[str, Any] | None = None,
) -> None:
    """Stamp contextvars after a phase attaches ``execution_mode_context``."""
    resolved = _coerce_domain_mode(mode)
    if resolved is None:
        resolved = peek_execution_mode_from_options(options)
    set_runtime_execution_mode(resolved)
    if isinstance(options, dict):
        set_runtime_scan_options(options)


def resolve_execution_mode_with_fallback(
    execution_mode: ExecutionMode | str | None = None,
    scan_options: dict[str, Any] | None = None,
) -> tuple[ExecutionMode, bool]:
    """Resolve mode from explicit arg, scan options, then contextvar.

    Returns ``(mode, missing)`` where ``missing`` is True when nothing supplied
    a valid mode and the caller should default to production.
    """
    explicit = _coerce_domain_mode(execution_mode)
    if explicit is not None:
        return explicit, False
    from_options = peek_execution_mode_from_options(scan_options)
    if from_options is not None:
        return from_options, False
    bound = get_runtime_execution_mode()
    if bound is not None:
        return bound, False
    from_bound_opts = peek_execution_mode_from_options(get_runtime_scan_options())
    if from_bound_opts is not None:
        return from_bound_opts, False
    return parse_execution_mode(None), True


def _coerce_domain_mode(raw: Any) -> ExecutionMode | None:
    if raw is None or raw == "":
        return None
    if isinstance(raw, ExecutionMode):
        return raw
    text = str(getattr(raw, "value", raw)).strip().lower()
    if text not in _VALID_MODE_VALUES:
        return None
    return ExecutionMode(text)
