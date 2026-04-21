"""ARG-041 — Structured JSON logging with OTel correlation + PII redaction.

The codebase logs through ``logging`` directly (no structlog) because the
operator surface is a single NDJSON stream consumed by Loki/CloudWatch.
This module wraps :mod:`pythonjsonlogger` with two composable filters:

* :class:`OTelTraceContextFilter` — pulls ``trace_id`` / ``span_id`` from
  the active OTel span and injects them into every record. The IDs match
  the OTLP exporter format (32-char hex trace_id, 16-char hex span_id) so
  Loki / Tempo can join logs ↔ traces in a single panel.
* :class:`SensitiveHeaderRedactor` — scans every record's ``args`` /
  ``extra`` payload for header-shaped strings (``Authorization``,
  ``Cookie``, ``X-Api-Key``, plus a small list of token-shaped keys) and
  replaces the value with ``"[REDACTED]"``. The processor is defence-in-
  depth — feature code should never log raw secrets in the first place,
  but tests and accidental ``print(headers)`` calls happen.

Public API:

* :func:`configure_logging()` — call once from FastAPI / Celery startup.
* :data:`SENSITIVE_HEADER_KEYS` — frozen set used by tests + middleware.
* :data:`REDACTION_PLACEHOLDER` — the literal string substituted in for
  any redacted value.

Backward compatibility:
* The function signature of ``configure_logging`` is preserved (no args).
* The behaviour when ``pythonjsonlogger`` is missing degrades to the
  legacy ``logging.basicConfig`` path — same as Cycle 4.
"""

from __future__ import annotations

import logging
import re
import sys
from collections.abc import Iterable
from typing import Any, Final

from src.core.config import settings

#: Header keys whose values are redacted on the way into JSON logs.
SENSITIVE_HEADER_KEYS: Final[frozenset[str]] = frozenset(
    {
        # HTTP authentication
        "authorization",
        "cookie",
        "set-cookie",
        "proxy-authorization",
        "x-api-key",
        "x-auth-token",
        "x-csrf-token",
        # ARGUS-internal
        "x-admin-key",
        "x-mcp-token",
    },
)

#: Substring patterns matched against the *value* (lowercase). When the
#: matched value belongs to one of the keys above, redaction is mandatory;
#: otherwise the pattern fires only when the surrounding key looks
#: token-shaped (defence-in-depth against accidental logging).
_TOKEN_VALUE_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"^bearer\s+\S+", re.IGNORECASE),
    re.compile(r"^basic\s+\S+", re.IGNORECASE),
)

REDACTION_PLACEHOLDER: Final[str] = "[REDACTED]"


# ---------------------------------------------------------------------------
# OTel correlation filter
# ---------------------------------------------------------------------------


class OTelTraceContextFilter(logging.Filter):
    """Inject ``trace_id`` / ``span_id`` from the active OTel span.

    The filter is a no-op when OTel is unavailable or no span is active —
    this keeps the cold path zero-overhead in dev where OTel is disabled.

    The injected fields use the OTLP-canonical names (``trace_id`` /
    ``span_id`` lowercased + lowercase hex) so Tempo's "Logs for trace"
    panel resolves them without translation.
    """

    _NULL_TRACE_ID: Final[str] = "0" * 32
    _NULL_SPAN_ID: Final[str] = "0" * 16

    def __init__(self) -> None:
        super().__init__()
        try:
            from opentelemetry import trace

            self._trace_module: Any | None = trace
        except ImportError:
            self._trace_module = None

    def filter(self, record: logging.LogRecord) -> bool:
        if self._trace_module is None:
            return True
        try:
            span = self._trace_module.get_current_span()
            if span is None:
                return True
            ctx = span.get_span_context()
            trace_id = format(ctx.trace_id, "032x") if ctx.trace_id else self._NULL_TRACE_ID
            span_id = format(ctx.span_id, "016x") if ctx.span_id else self._NULL_SPAN_ID
            if trace_id != self._NULL_TRACE_ID:
                record.trace_id = trace_id
                record.span_id = span_id
        except Exception:  # pragma: no cover — defensive
            pass
        return True


# ---------------------------------------------------------------------------
# Sensitive header redactor
# ---------------------------------------------------------------------------


def _is_sensitive_key(key: str) -> bool:
    return key.strip().lower() in SENSITIVE_HEADER_KEYS


def _redact_value(value: object) -> object:
    """Return a redacted copy of ``value`` if it looks like a secret string."""
    if not isinstance(value, str):
        return value
    lowered = value.strip().lower()
    if any(p.match(lowered) for p in _TOKEN_VALUE_PATTERNS):
        return REDACTION_PLACEHOLDER
    return value


def _redact_mapping(payload: dict[str, Any]) -> dict[str, Any]:
    """Return a NEW dict with sensitive keys / token-valued strings redacted."""
    out: dict[str, Any] = {}
    for key, value in payload.items():
        if _is_sensitive_key(key):
            out[key] = REDACTION_PLACEHOLDER
        elif isinstance(value, dict):
            out[key] = _redact_mapping(value)
        elif isinstance(value, (list, tuple)):
            out[key] = type(value)(
                _redact_mapping(v) if isinstance(v, dict) else _redact_value(v)
                for v in value
            )
        else:
            out[key] = _redact_value(value)
    return out


class SensitiveHeaderRedactor(logging.Filter):
    """Strip secret-bearing fields from ``record.__dict__`` before formatting.

    The filter walks two surfaces:

    1. The *extra* fields — anything attached via ``logger.info(msg, extra={...})``.
       Their dict lives on the record as direct attributes (the
       ``pythonjsonlogger`` formatter serialises them by name).
    2. ``record.args`` when it is a mapping or tuple — covers the
       ``logger.info("msg %(headers)s", {"headers": ...})`` pattern used
       by some legacy code paths.

    We never mutate the source dict — every redaction is performed on a
    shallow copy so threads / processes that share the dict are unaffected.
    """

    # Pre-defined LogRecord attribute names; never touch them so the formatter
    # keeps emitting them verbatim.
    _RESERVED_ATTRS: Final[frozenset[str]] = frozenset(
        {
            "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
            "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
            "created", "msecs", "relativeCreated", "thread", "threadName",
            "processName", "process", "trace_id", "span_id", "message", "asctime",
            "taskName",
        },
    )

    def filter(self, record: logging.LogRecord) -> bool:
        for attr_name in list(record.__dict__.keys()):
            if attr_name in self._RESERVED_ATTRS:
                continue
            value = record.__dict__[attr_name]
            if _is_sensitive_key(attr_name):
                record.__dict__[attr_name] = REDACTION_PLACEHOLDER
                continue
            if isinstance(value, dict):
                record.__dict__[attr_name] = _redact_mapping(value)
            elif isinstance(value, str):
                record.__dict__[attr_name] = _redact_value(value)

        if isinstance(record.args, dict):
            record.args = _redact_mapping(record.args)  # type: ignore[assignment]
        elif isinstance(record.args, tuple):
            record.args = tuple(
                _redact_mapping(v) if isinstance(v, dict) else _redact_value(v)
                for v in record.args
            )

        return True


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def _build_filters() -> Iterable[logging.Filter]:
    """Return the canonical filter chain (order matters: OTel before redact)."""
    return (OTelTraceContextFilter(), SensitiveHeaderRedactor())


def configure_logging() -> None:
    """Configure root logger with NDJSON formatter + OTel + redaction filters.

    Idempotent: the function clears any handlers it previously installed
    before re-installing the canonical chain so test code can call it
    multiple times safely.
    """
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    try:
        from pythonjsonlogger import jsonlogger

        handler.setFormatter(
            jsonlogger.JsonFormatter(
                "%(asctime)s %(name)s %(levelname)s %(message)s",
                timestamp=True,
            ),
        )
    except ImportError:  # pragma: no cover — pythonjsonlogger is a hard dep
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"),
        )
    for flt in _build_filters():
        handler.addFilter(flt)
    root.addHandler(handler)
    root.setLevel(getattr(logging, settings.log_level.upper(), logging.INFO))


__all__ = [
    "REDACTION_PLACEHOLDER",
    "SENSITIVE_HEADER_KEYS",
    "OTelTraceContextFilter",
    "SensitiveHeaderRedactor",
    "configure_logging",
]
