"""Quick audit events (QUICK-009). Secrets are redacted before emit/log.

Lives in ``src.quick`` so emit paths cannot cycle through
``src.orchestration`` (handlers → cancellation). ``scan_events`` re-exports
the same API.
"""

from __future__ import annotations

import logging
import re
import threading
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Final

logger = logging.getLogger(__name__)

QUICK_AUDIT_EVENT_TYPES: Final[frozenset[str]] = frozenset(
    {
        "quick.create",
        "quick.policy",
        "quick.plan",
        "quick.revision",
        "quick.tool",
        "quick.cancel",
        "quick.ai_route",
        "quick.prompt_model_version",
        "quick.report",
    }
)

REDACTION_PLACEHOLDER: Final[str] = "[REDACTED]"

_SECRET_KEY_TOKENS: Final[frozenset[str]] = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "authorization",
        "cookie",
        "set-cookie",
        "credential",
        "credentials",
        "private_key",
        "access_key",
        "refresh_token",
        "session",
        "bearer",
        "jwt",
        "x-api-key",
        "auth",
        "authenticated_context",
        "authenticated_context_secret",
    }
)
_SECRET_KEY_RE: Final[re.Pattern[str]] = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|authorization|cookie|credential|bearer|jwt)",
    re.IGNORECASE,
)
_TOKEN_VALUE_RE: Final[re.Pattern[str]] = re.compile(
    r"^(bearer|basic)\s+\S+",
    re.IGNORECASE,
)

_AUDIT_LOCK = threading.Lock()
_QUICK_AUDIT_EVENTS: list[dict[str, Any]] = []
_QUICK_AUDIT_CAP: Final[int] = 256


def _key_is_secret(key: str) -> bool:
    lowered = key.strip().lower().replace("-", "_")
    if lowered in _SECRET_KEY_TOKENS:
        return True
    return bool(_SECRET_KEY_RE.search(lowered))


def redact_quick_audit_payload(value: Any) -> Any:
    """Drop/redact secret keys and token-shaped strings. Never raises."""
    try:
        if isinstance(value, Mapping):
            cleaned: dict[str, Any] = {}
            for raw_key, raw_val in value.items():
                key = str(raw_key)
                if _key_is_secret(key):
                    cleaned[key] = REDACTION_PLACEHOLDER
                    continue
                cleaned[key] = redact_quick_audit_payload(raw_val)
            return cleaned
        if isinstance(value, list | tuple):
            return [redact_quick_audit_payload(item) for item in value]
        if isinstance(value, str):
            if _TOKEN_VALUE_RE.match(value.strip()):
                return REDACTION_PLACEHOLDER
            return value
        if isinstance(value, bytes):
            return redact_quick_audit_payload(value.decode("utf-8", errors="replace"))
        return value
    except Exception:  # noqa: BLE001 — redaction must never break emit
        return REDACTION_PLACEHOLDER


def reset_quick_audit_events() -> None:
    """Clear the in-memory audit sink — tests only."""
    with _AUDIT_LOCK:
        _QUICK_AUDIT_EVENTS.clear()


def get_quick_audit_events() -> list[dict[str, Any]]:
    with _AUDIT_LOCK:
        return list(_QUICK_AUDIT_EVENTS)


def emit_quick_audit_event(
    event_type: str,
    *,
    scan_id: str,
    tenant_id: str = "",
    payload: Mapping[str, Any] | None = None,
    message: str = "",
    phase: str = "",
) -> dict[str, Any]:
    """Emit a Quick audit event with secrets redacted. Fail-open."""
    kind = (event_type or "").strip()
    if kind not in QUICK_AUDIT_EVENT_TYPES:
        kind = "quick.tool"
    redacted = redact_quick_audit_payload(dict(payload or {}))
    if not isinstance(redacted, dict):
        redacted = {}
    event = {
        "event_type": kind,
        "scan_id": scan_id,
        "tenant_id": tenant_id,
        "phase": phase,
        "message": message,
        "data": redacted,
        "timestamp": datetime.now(UTC).isoformat(),
    }
    try:
        logger.info(
            kind,
            extra={
                "event": kind,
                "scan_id": scan_id,
                "phase": phase,
                "audit": redacted,
            },
        )
    except Exception:  # noqa: BLE001 — logging must never break emit
        logger.debug("quick_audit.log_failed", extra={"event": "quick_audit.log_failed"})
    try:
        with _AUDIT_LOCK:
            _QUICK_AUDIT_EVENTS.append(event)
            overflow = len(_QUICK_AUDIT_EVENTS) - _QUICK_AUDIT_CAP
            if overflow > 0:
                del _QUICK_AUDIT_EVENTS[:overflow]
    except Exception:  # noqa: BLE001 — sink must never break emit
        logger.debug("quick_audit.sink_failed", extra={"event": "quick_audit.sink_failed"})
    return event


__all__ = [
    "QUICK_AUDIT_EVENT_TYPES",
    "REDACTION_PLACEHOLDER",
    "emit_quick_audit_event",
    "get_quick_audit_events",
    "redact_quick_audit_payload",
    "reset_quick_audit_events",
]
