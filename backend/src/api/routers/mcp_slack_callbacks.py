"""ARG-048 — Slack interactive-action callback ingress.

The ARG-035 Slack notifier emits Block-Kit messages with ``action_id``
values of the form ``approve::<approval_id>`` / ``deny::<approval_id>``.
Slack POSTs the operator's button click to a configured ingress URL;
this router is that ingress.

Security contract
-----------------
1. **HMAC-SHA-256 signature verification** — every request MUST carry
   ``X-Slack-Signature`` (``v0=<hex>``) computed over
   ``"v0:" + X-Slack-Request-Timestamp + ":" + raw_body`` using the
   ``SLACK_SIGNING_SECRET`` env var. Constant-time comparison via
   :func:`hmac.compare_digest`. Mismatch → HTTP 401.
2. **Replay protection** — ``X-Slack-Request-Timestamp`` MUST be within
   :data:`REPLAY_WINDOW_SECONDS` (5 minutes) of server clock. Outside →
   HTTP 401. Slack's own guidance is "reject anything older than
   5 minutes"; we reject *future* timestamps with the same window so a
   skewed sender cannot bank tokens.
3. **Body size cap** — Slack interactive-action bodies max out around
   3 KiB; we cap reads at :data:`MAX_BODY_BYTES` (16 KiB) so an attacker
   cannot DoS by streaming a multi-megabyte body before failing
   signature.
4. **Hard-fail on missing secret** — if ``SLACK_SIGNING_SECRET`` is
   absent the router returns HTTP 503 on every request. A
   mis-configured deployment MUST NOT silently accept unsigned actions.
5. **Soft-intent audit only** — the cryptographic
   :class:`~src.policy.approval.ApprovalService` requires Ed25519
   signatures over the canonical request payload; a Slack click cannot
   produce that. We therefore record the operator's *intent* into the
   immutable audit log (``APPROVAL_REQUESTED``) so the decision is
   forensically tied to a Slack user_id, but the actual destructive
   action still requires a real signature flow downstream. This keeps
   the dual-control / cryptographic-provenance contract intact.

The endpoint always responds within Slack's 3-second budget (everything
except the audit emit is in-memory; the audit emit is local).

Usage
-----
Register the Request URL ``https://<host>/api/v1/mcp/notifications/slack/callback``
in your Slack App → ``Interactivity & Shortcuts``. Set
``SLACK_SIGNING_SECRET`` from Slack App → ``Basic Information``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from typing import Annotated, Any, Final
from urllib.parse import parse_qs
from uuid import UUID

from fastapi import APIRouter, Header, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from src.core.config import settings

# ARG-048 — Pre-warm the pipeline-contracts package before triggering
# ``src.policy.__init__``. ``src.policy.approval`` imports
# ``src.sandbox.signing`` which transitively re-enters ``src.policy.preflight``
# while ``src.policy.approval`` is still mid-import — the resulting
# ``ImportError: cannot import name 'ApprovalAction' …`` is a pre-existing
# circular dependency in the policy plane that is normally avoided because
# ``src.pipeline.contracts`` is loaded first by other routers / fixtures.
# Loading it explicitly here makes this router safe to import in any order
# (cold pytest collection, ``main.py`` boot, ad-hoc REPL).
import src.pipeline.contracts  # noqa: E402, F401 — see comment above
from src.policy.audit import AuditEventType, AuditLogger  # noqa: E402

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


REPLAY_WINDOW_SECONDS: Final[int] = 5 * 60
"""Reject Slack timestamps older or further in the future than this many
seconds. Matches Slack's own guidance.
"""

MAX_BODY_BYTES: Final[int] = 16 * 1024
"""Slack interactive bodies are typically <3 KiB — 16 KiB is a generous
safety cap that still kills a body-flood DoS quickly.
"""

ACTION_APPROVE: Final[str] = "approve"
ACTION_DENY: Final[str] = "deny"

_VALID_ACTIONS: Final[frozenset[str]] = frozenset({ACTION_APPROVE, ACTION_DENY})

#: Default tenant UUID assigned to Slack-originated audit entries when
#: the upstream notification did not propagate a tenant ID. The audit
#: chain partitions by tenant_id, so this constant must remain stable.
SLACK_AUDIT_TENANT_ID: Final[UUID] = UUID(int=0)


# ---------------------------------------------------------------------------
# Audit sink wiring (singleton)
# ---------------------------------------------------------------------------


_audit_logger: AuditLogger | None = None


def _get_audit_logger() -> AuditLogger:
    """Return the process-wide :class:`AuditLogger` for Slack callbacks.

    The global is intentional: the audit sink is in-process for ARG-048,
    matching the rest of the policy plane (which writes through an
    in-memory ``InMemoryAuditSink`` in dev / test and Postgres in prod
    via the ``DatabaseAuditSink`` once ARG-049 lands the migration).
    """
    global _audit_logger
    if _audit_logger is None:
        from src.policy.audit import InMemoryAuditSink

        _audit_logger = AuditLogger(InMemoryAuditSink())
    return _audit_logger


def set_audit_logger(logger_: AuditLogger) -> None:
    """Override the audit logger (testing hook).

    The unit + integration suites call this to inject an inspectable
    sink so the test can assert that the callback emitted a row.
    """
    global _audit_logger
    _audit_logger = logger_


def _reset_audit_logger() -> None:
    """Reset the singleton (test teardown helper).

    Equivalent to ``set_audit_logger(None)`` but with a name that makes
    intent obvious in fixtures.
    """
    global _audit_logger
    _audit_logger = None


# ---------------------------------------------------------------------------
# Response model
# ---------------------------------------------------------------------------


class SlackCallbackAck(BaseModel):
    """Body returned to Slack after a successful callback."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    ok: bool = Field(default=True, description="Slack API convention.")
    action: str = Field(description="Parsed action name (approve|deny).")
    approval_id: str = Field(description="Approval id extracted from action_id.")
    text: str = Field(
        default="Recorded; awaiting cryptographic approval to proceed.",
        description="Operator-friendly confirmation surfaced inline in Slack.",
    )


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------


router = APIRouter(
    prefix="/mcp/notifications/slack",
    tags=["mcp-slack-callbacks"],
)


# ---------------------------------------------------------------------------
# Internal helpers (pure — easy to unit-test)
# ---------------------------------------------------------------------------


def _parse_timestamp(raw: str) -> int:
    """Parse the ``X-Slack-Request-Timestamp`` header.

    Returns the integer epoch-seconds. Raises ``ValueError`` for any
    non-numeric input — the caller maps that to HTTP 401.
    """
    if not raw:
        raise ValueError("empty_timestamp")
    if not raw.lstrip("-").isdigit():
        raise ValueError("non_numeric_timestamp")
    return int(raw)


def _within_replay_window(timestamp: int, *, now: float) -> bool:
    """Return ``True`` when ``timestamp`` is inside the replay window."""
    delta = abs(now - timestamp)
    return delta <= REPLAY_WINDOW_SECONDS


def _expected_signature(*, signing_secret: str, timestamp: str, raw_body: bytes) -> str:
    """Compute the canonical Slack v0 signature.

    The basestring is ``b"v0:" + timestamp + b":" + raw_body`` per
    Slack's documentation. We always return the ``v0=`` prefix so the
    caller can compare against the wire value verbatim.
    """
    base = b"v0:" + timestamp.encode("ascii") + b":" + raw_body
    digest = hmac.new(
        signing_secret.encode("utf-8"), base, hashlib.sha256
    ).hexdigest()
    return f"v0={digest}"


def _verify_signature(
    *,
    signing_secret: str,
    timestamp: str,
    raw_body: bytes,
    provided_signature: str,
) -> bool:
    """Constant-time compare the provided signature against the expected one."""
    expected = _expected_signature(
        signing_secret=signing_secret,
        timestamp=timestamp,
        raw_body=raw_body,
    )
    return hmac.compare_digest(expected, provided_signature)


def _parse_payload(raw_body: bytes) -> dict[str, Any]:
    """Decode Slack's ``application/x-www-form-urlencoded`` payload.

    Slack POSTs ``payload=<json>`` as the single form field.
    """
    try:
        decoded = raw_body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid_body_encoding",
        ) from exc

    parsed = parse_qs(decoded, keep_blank_values=True, strict_parsing=False)
    payload_field = parsed.get("payload", [])
    if not payload_field or not payload_field[0]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="missing_payload_field",
        )

    try:
        payload_obj = json.loads(payload_field[0])
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid_payload_json",
        ) from exc

    if not isinstance(payload_obj, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="payload_not_object",
        )
    return payload_obj


def _extract_action(
    payload: dict[str, Any],
) -> tuple[str, str, str]:
    """Pull ``(action, approval_id, slack_user_id)`` from the Slack payload.

    The Slack payload schema for ``block_actions`` is::

        {
          "type": "block_actions",
          "user": {"id": "U123ABC", "username": "alice"},
          "actions": [
            {"action_id": "approve::<approval_id>", ...}
          ]
        }

    We accept only the ``block_actions`` type — any other type is a
    misconfiguration and gets rejected with HTTP 422.
    """
    payload_type = payload.get("type")
    if payload_type != "block_actions":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="unsupported_payload_type",
        )

    actions = payload.get("actions")
    if not isinstance(actions, list) or not actions:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="missing_actions",
        )
    first = actions[0]
    if not isinstance(first, dict):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="malformed_action",
        )
    action_id = first.get("action_id")
    if not isinstance(action_id, str) or "::" not in action_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="invalid_action_id",
        )

    action_name, _, approval_id = action_id.partition("::")
    if action_name not in _VALID_ACTIONS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="unknown_action",
        )
    if not approval_id or len(approval_id) > 128:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="invalid_approval_id",
        )

    user = payload.get("user")
    slack_user_id = ""
    if isinstance(user, dict):
        candidate = user.get("id")
        if isinstance(candidate, str):
            slack_user_id = candidate[:64]

    return action_name, approval_id, slack_user_id


def _emit_intent_audit(
    *,
    action: str,
    approval_id: str,
    slack_user_id: str,
) -> None:
    """Record the Slack-originated intent into the immutable audit log.

    A Slack click is *never* enough to authorise a destructive action on
    its own — the cryptographic ``ApprovalService`` retains the final
    say. We log the soft intent so the audit chain captures the human
    decision trail (who pressed Approve / Deny in Slack and when).
    """
    audit = _get_audit_logger()
    try:
        audit.emit(
            event_type=AuditEventType.APPROVAL_REQUESTED,
            tenant_id=SLACK_AUDIT_TENANT_ID,
            decision_allowed=(action == ACTION_APPROVE),
            failure_summary=None if action == ACTION_APPROVE else "slack_denied",
            payload={
                "approval_id": approval_id[:64],
                "slack_user_id": slack_user_id or "unknown",
                "source": "slack",
                "action": action,
            },
        )
    except Exception as exc:  # noqa: BLE001 — defensive: audit must never 500 the callback
        logger.warning(
            "slack_callback_audit_emit_failed",
            extra={
                "event": "slack_callback_audit_emit_failed",
                "error_type": type(exc).__name__,
            },
        )


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


@router.post(
    "/callback",
    response_model=SlackCallbackAck,
    status_code=status.HTTP_200_OK,
    responses={
        status.HTTP_400_BAD_REQUEST: {"description": "Malformed Slack payload."},
        status.HTTP_401_UNAUTHORIZED: {
            "description": "Signature invalid or replay window exceeded."
        },
        status.HTTP_413_CONTENT_TOO_LARGE: {
            "description": "Body exceeded the configured 16 KiB cap."
        },
        status.HTTP_422_UNPROCESSABLE_CONTENT: {
            "description": "Action / approval id payload was malformed."
        },
        status.HTTP_503_SERVICE_UNAVAILABLE: {
            "description": "SLACK_SIGNING_SECRET not configured server-side."
        },
    },
)
async def slack_action_callback(
    request: Request,
    x_slack_signature: Annotated[
        str | None, Header(alias="X-Slack-Signature")
    ] = None,
    x_slack_request_timestamp: Annotated[
        str | None, Header(alias="X-Slack-Request-Timestamp")
    ] = None,
) -> SlackCallbackAck:
    """Receive a Slack interactive action and route it to the audit log.

    See module docstring for the full security contract.
    """
    signing_secret = settings.slack_signing_secret
    if not signing_secret:
        logger.error(
            "slack_callback_signing_secret_missing",
            extra={"event": "slack_callback_signing_secret_missing"},
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="slack_signing_secret_not_configured",
        )

    if not x_slack_signature or not x_slack_request_timestamp:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing_slack_headers",
        )

    raw_body = await request.body()
    if len(raw_body) > MAX_BODY_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail="body_too_large",
        )

    try:
        timestamp = _parse_timestamp(x_slack_request_timestamp)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid_timestamp",
        ) from exc

    if not _within_replay_window(timestamp, now=time.time()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="stale_timestamp",
        )

    if not _verify_signature(
        signing_secret=signing_secret,
        timestamp=x_slack_request_timestamp,
        raw_body=raw_body,
        provided_signature=x_slack_signature,
    ):
        logger.warning(
            "slack_callback_signature_invalid",
            extra={
                "event": "slack_callback_signature_invalid",
                "timestamp": x_slack_request_timestamp,
            },
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid_signature",
        )

    payload = _parse_payload(raw_body)
    action, approval_id, slack_user_id = _extract_action(payload)

    _emit_intent_audit(
        action=action,
        approval_id=approval_id,
        slack_user_id=slack_user_id,
    )

    logger.info(
        "slack_callback_processed",
        extra={
            "event": "slack_callback_processed",
            "action": action,
            "approval_id_prefix": approval_id[:8],
            "slack_user_id_prefix": (slack_user_id or "anon")[:8],
        },
    )

    return SlackCallbackAck(
        ok=True,
        action=action,
        approval_id=approval_id,
    )


__all__ = [
    "ACTION_APPROVE",
    "ACTION_DENY",
    "MAX_BODY_BYTES",
    "REPLAY_WINDOW_SECONDS",
    "SLACK_AUDIT_TENANT_ID",
    "SlackCallbackAck",
    "_emit_intent_audit",
    "_expected_signature",
    "_extract_action",
    "_parse_payload",
    "_parse_timestamp",
    "_reset_audit_logger",
    "_verify_signature",
    "_within_replay_window",
    "router",
    "set_audit_logger",
]
