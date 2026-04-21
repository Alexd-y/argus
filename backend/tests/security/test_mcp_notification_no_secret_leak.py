"""ARG-035 — Security gate: zero secret leaks from webhook adapters.

Validates that the three concrete notification adapters
(:class:`SlackNotifier`, :class:`LinearAdapter`, :class:`JiraAdapter`)
never emit raw webhook URLs, API tokens, or finding-level secrets:

* in the :class:`AdapterResult` returned to the dispatcher;
* in the structured ``mcp.notifications.*`` log records;
* in the audit row produced by :meth:`NotificationDispatcher.dispatch`;
* in the :class:`NotificationEvent` payload after sanitisation.

The webhook *body* is allowed to contain finding text (that's the
whole point of the integration), but only after :func:`sanitize_replay_command`
has scrubbed it, and only inside the outbound HTTP request — never in
any in-process artefact retained by the system.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from typing import Final

import httpx
import pytest

from src.mcp.services.notifications import (
    AdapterResult,
    JiraAdapter,
    LinearAdapter,
    NotificationDispatcher,
    NotificationEvent,
    NotificationSeverity,
    SlackNotifier,
)
from src.reports.replay_command_sanitizer import (
    SanitizeContext,
    sanitize_replay_command,
)


# Each row: (label, raw_secret, needle).
# `needle` is the high-entropy substring that MUST never appear in any
# audit-side artefact — neither AdapterResult nor log record.
SECRET_PATTERNS: Final[tuple[tuple[str, str, str], ...]] = (
    (
        "slack_webhook",
        "https://notifications-test.example.invalid/post/T0/B0/SECRET-XYZ-1234",
        "SECRET-XYZ-1234",
    ),
    (
        "linear_api_key",
        "lin_api_RAW_LINEAR_TOKEN_DO_NOT_LEAK",
        "RAW_LINEAR_TOKEN_DO_NOT_LEAK",
    ),
    (
        "jira_api_token",
        "ATATT3xFfGF0_RAW_JIRA_TOKEN_DO_NOT_LEAK",
        "RAW_JIRA_TOKEN_DO_NOT_LEAK",
    ),
    (
        "jira_basic_auth",
        "Basic Ym90QGFyZ3VzLmV4YW1wbGU6QVRBVFQzeEZmR0YwX1NFQ1JFVA==",
        "Ym90QGFyZ3VzLmV4YW1wbGU6QVRBVFQzeEZmR0YwX1NFQ1JFVA",
    ),
    ("aws_access_key", "AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
    (
        "github_pat",
        "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
        "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
    ),
    ("password_kv", "password=hunter2_top_secret", "hunter2_top_secret"),
    (
        "rsa_private_key",
        "-----BEGIN RSA PRIVATE KEY-----MIIEpAIBAAKCAQEA1234-----END RSA PRIVATE KEY-----",
        "MIIEpAIBAAKCAQEA1234",
    ),
)


def _build_event(
    *,
    summary: str = "All good.",
    title: str = "Pending approval",
    severity: NotificationSeverity = NotificationSeverity.HIGH,
    event_id: str = "evt-sec-0001",
    event_type: str = "critical.finding.detected",
) -> NotificationEvent:
    return NotificationEvent(
        event_id=event_id,
        event_type=event_type,
        severity=severity,
        tenant_id="tenant-sec",
        title=title,
        summary=summary,
        scan_id="scan-sec-1",
        finding_id="finding-sec-1",
        approval_id=None,
        root_cause_hash="rch-sec-1",
        evidence_url="https://argus.example/evidence/x",
    )


def _http_handler_capture(
    captured: list[httpx.Request],
    response_factory: Callable[[], httpx.Response],
) -> Callable[[httpx.Request], httpx.Response]:
    def _handler(req: httpx.Request) -> httpx.Response:
        captured.append(req)
        return response_factory()

    return _handler


# ---------------------------------------------------------------------------
# AdapterResult never contains the secret material
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "label,raw_secret,needle",
    SECRET_PATTERNS,
    ids=[label for label, _, _ in SECRET_PATTERNS],
)
def test_slack_result_does_not_carry_secret(
    label: str, raw_secret: str, needle: str
) -> None:
    captured: list[httpx.Request] = []
    slack = SlackNotifier(
        webhook_url=raw_secret
        if "webhook" in label
        else "https://hooks.slack.example/T0/B0/inert",
        client=httpx.AsyncClient(
            transport=httpx.MockTransport(
                _http_handler_capture(captured, lambda: httpx.Response(200))
            ),
            timeout=5.0,
        ),
        backoff_base_seconds=0.0,
        backoff_factor=1.0,
        rng=lambda: 1.0,
    )
    ev = _build_event(summary="ok")
    result = asyncio.run(slack.send_with_retry(ev, tenant_id=ev.tenant_id))
    _assert_result_clean(result, needle=needle)


@pytest.mark.parametrize(
    "label,raw_secret,needle",
    SECRET_PATTERNS,
    ids=[label for label, _, _ in SECRET_PATTERNS],
)
def test_linear_result_does_not_carry_secret(
    label: str, raw_secret: str, needle: str
) -> None:
    captured: list[httpx.Request] = []
    linear = LinearAdapter(
        api_key=raw_secret if "linear" in label else "lin_api_inert",
        api_url="https://api.linear.example/graphql",
        team_map={"tenant-sec": "team-sec"},
        client=httpx.AsyncClient(
            transport=httpx.MockTransport(
                _http_handler_capture(
                    captured,
                    lambda: httpx.Response(
                        200, json={"data": {"issueCreate": {"success": True}}}
                    ),
                )
            ),
            timeout=5.0,
        ),
        backoff_base_seconds=0.0,
        backoff_factor=1.0,
        rng=lambda: 1.0,
    )
    ev = _build_event(severity=NotificationSeverity.HIGH)
    result = asyncio.run(linear.send_with_retry(ev, tenant_id=ev.tenant_id))
    _assert_result_clean(result, needle=needle)


@pytest.mark.parametrize(
    "label,raw_secret,needle",
    SECRET_PATTERNS,
    ids=[label for label, _, _ in SECRET_PATTERNS],
)
def test_jira_result_does_not_carry_secret(
    label: str, raw_secret: str, needle: str
) -> None:
    captured: list[httpx.Request] = []
    jira = JiraAdapter(
        site_url="https://argus.atlassian.example",
        user_email="bot@argus.example",
        api_token=raw_secret if "jira" in label else "jira_inert_token",
        project_key="SEC",
        client=httpx.AsyncClient(
            transport=httpx.MockTransport(
                _http_handler_capture(
                    captured, lambda: httpx.Response(201, json={"key": "SEC-1"})
                )
            ),
            timeout=5.0,
        ),
        backoff_base_seconds=0.0,
        backoff_factor=1.0,
        rng=lambda: 1.0,
    )
    ev = _build_event(severity=NotificationSeverity.HIGH)
    result = asyncio.run(jira.send_with_retry(ev, tenant_id=ev.tenant_id))
    _assert_result_clean(result, needle=needle)


# ---------------------------------------------------------------------------
# Audit log row never carries the secret
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "label,raw_secret,needle",
    SECRET_PATTERNS,
    ids=[label for label, _, _ in SECRET_PATTERNS],
)
def test_dispatch_audit_log_does_not_carry_secret(
    label: str, raw_secret: str, needle: str, caplog: pytest.LogCaptureFixture
) -> None:
    slack = SlackNotifier(
        webhook_url=raw_secret
        if "webhook" in label
        else "https://hooks.slack.example/T/B/x",
        client=httpx.AsyncClient(
            transport=httpx.MockTransport(lambda _: httpx.Response(200)),
            timeout=5.0,
        ),
        backoff_base_seconds=0.0,
        backoff_factor=1.0,
        rng=lambda: 1.0,
    )
    disp = NotificationDispatcher(
        adapters=[slack],
        enabled=True,
        audit_logger=object(),  # type: ignore[arg-type]
    )
    disp.set_adapter_enabled("slack", True)
    ev = _build_event()
    with caplog.at_level(
        logging.INFO, logger="src.mcp.services.notifications.dispatcher"
    ):
        asyncio.run(disp.dispatch(ev))
    asyncio.run(disp.aclose())

    for record in caplog.records:
        rendered = record.getMessage()
        for value in record.__dict__.values():
            rendered += " " + repr(value)
        assert needle not in rendered, (
            f"audit log row leaked {label!r} secret material: {needle!r} in record"
        )


# ---------------------------------------------------------------------------
# Sanitiser-driven event construction — defence in depth
# ---------------------------------------------------------------------------


def test_sanitiser_produces_summary_safe_for_all_adapters() -> None:
    """The dispatcher's caller MUST sanitise summary text before constructing
    a :class:`NotificationEvent`. This test demonstrates the contract by
    sanitising a leaky replay command and asserting the resulting summary
    can be safely shipped through every adapter without leaking the secret.
    """
    raw = ["echo", "Bearer ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"]
    ctx = SanitizeContext(
        target="https://victim.example.com",
        endpoints=("https://victim.example.com/api",),
        canaries=("CANARY-OBS-1",),
    )
    sanitised = sanitize_replay_command(raw, ctx)
    summary = " ".join(sanitised)
    assert "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789" not in summary

    captured: list[bytes] = []

    def _slack_handler(req: httpx.Request) -> httpx.Response:
        captured.append(bytes(req.content))
        return httpx.Response(200)

    slack = SlackNotifier(
        webhook_url="https://hooks.slack.example/T/B/x",
        client=httpx.AsyncClient(
            transport=httpx.MockTransport(_slack_handler), timeout=5.0
        ),
        backoff_base_seconds=0.0,
        backoff_factor=1.0,
        rng=lambda: 1.0,
    )
    ev = _build_event(summary=summary)
    asyncio.run(slack.send_with_retry(ev, tenant_id=ev.tenant_id))
    body = b"".join(captured)
    assert b"ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789" not in body


# ---------------------------------------------------------------------------
# Helper assertions
# ---------------------------------------------------------------------------


def _assert_result_clean(result: AdapterResult, *, needle: str) -> None:
    rendered = result.model_dump_json()
    assert needle not in rendered, (
        f"AdapterResult leaked secret material: {needle!r} in {rendered!r}"
    )
    for value in result.model_dump().values():
        assert needle not in str(value)
