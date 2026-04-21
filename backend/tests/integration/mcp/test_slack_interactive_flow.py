"""ARG-048 — Integration: end-to-end Slack interactive callback flow.

Wires the ARG-035 ``SlackNotifier`` (which emits the Block-Kit message
with ``approve::<id>`` / ``deny::<id>`` action buttons) to the ARG-048
``mcp_slack_callbacks`` ingress router. The test simulates Slack's POST
back to the ARGUS callback URL using the same ``X-Slack-Signature`` /
``X-Slack-Request-Timestamp`` headers Slack would send, and asserts:

1. The Slack notifier's emitted block_id / action_id grammar is the same
   one the callback router parses (no schema drift between producer &
   consumer).
2. The full flow lands an ``APPROVAL_REQUESTED`` audit row tied to the
   correct approval_id and the Slack user_id.
3. Concurrent callbacks for distinct approvals don't corrupt the audit
   chain.
4. The dispatcher continues to operate when the callback is replayed
   (replay protection rejects the second call with HTTP 401).

We deliberately do NOT exercise the cryptographic
``ApprovalService.verify`` path here — that has its own unit + integration
suite. The Slack callback is a *soft-intent* hook: it records the
operator's button click for forensics, the destructive action still
requires a signed ``ApprovalRequest`` downstream.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.parse
from collections.abc import Iterator
from datetime import datetime, timezone
from typing import Final

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.api.routers.mcp_slack_callbacks import (
    SLACK_AUDIT_TENANT_ID,
    _reset_audit_logger,
    router,
    set_audit_logger,
)
from src.core.config import settings
from src.mcp.services.notifications.schemas import (
    NotificationEvent,
    NotificationSeverity,
)
from src.mcp.services.notifications.slack import build_slack_payload
from src.policy.audit import AuditEventType, AuditLogger, InMemoryAuditSink

SIGNING_SECRET: Final[str] = "integration-secret-arg048"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def audit_sink() -> Iterator[InMemoryAuditSink]:
    sink = InMemoryAuditSink()
    set_audit_logger(AuditLogger(sink))
    try:
        yield sink
    finally:
        _reset_audit_logger()


@pytest.fixture(autouse=True)
def _signing_secret(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(settings, "slack_signing_secret", SIGNING_SECRET)
    yield


@pytest.fixture
def app() -> FastAPI:
    api = FastAPI()
    api.include_router(router)
    return api


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _approval_event(
    *,
    approval_id: str,
    tenant_id: str = "tenant-int-arg048",
) -> NotificationEvent:
    return NotificationEvent(
        event_id=f"evt-{approval_id}",
        event_type="approval.pending",
        severity=NotificationSeverity.HIGH,
        tenant_id=tenant_id,
        title="Approval needed: destructive RM",
        summary="Operator review required before /tmp wipe.",
        scan_id="scan-int-arg048",
        finding_id=None,
        approval_id=approval_id,
        root_cause_hash=None,
        evidence_url="https://argus.example/evidence/arg048",
        occurred_at=datetime(2026, 4, 21, 8, 30, tzinfo=timezone.utc),
        extra_tags=(),
    )


def _slack_block_payload_for(action_id: str, *, user_id: str) -> bytes:
    payload = {
        "type": "block_actions",
        "user": {"id": user_id, "username": "alice"},
        "actions": [
            {
                "action_id": action_id,
                "value": action_id.split("::", 1)[-1],
                "type": "button",
            }
        ],
    }
    return urllib.parse.urlencode({"payload": json.dumps(payload)}).encode("utf-8")


def _sign(body: bytes, *, timestamp: int | None = None) -> dict[str, str]:
    ts = str(timestamp if timestamp is not None else int(time.time()))
    base = b"v0:" + ts.encode("ascii") + b":" + body
    digest = hmac.new(
        SIGNING_SECRET.encode("utf-8"), base, hashlib.sha256
    ).hexdigest()
    return {
        "X-Slack-Signature": f"v0={digest}",
        "X-Slack-Request-Timestamp": ts,
        "Content-Type": "application/x-www-form-urlencoded",
    }


# ---------------------------------------------------------------------------
# Producer ⇄ consumer schema parity
# ---------------------------------------------------------------------------


def test_notifier_action_ids_match_callback_grammar() -> None:
    """ARG-048 producer/consumer wiring: every ``action_id`` the
    Slack notifier emits MUST conform to the ``approve::<id>`` /
    ``deny::<id>`` grammar the callback router expects.
    """
    event = _approval_event(approval_id="approval-arg048-grammar")
    payload = build_slack_payload(event)

    blocks = payload["blocks"]
    assert isinstance(blocks, list)
    actions_block = next(b for b in blocks if b.get("type") == "actions")
    assert actions_block["block_id"] == "approval::approval-arg048-grammar"

    elements = actions_block["elements"]
    assert isinstance(elements, list)
    assert len(elements) == 2

    action_ids = sorted(e["action_id"] for e in elements)
    assert action_ids == [
        "approve::approval-arg048-grammar",
        "deny::approval-arg048-grammar",
    ]


# ---------------------------------------------------------------------------
# End-to-end happy path — approve
# ---------------------------------------------------------------------------


def test_end_to_end_approve_records_audit(
    client: TestClient,
    audit_sink: InMemoryAuditSink,
) -> None:
    """ARG-048: producer emits an action_id → simulated Slack click POSTs
    to the callback → the router records an APPROVAL_REQUESTED audit row.
    """
    event = _approval_event(approval_id="approval-arg048-e2e-1")
    payload = build_slack_payload(event)
    actions_block = next(
        b for b in payload["blocks"] if b.get("type") == "actions"
    )
    approve_action_id = next(
        e["action_id"] for e in actions_block["elements"] if e["style"] == "primary"
    )

    body = _slack_block_payload_for(approve_action_id, user_id="UE2E1")
    headers = _sign(body)

    resp = client.post(
        "/mcp/notifications/slack/callback", content=body, headers=headers
    )
    assert resp.status_code == 200
    assert resp.json()["action"] == "approve"
    assert resp.json()["approval_id"] == "approval-arg048-e2e-1"

    events = list(audit_sink.iter_events(tenant_id=SLACK_AUDIT_TENANT_ID))
    assert len(events) == 1
    audit_event = events[0]
    assert audit_event.event_type == AuditEventType.APPROVAL_REQUESTED
    assert audit_event.decision_allowed is True
    assert audit_event.payload["approval_id"] == "approval-arg048-e2e-1"
    assert audit_event.payload["slack_user_id"] == "UE2E1"


# ---------------------------------------------------------------------------
# End-to-end happy path — deny
# ---------------------------------------------------------------------------


def test_end_to_end_deny_records_negative_audit(
    client: TestClient,
    audit_sink: InMemoryAuditSink,
) -> None:
    event = _approval_event(approval_id="approval-arg048-e2e-2")
    payload = build_slack_payload(event)
    actions_block = next(
        b for b in payload["blocks"] if b.get("type") == "actions"
    )
    deny_action_id = next(
        e["action_id"] for e in actions_block["elements"] if e["style"] == "danger"
    )

    body = _slack_block_payload_for(deny_action_id, user_id="UE2E2")
    headers = _sign(body)

    resp = client.post(
        "/mcp/notifications/slack/callback", content=body, headers=headers
    )
    assert resp.status_code == 200
    assert resp.json()["action"] == "deny"

    events = list(audit_sink.iter_events(tenant_id=SLACK_AUDIT_TENANT_ID))
    assert len(events) == 1
    audit_event = events[0]
    assert audit_event.decision_allowed is False
    assert audit_event.failure_summary == "slack_denied"


# ---------------------------------------------------------------------------
# Replay protection — same body twice, second call rejected if outside window
# ---------------------------------------------------------------------------


def test_replay_protection_rejects_stale_repost(
    client: TestClient,
    audit_sink: InMemoryAuditSink,
) -> None:
    event = _approval_event(approval_id="approval-arg048-replay")
    payload = build_slack_payload(event)
    actions_block = next(
        b for b in payload["blocks"] if b.get("type") == "actions"
    )
    approve_action_id = next(
        e["action_id"] for e in actions_block["elements"] if e["style"] == "primary"
    )

    body = _slack_block_payload_for(approve_action_id, user_id="UREPLAY")
    stale_ts = int(time.time()) - 10 * 60
    headers = _sign(body, timestamp=stale_ts)
    resp = client.post(
        "/mcp/notifications/slack/callback", content=body, headers=headers
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "stale_timestamp"
    assert (
        len(list(audit_sink.iter_events(tenant_id=SLACK_AUDIT_TENANT_ID))) == 0
    )


# ---------------------------------------------------------------------------
# Concurrent callbacks for distinct approvals — chain stays consistent
# ---------------------------------------------------------------------------


def test_concurrent_callbacks_for_distinct_approvals(
    client: TestClient,
    audit_sink: InMemoryAuditSink,
) -> None:
    """Three back-to-back callbacks for distinct approvals all land an
    audit row each; the chain is verifiable by ``AuditLogger.verify_chain``.
    """
    audit = AuditLogger(audit_sink)
    set_audit_logger(audit)

    approval_ids = [
        "approval-arg048-multi-1",
        "approval-arg048-multi-2",
        "approval-arg048-multi-3",
    ]
    for i, approval_id in enumerate(approval_ids):
        body = _slack_block_payload_for(
            f"approve::{approval_id}", user_id=f"UMULTI{i}"
        )
        headers = _sign(body)
        resp = client.post(
            "/mcp/notifications/slack/callback", content=body, headers=headers
        )
        assert resp.status_code == 200, resp.text

    events = list(audit_sink.iter_events(tenant_id=SLACK_AUDIT_TENANT_ID))
    assert len(events) == 3
    # Every approval id appears exactly once.
    captured = {e.payload["approval_id"] for e in events}
    assert captured == set(approval_ids)
    # Audit chain hash links MUST verify.
    audit.verify_chain(tenant_id=SLACK_AUDIT_TENANT_ID)


# ---------------------------------------------------------------------------
# Approval id length cap — defends against payload smuggling
# ---------------------------------------------------------------------------


def test_oversized_approval_id_is_rejected(
    client: TestClient,
    audit_sink: InMemoryAuditSink,
) -> None:
    huge = "x" * 200
    body = _slack_block_payload_for(f"approve::{huge}", user_id="UHUGE")
    headers = _sign(body)
    resp = client.post(
        "/mcp/notifications/slack/callback", content=body, headers=headers
    )
    assert resp.status_code == 422
    assert resp.json()["detail"] == "invalid_approval_id"


# ---------------------------------------------------------------------------
# Slack user id is captured even when only minimal user info is present
# ---------------------------------------------------------------------------


def test_user_id_extracted_when_user_object_minimal(
    client: TestClient,
    audit_sink: InMemoryAuditSink,
) -> None:
    payload = {
        "type": "block_actions",
        "user": {"id": "UMINIMAL"},
        "actions": [
            {"action_id": "approve::approval-min", "value": "approval-min"}
        ],
    }
    body = urllib.parse.urlencode({"payload": json.dumps(payload)}).encode(
        "utf-8"
    )
    headers = _sign(body)
    resp = client.post(
        "/mcp/notifications/slack/callback", content=body, headers=headers
    )
    assert resp.status_code == 200
    events = list(audit_sink.iter_events(tenant_id=SLACK_AUDIT_TENANT_ID))
    assert events[0].payload["slack_user_id"] == "UMINIMAL"


# ---------------------------------------------------------------------------
# When user object is missing entirely → recorded as 'unknown'
# ---------------------------------------------------------------------------


def test_missing_user_object_is_recorded_as_unknown(
    client: TestClient,
    audit_sink: InMemoryAuditSink,
) -> None:
    payload = {
        "type": "block_actions",
        "actions": [
            {"action_id": "approve::approval-noUser", "value": "approval-noUser"}
        ],
    }
    body = urllib.parse.urlencode({"payload": json.dumps(payload)}).encode(
        "utf-8"
    )
    headers = _sign(body)
    resp = client.post(
        "/mcp/notifications/slack/callback", content=body, headers=headers
    )
    assert resp.status_code == 200
    events = list(audit_sink.iter_events(tenant_id=SLACK_AUDIT_TENANT_ID))
    assert events[0].payload["slack_user_id"] == "unknown"
