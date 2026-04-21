"""ARG-048 — Unit tests for the Slack interactive-action callback router.

Suite focus: pure-function behaviour + per-request guards. Asserts that
the router

* hard-fails when ``SLACK_SIGNING_SECRET`` is unset (HTTP 503);
* rejects missing / mis-typed Slack headers (HTTP 401);
* enforces the 5-minute replay window symmetrically (past + future);
* enforces the 16 KiB body cap (HTTP 413);
* rejects malformed payloads (HTTP 400 / 422 depending on layer);
* records a ``APPROVAL_REQUESTED`` audit row on success;
* parses the ``approve::`` / ``deny::`` action_id grammar exactly.

Integration with the cryptographic ``ApprovalService`` is out of scope
here — see :mod:`tests.integration.mcp.test_slack_interactive_flow`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.parse
from collections.abc import Iterator
from typing import Any, Final

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.api.routers.mcp_slack_callbacks import (
    MAX_BODY_BYTES,
    REPLAY_WINDOW_SECONDS,
    SLACK_AUDIT_TENANT_ID,
    _expected_signature,
    _extract_action,
    _parse_payload,
    _parse_timestamp,
    _reset_audit_logger,
    _verify_signature,
    _within_replay_window,
    router,
    set_audit_logger,
)
from src.core.config import settings
from src.policy.audit import AuditEventType, AuditLogger, InMemoryAuditSink

SIGNING_SECRET: Final[str] = "test-signing-secret-arg048"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_payload(
    *,
    action_id: str = "approve::approval-arg048-1",
    user_id: str = "U0SLACK1",
    payload_type: str = "block_actions",
) -> bytes:
    body = {
        "type": payload_type,
        "user": {"id": user_id, "username": "alice"},
        "actions": [
            {
                "action_id": action_id,
                "value": action_id.split("::", 1)[-1] if "::" in action_id else "x",
                "type": "button",
            }
        ],
    }
    encoded = urllib.parse.urlencode({"payload": json.dumps(body)})
    return encoded.encode("utf-8")


def _signed_request(
    raw_body: bytes,
    *,
    timestamp: int | None = None,
    secret: str = SIGNING_SECRET,
) -> tuple[bytes, dict[str, str]]:
    ts = str(timestamp if timestamp is not None else int(time.time()))
    base = b"v0:" + ts.encode("ascii") + b":" + raw_body
    digest = hmac.new(secret.encode("utf-8"), base, hashlib.sha256).hexdigest()
    headers = {
        "X-Slack-Signature": f"v0={digest}",
        "X-Slack-Request-Timestamp": ts,
        "Content-Type": "application/x-www-form-urlencoded",
    }
    return raw_body, headers


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def audit_sink() -> Iterator[InMemoryAuditSink]:
    sink = InMemoryAuditSink()
    audit_logger = AuditLogger(sink)
    set_audit_logger(audit_logger)
    try:
        yield sink
    finally:
        _reset_audit_logger()


@pytest.fixture
def configured_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[None]:
    monkeypatch.setattr(settings, "slack_signing_secret", SIGNING_SECRET)
    yield


@pytest.fixture
def unconfigured_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[None]:
    monkeypatch.setattr(settings, "slack_signing_secret", None)
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
# Pure-function unit tests
# ---------------------------------------------------------------------------


class TestParseTimestamp:
    def test_accepts_positive_integer_string(self) -> None:
        assert _parse_timestamp("1700000000") == 1700000000

    def test_accepts_zero(self) -> None:
        assert _parse_timestamp("0") == 0

    def test_rejects_empty_string(self) -> None:
        with pytest.raises(ValueError):
            _parse_timestamp("")

    def test_rejects_non_numeric(self) -> None:
        with pytest.raises(ValueError):
            _parse_timestamp("not-a-number")

    def test_rejects_float(self) -> None:
        with pytest.raises(ValueError):
            _parse_timestamp("1700000000.5")


class TestReplayWindow:
    def test_recent_timestamp_inside_window(self) -> None:
        now = 1_700_000_000.0
        ts = int(now - 30)
        assert _within_replay_window(ts, now=now)

    def test_future_timestamp_inside_window(self) -> None:
        now = 1_700_000_000.0
        ts = int(now + 60)
        assert _within_replay_window(ts, now=now)

    def test_too_old_timestamp_outside_window(self) -> None:
        now = 1_700_000_000.0
        ts = int(now - REPLAY_WINDOW_SECONDS - 1)
        assert not _within_replay_window(ts, now=now)

    def test_too_future_timestamp_outside_window(self) -> None:
        now = 1_700_000_000.0
        ts = int(now + REPLAY_WINDOW_SECONDS + 1)
        assert not _within_replay_window(ts, now=now)


class TestSignature:
    def test_signature_is_deterministic(self) -> None:
        ts = "1700000000"
        body = b"payload=test"
        sig1 = _expected_signature(
            signing_secret=SIGNING_SECRET, timestamp=ts, raw_body=body
        )
        sig2 = _expected_signature(
            signing_secret=SIGNING_SECRET, timestamp=ts, raw_body=body
        )
        assert sig1 == sig2
        assert sig1.startswith("v0=")

    def test_signature_changes_with_body(self) -> None:
        ts = "1700000000"
        sig_a = _expected_signature(
            signing_secret=SIGNING_SECRET, timestamp=ts, raw_body=b"a"
        )
        sig_b = _expected_signature(
            signing_secret=SIGNING_SECRET, timestamp=ts, raw_body=b"b"
        )
        assert sig_a != sig_b

    def test_signature_changes_with_timestamp(self) -> None:
        body = b"payload=t"
        sig_a = _expected_signature(
            signing_secret=SIGNING_SECRET, timestamp="1700000000", raw_body=body
        )
        sig_b = _expected_signature(
            signing_secret=SIGNING_SECRET, timestamp="1700000001", raw_body=body
        )
        assert sig_a != sig_b

    def test_verify_accepts_correct_signature(self) -> None:
        ts = "1700000000"
        body = b"payload=test"
        sig = _expected_signature(
            signing_secret=SIGNING_SECRET, timestamp=ts, raw_body=body
        )
        assert _verify_signature(
            signing_secret=SIGNING_SECRET,
            timestamp=ts,
            raw_body=body,
            provided_signature=sig,
        )

    def test_verify_rejects_tampered_signature(self) -> None:
        ts = "1700000000"
        body = b"payload=test"
        sig = _expected_signature(
            signing_secret=SIGNING_SECRET, timestamp=ts, raw_body=body
        )
        tampered = sig[:-1] + ("0" if sig[-1] != "0" else "1")
        assert not _verify_signature(
            signing_secret=SIGNING_SECRET,
            timestamp=ts,
            raw_body=body,
            provided_signature=tampered,
        )

    def test_verify_rejects_wrong_secret(self) -> None:
        ts = "1700000000"
        body = b"payload=test"
        sig = _expected_signature(
            signing_secret=SIGNING_SECRET, timestamp=ts, raw_body=body
        )
        assert not _verify_signature(
            signing_secret="other-secret",
            timestamp=ts,
            raw_body=body,
            provided_signature=sig,
        )


class TestParsePayload:
    def test_parses_valid_payload(self) -> None:
        body = _make_payload()
        parsed = _parse_payload(body)
        assert parsed["type"] == "block_actions"
        assert isinstance(parsed["actions"], list)

    def test_rejects_missing_payload_field(self) -> None:
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc:
            _parse_payload(b"foo=bar")
        assert exc.value.status_code == 400

    def test_rejects_invalid_json(self) -> None:
        from fastapi import HTTPException

        body = urllib.parse.urlencode({"payload": "{not-json"}).encode("utf-8")
        with pytest.raises(HTTPException) as exc:
            _parse_payload(body)
        assert exc.value.status_code == 400

    def test_rejects_non_object_payload(self) -> None:
        from fastapi import HTTPException

        body = urllib.parse.urlencode({"payload": json.dumps([1, 2, 3])}).encode(
            "utf-8"
        )
        with pytest.raises(HTTPException) as exc:
            _parse_payload(body)
        assert exc.value.status_code == 400


def _decode_payload_dict(raw: bytes) -> dict[str, Any]:
    """Reverse :func:`_make_payload` back into a Python ``dict``.

    Slack's wire format is ``application/x-www-form-urlencoded`` with a
    single ``payload=<json>`` field, so we have to URL-decode (using
    ``unquote_plus`` — JSON whitespace lands on the wire as ``+``)
    before re-parsing the JSON. Centralising this in one helper avoids
    five copies of a fragile expression that previously dropped the
    ``+ → space`` step and broke ``json.loads``.
    """
    decoded = urllib.parse.unquote_plus(raw.decode("utf-8"))
    json_text = decoded.split("payload=", 1)[1]
    return json.loads(json_text)


class TestExtractAction:
    def test_extracts_approve_action(self) -> None:
        payload = _decode_payload_dict(
            _make_payload(action_id="approve::approval-1", user_id="U123")
        )
        action, approval_id, user_id = _extract_action(payload)
        assert action == "approve"
        assert approval_id == "approval-1"
        assert user_id == "U123"

    def test_extracts_deny_action(self) -> None:
        payload = _decode_payload_dict(
            _make_payload(action_id="deny::approval-1")
        )
        action, approval_id, _ = _extract_action(payload)
        assert action == "deny"
        assert approval_id == "approval-1"

    def test_rejects_unknown_action(self) -> None:
        from fastapi import HTTPException

        payload = _decode_payload_dict(
            _make_payload(action_id="forge::approval-1")
        )
        with pytest.raises(HTTPException) as exc:
            _extract_action(payload)
        assert exc.value.status_code == 422

    def test_rejects_missing_separator(self) -> None:
        from fastapi import HTTPException

        payload = _decode_payload_dict(
            _make_payload(action_id="approve_approval_1")
        )
        with pytest.raises(HTTPException) as exc:
            _extract_action(payload)
        assert exc.value.status_code == 422

    def test_rejects_unsupported_payload_type(self) -> None:
        from fastapi import HTTPException

        payload = _decode_payload_dict(
            _make_payload(payload_type="view_submission")
        )
        with pytest.raises(HTTPException) as exc:
            _extract_action(payload)
        assert exc.value.status_code == 422


# ---------------------------------------------------------------------------
# End-to-end via TestClient
# ---------------------------------------------------------------------------


class TestCallbackEndpoint:
    def test_returns_503_when_signing_secret_missing(
        self,
        client: TestClient,
        unconfigured_secret: None,
        audit_sink: InMemoryAuditSink,
    ) -> None:
        body, headers = _signed_request(_make_payload())
        resp = client.post(
            "/mcp/notifications/slack/callback", content=body, headers=headers
        )
        assert resp.status_code == 503
        assert resp.json()["detail"] == "slack_signing_secret_not_configured"

    def test_returns_401_when_signature_header_missing(
        self,
        client: TestClient,
        configured_secret: None,
        audit_sink: InMemoryAuditSink,
    ) -> None:
        body, headers = _signed_request(_make_payload())
        del headers["X-Slack-Signature"]
        resp = client.post(
            "/mcp/notifications/slack/callback", content=body, headers=headers
        )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "missing_slack_headers"

    def test_returns_401_when_timestamp_header_missing(
        self,
        client: TestClient,
        configured_secret: None,
        audit_sink: InMemoryAuditSink,
    ) -> None:
        body, headers = _signed_request(_make_payload())
        del headers["X-Slack-Request-Timestamp"]
        resp = client.post(
            "/mcp/notifications/slack/callback", content=body, headers=headers
        )
        assert resp.status_code == 401

    def test_returns_401_on_stale_timestamp(
        self,
        client: TestClient,
        configured_secret: None,
        audit_sink: InMemoryAuditSink,
    ) -> None:
        stale = int(time.time()) - REPLAY_WINDOW_SECONDS - 30
        body, headers = _signed_request(_make_payload(), timestamp=stale)
        resp = client.post(
            "/mcp/notifications/slack/callback", content=body, headers=headers
        )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "stale_timestamp"

    def test_returns_401_on_future_timestamp(
        self,
        client: TestClient,
        configured_secret: None,
        audit_sink: InMemoryAuditSink,
    ) -> None:
        future = int(time.time()) + REPLAY_WINDOW_SECONDS + 30
        body, headers = _signed_request(_make_payload(), timestamp=future)
        resp = client.post(
            "/mcp/notifications/slack/callback", content=body, headers=headers
        )
        assert resp.status_code == 401

    def test_returns_401_on_invalid_signature(
        self,
        client: TestClient,
        configured_secret: None,
        audit_sink: InMemoryAuditSink,
    ) -> None:
        body, headers = _signed_request(_make_payload())
        headers["X-Slack-Signature"] = "v0=" + ("0" * 64)
        resp = client.post(
            "/mcp/notifications/slack/callback", content=body, headers=headers
        )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "invalid_signature"

    def test_returns_401_on_invalid_timestamp_format(
        self,
        client: TestClient,
        configured_secret: None,
        audit_sink: InMemoryAuditSink,
    ) -> None:
        body, headers = _signed_request(_make_payload())
        headers["X-Slack-Request-Timestamp"] = "not-a-number"
        resp = client.post(
            "/mcp/notifications/slack/callback", content=body, headers=headers
        )
        assert resp.status_code == 401

    def test_returns_413_on_oversized_body(
        self,
        client: TestClient,
        configured_secret: None,
        audit_sink: InMemoryAuditSink,
    ) -> None:
        oversized = b"payload=" + b"A" * (MAX_BODY_BYTES + 100)
        body, headers = _signed_request(oversized)
        resp = client.post(
            "/mcp/notifications/slack/callback", content=body, headers=headers
        )
        assert resp.status_code == 413
        assert resp.json()["detail"] == "body_too_large"

    def test_returns_400_on_missing_payload_field(
        self,
        client: TestClient,
        configured_secret: None,
        audit_sink: InMemoryAuditSink,
    ) -> None:
        body, headers = _signed_request(b"foo=bar")
        resp = client.post(
            "/mcp/notifications/slack/callback", content=body, headers=headers
        )
        assert resp.status_code == 400

    def test_returns_400_on_invalid_json(
        self,
        client: TestClient,
        configured_secret: None,
        audit_sink: InMemoryAuditSink,
    ) -> None:
        body, headers = _signed_request(
            urllib.parse.urlencode({"payload": "{notjson"}).encode("utf-8")
        )
        resp = client.post(
            "/mcp/notifications/slack/callback", content=body, headers=headers
        )
        assert resp.status_code == 400

    def test_returns_422_on_unknown_action(
        self,
        client: TestClient,
        configured_secret: None,
        audit_sink: InMemoryAuditSink,
    ) -> None:
        body, headers = _signed_request(
            _make_payload(action_id="forge::approval-x")
        )
        resp = client.post(
            "/mcp/notifications/slack/callback", content=body, headers=headers
        )
        assert resp.status_code == 422

    def test_returns_200_on_valid_approve(
        self,
        client: TestClient,
        configured_secret: None,
        audit_sink: InMemoryAuditSink,
    ) -> None:
        body, headers = _signed_request(
            _make_payload(action_id="approve::approval-arg048-1", user_id="UABC")
        )
        resp = client.post(
            "/mcp/notifications/slack/callback", content=body, headers=headers
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["action"] == "approve"
        assert data["approval_id"] == "approval-arg048-1"

    def test_returns_200_on_valid_deny(
        self,
        client: TestClient,
        configured_secret: None,
        audit_sink: InMemoryAuditSink,
    ) -> None:
        body, headers = _signed_request(
            _make_payload(action_id="deny::approval-arg048-2", user_id="UDEF")
        )
        resp = client.post(
            "/mcp/notifications/slack/callback", content=body, headers=headers
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["action"] == "deny"

    def test_audit_log_records_intent_on_approve(
        self,
        client: TestClient,
        configured_secret: None,
        audit_sink: InMemoryAuditSink,
    ) -> None:
        body, headers = _signed_request(
            _make_payload(
                action_id="approve::approval-arg048-3", user_id="UXYZ"
            )
        )
        resp = client.post(
            "/mcp/notifications/slack/callback", content=body, headers=headers
        )
        assert resp.status_code == 200
        events = list(audit_sink.iter_events(tenant_id=SLACK_AUDIT_TENANT_ID))
        assert len(events) == 1
        event = events[0]
        assert event.event_type == AuditEventType.APPROVAL_REQUESTED
        assert event.decision_allowed is True
        assert event.payload["action"] == "approve"
        assert event.payload["approval_id"] == "approval-arg048-3"
        assert event.payload["slack_user_id"] == "UXYZ"
        assert event.payload["source"] == "slack"

    def test_audit_log_records_intent_on_deny(
        self,
        client: TestClient,
        configured_secret: None,
        audit_sink: InMemoryAuditSink,
    ) -> None:
        body, headers = _signed_request(
            _make_payload(action_id="deny::approval-arg048-4", user_id="UDENY")
        )
        resp = client.post(
            "/mcp/notifications/slack/callback", content=body, headers=headers
        )
        assert resp.status_code == 200
        events = list(audit_sink.iter_events(tenant_id=SLACK_AUDIT_TENANT_ID))
        assert len(events) == 1
        event = events[0]
        assert event.decision_allowed is False
        assert event.failure_summary == "slack_denied"
