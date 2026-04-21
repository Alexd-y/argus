"""ARG-048 — Security: Slack callback signature, replay & tampering defences.

Adversary model
---------------
* Attacker can:
  - Intercept and replay legitimate Slack callbacks.
  - Re-sign payloads with a wrong secret (e.g. a leaked dev secret).
  - Tamper with the body, the timestamp, or the signature.
  - Inject extra Slack headers, oversized bodies, or unusual encodings.
  - Probe for unset / mis-set ``SLACK_SIGNING_SECRET``.
* Attacker cannot forge HMAC-SHA-256 with the production signing secret.
* The router runs behind TLS — header injection / smuggling at the
  transport layer is out of scope for this test (covered by the gateway
  / FastAPI middleware suite).

Each test asserts the router fails *closed* (HTTP 4xx / 5xx, no audit
emit, no side effects) for a specific attack class.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.parse
from collections.abc import Iterator
from typing import Final

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.api.routers.mcp_slack_callbacks import (
    MAX_BODY_BYTES,
    REPLAY_WINDOW_SECONDS,
    SLACK_AUDIT_TENANT_ID,
    _reset_audit_logger,
    router,
    set_audit_logger,
)
from src.core.config import settings
from src.policy.audit import AuditLogger, InMemoryAuditSink

SIGNING_SECRET: Final[str] = "production-grade-secret-arg048"
ATTACKER_SECRET: Final[str] = "leaked-dev-secret"


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


def _payload_body(*, action_id: str = "approve::approval-attack-1") -> bytes:
    payload = {
        "type": "block_actions",
        "user": {"id": "UATTACK"},
        "actions": [{"action_id": action_id}],
    }
    return urllib.parse.urlencode({"payload": json.dumps(payload)}).encode("utf-8")


def _sign(body: bytes, *, secret: str, timestamp: int | None = None) -> dict[str, str]:
    ts = str(timestamp if timestamp is not None else int(time.time()))
    base = b"v0:" + ts.encode("ascii") + b":" + body
    digest = hmac.new(secret.encode("utf-8"), base, hashlib.sha256).hexdigest()
    return {
        "X-Slack-Signature": f"v0={digest}",
        "X-Slack-Request-Timestamp": ts,
        "Content-Type": "application/x-www-form-urlencoded",
    }


def _assert_no_audit_side_effects(audit_sink: InMemoryAuditSink) -> None:
    assert (
        len(list(audit_sink.iter_events(tenant_id=SLACK_AUDIT_TENANT_ID))) == 0
    ), "Failed callback MUST NOT have written an audit row"


# ---------------------------------------------------------------------------
# Replay attacks
# ---------------------------------------------------------------------------


class TestReplayAttacks:
    def test_capture_then_replay_outside_window_rejected(
        self,
        client: TestClient,
        audit_sink: InMemoryAuditSink,
    ) -> None:
        """An attacker captures a legitimate callback signed N seconds
        ago and replays it after the 5-min window — MUST fail."""
        body = _payload_body()
        old_ts = int(time.time()) - REPLAY_WINDOW_SECONDS - 5
        headers = _sign(body, secret=SIGNING_SECRET, timestamp=old_ts)
        resp = client.post(
            "/mcp/notifications/slack/callback", content=body, headers=headers
        )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "stale_timestamp"
        _assert_no_audit_side_effects(audit_sink)

    def test_future_timestamp_attack_rejected(
        self,
        client: TestClient,
        audit_sink: InMemoryAuditSink,
    ) -> None:
        """Defends against a clock-skew attacker who tries to bank a
        signed payload with a far-future timestamp."""
        body = _payload_body()
        future_ts = int(time.time()) + REPLAY_WINDOW_SECONDS + 5
        headers = _sign(body, secret=SIGNING_SECRET, timestamp=future_ts)
        resp = client.post(
            "/mcp/notifications/slack/callback", content=body, headers=headers
        )
        assert resp.status_code == 401
        _assert_no_audit_side_effects(audit_sink)

    def test_zero_timestamp_attack_rejected(
        self,
        client: TestClient,
        audit_sink: InMemoryAuditSink,
    ) -> None:
        """Edge case — ``X-Slack-Request-Timestamp: 0`` is well outside
        the replay window for any host with a roughly-correct clock."""
        body = _payload_body()
        headers = _sign(body, secret=SIGNING_SECRET, timestamp=0)
        resp = client.post(
            "/mcp/notifications/slack/callback", content=body, headers=headers
        )
        assert resp.status_code == 401
        _assert_no_audit_side_effects(audit_sink)

    def test_negative_timestamp_attack_rejected(
        self,
        client: TestClient,
        audit_sink: InMemoryAuditSink,
    ) -> None:
        body = _payload_body()
        headers = _sign(body, secret=SIGNING_SECRET, timestamp=-10)
        resp = client.post(
            "/mcp/notifications/slack/callback", content=body, headers=headers
        )
        assert resp.status_code == 401
        _assert_no_audit_side_effects(audit_sink)


# ---------------------------------------------------------------------------
# Signature tampering
# ---------------------------------------------------------------------------


class TestSignatureTampering:
    def test_signature_signed_with_wrong_secret_rejected(
        self,
        client: TestClient,
        audit_sink: InMemoryAuditSink,
    ) -> None:
        """An attacker who knows the body + a leaked secret cannot
        impersonate Slack."""
        body = _payload_body()
        headers = _sign(body, secret=ATTACKER_SECRET)
        resp = client.post(
            "/mcp/notifications/slack/callback", content=body, headers=headers
        )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "invalid_signature"
        _assert_no_audit_side_effects(audit_sink)

    def test_signature_for_different_body_rejected(
        self,
        client: TestClient,
        audit_sink: InMemoryAuditSink,
    ) -> None:
        """Attacker takes a legitimate signature and swaps the body
        (e.g. flips approve to deny)."""
        original = _payload_body(action_id="approve::approval-orig")
        headers = _sign(original, secret=SIGNING_SECRET)

        forged = _payload_body(action_id="deny::approval-orig")
        resp = client.post(
            "/mcp/notifications/slack/callback", content=forged, headers=headers
        )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "invalid_signature"
        _assert_no_audit_side_effects(audit_sink)

    def test_signature_for_different_timestamp_rejected(
        self,
        client: TestClient,
        audit_sink: InMemoryAuditSink,
    ) -> None:
        """Attacker keeps the body but advances the timestamp to slip
        past the replay window."""
        body = _payload_body()
        ts_old = int(time.time()) - 60
        headers = _sign(body, secret=SIGNING_SECRET, timestamp=ts_old)
        # Tamper: bump timestamp without re-signing.
        headers["X-Slack-Request-Timestamp"] = str(int(time.time()))
        resp = client.post(
            "/mcp/notifications/slack/callback", content=body, headers=headers
        )
        assert resp.status_code == 401
        _assert_no_audit_side_effects(audit_sink)

    def test_truncated_signature_rejected(
        self,
        client: TestClient,
        audit_sink: InMemoryAuditSink,
    ) -> None:
        body = _payload_body()
        headers = _sign(body, secret=SIGNING_SECRET)
        headers["X-Slack-Signature"] = headers["X-Slack-Signature"][:20]
        resp = client.post(
            "/mcp/notifications/slack/callback", content=body, headers=headers
        )
        assert resp.status_code == 401
        _assert_no_audit_side_effects(audit_sink)

    def test_empty_signature_rejected(
        self,
        client: TestClient,
        audit_sink: InMemoryAuditSink,
    ) -> None:
        body = _payload_body()
        headers = _sign(body, secret=SIGNING_SECRET)
        headers["X-Slack-Signature"] = ""
        resp = client.post(
            "/mcp/notifications/slack/callback", content=body, headers=headers
        )
        assert resp.status_code == 401
        _assert_no_audit_side_effects(audit_sink)

    def test_signature_without_v0_prefix_rejected(
        self,
        client: TestClient,
        audit_sink: InMemoryAuditSink,
    ) -> None:
        """The router compares against the canonical ``v0=<hex>`` form;
        a bare hex without the prefix MUST NOT be accepted."""
        body = _payload_body()
        headers = _sign(body, secret=SIGNING_SECRET)
        headers["X-Slack-Signature"] = headers["X-Slack-Signature"].removeprefix(
            "v0="
        )
        resp = client.post(
            "/mcp/notifications/slack/callback", content=body, headers=headers
        )
        assert resp.status_code == 401
        _assert_no_audit_side_effects(audit_sink)


# ---------------------------------------------------------------------------
# Body smuggling / DoS
# ---------------------------------------------------------------------------


class TestBodySmuggling:
    def test_oversized_body_rejected(
        self,
        client: TestClient,
        audit_sink: InMemoryAuditSink,
    ) -> None:
        body = b"payload=" + b"A" * (MAX_BODY_BYTES + 1024)
        headers = _sign(body, secret=SIGNING_SECRET)
        resp = client.post(
            "/mcp/notifications/slack/callback", content=body, headers=headers
        )
        assert resp.status_code == 413
        _assert_no_audit_side_effects(audit_sink)

    def test_invalid_utf8_body_rejected(
        self,
        client: TestClient,
        audit_sink: InMemoryAuditSink,
    ) -> None:
        """A signature-valid body that fails UTF-8 decode MUST 400."""
        body = b"\xff\xfe\xfd" + b"x" * 10
        headers = _sign(body, secret=SIGNING_SECRET)
        resp = client.post(
            "/mcp/notifications/slack/callback", content=body, headers=headers
        )
        # 400 (invalid_body_encoding) or 400 (missing_payload_field) — both
        # are accepted defensive responses.
        assert resp.status_code == 400
        _assert_no_audit_side_effects(audit_sink)

    def test_empty_body_rejected(
        self,
        client: TestClient,
        audit_sink: InMemoryAuditSink,
    ) -> None:
        body = b""
        headers = _sign(body, secret=SIGNING_SECRET)
        resp = client.post(
            "/mcp/notifications/slack/callback", content=body, headers=headers
        )
        assert resp.status_code == 400
        _assert_no_audit_side_effects(audit_sink)


# ---------------------------------------------------------------------------
# Configuration / hard-fail mode
# ---------------------------------------------------------------------------


class TestHardFailMode:
    def test_unset_signing_secret_returns_503(
        self,
        client: TestClient,
        audit_sink: InMemoryAuditSink,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A mis-configured deployment (no ``SLACK_SIGNING_SECRET``) MUST
        NOT silently accept callbacks. Returns HTTP 503 instead."""
        monkeypatch.setattr(settings, "slack_signing_secret", None)
        body = _payload_body()
        headers = _sign(body, secret=SIGNING_SECRET)
        resp = client.post(
            "/mcp/notifications/slack/callback", content=body, headers=headers
        )
        assert resp.status_code == 503
        assert resp.json()["detail"] == "slack_signing_secret_not_configured"
        _assert_no_audit_side_effects(audit_sink)

    def test_empty_signing_secret_returns_503(
        self,
        client: TestClient,
        audit_sink: InMemoryAuditSink,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(settings, "slack_signing_secret", "")
        body = _payload_body()
        headers = _sign(body, secret=SIGNING_SECRET)
        resp = client.post(
            "/mcp/notifications/slack/callback", content=body, headers=headers
        )
        assert resp.status_code == 503
        _assert_no_audit_side_effects(audit_sink)


# ---------------------------------------------------------------------------
# Constant-time comparison — leakage probe
# ---------------------------------------------------------------------------


class TestConstantTimeCompare:
    def test_signature_with_correct_prefix_but_wrong_tail_rejected(
        self,
        client: TestClient,
        audit_sink: InMemoryAuditSink,
    ) -> None:
        """The router uses ``hmac.compare_digest`` — a timing attacker
        who guesses the first half of the signature still gets HTTP 401
        and no audit emit, with no observable success path."""
        body = _payload_body()
        headers = _sign(body, secret=SIGNING_SECRET)
        good_sig = headers["X-Slack-Signature"]
        forged = good_sig[:35] + ("0" * (len(good_sig) - 35))
        headers["X-Slack-Signature"] = forged
        resp = client.post(
            "/mcp/notifications/slack/callback", content=body, headers=headers
        )
        assert resp.status_code == 401
        _assert_no_audit_side_effects(audit_sink)
