"""Block 4.6c — Stripe webhook signature + checkout gating tests."""

from __future__ import annotations

import hashlib
import hmac

import pytest
from src.core.config import settings
from src.quota import stripe_client
from src.quota.stripe_client import (
    create_checkout_session,
    stripe_enabled,
    verify_webhook_signature,
)

_SECRET = "whsec_test"
_PAYLOAD = b'{"type":"checkout.session.completed"}'
_TS = 1_000_000


def _sig_header(ts: int = _TS, payload: bytes = _PAYLOAD, secret: str = _SECRET) -> str:
    signed = f"{ts}.".encode() + payload
    mac = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    return f"t={ts},v1={mac}"


class TestSignature:
    def test_valid_signature(self):
        assert verify_webhook_signature(_PAYLOAD, _sig_header(), _SECRET, now=_TS) is True

    def test_expired_timestamp_rejected(self):
        assert verify_webhook_signature(
            _PAYLOAD, _sig_header(), _SECRET, now=_TS + 10_000
        ) is False

    def test_wrong_secret_rejected(self):
        assert verify_webhook_signature(_PAYLOAD, _sig_header(), "whsec_other", now=_TS) is False

    def test_tampered_payload_rejected(self):
        assert verify_webhook_signature(b'{"evil":1}', _sig_header(), _SECRET, now=_TS) is False

    def test_malformed_header_rejected(self):
        assert verify_webhook_signature(_PAYLOAD, "garbage", _SECRET, now=_TS) is False

    def test_missing_inputs_rejected(self):
        assert verify_webhook_signature(b"", _sig_header(), _SECRET, now=_TS) is False
        assert verify_webhook_signature(_PAYLOAD, "", _SECRET, now=_TS) is False
        assert verify_webhook_signature(_PAYLOAD, _sig_header(), "", now=_TS) is False

    def test_multiple_v1_signatures(self):
        header = f"t={_TS},v1=deadbeef,{_sig_header().split(',', 1)[1]}"
        assert verify_webhook_signature(_PAYLOAD, header, _SECRET, now=_TS) is True


class TestCheckout:
    def test_enabled_flag(self, monkeypatch):
        monkeypatch.setattr(settings, "stripe_secret_key", "")
        monkeypatch.setattr(settings, "stripe_extra_scan_price_id", "")
        assert stripe_enabled() is False
        monkeypatch.setattr(settings, "stripe_secret_key", "sk_test")
        monkeypatch.setattr(settings, "stripe_extra_scan_price_id", "price_1")
        assert stripe_enabled() is True

    @pytest.mark.asyncio
    async def test_checkout_noop_without_config(self, monkeypatch):
        monkeypatch.setattr(settings, "stripe_secret_key", "")
        url = await create_checkout_session(
            tenant_id="t", tier="standard", quantity=1,
            success_url="https://x/ok", cancel_url="https://x/no",
        )
        assert url is None

    @pytest.mark.asyncio
    async def test_checkout_success(self, monkeypatch):
        monkeypatch.setattr(settings, "stripe_secret_key", "sk_test")
        monkeypatch.setattr(settings, "stripe_extra_scan_price_id", "price_1")

        class _Resp:
            status_code = 200

            def json(self):
                return {"url": "https://checkout.stripe.com/c/pay/cs_test_123"}

        class _Client:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_a):
                return False

            async def post(self, *_a, **_k):
                return _Resp()

        monkeypatch.setattr(stripe_client.httpx, "AsyncClient", lambda **_k: _Client())
        url = await create_checkout_session(
            tenant_id="t", tier="standard", quantity=2,
            success_url="https://x/ok", cancel_url="https://x/no",
        )
        assert url == "https://checkout.stripe.com/c/pay/cs_test_123"
