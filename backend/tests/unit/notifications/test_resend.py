"""Block 4.7 — Resend transactional email tests."""

from __future__ import annotations

import pytest
from src.core.config import settings
from src.notifications import resend as resend_mod
from src.notifications.email_templates import (
    purchase_confirmation_email,
    quota_low_email,
    report_ready_email,
)


class TestTemplates:
    def test_report_ready_contains_target_and_url(self):
        subject, html, text = report_ready_email("alleksy.com", "abc123", "https://x/scan/abc123")
        assert "alleksy.com" in subject
        assert "https://x/scan/abc123" in html
        assert "https://x/scan/abc123" in text

    def test_target_is_html_escaped(self):
        _s, html, _t = report_ready_email("<script>alert(1)</script>", "id", "https://x")
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html

    def test_quota_low_shows_remaining(self):
        subject, html, _t = quota_low_email("alleksy.com", 2, "https://x/?buy=1")
        assert "2" in subject
        assert "Buy more scans" in html

    def test_purchase_confirmation_optional_receipt(self):
        _s, html_no, _t = purchase_confirmation_email("alleksy.com", 5)
        assert "View receipt" not in html_no
        _s2, html_yes, _t2 = purchase_confirmation_email("alleksy.com", 5, "https://x/receipt")
        assert "View receipt" in html_yes

    def test_purchase_receipt_rejects_javascript_scheme(self):
        _s, html, _t = purchase_confirmation_email("alleksy.com", 5, "javascript:alert(1)")
        assert "View receipt" not in html
        assert "javascript:" not in html


class _FakeResp:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


class _FakeClient:
    def __init__(self, status_code: int) -> None:
        self._status = status_code

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    async def post(self, *_args, **_kwargs):
        return _FakeResp(self._status)


@pytest.mark.asyncio
async def test_send_email_noop_without_key(monkeypatch):
    monkeypatch.setattr(settings, "resend_api_key", "")
    assert await resend_mod.send_email("a@b.com", "s", "<p>h</p>") is False


@pytest.mark.asyncio
async def test_send_email_rejects_invalid_recipient(monkeypatch):
    monkeypatch.setattr(settings, "resend_api_key", "re_test")
    assert await resend_mod.send_email("not-an-email", "s", "<p>h</p>") is False


@pytest.mark.asyncio
async def test_send_email_success(monkeypatch):
    monkeypatch.setattr(settings, "resend_api_key", "re_test")
    monkeypatch.setattr(resend_mod.httpx, "AsyncClient", lambda **_k: _FakeClient(200))
    assert await resend_mod.send_email("a@b.com", "s", "<p>h</p>", text="h") is True


@pytest.mark.asyncio
async def test_send_email_api_rejection(monkeypatch):
    monkeypatch.setattr(settings, "resend_api_key", "re_test")
    monkeypatch.setattr(resend_mod.httpx, "AsyncClient", lambda **_k: _FakeClient(422))
    assert await resend_mod.send_email("a@b.com", "s", "<p>h</p>") is False


@pytest.mark.asyncio
async def test_notify_report_ready_requires_recipient(monkeypatch):
    monkeypatch.setattr(settings, "resend_api_key", "re_test")
    assert await resend_mod.notify_report_ready(to_email=None, target="x", scan_id="id") is False
