"""XSS-006/007 — Integration: full detect → generate → verify pipeline (all I/O mocked)."""

from __future__ import annotations

import sys
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest

from src.recon.vulnerability_analysis.context_detector import detect_reflection_context
from src.recon.vulnerability_analysis.active_scan.payload_generator import (
    AdaptivePayloadGenerator,
)
from src.recon.vulnerability_analysis.xss_payload_manager import XSSPayloadManager
from src.recon.vulnerability_analysis.xss_verifier import verify_xss_with_browser


def _mock_settings() -> MagicMock:
    mock = MagicMock()
    mock.xss_payload_repos = ""
    mock.xss_payload_collection_url = ""
    mock.xss_playwright_timeout_ms = 10_000
    mock.default_tenant_id = "tenant-integration"
    return mock


def _make_mock_playwright(dialog_type: str | None, page_content: str) -> MagicMock:
    mock_dialog = MagicMock()
    if dialog_type:
        mock_dialog.type = dialog_type
        mock_dialog.message = "1"

    mock_page = MagicMock()
    mock_page.content.return_value = page_content
    mock_page.screenshot.return_value = b"\x89PNG"

    dialog_callback = None

    def _capture_on(event: str, handler):
        nonlocal dialog_callback
        if event == "dialog":
            dialog_callback = handler

    mock_page.on.side_effect = _capture_on

    def _goto(*args, **kwargs):
        if dialog_callback and dialog_type:
            dialog_callback(mock_dialog)

    mock_page.goto.side_effect = _goto
    mock_page.set_default_timeout = MagicMock()
    mock_page.wait_for_timeout = MagicMock()

    mock_browser = MagicMock()
    mock_browser.new_page.return_value = mock_page
    mock_browser.close = MagicMock()

    mock_chromium = MagicMock()
    mock_chromium.launch.return_value = mock_browser

    mock_pw = MagicMock()
    mock_pw.chromium = mock_chromium

    mock_sync_pw = MagicMock()
    mock_sync_pw.__enter__ = MagicMock(return_value=mock_pw)
    mock_sync_pw.__exit__ = MagicMock(return_value=False)
    return mock_sync_pw


class TestFullPipeline:
    """XSS integration: detect context → generate payloads → verify (mocked)."""

    def test_html_reflected_xss_full_flow(self) -> None:
        """Simulate: server reflects value in HTML body, browser confirms alert."""
        reflected_value = "TESTINPUT"
        server_response = f"<html><body><div>Your search: {reflected_value}</div></body></html>"

        # Step 1: detect context
        ctx = detect_reflection_context(server_response, reflected_value)
        assert ctx.context_type == "html"

        # Step 2: load seed payloads
        settings_mock = _mock_settings()
        with patch(
            "src.recon.vulnerability_analysis.active_scan.xss_payload_manager.settings",
            settings_mock,
        ):
            mgr = XSSPayloadManager()
            seed_payloads = mgr.get_payloads(context_hint="html", max_payloads=10)

        assert len(seed_payloads) > 0

        # Step 3: generate context-adapted payloads
        gen = AdaptivePayloadGenerator()
        payloads = gen.generate(ctx, base_payloads=seed_payloads, max_output=15)
        assert len(payloads) > 0
        assert any("alert" in p for p in payloads)

        # Step 4: verify top payload with mocked browser (alert fires)
        chosen_payload = payloads[0]
        mock_pw = _make_mock_playwright(
            dialog_type="alert",
            page_content=f"<html><body>{chosen_payload}</body></html>",
        )

        fake_module = ModuleType("playwright.sync_api")
        fake_module.sync_playwright = MagicMock(return_value=mock_pw)

        with (
            patch.dict(sys.modules, {
                "playwright": ModuleType("playwright"),
                "playwright.sync_api": fake_module,
            }),
            patch("src.recon.vulnerability_analysis.active_scan.xss_verifier.settings", settings_mock),
            patch(
                "src.recon.vulnerability_analysis.active_scan.xss_verifier._upload_screenshot",
                return_value=None,
            ),
        ):
            result = verify_xss_with_browser(
                "https://target.test/search?q=test",
                "q",
                chosen_payload,
                "scan-int-001",
                tenant_id="tenant-int",
            )

        assert result.verified is True

    def test_attribute_reflected_xss_no_dialog(self) -> None:
        """Simulate: server reflects in attribute, browser does NOT fire dialog."""
        reflected_value = "USERINPUT"
        server_response = f'<html><body><input value="{reflected_value}"></body></html>'

        # Step 1: detect context
        ctx = detect_reflection_context(server_response, reflected_value)
        assert ctx.context_type == "attribute"

        # Step 2 + 3: generate payloads
        gen = AdaptivePayloadGenerator()
        payloads = gen.generate(ctx, base_payloads=[], max_output=10)
        assert len(payloads) > 0
        has_quote_breakout = any(p.startswith('"') for p in payloads)
        assert has_quote_breakout

        # Step 4: verify — no dialog fires → verified=False
        mock_pw = _make_mock_playwright(
            dialog_type=None,
            page_content=f'<html><input value="{payloads[0]}"></html>',
        )

        fake_module = ModuleType("playwright.sync_api")
        fake_module.sync_playwright = MagicMock(return_value=mock_pw)
        settings_mock = _mock_settings()

        with (
            patch.dict(sys.modules, {
                "playwright": ModuleType("playwright"),
                "playwright.sync_api": fake_module,
            }),
            patch("src.recon.vulnerability_analysis.active_scan.xss_verifier.settings", settings_mock),
            patch(
                "src.recon.vulnerability_analysis.active_scan.xss_verifier._upload_screenshot",
                return_value=None,
            ),
        ):
            result = verify_xss_with_browser(
                "https://target.test/form?name=x",
                "name",
                payloads[0],
                "scan-int-002",
                tenant_id="tenant-int",
            )

        assert result.verified is False


@pytest.mark.asyncio
async def test_xss_engine_enrich_playwright_unavailable_sets_http_reflection_poc() -> None:
    """T5: при недоступном Playwright PoC остаётся http_reflection и verified_via_browser=false."""
    from urllib.parse import parse_qs, urlparse

    from src.recon.vulnerability_analysis.active_scan import va_active_scan_phase as vmod
    from src.recon.vulnerability_analysis.active_scan.xss_verifier import XSSVerificationResult

    async def fake_verify(*_a, **_k):
        return XSSVerificationResult(verified=False, error="playwright not available")

    class FakeHttpxClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return None

        async def get(self, url, **kwargs):
            m = MagicMock()
            q = parse_qs(urlparse(str(url)).query)
            raw = (q.get("q") or [""])[0]
            m.text = f"<html><body>{raw}</body></html>"
            return m

    row = {
        "data": {
            "type": "XSS",
            "url": "https://target.test/search?q=init",
            "parameter": "q",
            "proof_of_concept": {"parameter": "q"},
        },
    }

    mock_settings = _mock_settings()
    with (
        patch.object(vmod, "settings", mock_settings),
        patch.object(vmod.httpx, "AsyncClient", side_effect=lambda **kw: FakeHttpxClient()),
        patch(
            "src.recon.vulnerability_analysis.xss_verifier.verify_xss_with_browser_async",
            side_effect=fake_verify,
        ),
        patch(
            "src.recon.vulnerability_analysis.active_scan.xss_payload_manager.settings",
            mock_settings,
        ),
    ):
        mock_settings.xss_context_detection_enabled = False
        mock_settings.xss_verification_enabled = True
        mock_settings.xss_max_payloads_per_param = 10

        out = await vmod._xss_engine_enrich([row], "https://target.test", "scan-t5", "tenant-t5")

    poc = (out[0].get("data") or {}).get("proof_of_concept") or {}
    assert poc.get("verified_via_browser") is False
    assert poc.get("verification_method") == "http_reflection"
    assert poc.get("payload_reflected") is True


@pytest.mark.asyncio
async def test_xss_engine_enrich_verification_disabled_http_reflection_poc() -> None:
    """T5: XSS_VERIFICATION выключен — только HTTP-отражение, без вызова браузера."""
    from urllib.parse import parse_qs, urlparse

    from src.recon.vulnerability_analysis.active_scan import va_active_scan_phase as vmod

    class FakeHttpxClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return None

        async def get(self, url, **kwargs):
            m = MagicMock()
            q = parse_qs(urlparse(str(url)).query)
            raw = (q.get("q") or [""])[0]
            m.text = f"<html><body>{raw}</body></html>"
            return m

    row = {
        "data": {
            "type": "XSS",
            "url": "https://target.test/search?q=init",
            "parameter": "q",
            "proof_of_concept": {"parameter": "q"},
        },
    }

    mock_settings = _mock_settings()
    verify_mock = MagicMock()

    with (
        patch.object(vmod, "settings", mock_settings),
        patch.object(vmod.httpx, "AsyncClient", side_effect=lambda **kw: FakeHttpxClient()),
        patch(
            "src.recon.vulnerability_analysis.xss_verifier.verify_xss_with_browser_async",
            verify_mock,
        ),
        patch(
            "src.recon.vulnerability_analysis.active_scan.xss_payload_manager.settings",
            mock_settings,
        ),
    ):
        # Нужен хотя бы один флаг, иначе _xss_engine_enrich выходит сразу (backward compat).
        mock_settings.xss_context_detection_enabled = True
        mock_settings.xss_verification_enabled = False
        mock_settings.xss_max_payloads_per_param = 10

        out = await vmod._xss_engine_enrich([row], "https://target.test", "scan-t5b", "tenant-t5b")

    verify_mock.assert_not_called()
    poc = (out[0].get("data") or {}).get("proof_of_concept") or {}
    assert poc.get("verified_via_browser") is False
    assert poc.get("verification_method") == "http_reflection"


@pytest.mark.asyncio
async def test_xss_engine_enrich_no_reflection_verification_method_none() -> None:
    """T5: нет отражения в ответе — verification_method=none, verified_via_browser=false."""
    from src.recon.vulnerability_analysis.active_scan import va_active_scan_phase as vmod

    class FakeHttpxClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return None

        async def get(self, url, **kwargs):
            m = MagicMock()
            m.text = "<html><body>static</body></html>"
            return m

    row = {
        "data": {
            "type": "XSS",
            "url": "https://target.test/search?q=init",
            "parameter": "q",
            "proof_of_concept": {"parameter": "q"},
        },
    }

    mock_settings = _mock_settings()
    with (
        patch.object(vmod, "settings", mock_settings),
        patch.object(vmod.httpx, "AsyncClient", side_effect=lambda **kw: FakeHttpxClient()),
        patch(
            "src.recon.vulnerability_analysis.active_scan.xss_payload_manager.settings",
            mock_settings,
        ),
    ):
        mock_settings.xss_context_detection_enabled = True
        mock_settings.xss_verification_enabled = False
        mock_settings.xss_max_payloads_per_param = 10

        out = await vmod._xss_engine_enrich([row], "https://target.test", "scan-t5c", "tenant-t5c")

    poc = (out[0].get("data") or {}).get("proof_of_concept") or {}
    assert poc.get("verified_via_browser") is False
    assert poc.get("verification_method") == "none"
    assert poc.get("payload_reflected") is False


@pytest.mark.asyncio
async def test_xss_engine_enrich_reflection_payload_manager_verifier_mocked_browser_ok() -> None:
    """T10: HTTP-отражение (canary + payload) → менеджер пейлоадов → verify_xss_with_browser_async замокан → browser."""
    from urllib.parse import parse_qs, unquote, urlparse

    from src.recon.vulnerability_analysis.active_scan import va_active_scan_phase as vmod
    from src.recon.vulnerability_analysis.active_scan.xss_verifier import XSSVerificationResult

    async def fake_verify(*_a, **_k):
        return XSSVerificationResult(
            verified=True,
            alert_text="1",
            dialog_type="alert",
        )

    class FakeHttpxClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return None

        async def get(self, url, **kwargs):
            m = MagicMock()
            q = parse_qs(urlparse(str(url)).query)
            raw_list = q.get("q") or [""]
            raw = unquote((raw_list[0] or "") if raw_list else "")
            m.text = f"<html><body><div>{raw}</div></body></html>"
            return m

    row = {
        "data": {
            "type": "XSS",
            "url": "https://target.test/page?q=init",
            "parameter": "q",
            "proof_of_concept": {"parameter": "q"},
        },
    }

    mock_settings = _mock_settings()
    with (
        patch.object(vmod, "settings", mock_settings),
        patch.object(vmod.httpx, "AsyncClient", side_effect=lambda **kw: FakeHttpxClient()),
        patch(
            "src.recon.vulnerability_analysis.xss_verifier.verify_xss_with_browser_async",
            side_effect=fake_verify,
        ),
        patch(
            "src.recon.vulnerability_analysis.active_scan.xss_payload_manager.settings",
            mock_settings,
        ),
    ):
        mock_settings.xss_context_detection_enabled = True
        mock_settings.xss_verification_enabled = True
        mock_settings.xss_max_payloads_per_param = 10

        out = await vmod._xss_engine_enrich([row], "https://target.test", "scan-t10", "tenant-t10")

    poc = (out[0].get("data") or {}).get("proof_of_concept") or {}
    assert poc.get("verified_via_browser") is True
    assert poc.get("verification_method") == "browser"
    assert poc.get("browser_alert_text") == "1"
    assert poc.get("payload_reflected") is True
    assert poc.get("reflection_context")
