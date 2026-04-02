"""XSS-005 — XSS Verifier: headless browser verification with mocked Playwright."""

from __future__ import annotations

import sys
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest

from src.recon.vulnerability_analysis.active_scan.xss_verifier import (
    _build_verification_url,
    _extract_snippet,
)
from src.recon.vulnerability_analysis.xss_verifier import (
    XSSVerificationResult,
    verify_xss_with_browser,
)

TARGET_URL = "https://target.test/search?q=test"
PARAM = "q"
PAYLOAD = "<script>alert(1)</script>"
SCAN_ID = "scan-xss-verify-001"
TENANT_ID = "tenant-001"


def _mock_settings(**overrides: object) -> MagicMock:
    mock = MagicMock()
    mock.xss_playwright_timeout_ms = overrides.get("timeout_ms", 10_000)
    mock.default_tenant_id = overrides.get("default_tenant_id", TENANT_ID)
    return mock


def _make_mock_playwright(
    dialog_type: str | None = None,
    dialog_message: str | None = None,
    page_content: str = "<html><body>result</body></html>",
    screenshot_bytes: bytes = b"\x89PNG\r\n",
    raise_on_goto: Exception | None = None,
) -> MagicMock:
    """Build a fully wired mock for ``sync_playwright()`` context."""
    mock_dialog = MagicMock()
    if dialog_type:
        mock_dialog.type = dialog_type
        mock_dialog.message = dialog_message or ""

    mock_page = MagicMock()
    mock_page.content.return_value = page_content
    mock_page.screenshot.return_value = screenshot_bytes

    dialog_callback = None

    def _capture_on(event: str, handler):
        nonlocal dialog_callback
        if event == "dialog":
            dialog_callback = handler

    mock_page.on.side_effect = _capture_on

    def _goto(*args, **kwargs):
        if raise_on_goto:
            raise raise_on_goto
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


class TestVerifiedTrueOnDialog:
    """XSS-005-T1: verified=True when JS dialog fires."""

    def test_alert_dialog_triggers_verified(self) -> None:
        mock_pw = _make_mock_playwright(
            dialog_type="alert",
            dialog_message="1",
            page_content=f"<html>{PAYLOAD}</html>",
        )

        fake_module = ModuleType("playwright.sync_api")
        fake_module.sync_playwright = MagicMock(return_value=mock_pw)

        with (
            patch.dict(sys.modules, {"playwright": ModuleType("playwright"), "playwright.sync_api": fake_module}),
            patch("src.recon.vulnerability_analysis.active_scan.xss_verifier.settings", _mock_settings()),
            patch("src.recon.vulnerability_analysis.active_scan.xss_verifier._upload_screenshot", return_value=None),
        ):
            result = verify_xss_with_browser(TARGET_URL, PARAM, PAYLOAD, SCAN_ID, tenant_id=TENANT_ID)

        assert result.verified is True
        assert result.alert_text == "1"
        assert result.dialog_type == "alert"

    def test_confirm_dialog_triggers_verified(self) -> None:
        mock_pw = _make_mock_playwright(
            dialog_type="confirm",
            dialog_message="are you sure",
            page_content=f"<html>{PAYLOAD}</html>",
        )

        fake_module = ModuleType("playwright.sync_api")
        fake_module.sync_playwright = MagicMock(return_value=mock_pw)

        with (
            patch.dict(sys.modules, {"playwright": ModuleType("playwright"), "playwright.sync_api": fake_module}),
            patch("src.recon.vulnerability_analysis.active_scan.xss_verifier.settings", _mock_settings()),
            patch("src.recon.vulnerability_analysis.active_scan.xss_verifier._upload_screenshot", return_value=None),
        ):
            result = verify_xss_with_browser(TARGET_URL, PARAM, PAYLOAD, SCAN_ID, tenant_id=TENANT_ID)

        assert result.verified is True
        assert result.dialog_type == "confirm"


class TestVerifiedFalseNoDialog:
    """XSS-005-T2: verified=False when no dialog fires."""

    def test_no_dialog_returns_false(self) -> None:
        mock_pw = _make_mock_playwright(
            dialog_type=None,
            page_content="<html><body>safe</body></html>",
        )

        fake_module = ModuleType("playwright.sync_api")
        fake_module.sync_playwright = MagicMock(return_value=mock_pw)

        with (
            patch.dict(sys.modules, {"playwright": ModuleType("playwright"), "playwright.sync_api": fake_module}),
            patch("src.recon.vulnerability_analysis.active_scan.xss_verifier.settings", _mock_settings()),
            patch("src.recon.vulnerability_analysis.active_scan.xss_verifier._upload_screenshot", return_value=None),
        ):
            result = verify_xss_with_browser(TARGET_URL, PARAM, PAYLOAD, SCAN_ID, tenant_id=TENANT_ID)

        assert result.verified is False
        assert result.alert_text is None
        assert result.dialog_type is None


class TestPlaywrightNotInstalled:
    """XSS-005-T3: returns error when Playwright not available."""

    def test_import_error_returns_graceful_error(self) -> None:
        with (
            patch.dict(sys.modules, {"playwright": None, "playwright.sync_api": None}),
            patch("src.recon.vulnerability_analysis.active_scan.xss_verifier.settings", _mock_settings()),
        ):
            original_import = __builtins__.__import__ if hasattr(__builtins__, '__import__') else __import__

            def _mock_import(name, *args, **kwargs):
                if name == "playwright.sync_api":
                    raise ImportError("No module named 'playwright'")
                return original_import(name, *args, **kwargs)

            with patch("builtins.__import__", side_effect=_mock_import):
                result = verify_xss_with_browser(TARGET_URL, PARAM, PAYLOAD, SCAN_ID)

        assert result.verified is False
        assert result.error is not None
        assert "playwright" in result.error.lower() or "not available" in result.error.lower()


class TestTimeoutHandling:
    """XSS-005-T4: timeout during navigation is handled gracefully."""

    def test_navigation_timeout_returns_error(self) -> None:
        class TimeoutError(Exception):
            pass

        mock_pw = _make_mock_playwright(
            raise_on_goto=TimeoutError("Timeout 30000ms exceeded"),
        )

        fake_module = ModuleType("playwright.sync_api")
        fake_module.sync_playwright = MagicMock(return_value=mock_pw)

        with (
            patch.dict(sys.modules, {"playwright": ModuleType("playwright"), "playwright.sync_api": fake_module}),
            patch("src.recon.vulnerability_analysis.active_scan.xss_verifier.settings", _mock_settings()),
        ):
            result = verify_xss_with_browser(TARGET_URL, PARAM, PAYLOAD, SCAN_ID, tenant_id=TENANT_ID)

        assert result.verified is False
        assert result.error is not None
        assert "timeout" in result.error.lower() or "Timeout" in (result.error or "")


class TestScreenshotKey:
    """XSS-005-T5: screenshot_key populated when available."""

    def test_screenshot_key_set_on_verification(self) -> None:
        mock_pw = _make_mock_playwright(
            dialog_type="alert",
            dialog_message="1",
            page_content=f"<html>{PAYLOAD}</html>",
            screenshot_bytes=b"\x89PNG_fake_screenshot",
        )

        fake_module = ModuleType("playwright.sync_api")
        fake_module.sync_playwright = MagicMock(return_value=mock_pw)

        expected_key = "screenshots/xss_verify_abc123.png"

        with (
            patch.dict(sys.modules, {"playwright": ModuleType("playwright"), "playwright.sync_api": fake_module}),
            patch("src.recon.vulnerability_analysis.active_scan.xss_verifier.settings", _mock_settings()),
            patch(
                "src.recon.vulnerability_analysis.active_scan.xss_verifier._upload_screenshot",
                return_value=expected_key,
            ),
        ):
            result = verify_xss_with_browser(TARGET_URL, PARAM, PAYLOAD, SCAN_ID, tenant_id=TENANT_ID)

        assert result.verified is True
        assert result.screenshot_key == expected_key


class TestHelperFunctions:
    """Utility function tests."""

    def test_build_verification_url_injects_payload(self) -> None:
        url = _build_verification_url("https://ex.test/page?q=old&x=1", "q", "INJECTED")
        assert url is not None
        assert "q=INJECTED" in url
        assert "x=1" in url

    def test_build_verification_url_invalid_scheme(self) -> None:
        assert _build_verification_url("ftp://x.test/?q=1", "q", "p") is None

    def test_build_verification_url_empty_param(self) -> None:
        assert _build_verification_url("https://x.test/?q=1", "", "p") is None

    def test_extract_snippet_finds_payload(self) -> None:
        html = "A" * 300 + PAYLOAD + "B" * 300
        snippet = _extract_snippet(html, PAYLOAD)
        assert snippet is not None
        assert PAYLOAD in snippet
        assert len(snippet) <= len(PAYLOAD) + 500

    def test_extract_snippet_missing_payload(self) -> None:
        assert _extract_snippet("<html>nothing</html>", "NOT_HERE") is None
