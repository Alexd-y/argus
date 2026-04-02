"""XSS-002 — XSSPayloadManager: loading, deduplication, context hints, error handling."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.recon.vulnerability_analysis.context_detector import ReflectionContextKey
from src.recon.vulnerability_analysis.active_scan.xss_payload_manager import (
    XSSPayloadManager,
    _BUILTIN_ATTRIBUTE_CONTEXT,
    _BUILTIN_DOM_CONTEXT,
    _BUILTIN_HTML_CONTEXT,
    _BUILTIN_JS_CONTEXT,
    _BUILTIN_MAP,
    _CONTEXT_CATEGORIES,
    _REFLECTION_TO_CATEGORY,
    _load_file_payloads,
)


def _fresh_manager(**settings_overrides: object) -> XSSPayloadManager:
    """Create a new manager with patched settings (no remote repos by default)."""
    mgr = XSSPayloadManager()
    return mgr


class TestReflectionToCategoryContract:
    """Contract: ``_REFLECTION_TO_CATEGORY`` keys match ``ReflectionContextKey`` (except UNKNOWN)."""

    def test_keys_match_enum_excluding_unknown(self) -> None:
        expected = {
            m.value for m in ReflectionContextKey if m is not ReflectionContextKey.UNKNOWN
        }
        assert set(_REFLECTION_TO_CATEGORY.keys()) == expected

    def test_values_are_valid_context_categories(self) -> None:
        for cat in _REFLECTION_TO_CATEGORY.values():
            assert cat in _CONTEXT_CATEGORIES


class TestBuiltinPayloadsLoaded:
    """XSS-002-T1: built-in payloads load without errors."""

    def test_builtin_payloads_loaded_without_errors(self) -> None:
        with patch(
            "src.recon.vulnerability_analysis.active_scan.xss_payload_manager.settings"
        ) as mock_settings:
            mock_settings.xss_payload_repos = ""
            mock_settings.xss_payload_collection_url = ""
            mgr = XSSPayloadManager()
            payloads = mgr.get_payloads()

        assert len(payloads) > 0
        assert "<script>alert(1)</script>" in payloads

    def test_all_builtin_categories_populated(self) -> None:
        with patch(
            "src.recon.vulnerability_analysis.active_scan.xss_payload_manager.settings"
        ) as mock_settings:
            mock_settings.xss_payload_repos = ""
            mock_settings.xss_payload_collection_url = ""
            mgr = XSSPayloadManager()
            counts = mgr.get_category_counts()

        for cat in _CONTEXT_CATEGORIES:
            assert counts[cat] >= len(_BUILTIN_MAP[cat]), (
                f"{cat} has fewer payloads than built-in minimum"
            )


class TestGetPayloadsDeduplicationAndCap:
    """XSS-002-T2: get_payloads() returns deduplicated list capped at max_payloads."""

    def test_capped_at_max_payloads(self) -> None:
        with patch(
            "src.recon.vulnerability_analysis.active_scan.xss_payload_manager.settings"
        ) as mock_settings:
            mock_settings.xss_payload_repos = ""
            mock_settings.xss_payload_collection_url = ""
            mgr = XSSPayloadManager()
            result = mgr.get_payloads(max_payloads=5)

        assert len(result) == 5

    def test_no_duplicates_in_output(self) -> None:
        with patch(
            "src.recon.vulnerability_analysis.active_scan.xss_payload_manager.settings"
        ) as mock_settings:
            mock_settings.xss_payload_repos = ""
            mock_settings.xss_payload_collection_url = ""
            mgr = XSSPayloadManager()
            result = mgr.get_payloads(max_payloads=200)

        assert len(result) == len(set(result))

    def test_max_payloads_floor_is_one(self) -> None:
        with patch(
            "src.recon.vulnerability_analysis.active_scan.xss_payload_manager.settings"
        ) as mock_settings:
            mock_settings.xss_payload_repos = ""
            mock_settings.xss_payload_collection_url = ""
            mgr = XSSPayloadManager()
            result = mgr.get_payloads(max_payloads=0)

        assert len(result) == 1


class TestContextHintFiltering:
    """XSS-002-T3: context_hint prioritises relevant payloads."""

    def test_html_context_hint_returns_html_payloads_first(self) -> None:
        with patch(
            "src.recon.vulnerability_analysis.active_scan.xss_payload_manager.settings"
        ) as mock_settings:
            mock_settings.xss_payload_repos = ""
            mock_settings.xss_payload_collection_url = ""
            mgr = XSSPayloadManager()
            result = mgr.get_payloads(context_hint="html_context", max_payloads=12)

        for builtin in _BUILTIN_HTML_CONTEXT:
            assert builtin in result, f"Expected html builtin payload: {builtin[:40]}"

    def test_alias_hint_resolves(self) -> None:
        with patch(
            "src.recon.vulnerability_analysis.active_scan.xss_payload_manager.settings"
        ) as mock_settings:
            mock_settings.xss_payload_repos = ""
            mock_settings.xss_payload_collection_url = ""
            mgr = XSSPayloadManager()
            via_alias = mgr.get_payloads(context_hint="html", max_payloads=10)
            via_full = mgr.get_payloads(context_hint="html_context", max_payloads=10)

        assert via_alias == via_full

    def test_unknown_hint_falls_back_to_all(self) -> None:
        with patch(
            "src.recon.vulnerability_analysis.active_scan.xss_payload_manager.settings"
        ) as mock_settings:
            mock_settings.xss_payload_repos = ""
            mock_settings.xss_payload_collection_url = ""
            mgr = XSSPayloadManager()
            result = mgr.get_payloads(context_hint="nonexistent_context", max_payloads=50)

        assert len(result) > 0


class TestMissingPayloadFiles:
    """XSS-002-T4: handles missing payload files gracefully."""

    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        result = _load_file_payloads(tmp_path / "nonexistent.txt")
        assert result == []

    def test_manager_works_with_missing_data_dir(self) -> None:
        fake_dir = Path("/nonexistent_xss_dir_12345")
        with (
            patch(
                "src.recon.vulnerability_analysis.active_scan.xss_payload_manager._DATA_DIR",
                fake_dir,
            ),
            patch(
                "src.recon.vulnerability_analysis.active_scan.xss_payload_manager.settings",
            ) as mock_settings,
        ):
            mock_settings.xss_payload_repos = ""
            mock_settings.xss_payload_collection_url = ""
            mgr = XSSPayloadManager()
            result = mgr.get_payloads(max_payloads=50)

        assert len(result) >= len(_BUILTIN_HTML_CONTEXT)


class TestRemoteFetchFailure:
    """XSS-002-T5: remote repo fetch failure doesn't crash."""

    def test_http_error_does_not_raise(self) -> None:
        import httpx

        def _exploding_get(*args, **kwargs):
            raise httpx.ConnectError("simulated network failure")

        with (
            patch(
                "src.recon.vulnerability_analysis.active_scan.xss_payload_manager.settings"
            ) as mock_settings,
            patch(
                "src.recon.vulnerability_analysis.active_scan.xss_payload_manager.httpx.Client"
            ) as mock_client_cls,
        ):
            mock_settings.xss_payload_repos = "https://evil.test/payloads.txt"
            mock_settings.xss_payload_collection_url = ""
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.side_effect = _exploding_get
            mock_client_cls.return_value = mock_client

            mgr = XSSPayloadManager()
            result = mgr.get_payloads(max_payloads=50)

        assert len(result) >= len(_BUILTIN_HTML_CONTEXT)

    def test_timeout_does_not_crash(self) -> None:
        import httpx

        with (
            patch(
                "src.recon.vulnerability_analysis.active_scan.xss_payload_manager.settings"
            ) as mock_settings,
            patch(
                "src.recon.vulnerability_analysis.active_scan.xss_payload_manager.httpx.Client"
            ) as mock_client_cls,
        ):
            mock_settings.xss_payload_repos = "https://slow.test/p.txt"
            mock_settings.xss_payload_collection_url = ""
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.side_effect = httpx.ReadTimeout("timeout")
            mock_client_cls.return_value = mock_client

            mgr = XSSPayloadManager()
            result = mgr.get_payloads()

        assert len(result) > 0


class TestReflectionContextHintPayloadChoice:
    """T2: ``reflection_context`` strings map to the expected primary payload category."""

    @pytest.mark.parametrize(
        ("hint", "expected_first"),
        [
            ("html_body", _BUILTIN_HTML_CONTEXT[0]),
            ("attribute_value", _BUILTIN_ATTRIBUTE_CONTEXT[0]),
            ("dom_event_handler", _BUILTIN_DOM_CONTEXT[0]),
            ("js_string", _BUILTIN_JS_CONTEXT[0]),
            ("js_block", _BUILTIN_JS_CONTEXT[0]),
            ("url_attribute", _BUILTIN_DOM_CONTEXT[0]),
        ],
    )
    def test_first_payload_matches_context_category(
        self, hint: str, expected_first: str,
    ) -> None:
        with patch(
            "src.recon.vulnerability_analysis.active_scan.xss_payload_manager.settings"
        ) as mock_settings:
            mock_settings.xss_payload_repos = ""
            mock_settings.xss_payload_collection_url = ""
            mgr = XSSPayloadManager()
            got = mgr.get_payloads(context_hint=hint, max_payloads=20)

        assert got[0] == expected_first


class TestXssPayloadCollectionUrl:
    """Optional ``XSS_PAYLOAD_COLLECTION_URL`` — JSON array merged into categories."""

    def test_json_collection_merges_string_entries(self) -> None:
        import json

        needle = "<xss-collection-unique-7f3a>alert(1)</xss-collection-unique-7f3a>"
        mock_resp = MagicMock()
        mock_resp.text = json.dumps([needle, "  ", 99])
        mock_resp.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = mock_resp

        with (
            patch(
                "src.recon.vulnerability_analysis.active_scan.xss_payload_manager.settings"
            ) as mock_settings,
            patch(
                "src.recon.vulnerability_analysis.active_scan.xss_payload_manager.httpx.Client",
                return_value=mock_client,
            ),
        ):
            mock_settings.xss_payload_repos = ""
            mock_settings.xss_payload_collection_url = "https://collection.test/payloads.json"
            mgr = XSSPayloadManager()
            payloads = mgr.get_payloads(max_payloads=300)

        assert needle in payloads

    def test_invalid_json_falls_back_to_builtins_only(self) -> None:
        mock_resp = MagicMock()
        mock_resp.text = "NOT_JSON{"
        mock_resp.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = mock_resp

        with (
            patch(
                "src.recon.vulnerability_analysis.active_scan.xss_payload_manager.settings"
            ) as mock_settings,
            patch(
                "src.recon.vulnerability_analysis.active_scan.xss_payload_manager.httpx.Client",
                return_value=mock_client,
            ),
        ):
            mock_settings.xss_payload_repos = ""
            mock_settings.xss_payload_collection_url = "https://collection.test/bad.json"
            mgr = XSSPayloadManager()
            payloads = mgr.get_payloads(max_payloads=50)

        assert len(payloads) >= len(_BUILTIN_HTML_CONTEXT)
        assert _BUILTIN_HTML_CONTEXT[0] in payloads

    @pytest.mark.parametrize(
        "blocked_url",
        [
            "file:///tmp/xss-payloads.json",
            "javascript:fetch('http://evil.test')",
        ],
    )
    def test_blocked_collection_scheme_skips_http_and_uses_builtins_only(
        self, blocked_url: str,
    ) -> None:
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        with (
            patch(
                "src.recon.vulnerability_analysis.active_scan.xss_payload_manager.settings"
            ) as mock_settings,
            patch(
                "src.recon.vulnerability_analysis.active_scan.xss_payload_manager.httpx.Client",
                return_value=mock_client,
            ),
        ):
            mock_settings.xss_payload_repos = ""
            mock_settings.xss_payload_collection_url = blocked_url
            mgr = XSSPayloadManager()
            payloads = mgr.get_payloads(max_payloads=80)

        mock_client.get.assert_not_called()
        assert len(payloads) >= len(_BUILTIN_HTML_CONTEXT)
        assert _BUILTIN_HTML_CONTEXT[0] in payloads
