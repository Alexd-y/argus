"""HIBP Pwned Passwords k-anonymity hook (opt-in)."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from src.data_sources.hibp_pwned_passwords import (
    collect_password_candidates_from_structure,
    summarize_pwned_passwords_for_report,
)


def test_collect_password_candidates_max():
    blob = {
        "exploits": [{"password": "secret1"}, {"other": {"user_password": "secret2"}}],
        "evidence": [{"pwd": "x"}],
    }
    found = collect_password_candidates_from_structure(blob, max_values=3)
    assert "secret1" in found
    assert "secret2" in found


@pytest.mark.asyncio
async def test_summarize_returns_none_without_opt_in():
    mock_settings = SimpleNamespace(hibp_password_check_opt_in=False)
    with patch("src.data_sources.hibp_pwned_passwords.settings", mock_settings):
        out = await summarize_pwned_passwords_for_report({"exploits": [{"password": "x"}]})
        assert out is None


@pytest.mark.asyncio
async def test_summarize_opt_in_no_passwords():
    mock_settings = SimpleNamespace(hibp_password_check_opt_in=True)
    with patch("src.data_sources.hibp_pwned_passwords.settings", mock_settings):
        out = await summarize_pwned_passwords_for_report({"exploits": [], "evidence": []})
        assert out is not None
        assert out.get("checks_run") == 0
        assert out.get("pwned_count") == 0
        assert out.get("data_breach_password_exposure") == "unknown"
        assert "breach_signal_note" in out


@pytest.mark.asyncio
async def test_summarize_pwned_count_with_mock():
    mock_settings = SimpleNamespace(hibp_password_check_opt_in=True)
    with patch("src.data_sources.hibp_pwned_passwords.settings", mock_settings):
        with patch(
            "src.data_sources.hibp_pwned_passwords.pwned_password_usage_count",
            new_callable=AsyncMock,
        ) as mock_pwned:
            mock_pwned.return_value = 3
            out = await summarize_pwned_passwords_for_report(
                {"exploits": [{"password": "hunter2"}]},
                max_checks=2,
            )
    assert out is not None
    assert out.get("checks_run") == 1
    assert out.get("pwned_count") == 1
    assert out.get("data_breach_password_exposure") == "yes"
    assert "breach_signal_note" in out
    mock_pwned.assert_awaited()
