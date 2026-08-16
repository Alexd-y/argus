"""QUICK-001 / QUICK-010 — ARGUS_QUICK_MODE_ENABLED defaults fail-closed."""

from __future__ import annotations

import pytest

from src.core.config import Settings


def test_quick_mode_enabled_defaults_false(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ARGUS_QUICK_MODE_ENABLED", raising=False)
    monkeypatch.delenv("quick_mode_enabled", raising=False)
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    assert settings.quick_mode_enabled is False


def test_quick_mode_enabled_empty_env_is_false(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ARGUS_QUICK_MODE_ENABLED", "")
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    assert settings.quick_mode_enabled is False


@pytest.mark.parametrize("raw", ["true", "1", "yes", "on", "TRUE"])
def test_quick_mode_enabled_env_override_true(
    monkeypatch: pytest.MonkeyPatch, raw: str
) -> None:
    monkeypatch.setenv("ARGUS_QUICK_MODE_ENABLED", raw)
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    assert settings.quick_mode_enabled is True
