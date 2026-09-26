"""Phase 10 — Cairn configuration defaults + timeout>tick validator (D-02)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from src.core.config import Settings


def test_cairn_defaults_are_off() -> None:
    s = Settings(_env_file=None)
    assert s.cairn_enabled is False
    assert s.cairn_default_engine == "pipeline"
    assert s.cairn_cli_drivers_enabled is False
    assert s.cairn_local_execution_enabled is False
    assert s.cairn_tick_interval_sec == 10
    assert s.cairn_intent_timeout_sec > s.cairn_tick_interval_sec


def test_intent_timeout_must_exceed_tick() -> None:
    with pytest.raises(ValidationError, match="cairn_intent_timeout_sec must be greater"):
        Settings(_env_file=None, cairn_intent_timeout_sec=5, cairn_tick_interval_sec=10)


def test_reason_timeout_must_exceed_tick() -> None:
    with pytest.raises(ValidationError, match="cairn_reason_timeout_sec must be greater"):
        Settings(_env_file=None, cairn_reason_timeout_sec=10, cairn_tick_interval_sec=10)


def test_valid_timeouts_accepted() -> None:
    s = Settings(
        _env_file=None,
        cairn_tick_interval_sec=5,
        cairn_intent_timeout_sec=60,
        cairn_reason_timeout_sec=60,
    )
    assert s.cairn_tick_interval_sec == 5
