"""Tests for P2-002 active injection env settings and lab preflight."""

from __future__ import annotations

import pytest

from src.core.config import Settings, lab_destructive_execution_allowed


def test_active_injection_defaults() -> None:
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.argus_active_injection_mode == "standard"
    assert s.argus_destructive_lab_mode is False
    assert s.argus_lab_allowed_targets == ""
    assert s.argus_lab_operator_id == ""
    assert s.argus_lab_signed_approval_id == ""
    assert s.argus_ai_payload_candidates == ""
    assert s.argus_ai_generated_lab_payloads is False
    assert s.argus_oast_enabled is False
    assert s.argus_kill_switch_required is True
    assert s.argus_active_injection_rate_limit_per_sec == 10.0
    assert s.argus_active_injection_timeout_sec == 120.0
    assert s.argus_active_injection_max_concurrency == 3


def test_active_injection_invalid_mode_falls_back_to_standard() -> None:
    s = Settings(_env_file=None, argus_active_injection_mode="not_a_mode")  # type: ignore[call-arg]
    assert s.argus_active_injection_mode == "standard"


@pytest.mark.parametrize(
    "mode",
    ("quick", "standard", "deep", "maximum", "lab"),
)
def test_active_injection_valid_modes(mode: str) -> None:
    s = Settings(_env_file=None, argus_active_injection_mode=mode)  # type: ignore[call-arg]
    assert s.argus_active_injection_mode == mode


def test_lab_allowed_targets_csv_normalized() -> None:
    s = Settings(
        _env_file=None,  # type: ignore[call-arg]
        argus_lab_allowed_targets=" https://a.test ,https://b.test ",
    )
    assert s.argus_lab_allowed_targets == "https://a.test ,https://b.test"


def test_lab_allowed_targets_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ARGUS_LAB_ALLOWED_TARGETS", "https://one.lab,https://two.lab")
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.argus_lab_allowed_targets == "https://one.lab,https://two.lab"


def test_destructive_lab_mode_property_still_aliases_argus_lab_mode() -> None:
    s = Settings(_env_file=None, argus_lab_mode=True)  # type: ignore[call-arg]
    assert s.destructive_lab_mode is True
    assert s.argus_destructive_lab_mode is False


def test_lab_destructive_execution_allowed_happy_path() -> None:
    s = Settings(
        _env_file=None,  # type: ignore[call-arg]
        argus_lab_mode=True,
        argus_destructive_lab_mode=True,
        sandbox_enabled=True,
        argus_lab_operator_id="operator-1",
        argus_lab_signed_approval_id="approval-sig-9f2",
        argus_lab_allowed_targets="https://lab.target",
        argus_kill_switch_required=False,
    )
    assert lab_destructive_execution_allowed(s) is True


@pytest.mark.parametrize(
    "kwargs",
    [
        {"argus_lab_mode": False},
        {"argus_destructive_lab_mode": False},
        {"sandbox_enabled": False},
        {"argus_lab_operator_id": ""},
        {"argus_lab_signed_approval_id": ""},
        {"argus_lab_allowed_targets": ""},
        {"argus_kill_switch_required": True},
    ],
)
def test_lab_destructive_execution_invalid_combo_false(kwargs: dict) -> None:
    base = dict(
        _env_file=None,
        argus_lab_mode=True,
        argus_destructive_lab_mode=True,
        sandbox_enabled=True,
        argus_lab_operator_id="op",
        argus_lab_signed_approval_id="appr",
        argus_lab_allowed_targets="https://t",
        argus_kill_switch_required=False,
    )
    base.update(kwargs)
    s = Settings(**base)  # type: ignore[arg-type]
    assert lab_destructive_execution_allowed(s) is False
