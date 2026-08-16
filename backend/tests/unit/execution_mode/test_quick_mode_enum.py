"""QUICK-001 — ExecutionMode.QUICK enum, parse, immutability, legacy coerce."""

from __future__ import annotations

import pytest

from src.execution_mode import (
    ALLOWED_EXECUTION_MODES,
    ExecutionMode,
    ExecutionModeImmutableError,
    ModeContext,
    assert_mode_immutable,
    coerce_legacy_mode_field,
    parse_execution_mode,
)
from src.execution_mode.mode import ExecutionMode as CanonicalExecutionMode
from src.llm.schemas import ExecutionMode as LlmExecutionMode


def test_quick_value_is_quick() -> None:
    assert ExecutionMode.QUICK.value == "quick"
    assert ExecutionMode.QUICK is CanonicalExecutionMode.QUICK


def test_allowed_execution_modes_has_exactly_three_values() -> None:
    assert ALLOWED_EXECUTION_MODES == frozenset(
        {"production", "lab_unrestricted", "quick"}
    )
    assert len(ALLOWED_EXECUTION_MODES) == 3
    assert len(ExecutionMode) == 3


def test_parse_execution_mode_quick() -> None:
    assert parse_execution_mode("quick") is ExecutionMode.QUICK
    assert parse_execution_mode("QUICK") is ExecutionMode.QUICK
    assert parse_execution_mode("  Quick  ") is ExecutionMode.QUICK
    assert parse_execution_mode(ExecutionMode.QUICK) is ExecutionMode.QUICK


def test_parse_execution_mode_unknown_raises() -> None:
    with pytest.raises(ValueError, match="unsupported_execution_mode"):
        parse_execution_mode("stealth")


def test_mode_context_is_quick_not_lab_or_production() -> None:
    ctx = ModeContext(
        tenant_id="t-1",
        engagement_id="e-1",
        mode=ExecutionMode.QUICK,
    )
    assert ctx.is_quick is True
    assert ctx.is_lab is False
    assert ctx.is_production is False


def test_mode_context_production_and_lab_flags_unchanged() -> None:
    prod = ModeContext(
        tenant_id="t-1",
        engagement_id="e-1",
        mode=ExecutionMode.PRODUCTION,
    )
    assert prod.is_production is True
    assert prod.is_quick is False
    assert prod.is_lab is False

    lab = ModeContext(
        tenant_id="t-1",
        engagement_id="e-1",
        mode=ExecutionMode.LAB_UNRESTRICTED,
    )
    assert lab.is_lab is True
    assert lab.is_quick is False
    assert lab.is_production is False


def test_assert_mode_immutable_blocks_quick_to_lab_after_first_execution() -> None:
    with pytest.raises(ExecutionModeImmutableError, match="execution_mode_immutable"):
        assert_mode_immutable(
            ExecutionMode.QUICK,
            ExecutionMode.LAB_UNRESTRICTED,
            has_started_execution=True,
        )


def test_assert_mode_immutable_allows_same_quick_after_execution() -> None:
    assert (
        assert_mode_immutable(
            ExecutionMode.QUICK,
            "quick",
            has_started_execution=True,
        )
        is ExecutionMode.QUICK
    )


def test_assert_mode_immutable_allows_switch_before_first_execution() -> None:
    assert (
        assert_mode_immutable(
            ExecutionMode.QUICK,
            ExecutionMode.LAB_UNRESTRICTED,
            has_started_execution=False,
        )
        is ExecutionMode.LAB_UNRESTRICTED
    )


@pytest.mark.parametrize(
    "raw",
    ["quick", "QUICK", "  quick  ", "standard", "deep", "lab"],
)
def test_coerce_legacy_mode_field_scan_depth_quick_is_not_execution_mode(
    raw: str,
) -> None:
    """``mode=quick`` is scan depth (Strix-style), not ExecutionMode.QUICK."""
    assert coerce_legacy_mode_field(raw) is None


def test_coerce_legacy_mode_field_rejects_quick_enum() -> None:
    assert coerce_legacy_mode_field(ExecutionMode.QUICK) is None


def test_coerce_legacy_mode_field_accepts_legacy_execution_values() -> None:
    assert coerce_legacy_mode_field("production") is ExecutionMode.PRODUCTION
    assert coerce_legacy_mode_field("lab_unrestricted") is ExecutionMode.LAB_UNRESTRICTED
    assert coerce_legacy_mode_field(ExecutionMode.PRODUCTION) is ExecutionMode.PRODUCTION
    assert (
        coerce_legacy_mode_field(ExecutionMode.LAB_UNRESTRICTED)
        is ExecutionMode.LAB_UNRESTRICTED
    )


def test_coerce_legacy_mode_field_empty_and_unknown() -> None:
    assert coerce_legacy_mode_field(None) is None
    assert coerce_legacy_mode_field("") is None
    assert coerce_legacy_mode_field("stealth") is None


def test_llm_schemas_reexports_canonical_execution_mode() -> None:
    assert LlmExecutionMode is CanonicalExecutionMode
    assert LlmExecutionMode.QUICK is ExecutionMode.QUICK
    assert LlmExecutionMode.QUICK.value == "quick"
