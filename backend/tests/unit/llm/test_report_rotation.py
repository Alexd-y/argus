"""WP C — in-process report-role LLM rotation for the facade dispatch.

Rotation applies ONLY to report/cloud-eligible tasks (never pentest analysis —
WRB-001). The cursor advances per scan, giving A,B,A,B across successive
report-eligible calls within one scan, and is keyed by scan so two scans rotate
independently.
"""

from __future__ import annotations

import pytest
from src.llm.report_rotation import pick_report_rotation_alias, reset_report_rotation


@pytest.fixture(autouse=True)
def _clean():
    reset_report_rotation()
    yield
    reset_report_rotation()


def test_rotates_a_b_a_b_within_a_scan() -> None:
    opts = {"llm_rotate": True, "llm_profile_ids": ["A", "B"]}
    seq = [pick_report_rotation_alias(opts, scan_id="s1", eligible=True) for _ in range(4)]
    assert seq == ["A", "B", "A", "B"]


def test_scans_rotate_independently() -> None:
    opts = {"llm_rotate": True, "llm_profile_ids": ["A", "B", "C"]}
    assert pick_report_rotation_alias(opts, scan_id="s1", eligible=True) == "A"
    assert pick_report_rotation_alias(opts, scan_id="s2", eligible=True) == "A"
    assert pick_report_rotation_alias(opts, scan_id="s1", eligible=True) == "B"


def test_not_eligible_returns_none() -> None:
    # Analysis tasks are never rotated (WRB-001): eligible=False short-circuits.
    opts = {"llm_rotate": True, "llm_profile_ids": ["A", "B"]}
    assert pick_report_rotation_alias(opts, scan_id="s1", eligible=False) is None


def test_rotate_off_returns_none() -> None:
    opts = {"llm_rotate": False, "llm_profile_ids": ["A", "B"]}
    assert pick_report_rotation_alias(opts, scan_id="s1", eligible=True) is None


def test_empty_or_missing_chain_returns_none() -> None:
    assert (
        pick_report_rotation_alias(
            {"llm_rotate": True, "llm_profile_ids": []}, scan_id="s", eligible=True
        )
        is None
    )
    assert pick_report_rotation_alias(None, scan_id="s", eligible=True) is None
    assert pick_report_rotation_alias({}, scan_id="s", eligible=True) is None


def test_accepts_object_with_attrs() -> None:
    class _Opts:
        llm_rotate = True
        llm_profile_ids = ["X", "Y"]

    assert pick_report_rotation_alias(_Opts(), scan_id="s1", eligible=True) == "X"
    assert pick_report_rotation_alias(_Opts(), scan_id="s1", eligible=True) == "Y"


def test_single_member_chain_is_stable() -> None:
    opts = {"llm_rotate": True, "llm_profile_ids": ["ONLY"]}
    assert [pick_report_rotation_alias(opts, scan_id="s1", eligible=True) for _ in range(3)] == [
        "ONLY",
        "ONLY",
        "ONLY",
    ]
