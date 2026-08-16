"""F-M08: reconciliation between the bundle-based and mode-based tool planners.

The two planners (:func:`build_va_active_scan_plan` — tech-profile driven — and
:func:`plan_tools_by_scan_mode` — quick/standard/deep) are merged at a single
point, :func:`reconcile_mode_steps_into_plan`, under one documented precedence
rule: the bundle plan is authoritative and mode steps are additive-only, keyed
on ``(tool_id, url)``. These tests pin that contract so the execution path stays
predictable for operators.
"""

from __future__ import annotations

from src.recon.vulnerability_analysis.active_scan.planner import (
    ActiveScanPlanStep,
    reconcile_mode_steps_into_plan,
)


def _step(tool_id: str, url: str, *, plan_index: int = 0, job_source: str = "bundle") -> ActiveScanPlanStep:
    return ActiveScanPlanStep(
        plan_index=plan_index,
        tool_id=tool_id,
        url=url,
        post_data=None,
        job_source=job_source,
        job_index=-1,
        extra_hints={},
        host_slug="example",
    )


def test_bundle_plan_is_authoritative_and_ordered_first() -> None:
    base = [_step("dalfox", "http://t/?q=1"), _step("sqlmap", "http://t/?q=1")]
    mode = [_step("nuclei", "http://t/?q=1", job_source="mode")]

    merged = reconcile_mode_steps_into_plan(base, mode)

    assert [(s.tool_id, s.job_source) for s in merged] == [
        ("dalfox", "bundle"),
        ("sqlmap", "bundle"),
        ("nuclei", "mode"),
    ]


def test_mode_step_colliding_on_tool_and_url_is_dropped() -> None:
    base = [_step("nuclei", "http://t/?q=1", job_source="bundle")]
    mode = [_step("nuclei", "http://t/?q=1", job_source="mode")]

    merged = reconcile_mode_steps_into_plan(base, mode)

    # Collision resolves in favour of the existing (bundle) step; no duplicate.
    assert len(merged) == 1
    assert merged[0].job_source == "bundle"


def test_same_tool_different_url_is_kept() -> None:
    base = [_step("nuclei", "http://t/?q=1")]
    mode = [_step("nuclei", "http://t/?q=2", job_source="mode")]

    merged = reconcile_mode_steps_into_plan(base, mode)

    assert {(s.tool_id, s.url) for s in merged} == {
        ("nuclei", "http://t/?q=1"),
        ("nuclei", "http://t/?q=2"),
    }


def test_duplicate_mode_steps_are_deduped_among_themselves() -> None:
    base: list[ActiveScanPlanStep] = []
    mode = [
        _step("nikto", "http://t/", job_source="mode"),
        _step("nikto", "http://t/", job_source="mode"),
    ]

    merged = reconcile_mode_steps_into_plan(base, mode)

    assert len(merged) == 1


def test_plan_index_renumbered_contiguously() -> None:
    base = [_step("dalfox", "http://t/?q=1", plan_index=7)]
    mode = [
        _step("nuclei", "http://t/?q=1", plan_index=42, job_source="mode"),
        _step("gobuster", "http://t/", plan_index=99, job_source="mode"),
    ]

    merged = reconcile_mode_steps_into_plan(base, mode)

    assert [s.plan_index for s in merged] == [0, 1, 2]


def test_inputs_not_mutated() -> None:
    base = [_step("dalfox", "http://t/?q=1")]
    mode = [_step("nuclei", "http://t/?q=1", job_source="mode")]

    reconcile_mode_steps_into_plan(base, mode)

    assert len(base) == 1
    assert len(mode) == 1


def test_empty_mode_steps_returns_renumbered_base() -> None:
    base = [_step("dalfox", "http://t/?q=1", plan_index=5)]

    merged = reconcile_mode_steps_into_plan(base, [])

    assert len(merged) == 1
    assert merged[0].plan_index == 0
    assert merged[0].tool_id == "dalfox"
