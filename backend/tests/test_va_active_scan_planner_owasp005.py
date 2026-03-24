"""OWASP-005 — deterministic VA active-scan planner from input bundle."""

from __future__ import annotations

from app.schemas.vulnerability_analysis.schemas import VulnerabilityAnalysisInputBundle
from src.recon.vulnerability_analysis.active_scan.planner import (
    DB_SQL_TOOL_SEQUENCE,
    DEFAULT_TOOL_SEQUENCE,
    artifact_slug_for_plan_step,
    build_va_active_scan_plan,
    plan_step_to_public_dict,
)
from src.recon.vulnerability_analysis.xsstrike_targets import collect_xsstrike_scan_jobs


def _fixed_bundle_no_tech() -> VulnerabilityAnalysisInputBundle:
    return VulnerabilityAnalysisInputBundle(
        engagement_id="e1",
        params_inventory=[
            {"param": "q", "full_url": "https://alpha.example.com/search"},
            {"param": "x", "full_url": "https://beta.example.com/p"},
        ],
        forms_inventory=[
            {
                "method": "POST",
                "page_url": "https://alpha.example.com/",
                "action": "/login",
                "input_name": "user",
            }
        ],
    )


def _fixed_bundle_php() -> VulnerabilityAnalysisInputBundle:
    b = _fixed_bundle_no_tech()
    return b.model_copy(
        update={
            "tech_profile": [
                {"name": "PHP", "category": "language"},
                {"product": "MySQL"},
            ]
        }
    )


def test_build_va_active_scan_plan_deterministic_repeat() -> None:
    bundle = _fixed_bundle_no_tech()
    a = build_va_active_scan_plan(bundle)
    b = build_va_active_scan_plan(bundle)
    assert a == b
    sig_a = [(s.tool_id, s.url, s.plan_index, s.job_source) for s in a]
    sig_b = [(s.tool_id, s.url, s.plan_index, s.job_source) for s in b]
    assert sig_a == sig_b


def test_build_va_active_scan_plan_public_dict_stable_json_keys() -> None:
    bundle = _fixed_bundle_no_tech()
    plan = build_va_active_scan_plan(bundle)
    d0 = plan_step_to_public_dict(plan[0])
    assert list(d0.keys()) == [
        "plan_index",
        "tool_id",
        "url",
        "job_source",
        "job_index",
        "host_slug",
        "extra_hints",
    ]
    assert "tech_signals" in d0["extra_hints"]


def test_php_stack_orders_sqlmap_first() -> None:
    plan = build_va_active_scan_plan(_fixed_bundle_php())
    assert plan
    assert plan[0].tool_id == "sqlmap"
    assert plan[0].extra_hints.get("tool_order_rationale") == "db_sql_surface"


def test_default_stack_orders_dalfox_first() -> None:
    plan = build_va_active_scan_plan(_fixed_bundle_no_tech())
    assert plan
    assert plan[0].tool_id == "dalfox"
    assert plan[0].extra_hints.get("tool_order_rationale") == "default_xss_then_fuzz"


def test_owasp002_default_sequence_includes_nuclei_gobuster_wfuzz_commix() -> None:
    plan = build_va_active_scan_plan(_fixed_bundle_no_tech())
    assert plan[0].extra_hints["tool_sequence"] == list(DEFAULT_TOOL_SEQUENCE)
    tail = ("nuclei", "gobuster", "wfuzz", "commix")
    assert DEFAULT_TOOL_SEQUENCE[-len(tail) :] == tail


def test_owasp002_db_sequence_includes_tail_after_sql_core() -> None:
    plan = build_va_active_scan_plan(_fixed_bundle_php())
    assert plan[0].extra_hints["tool_sequence"] == list(DB_SQL_TOOL_SEQUENCE)
    assert DB_SQL_TOOL_SEQUENCE[:3] == ("sqlmap", "dalfox", "ffuf")
    assert DB_SQL_TOOL_SEQUENCE[-4:] == ("nuclei", "gobuster", "wfuzz", "commix")


def test_owasp002_plan_length_respects_jobs_cap_not_tool_count() -> None:
    bundle = _fixed_bundle_no_tech()
    jobs = collect_xsstrike_scan_jobs(bundle)
    plan = build_va_active_scan_plan(bundle)
    assert len(plan) == len(jobs) * len(DEFAULT_TOOL_SEQUENCE)


def test_artifact_slugs_unique_per_step() -> None:
    plan = build_va_active_scan_plan(_fixed_bundle_no_tech())
    slugs = {artifact_slug_for_plan_step(s) for s in plan}
    assert len(slugs) == len(plan)


def test_sqlmap_step_gets_post_data_when_form_job() -> None:
    bundle = VulnerabilityAnalysisInputBundle(
        engagement_id="e",
        params_inventory=[],
        forms_inventory=[
            {
                "method": "POST",
                "page_url": "https://z.example.com/",
                "action": "/",
                "input_name": "token",
            }
        ],
    )
    plan = build_va_active_scan_plan(bundle)
    sql_steps = [s for s in plan if s.tool_id == "sqlmap"]
    assert len(sql_steps) == 1
    assert sql_steps[0].post_data is not None
    dalfox_steps = [s for s in plan if s.tool_id == "dalfox"]
    assert dalfox_steps[0].post_data is None
    commix_steps = [s for s in plan if s.tool_id == "commix"]
    assert len(commix_steps) == 1
    assert commix_steps[0].post_data is not None
