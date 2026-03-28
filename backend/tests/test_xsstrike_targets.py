"""Unit tests for XSStrike VA target collection (XSS-002)."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from app.schemas.vulnerability_analysis.schemas import VulnerabilityAnalysisInputBundle

from src.recon.vulnerability_analysis.xsstrike_targets import (
    MAX_XSSTRIKE_SCANS_PER_RUN,
    collect_xsstrike_scan_jobs,
)


def _minimal_bundle(
    *,
    params_inventory: list[dict[str, Any]] | None = None,
    forms_inventory: list[dict[str, Any]] | None = None,
    live_hosts: list[dict[str, Any]] | None = None,
) -> VulnerabilityAnalysisInputBundle:
    return VulnerabilityAnalysisInputBundle(
        engagement_id="e1",
        params_inventory=params_inventory or [],
        forms_inventory=forms_inventory or [],
        live_hosts=live_hosts or [],
    )


def test_collect_jobs_from_params_legacy_csv_shape() -> None:
    bundle = _minimal_bundle(
        params_inventory=[{"param": "q", "route": "/search", "host": "example.com"}],
    )
    jobs = collect_xsstrike_scan_jobs(bundle)
    assert len(jobs) == 1
    assert jobs[0].source == "params_inventory"
    assert "example.com" in jobs[0].url and "q" in jobs[0].url
    assert jobs[0].post_data is None


def test_collect_jobs_live_hosts_host_field_accepts_full_target_url() -> None:
    """Handlers used to pass live_hosts=[{host: full URL}]; scope must still match job hostname."""
    bundle = _minimal_bundle(
        params_inventory=[
            {"url": "https://alf.nu/alert1", "param": "world", "method": "GET"},
        ],
        live_hosts=[{"host": "https://alf.nu/alert1?world=alert&level=alert0"}],
    )
    jobs = collect_xsstrike_scan_jobs(bundle)
    assert len(jobs) == 1
    assert "alf.nu" in jobs[0].url
    assert "world" in jobs[0].url


def test_collect_jobs_scoped_by_live_hosts() -> None:
    bundle = _minimal_bundle(
        params_inventory=[
            {"param": "a", "route": "/", "host": "allowed.example"},
        ],
        forms_inventory=[
            {
                "page_url": "https://other.example/page",
                "action": "https://other.example/submit",
                "method": "POST",
                "input_name": "x",
            }
        ],
        live_hosts=[{"host": "allowed.example", "final_url": "https://allowed.example/"}],
    )
    jobs = collect_xsstrike_scan_jobs(bundle)
    assert len(jobs) == 1
    assert "allowed.example" in jobs[0].url


def test_collect_jobs_empty_when_no_params_or_forms() -> None:
    bundle = _minimal_bundle()
    assert collect_xsstrike_scan_jobs(bundle) == []


def test_collect_jobs_respects_max() -> None:
    rows = [
        {"param": "p", "route": f"/r{i}", "host": "example.com"} for i in range(MAX_XSSTRIKE_SCANS_PER_RUN + 5)
    ]
    bundle = _minimal_bundle(params_inventory=rows)
    jobs = collect_xsstrike_scan_jobs(bundle)
    assert len(jobs) == MAX_XSSTRIKE_SCANS_PER_RUN


def test_collect_jobs_prefers_full_url_in_params_row() -> None:
    bundle = _minimal_bundle(
        params_inventory=[
            {
                "full_url": "https://cdn.example/items?existing=1",
                "host": "ignored.example",
                "route": "/should-not-use",
                "param": "ref",
            }
        ],
    )
    jobs = collect_xsstrike_scan_jobs(bundle)
    assert len(jobs) == 1
    assert jobs[0].url.startswith("https://cdn.example/items")
    assert "ref=1" in jobs[0].url
    assert jobs[0].post_data is None


def test_collect_jobs_accepts_param_name_key() -> None:
    bundle = _minimal_bundle(
        params_inventory=[{"param_name": "q", "route": "/search", "host": "example.com"}],
    )
    jobs = collect_xsstrike_scan_jobs(bundle)
    assert len(jobs) == 1
    assert "q=1" in jobs[0].url


def test_collect_jobs_deduplicates_identical_url_and_post() -> None:
    row = {"param": "p", "route": "/same", "host": "example.com"}
    bundle = _minimal_bundle(params_inventory=[row, row])
    assert len(collect_xsstrike_scan_jobs(bundle)) == 1


def test_collect_jobs_skips_non_dict_params_rows() -> None:
    """Bundle schema requires dict rows; malformed runtime data is modeled with a duck-typed object."""
    bundle = SimpleNamespace(
        params_inventory=[
            {"param": "p", "route": "/", "host": "example.com"},
            "not-a-dict",
        ],
        forms_inventory=[],
        live_hosts=[],
    )
    jobs = collect_xsstrike_scan_jobs(bundle)  # type: ignore[arg-type]
    assert len(jobs) == 1


def test_collect_jobs_forms_get_without_post_body() -> None:
    bundle = _minimal_bundle(
        forms_inventory=[
            {
                "page_url": "https://example.com/app/",
                "action": "results",
                "method": "GET",
                "input_name": "query",
            }
        ],
    )
    jobs = collect_xsstrike_scan_jobs(bundle)
    assert len(jobs) == 1
    assert jobs[0].source == "forms_inventory"
    assert jobs[0].post_data is None
    assert jobs[0].url.startswith("https://example.com/app/")
