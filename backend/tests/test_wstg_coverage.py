"""Test WSTG coverage map."""

from src.reports.wstg_coverage import (
    WstgCoverageResult,
    build_test_limitations,
    build_wstg_coverage,
)


def test_total_wstg_tests() -> None:
    result = build_wstg_coverage([])
    assert result.total_tests >= 90


def test_coverage_with_common_tools() -> None:
    result = build_wstg_coverage(
        ["nmap", "nikto", "nuclei", "dalfox", "sqlmap", "testssl"]
    )
    assert result.covered > 0
    assert result.coverage_percentage > 0


def test_empty_tools_zero_coverage() -> None:
    result = build_wstg_coverage([])
    assert result.covered == 0
    assert result.coverage_percentage == 0


def test_by_category_breakdown() -> None:
    result = build_wstg_coverage(["nmap", "nuclei"])
    assert len(result.by_category) > 0
    for _cat_name, cat_data in result.by_category.items():
        assert "covered" in cat_data
        assert "not_covered" in cat_data


def test_limitations_standard() -> None:
    lims = build_test_limitations({})
    assert len(lims) >= 4


def test_limitations_quick_mode() -> None:
    lims = build_test_limitations({"scan_mode": "quick"})
    assert any(
        "quick" in lim.get("description", "").lower()
        or "reduced" in lim.get("description", "").lower()
        for lim in lims
    )


def test_partial_coverage_single_tool() -> None:
    result = build_wstg_coverage(["nmap"])
    assert result.partial > 0 or result.covered > 0
    assert result.not_covered > 0


def test_coverage_result_type() -> None:
    result = build_wstg_coverage(["dalfox"])
    assert isinstance(result, WstgCoverageResult)
    assert isinstance(result.tests, list)
    assert all("id" in t and "status" in t for t in result.tests)


def test_tool_aliases_resolved() -> None:
    result_alias = build_wstg_coverage(["testssl.sh"])
    result_canonical = build_wstg_coverage(["testssl"])
    assert result_alias.covered == result_canonical.covered


def test_limitations_waf_detected() -> None:
    lims = build_test_limitations({}, scan_results={"waf_detected": True})
    assert any("WAF" in lim.get("description", "") for lim in lims)


def test_limitations_external_perspective() -> None:
    lims = build_test_limitations({"scan_perspective": "external"})
    assert any("external" in lim.get("description", "").lower() for lim in lims)
