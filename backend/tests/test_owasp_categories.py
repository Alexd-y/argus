"""OWASP Top 10:2025 — one representative mapping per A01..A10 + Asgard HTML compliance fragment."""

from __future__ import annotations

import json
from pathlib import Path

from src.recon.vulnerability_analysis.owasp_category_map import (
    apply_owasp_category_to_intel_row,
    resolve_owasp_category,
)
from src.reports.data_collector import FindingRow, ScanReportData
from src.reports.generators import build_owasp_compliance_rows
from src.services.reporting import findings_rows_for_jinja, render_findings_table_html


def test_resolve_owasp_a01_broken_access_cwe352() -> None:
    assert resolve_owasp_category(cwe="CWE-352") == "A01"


def test_resolve_owasp_a02_misconfiguration_cwe11() -> None:
    assert resolve_owasp_category(cwe="CWE-11") == "A02"


def test_resolve_owasp_a03_supply_chain_cwe1104() -> None:
    assert resolve_owasp_category(cwe="CWE-1104") == "A03"


def test_resolve_owasp_a04_crypto_cwe321() -> None:
    assert resolve_owasp_category(cwe="CWE-321") == "A04"


def test_resolve_owasp_a05_injection_cwe79() -> None:
    assert resolve_owasp_category(cwe="CWE-79") == "A05"


def test_resolve_owasp_a06_insecure_design_cwe1068() -> None:
    assert resolve_owasp_category(cwe="CWE-1068") == "A06"


def test_resolve_owasp_cwe693_header_protection_maps_a02_misconfiguration() -> None:
    """VH-005: missing security header class (CWE-693) maps to A02 / A05:2021 display, not A06."""
    assert resolve_owasp_category(cwe="CWE-693") == "A02"


def test_resolve_owasp_a07_auth_failures_cwe287() -> None:
    assert resolve_owasp_category(cwe="CWE-287") == "A07"


def test_resolve_owasp_a08_integrity_cwe345() -> None:
    assert resolve_owasp_category(cwe="CWE-345") == "A08"


def test_resolve_owasp_a09_logging_cwe223() -> None:
    assert resolve_owasp_category(cwe="CWE-223") == "A09"


def test_resolve_owasp_a10_exceptional_conditions_cwe209() -> None:
    assert resolve_owasp_category(cwe="CWE-209") == "A10"


def test_intel_row_apply_owasp_from_cwe_in_data() -> None:
    row = {
        "finding_type": "vulnerability",
        "source_tool": "nuclei",
        "data": {"type": "custom", "cwe": "CWE-760", "url": "https://x.test/"},
    }
    apply_owasp_category_to_intel_row(row)
    assert row["owasp_category"] == "A04"


def test_asgard_findings_table_includes_owasp_compliance_section() -> None:
    data = ScanReportData(
        scan_id="s-owasp-doc",
        tenant_id="t1",
        findings=[
            FindingRow(
                id="f1",
                tenant_id="t1",
                scan_id="s-owasp-doc",
                severity="high",
                title="XSS",
                description="Reflected",
                cwe="CWE-79",
                cvss=7.2,
                owasp_category="A05",
            ),
        ],
    )
    rows_asgard = findings_rows_for_jinja(data, report_tier="asgard")
    rows_valhalla = findings_rows_for_jinja(data, report_tier="valhalla")
    owasp_ru_path = Path(__file__).resolve().parent.parent / "data" / "owasp_top_10_2025_ru.json"
    owasp_ru = json.loads(owasp_ru_path.read_text(encoding="utf-8"))
    a05_title_ru = (owasp_ru.get("A05") or {}).get("title_ru") or ""
    assert a05_title_ru, "fixture owasp_top_10_2025_ru.json must define A05.title_ru"

    html_asgard = render_findings_table_html("asgard", rows_asgard)
    html_valhalla = render_findings_table_html("valhalla", rows_valhalla)
    assert "OWASP Top 10:2025 compliance mapping" in html_asgard
    assert "owasp-compliance-table" in html_asgard
    assert "A05" in html_asgard
    assert a05_title_ru in html_asgard
    assert "owasp-compliance-table" in html_valhalla
    assert "A05" in html_valhalla
    assert a05_title_ru in html_valhalla
    assert "A05:2021" in html_valhalla


def test_build_owasp_compliance_rows_empty_findings_title_ru_nonempty() -> None:
    """Loader-backed summary fills title_ru for all A01..A10 even when there are no findings."""
    rows = build_owasp_compliance_rows([])
    assert len(rows) == 10
    for r in rows:
        tr = (r.get("title_ru") or "").strip()
        assert tr, f"title_ru must be non-empty for category {r.get('category_id')}"
