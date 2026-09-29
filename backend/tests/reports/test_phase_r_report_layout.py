"""Part III Phase R — canonical HTML report layout: cover, tiles, page numbers, cards."""

from __future__ import annotations

from datetime import UTC, datetime

from src.reports.renderers import render_html
from src.reports.report_document import ReportFinding, ReportPoC, build_report_document

_TS = datetime(2026, 1, 1, tzinfo=UTC)


def _doc():
    return build_report_document(
        scan_id="scan-1",
        tenant_id="t1",
        target="https://target.example",
        findings=[
            ReportFinding(
                finding_id="F-1",
                title="SQL Injection in /search",
                severity="high",
                verification_status="confirmed",
                description="The q parameter is injectable via boolean and error-based vectors.",
                evidence_ids=["E-1"],
                validator_id="sqlmap",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cvss_score=9.8,
                poc=ReportPoC(discriminator="SQL error", negative_control="clean 200"),
            )
        ],
        generated_at=_TS,
    )


def test_html_has_cover_and_metric_tiles():
    html = render_html(_doc())
    assert 'class="cover"' in html
    assert 'class="tile"' in html
    assert "CONFIDENTIAL" in html
    assert "PREPARED FOR" in html
    assert "SCAN ID" in html


def test_html_has_page_number_running_footer():
    html = render_html(_doc())
    assert "@page" in html
    assert "counter(page)" in html and "counter(pages)" in html
    assert "Page " in html  # 'Page ' counter(page) ' of ' counter(pages)


def test_html_metric_tiles_are_not_flex():
    # Phase V — content layout must be print-safe (WeasyPrint cannot fragment flex).
    html = render_html(_doc())
    assert ".tile{display:inline-block" in html
    assert "display:flex" not in html
    assert "display:grid" not in html


def test_finding_card_has_section_blocks_and_discriminator():
    html = render_html(_doc())
    assert 'class="finding-card"' in html
    assert "What We Found" in html
    assert "Evidence" in html
    assert "Recommended Remediation" in html or "F-1" in html  # remediation absent here
    assert "discriminator" in html
    assert "negative_control" in html


def test_finding_card_shows_cvss_vector():
    html = render_html(_doc())
    assert "AV:N/AC:L" in html
