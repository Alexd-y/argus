"""RPT-006 — Canonical export bundle parity: JSON / CSV / HTML / PDF share finding content.

Uses a synthetic :class:`ScanReportData` with ``FindingRow.report_id is None`` (scan-scoped
finding) plus a mocked :meth:`ReportGenerator.build_context` so no live DB or MinIO is
required. Asserts full ``jinja_context`` from :func:`build_report_export_payload` includes
fields omitted by :func:`offline_minimal_jinja_context_from_report_data` (e.g. ``report_language``).
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest

from src.reports.data_collector import (
    FindingRow,
    ReportRowSlice,
    ScanReportData,
    ScanRowData,
)
from src.reports.generators import (
    generate_csv,
    generate_html,
    generate_json,
    generate_pdf,
)
from src.reports.jinja_minimal_context import offline_minimal_jinja_context_from_report_data
from src.services.reporting import (
    ReportContextBuildResult,
    ReportGenerator,
    build_report_export_payload,
    build_scan_artifacts_section_context,
)
from tests.weasyprint_skips import WSP_REASON, WSP_SKIP

_RPT006_CVE = "CVE-2021-44228"
_RPT006_TITLE = f"{_RPT006_CVE} Log4j (scan-scoped row)"
_TENANT = "tenant-rpt006"
_SCAN_ID = "scan-rpt006"
_REPORT_ID = "report-rpt006"


def _rpt006_scan_report_with_scan_only_finding() -> ScanReportData:
    """One finding: ``report_id`` NULL at row level, ``scan_id`` matches report (collector semantics)."""
    now = datetime.now(UTC)
    finding = FindingRow(
        id="fin-rpt006-scanonly",
        tenant_id=_TENANT,
        scan_id=_SCAN_ID,
        report_id=None,
        severity="critical",
        title=_RPT006_TITLE,
        description="JNDI lookup to attacker host",
        cwe="CWE-502",
        cvss=10.0,
    )
    scan = ScanRowData(
        id=_SCAN_ID,
        tenant_id=_TENANT,
        target_id="tar-rpt006",
        target_url="https://scan-parity.rpt006.example",
        status="succeeded",
        progress=100,
        phase="complete",
        options={},
        created_at=now,
        updated_at=now,
    )
    report = ReportRowSlice(
        id=_REPORT_ID,
        tenant_id=_TENANT,
        target="https://scan-parity.rpt006.example",
        scan_id=_SCAN_ID,
        tier="midgard",
        generation_status="ready",
        summary={
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        },
    )
    return ScanReportData(
        scan_id=_SCAN_ID,
        tenant_id=_TENANT,
        scan=scan,
        report=report,
        findings=[finding],
    )


def _build_full_template_context(
    data: ScanReportData,
) -> dict[str, object]:
    """Same shape as a real :meth:`ReportGenerator.build_context` result (incl. ``scan_artifacts``)."""
    gen = ReportGenerator()
    text_map = gen.ai_results_to_text_map({})
    extra = {
        "scan_artifacts": build_scan_artifacts_section_context(
            _TENANT,
            _SCAN_ID,
            attempt_listing=False,
        )
    }
    return gen.prepare_template_context("midgard", data, text_map, extra=extra)


@pytest.fixture
def rpt006_built() -> ReportContextBuildResult:
    data = _rpt006_scan_report_with_scan_only_finding()
    tctx = _build_full_template_context(data)
    return ReportContextBuildResult(
        scan_report_data=data,
        template_context=dict(tctx),
        ai_section_results={},
    )


@pytest.mark.asyncio
async def test_build_report_export_payload_finds_scan_only_finding_and_full_jinja(
    monkeypatch: pytest.MonkeyPatch, rpt006_built: ReportContextBuildResult
) -> None:
    async def _fake_build_context(
        _self: ReportGenerator, *_a: object, **_k: object
    ) -> ReportContextBuildResult:
        return rpt006_built

    monkeypatch.setattr(ReportGenerator, "build_context", _fake_build_context)
    monkeypatch.setattr("src.core.redis_client.get_redis", lambda: MagicMock())

    session = MagicMock()
    report_data, jctx = await build_report_export_payload(
        session,
        tenant_id=_TENANT,
        report_id=_REPORT_ID,
        scan_id=_SCAN_ID,
        tier="midgard",
    )

    assert len([f for f in rpt006_built.scan_report_data.findings if f.report_id is None]) == 1
    assert any(_RPT006_CVE in (f.title or "") for f in report_data.findings)

    # Full pipeline jinja: settings-backed + recon counts from collector-shaped data
    assert "report_language" in jctx
    assert "tool_runs" in jctx
    assert jctx.get("recon_summary", {}).get("findings_count") == 1
    assert "scan" in (jctx.get("recon_summary") or {}) or (jctx.get("recon_summary") or {}).get(
        "target_url"
    )
    sa = jctx.get("scan_artifacts")
    assert isinstance(sa, dict) and "phase_blocks" in sa and "status" in sa

    minimal = offline_minimal_jinja_context_from_report_data(
        report_data, "midgard"
    )
    assert "report_language" not in minimal


def _assert_rpt006_marker_in_output(blob: bytes) -> None:
    text = blob.decode("utf-8", errors="replace")
    assert _RPT006_CVE in text or _RPT006_TITLE in text


@pytest.mark.parametrize(
    "generator",
    [
        ("json", lambda d, j: generate_json(d, jinja_context=j)),
        ("csv", lambda d, j: generate_csv(d, jinja_context=j)),
        ("html", lambda d, j: generate_html(d, jinja_context=j, tier="midgard")),
    ],
    ids=["json", "csv", "html"],
)
def test_rpt006_shared_finding_in_machine_and_html_outputs(
    generator: tuple[str, object], rpt006_built: ReportContextBuildResult
) -> None:
    """``generate_*`` (JSON, CSV, HTML) all contain the same finding marker when using export jinja."""
    gen = ReportGenerator()
    texts = gen.ai_results_to_text_map(rpt006_built.ai_section_results)
    report_data = gen.to_generator_report_data(
        rpt006_built.scan_report_data,
        texts,
        report_id=_REPORT_ID,
    )
    _, gen_fn = generator
    out = gen_fn(report_data, rpt006_built.template_context)  # type: ignore[misc]
    assert isinstance(out, bytes)
    _assert_rpt006_marker_in_output(out)


@pytest.mark.weasyprint_pdf
@pytest.mark.skipif(WSP_SKIP, reason=WSP_REASON)
def test_rpt006_pdf_contains_finding_marker(rpt006_built: ReportContextBuildResult) -> None:
    """PDF (WeasyPrint when available) includes the same CVE / title bytes as other formats."""
    gen = ReportGenerator()
    texts = gen.ai_results_to_text_map(rpt006_built.ai_section_results)
    report_data = gen.to_generator_report_data(
        rpt006_built.scan_report_data,
        texts,
        report_id=_REPORT_ID,
    )
    pdf = generate_pdf(
        report_data, jinja_context=rpt006_built.template_context, tier="midgard"
    )
    assert isinstance(pdf, bytes) and pdf.startswith(b"%PDF")
    # Text extraction: CVE id or title substring should appear in content stream
    assert _RPT006_CVE.encode() in pdf or b"Log4j" in pdf
