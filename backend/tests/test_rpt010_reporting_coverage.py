"""RPT-010 — Extra coverage for src/reports/* and src/services/reporting.py."""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.orchestration.prompt_registry import EXPLOITATION
from src.recon.stage_object_download import StageObjectFetchError
from src.reports import data_collector as dc
from src.reports.data_collector import ScanReportData
from src.api.schemas import ReportSummary
from src.reports.generators import (
    PhaseOutputEntry,
    ReportData,
    TimelineEntry,
    build_report_data_from_scan_report,
)
from src.reports.jinja_minimal_context import minimal_jinja_context_from_report_data
from src.reports.report_pipeline import (
    normalize_generation_formats,
    resolve_scan_id_for_report,
    run_generate_report_pipeline,
)
from src.services.reporting import (
    ReportGenerator,
    exploitation_outputs_for_jinja,
    findings_rows_for_jinja,
    recon_summary_for_jinja,
)


class _FakeResult:
    def __init__(self, *, scalar=None, rows=None) -> None:
        self._scalar = scalar
        self._rows = rows if rows is not None else []

    def scalar_one_or_none(self):
        return self._scalar

    def scalars(self):
        rows = self._rows

        class _S:
            def all(self_inner):
                return rows

        return _S()


class TestDecodeAndShapeArtifact:
    def test_json_ok(self) -> None:
        item = dc._decode_and_shape_artifact("x.json", "s1", b'{"a": 1}')
        assert item.json_value == {"a": 1}
        assert item.error is None

    def test_json_parse_error(self) -> None:
        item = dc._decode_and_shape_artifact("x.json", "s1", b"{not json")
        assert item.error == "json_parse_error"

    def test_md_preview(self) -> None:
        item = dc._decode_and_shape_artifact("n.md", "s1", b"# hi")
        assert item.text_preview == "# hi"

    def test_payload_too_large_non_json(self) -> None:
        big = b"x" * (dc._MAX_TEXT_BYTES + 1)
        item = dc._decode_and_shape_artifact("huge.txt", "s1", big)
        assert item.error == "payload_too_large"

    def test_decode_error(self) -> None:
        item = dc._decode_and_shape_artifact("b.bin", "s1", b"\xff\xfe\x00")
        assert item.error == "decode_error"

    def test_binary_skipped(self) -> None:
        item = dc._decode_and_shape_artifact("f.dat", "s1", b"not a known text artifact type")
        assert item.error == "binary_skipped"

    def test_large_md_payload_too_large(self) -> None:
        body = b"x" * (dc._MAX_TEXT_BYTES + 10)
        item = dc._decode_and_shape_artifact("t.md", "s1", body)
        assert item.error == "payload_too_large"


class TestFetchStageFile:
    def test_success(self) -> None:
        item = dc._fetch_stage_file("sid", "st", "a.json", lambda _s, _f: b'{"k":1}')
        assert item.fetched is True
        assert item.json_value == {"k": 1}

    def test_not_found(self) -> None:
        item = dc._fetch_stage_file("sid", "st", "a.json", lambda _s, _f: None)
        assert item.error == "not_found"

    def test_stage_fetch_error(self) -> None:
        def boom(_s, _f):
            raise StageObjectFetchError("storage_error")

        item = dc._fetch_stage_file("sid", "st", "a.json", boom)
        assert item.fetched is False
        assert item.error == "storage_error"

    def test_generic_exception(self) -> None:
        def boom(_s, _f):
            raise RuntimeError("x")

        item = dc._fetch_stage_file("sid", "st", "a.json", boom)
        assert item.error == "fetch_failed"

    def test_valueerror_propagates(self) -> None:
        def bad(_s, _f):
            raise ValueError("invalid")

        with pytest.raises(ValueError, match="invalid"):
            dc._fetch_stage_file("sid", "st", "a.json", bad)

    def test_valueerror_propagates_caller_contract(self) -> None:
        def bad(_s, _f):
            raise ValueError("caller contract")

        with pytest.raises(ValueError, match="caller contract"):
            dc._fetch_stage_file("sid", "st", "a.json", bad)


@pytest.mark.asyncio
async def test_collect_async_scan_missing() -> None:
    session = MagicMock()
    session.execute = AsyncMock(return_value=_FakeResult(scalar=None))
    out = await dc.ReportDataCollector().collect_async(session, "t1", "missing", include_minio=False)
    assert out.scan is None
    assert out.scan_id == "missing"


@pytest.mark.asyncio
async def test_collect_async_full_no_minio() -> None:
    now = datetime.now(timezone.utc)
    scan_orm = SimpleNamespace(
        id="sc1",
        tenant_id="t1",
        target_id=None,
        target_url="https://a.test",
        status="done",
        progress=100,
        phase="reporting",
        options={},
        created_at=now,
        updated_at=now,
    )
    tl = SimpleNamespace(phase="recon", order_index=0, entry={"x": 1}, created_at=now)
    pi = SimpleNamespace(phase="recon", input_data={}, created_at=now)
    po = SimpleNamespace(phase=(EXPLOITATION or "exploitation"), output_data={"shell": True}, created_at=now)
    fin = SimpleNamespace(
        id="f1",
        tenant_id="t1",
        scan_id="sc1",
        report_id=None,
        severity="high",
        title="T",
        description="D",
        cwe="79",
        cvss=5.0,
        created_at=now,
    )

    exec_order = [
        _FakeResult(scalar=scan_orm),
        _FakeResult(rows=[tl]),
        _FakeResult(rows=[pi]),
        _FakeResult(rows=[po]),
        _FakeResult(rows=[]),  # tool_runs (ToolRunModel)
        _FakeResult(rows=[fin]),
    ]
    session = MagicMock()
    session.execute = AsyncMock(side_effect=exec_order)

    out = await dc.ReportDataCollector().collect_async(session, "t1", "sc1", include_minio=False)
    assert out.scan and out.scan.target_url == "https://a.test"
    assert len(out.timeline) == 1
    assert len(out.findings) == 1
    assert len(out.stage1.items) == 0


@pytest.mark.asyncio
async def test_collect_async_with_report_id() -> None:
    now = datetime.now(timezone.utc)
    scan_orm = SimpleNamespace(
        id="sc1",
        tenant_id="t1",
        target_id=None,
        target_url="https://a.test",
        status="done",
        progress=100,
        phase="reporting",
        options=None,
        created_at=now,
        updated_at=now,
    )
    rep_orm = SimpleNamespace(
        id="r1",
        tenant_id="t1",
        target="https://a.test",
        scan_id="sc1",
        tier="valhalla",
        generation_status="pending",
        template_version="v1",
        prompt_version="p1",
        summary={"critical": 1},
        technologies=["nginx"],
        created_at=now,
    )
    exec_order = [
        _FakeResult(scalar=scan_orm),
        _FakeResult(scalar=rep_orm),
        _FakeResult(rows=[]),
        _FakeResult(rows=[]),
        _FakeResult(rows=[]),
        _FakeResult(rows=[]),  # tool_runs
        _FakeResult(rows=[]),
    ]
    session = MagicMock()
    session.execute = AsyncMock(side_effect=exec_order)

    out = await dc.ReportDataCollector().collect_async(
        session, "t1", "sc1", report_id="r1", include_minio=False
    )
    assert out.report and out.report.tier == "valhalla"


def test_normalize_generation_formats_dict_keys_fallback() -> None:
    out = normalize_generation_formats(None, {"pdf", "html", "nope"})  # type: ignore[arg-type]
    assert "pdf" in out and "html" in out


def test_safe_error_message_empty_body() -> None:
    from src.reports.report_pipeline import safe_report_task_error_message

    assert safe_report_task_error_message(ValueError()) == "ValueError"


@pytest.mark.asyncio
async def test_resolve_scan_id_from_finding() -> None:
    report = SimpleNamespace(scan_id=None, tenant_id="t1")
    session = MagicMock()
    res = MagicMock()
    res.first = MagicMock(return_value=("sc-from-finding",))
    session.execute = AsyncMock(return_value=res)
    sid = await resolve_scan_id_for_report(session, "r1", report, None)
    assert sid == "sc-from-finding"


@pytest.mark.asyncio
async def test_run_pipeline_tenant_mismatch() -> None:
    report = SimpleNamespace(id="r1", tenant_id="other", scan_id="s1", tier="midgard", requested_formats=None)
    session = MagicMock()
    session.execute = AsyncMock(return_value=MagicMock(scalar_one_or_none=lambda: report))
    session.commit = AsyncMock()
    out = await run_generate_report_pipeline(
        session,
        report_id="r1",
        tenant_id="t1",
        scan_id_hint=None,
        formats=["html"],
        upload_fn=lambda *a, **k: "k",
        ensure_bucket_fn=lambda: True,
    )
    assert out["status"] == "failed"
    assert out.get("error") == "Tenant mismatch"


@pytest.mark.asyncio
async def test_run_pipeline_missing_scan_id() -> None:
    report = SimpleNamespace(id="r1", tenant_id="t1", scan_id=None, tier="midgard", requested_formats=None)
    session = MagicMock()

    class _ReportResult:
        def scalar_one_or_none(self):
            return report

    class _FindingResult:
        def first(self):
            return None

    session.execute = AsyncMock(side_effect=[_ReportResult(), _FindingResult(), MagicMock()])
    session.commit = AsyncMock()
    out = await run_generate_report_pipeline(
        session,
        report_id="r1",
        tenant_id="t1",
        scan_id_hint=None,
        formats=["html"],
        upload_fn=lambda *a, **k: "k",
        ensure_bucket_fn=lambda: True,
    )
    assert out["status"] == "failed"
    assert "scan" in (out.get("error") or "").lower()


def test_reporting_jinja_helpers() -> None:
    from src.reports.data_collector import (
        FindingRow,
        PhaseOutputRow,
        ReportRowSlice,
        ScanReportData,
        ScanRowData,
        TimelineRow,
    )

    data = ScanReportData(
        scan_id="s",
        tenant_id="t",
        scan=ScanRowData(
            id="s",
            tenant_id="t",
            target_id=None,
            target_url="https://x",
            status="x",
            progress=1,
            phase="p",
            options=None,
        ),
        report=ReportRowSlice(
            id="r",
            tenant_id="t",
            target="https://x",
            scan_id="s",
            tier="midgard",
            generation_status="ready",
            summary={"critical": 2, "high": 1},
            technologies=["a", "b"],
        ),
        timeline=[
            TimelineRow(phase="recon", order_index=1, entry={"msg": "hello world " * 50}, created_at=None)
        ],
        phase_outputs=[
            PhaseOutputRow(phase=(EXPLOITATION or "exploitation"), output_data={"k": 1}, created_at=None)
        ],
        findings=[
            FindingRow(
                id="f",
                tenant_id="t",
                scan_id="s",
                report_id="r",
                severity="high",
                title="T",
                description="D",
                cwe="89",
                cvss=8.0,
            )
        ],
    )
    rows = findings_rows_for_jinja(data)
    assert rows[0]["severity"] == "high"
    rec = recon_summary_for_jinja(data)
    assert rec["summary_counts"]["critical"] == 2
    assert rec["findings_count"] == 1
    assert len(rec["timeline_preview"][0]["snippet"]) <= 240
    ex = exploitation_outputs_for_jinja(data)
    assert len(ex) == 1


def test_minimal_jinja_context_valhalla_executive() -> None:
    rd = ReportData(
        report_id="r",
        target="https://z",
        summary=ReportSummary(),
        findings=[],
        technologies=[],
        scan_id="s",
        executive_summary="Exec",
        remediation=["step1"],
        ai_insights=["insight"],
        timeline=[
            TimelineEntry(phase="recon", order_index=0, entry={"a": 1}, created_at=None),
        ],
        phase_outputs=[
            PhaseOutputEntry(phase=(EXPLOITATION or "exploitation"), output_data={"x": 1}),
        ],
    )
    ctx = minimal_jinja_context_from_report_data(rd, "valhalla")
    assert ctx["tier"] == "valhalla"
    assert ctx["jinja"]["valhalla"]["active"] is True
    slots = ctx["jinja"]["valhalla"]["slots"]
    assert slots.get("executive_summary_valhalla") == "Exec"
    assert "exploitation" in ctx and len(ctx["exploitation"]) == 1
    ai = ctx["ai_sections"]
    for key in (
        "attack_scenarios",
        "exploit_chains",
        "remediation_stages",
        "zero_day_potential",
    ):
        assert key in ai and isinstance(ai[key], str)
    assert "appendix_tools" in ctx["valhalla_context"]
    assert ctx["tool_runs"] == []


def test_build_report_data_from_scan_report_summary_branches() -> None:
    from src.reports.data_collector import ReportRowSlice, ScanReportData

    data = ScanReportData(
        scan_id="s",
        tenant_id="t",
        report=ReportRowSlice(
            id="rid",
            tenant_id="t",
            target="https://t",
            scan_id="s",
            tier="midgard",
            generation_status="ready",
            summary={
                "executive_summary": "From summary",
                "remediation": ["A", "B"],
                "ai_insights": ["i1"],
            },
            technologies=None,
        ),
    )
    rd = build_report_data_from_scan_report(data)
    assert rd.executive_summary == "From summary"
    assert rd.remediation == ["A", "B"]
    assert rd.ai_insights == ["i1"]


def test_build_report_data_exec_summary_dict_stringify() -> None:
    from src.reports.data_collector import ReportRowSlice, ScanReportData

    data = ScanReportData(
        scan_id="s",
        tenant_id="t",
        report=ReportRowSlice(
            id="rid",
            tenant_id="t",
            target="https://t",
            scan_id="s",
            tier="midgard",
            generation_status="ready",
            summary={"executive_summary": {"nested": True}},
            technologies=None,
        ),
    )
    rd = build_report_data_from_scan_report(data)
    assert "nested" in (rd.executive_summary or "")


def test_storage_ensure_bucket_delegates() -> None:
    with patch("src.reports.storage._ensure_bucket_named", return_value=True) as m:
        from src.reports import storage as rs

        assert rs.ensure_bucket() is True
        m.assert_called_once()


@pytest.mark.asyncio
async def test_shape_failed_branch(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a, **_k):
        raise AssertionError("shape")

    monkeypatch.setattr(dc, "_decode_and_shape_artifact", boom)
    item = dc._fetch_stage_file("sid", "st", "a.json", lambda _s, _f: b"{}")
    assert item.error == "shape_failed"
    assert item.fetched is True


def test_serialize_requested_formats_helper() -> None:
    from src.api.routers.reports import _serialize_requested_formats

    assert _serialize_requested_formats(None) is None
    assert _serialize_requested_formats(["pdf", "html"]) == ["pdf", "html"]
    assert _serialize_requested_formats({"formats": ["json"]}) == ["json"]
    assert _serialize_requested_formats({"other": 1}) is None


@pytest.mark.asyncio
async def test_resolve_scan_id_whitespace_hint() -> None:
    report = SimpleNamespace(scan_id=None, tenant_id="t1")
    session = MagicMock()
    session.execute = AsyncMock(return_value=MagicMock(first=lambda: None))
    sid = await resolve_scan_id_for_report(session, "r1", report, "   ")
    assert sid is None


class _ExecScalar:
    def __init__(self, scalar: object) -> None:
        self._scalar = scalar

    def scalar_one_or_none(self) -> object:
        return self._scalar


@pytest.mark.asyncio
async def test_run_pipeline_upload_empty_key_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    import src.reports.report_pipeline as rp
    from src.services.reporting import ReportContextBuildResult

    report = SimpleNamespace(
        id="rep-a",
        tenant_id="ten-a",
        scan_id="scan-a",
        tier="midgard",
        requested_formats=None,
    )
    built = ReportContextBuildResult(
        scan_report_data=ScanReportData(scan_id="scan-a", tenant_id="ten-a", findings=[]),
        template_context={},
        ai_section_results={"executive_summary": {"status": "ok", "text": "x"}},
    )

    async def fake_build_context(self, session, tenant_id, scan_id, tier, **kwargs):  # noqa: ANN001
        return built

    monkeypatch.setattr(rp.ReportGenerator, "build_context", fake_build_context)
    monkeypatch.setattr(rp, "generate_html", lambda *a, **k: b"<html/>")

    exec_results = [
        _ExecScalar(report),
        MagicMock(),
        _ExecScalar(None),
        MagicMock(),
    ]
    session = MagicMock()
    session.execute = AsyncMock(side_effect=exec_results)
    session.commit = AsyncMock()

    out = await run_generate_report_pipeline(
        session,
        report_id="rep-a",
        tenant_id="ten-a",
        scan_id_hint=None,
        formats=["html"],
        upload_fn=lambda *a, **k: "",
        ensure_bucket_fn=lambda: True,
        redis_client=MagicMock(),
    )
    assert out["status"] == "failed"
    assert out.get("error") == "generation_failed"


def test_to_generator_valhalla_executive_preference() -> None:
    from src.orchestration.prompt_registry import REPORT_AI_SECTION_EXECUTIVE_SUMMARY_VALHALLA

    gen = ReportGenerator()
    rd = gen.to_generator_report_data(
        ScanReportData(scan_id="s", tenant_id="t"),
        {
            REPORT_AI_SECTION_EXECUTIVE_SUMMARY_VALHALLA: "Valhalla exec",
            "vulnerability_description": "vd",
        },
    )
    assert rd.executive_summary == "Valhalla exec"


@pytest.mark.asyncio
async def test_collect_async_minio_all_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dc, "download_stage1_artifact", lambda _s, _f: None)
    monkeypatch.setattr(dc, "download_stage2_artifact", lambda _s, _f: None)
    monkeypatch.setattr(dc, "download_stage3_artifact", lambda _s, _f: None)
    monkeypatch.setattr(dc, "download_stage4_artifact", lambda _s, _f: None)

    now = datetime.now(timezone.utc)
    scan_orm = SimpleNamespace(
        id="sc1",
        tenant_id="t1",
        target_id=None,
        target_url="https://a.test",
        status="done",
        progress=100,
        phase="reporting",
        options={},
        created_at=now,
        updated_at=now,
    )
    exec_order = [
        _FakeResult(scalar=scan_orm),
        _FakeResult(rows=[]),
        _FakeResult(rows=[]),
        _FakeResult(rows=[]),
        _FakeResult(rows=[]),  # tool_runs
        _FakeResult(rows=[]),
    ]
    session = MagicMock()
    session.execute = AsyncMock(side_effect=exec_order)

    out = await dc.ReportDataCollector().collect_async(session, "t1", "sc1", include_minio=True)
    assert len(out.stage1.items) >= 1
    assert all(x.error == "not_found" for x in out.stage1.items)


def test_get_report_jinja_environment_autoescape() -> None:
    from src.reports.template_env import get_report_jinja_environment

    env = get_report_jinja_environment()
    assert env.autoescape is True


def test_recon_summary_prefers_report_target_without_scan() -> None:
    from src.reports.data_collector import ReportRowSlice

    data = ScanReportData(
        scan_id="s",
        tenant_id="t",
        scan=None,
        report=ReportRowSlice(
            id="r",
            tenant_id="t",
            target="https://from-report-only",
            scan_id="s",
            tier="midgard",
            generation_status="ready",
            summary=None,
            technologies=None,
        ),
    )
    rec = recon_summary_for_jinja(data)
    assert rec["target_url"] == "https://from-report-only"


def test_prepare_template_context_merges_extra() -> None:
    from src.reports.data_collector import ScanRowData

    data = ScanReportData(
        scan_id="s1",
        tenant_id="t1",
        scan=ScanRowData(
            id="s1",
            tenant_id="t1",
            target_id=None,
            target_url="https://x",
            status="done",
            progress=100,
            phase="reporting",
            options=None,
        ),
    )
    gen = ReportGenerator()
    ctx = gen.prepare_template_context("midgard", data, {}, extra={"custom_key": 42})
    assert ctx["custom_key"] == 42
