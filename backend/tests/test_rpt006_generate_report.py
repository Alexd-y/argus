"""RPT-006 — Report pipeline helpers, Celery task/route, mocked pipeline run."""

from __future__ import annotations

import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.reports.generators import VALHALLA_SECTIONS_CSV_FORMAT
from src.reports.report_pipeline import (
    normalize_generation_formats,
    run_generate_report_pipeline,
    safe_report_task_error_message,
)


class TestRpt006FormatNormalization:
    def test_explicit_formats_filtered(self) -> None:
        assert normalize_generation_formats(["HTML", "pdf", "bad"], None) == ["html", "pdf"]

    def test_explicit_empty_uses_default(self) -> None:
        out = normalize_generation_formats([], None)
        assert set(out) == {"html", "json", "csv", "pdf"}

    def test_requested_list(self) -> None:
        assert normalize_generation_formats(None, ["json"]) == ["json"]

    def test_requested_dict_formats_key(self) -> None:
        assert normalize_generation_formats(None, {"formats": ["csv", "html"]}) == ["csv", "html"]

    def test_safe_error_truncates(self) -> None:
        long = "x" * 600
        s = safe_report_task_error_message(ValueError(long))
        assert len(s) <= 480


class TestRpt006CeleryRegistration:
    def test_generate_report_task_registered_and_routed(self) -> None:
        import src.tasks  # noqa: F401 — register tasks
        from src.celery_app import app as celery_app

        assert "argus.generate_report" in celery_app.tasks
        routes = celery_app.conf.task_routes or {}
        assert routes.get("argus.generate_report", {}).get("queue") == "argus.reports"
        assert "argus.generate_all_reports" in celery_app.tasks
        assert routes.get("argus.generate_all_reports", {}).get("queue") == "argus.reports"


class ExecScalar:
    def __init__(self, scalar: object) -> None:
        self._scalar = scalar

    def scalar_one_or_none(self) -> object:
        return self._scalar


@pytest.mark.asyncio
async def test_run_generate_report_pipeline_success(monkeypatch: pytest.MonkeyPatch) -> None:
    import src.reports.report_pipeline as rp
    from src.reports.data_collector import ScanReportData
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
        ai_section_results={"executive_summary": {"status": "ok", "text": "summary text"}},
    )

    async def fake_build_context(self, session, tenant_id, scan_id, tier, **kwargs):  # noqa: ANN001
        return built

    monkeypatch.setattr(rp.ReportGenerator, "build_context", fake_build_context)
    monkeypatch.setattr(rp, "generate_html", lambda *args, **kwargs: b"<html/>")

    upload_keys: list[str | None] = []

    def fake_upload(*_a, **_kw) -> str:
        upload_keys.append("ok")
        return "ten-a/scan-a/reports/midgard/rep-a.html"

    exec_results = [
        ExecScalar(report),
        MagicMock(),  # processing → generation_status
        ExecScalar(None),  # tenant pdf_archival_format lookup
        ExecScalar(None),  # ReportObject upsert select
        MagicMock(),  # ready → generation_status
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
        upload_fn=fake_upload,
        ensure_bucket_fn=lambda: True,
        redis_client=MagicMock(),
    )

    assert out["status"] == "completed"
    assert out["formats"] == ["html"]
    assert upload_keys == ["ok"]
    assert session.commit.await_count >= 2


@pytest.mark.asyncio
async def test_run_generate_report_not_found() -> None:
    session = MagicMock()
    session.execute = AsyncMock(return_value=ExecScalar(None))
    session.commit = AsyncMock()

    out = await run_generate_report_pipeline(
        session,
        report_id="missing",
        tenant_id="ten-a",
        scan_id_hint=None,
        formats=["html"],
        upload_fn=lambda *a, **k: "x",
        ensure_bucket_fn=lambda: True,
    )

    assert out["status"] == "failed"
    assert out.get("error") == "Report not found"


@pytest.mark.asyncio
async def test_run_generate_report_pipeline_valhalla_csv_uploads_valhalla_sections(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """VHL-005: Valhalla tier + csv also uploads ``{report_id}.valhalla_sections.csv``."""
    import src.reports.report_pipeline as rp
    from src.reports.data_collector import ScanReportData
    from src.reports.valhalla_report_context import ValhallaReportContext
    from src.services.reporting import ReportContextBuildResult

    report = SimpleNamespace(
        id="rep-v",
        tenant_id="ten-v",
        scan_id="scan-v",
        tier="valhalla",
        requested_formats=None,
    )
    vctx = ValhallaReportContext().model_dump(mode="json")
    built = ReportContextBuildResult(
        scan_report_data=ScanReportData(scan_id="scan-v", tenant_id="ten-v", findings=[]),
        template_context={
            "tier": "valhalla",
            "valhalla_context": vctx,
            "scan_artifacts": {"status": "skipped", "phase_blocks": []},
            "ai_sections": {},
            "recon_summary": {},
        },
        ai_section_results={},
    )

    async def fake_build_context(self, session, tenant_id, scan_id, tier, **kwargs):  # noqa: ANN001
        return built

    monkeypatch.setattr(rp.ReportGenerator, "build_context", fake_build_context)
    monkeypatch.setattr(rp, "generate_csv", lambda *a, **k: b"a,b\n")

    upload_calls: list[tuple[str, ...]] = []

    def fake_upload(_tenant, _scan, _tier, rid, fmt, data, *, content_type) -> str:
        upload_calls.append((rid, fmt, len(data)))
        return f"ten-v/scan-v/reports/valhalla/{rid}.{fmt}"

    exec_results = [
        ExecScalar(report),
        MagicMock(),  # processing
        ExecScalar(None),  # tenant pdf_archival_format
        ExecScalar(None),  # upsert csv
        ExecScalar(None),  # upsert valhalla_sections csv
        MagicMock(),  # ready
    ]

    session = MagicMock()
    session.execute = AsyncMock(side_effect=exec_results)
    session.commit = AsyncMock()

    out = await run_generate_report_pipeline(
        session,
        report_id="rep-v",
        tenant_id="ten-v",
        scan_id_hint=None,
        formats=["csv"],
        upload_fn=fake_upload,
        ensure_bucket_fn=lambda: True,
        redis_client=MagicMock(),
    )

    assert out["status"] == "completed"
    fmts = {c[1] for c in upload_calls}
    assert "csv" in fmts
    assert VALHALLA_SECTIONS_CSV_FORMAT in fmts
    assert out["object_keys"]["csv"]
    assert out["object_keys"][VALHALLA_SECTIONS_CSV_FORMAT]


@pytest.mark.asyncio
async def test_run_generate_report_pipeline_validation_failure_skips_upload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import src.reports.report_pipeline as rp
    from src.reports.data_collector import ScanReportData
    from src.reports.report_data_validation import ReportDataValidationResult
    from src.services.reporting import ReportContextBuildResult

    report = SimpleNamespace(
        id="rep-val",
        tenant_id="ten-a",
        scan_id="scan-a",
        tier="midgard",
        requested_formats=None,
    )
    built = ReportContextBuildResult(
        scan_report_data=ScanReportData(scan_id="scan-a", tenant_id="ten-a", findings=[]),
        template_context={},
        ai_section_results={"executive_summary": {"status": "ok", "text": "summary text"}},
    )

    async def fake_build_context(self, session, tenant_id, scan_id, tier, **kwargs):  # noqa: ANN001
        return built

    monkeypatch.setattr(rp.ReportGenerator, "build_context", fake_build_context)
    upload_called: list[bool] = []

    def fake_upload(*_a, **_kw) -> str:
        upload_called.append(True)
        return "k"

    monkeypatch.setattr(
        rp,
        "validate_report_data",
        lambda *a, **k: ReportDataValidationResult(ok=False, reason_codes=["unit_test"]),
    )

    exec_results = [
        ExecScalar(report),
        MagicMock(),  # processing
        MagicMock(),  # validation failure → generation_status failed
    ]
    session = MagicMock()
    session.execute = AsyncMock(side_effect=exec_results)
    session.commit = AsyncMock()

    out = await run_generate_report_pipeline(
        session,
        report_id="rep-val",
        tenant_id="ten-a",
        scan_id_hint=None,
        formats=["html"],
        upload_fn=fake_upload,
        ensure_bucket_fn=lambda: True,
        redis_client=MagicMock(),
    )

    assert out["status"] == "failed"
    assert out.get("error") == "validation_failed"
    assert upload_called == []


@pytest.mark.asyncio
async def test_run_generate_report_pipeline_success_emits_structured_completion_log(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """RPT-001: completion path logs one INFO event with operator-safe structured ``extra``."""
    import src.reports.report_pipeline as rp
    from src.reports.data_collector import ScanReportData
    from src.services.reporting import ReportContextBuildResult

    report = SimpleNamespace(
        id="rep-log",
        tenant_id="ten-log",
        scan_id="scan-log",
        tier="midgard",
        requested_formats=None,
    )
    built = ReportContextBuildResult(
        scan_report_data=ScanReportData(scan_id="scan-log", tenant_id="ten-log", findings=[]),
        template_context={
            "report_quality": {
                "coverage_label": "full",
                "tool_health": "healthy",
                "warnings": ["w1", "w2"],
            },
        },
        ai_section_results={"executive_summary": {"status": "ok", "text": "summary text"}},
    )

    async def fake_build_context(self, session, tenant_id, scan_id, tier, **kwargs):  # noqa: ANN001
        return built

    monkeypatch.setattr(rp.ReportGenerator, "build_context", fake_build_context)
    monkeypatch.setattr(rp, "generate_html", lambda *args, **kwargs: b"<html/>")

    session = MagicMock()
    session.execute = AsyncMock(
        side_effect=[
            ExecScalar(report),
            MagicMock(),
            ExecScalar(None),
            ExecScalar(None),
            MagicMock(),
        ]
    )
    session.commit = AsyncMock()

    with caplog.at_level(logging.INFO, logger="src.reports.report_pipeline"):
        out = await run_generate_report_pipeline(
            session,
            report_id="rep-log",
            tenant_id="ten-log",
            scan_id_hint=None,
            formats=["html"],
            upload_fn=lambda *a, **k: "ten-log/scan-log/reports/midgard/rep-log.html",
            ensure_bucket_fn=lambda: True,
            redis_client=MagicMock(),
        )

    assert out["status"] == "completed"
    rec = next(r for r in caplog.records if r.getMessage() == "report_generation_completed")
    assert getattr(rec, "event", None) == "report_generation_completed"
    assert getattr(rec, "report_id", None) == "rep-log"
    assert getattr(rec, "tenant_id", None) == "ten-log"
    assert getattr(rec, "scan_id", None) == "scan-log"
    assert getattr(rec, "tier", None) == "midgard"
    assert getattr(rec, "formats_n", None) == 1
    assert getattr(rec, "coverage_label", None) == "full"
    assert getattr(rec, "tool_health", None) == "healthy"
    assert getattr(rec, "warnings_n", None) == 2
    assert getattr(rec, "full_valhalla", None) is None


@pytest.mark.asyncio
async def test_run_generate_report_pipeline_valhalla_completion_log_includes_full_flag(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """RPT-001: Valhalla completion log carries ``full_valhalla`` when present in template context."""
    import src.reports.report_pipeline as rp
    from src.reports.data_collector import ScanReportData
    from src.reports.valhalla_report_context import ValhallaReportContext
    from src.services.reporting import ReportContextBuildResult

    report = SimpleNamespace(
        id="rep-vlog",
        tenant_id="ten-v",
        scan_id="scan-v",
        tier="valhalla",
        requested_formats=None,
    )
    vctx = ValhallaReportContext(full_valhalla=True).model_dump(mode="json")
    built = ReportContextBuildResult(
        scan_report_data=ScanReportData(scan_id="scan-v", tenant_id="ten-v", findings=[]),
        template_context={
            "tier": "valhalla",
            "valhalla_context": vctx,
            "report_quality": {
                "coverage_label": "partial",
                "tool_health": "healthy",
                "warnings": [],
            },
            "scan_artifacts": {"status": "skipped", "phase_blocks": []},
            "ai_sections": {},
            "recon_summary": {},
        },
        ai_section_results={},
    )

    async def fake_build_context(self, session, tenant_id, scan_id, tier, **kwargs):  # noqa: ANN001
        return built

    monkeypatch.setattr(rp.ReportGenerator, "build_context", fake_build_context)
    monkeypatch.setattr(rp, "generate_html", lambda *args, **kwargs: b"<html/>")

    session = MagicMock()
    session.execute = AsyncMock(
        side_effect=[
            ExecScalar(report),
            MagicMock(),
            ExecScalar(None),
            ExecScalar(None),
            MagicMock(),
        ]
    )
    session.commit = AsyncMock()

    with caplog.at_level(logging.INFO, logger="src.reports.report_pipeline"):
        out = await run_generate_report_pipeline(
            session,
            report_id="rep-vlog",
            tenant_id="ten-v",
            scan_id_hint=None,
            formats=["html"],
            upload_fn=lambda *a, **k: "k",
            ensure_bucket_fn=lambda: True,
            redis_client=MagicMock(),
        )

    assert out["status"] == "completed"
    rec = next(r for r in caplog.records if r.getMessage() == "report_generation_completed")
    assert getattr(rec, "tier", None) == "valhalla"
    assert getattr(rec, "full_valhalla", None) is True
    assert getattr(rec, "warnings_n", None) == 0
