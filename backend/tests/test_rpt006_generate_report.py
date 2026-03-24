"""RPT-006 — Report pipeline helpers, Celery task/route, mocked pipeline run."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

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
        MagicMock(),
        ExecScalar(None),
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
