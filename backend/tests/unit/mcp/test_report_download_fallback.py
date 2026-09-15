"""MCP report.download resolves valhalla_llm_* artifacts via the ReportObject fallback."""

import pytest
import src.mcp.services.report_service as svc
from src.mcp.schemas.report import ReportDownloadInput, ReportFormat


class _FakeResult:
    def __init__(self, obj):
        self._obj = obj

    def scalar_one_or_none(self):
        return self._obj


class _FakeSession:
    """Async-context session returning queued query results in order."""

    def __init__(self, results):
        self._results = list(results)
        self._i = 0

    async def execute(self, *_args, **_kwargs):
        result = self._results[self._i]
        self._i += 1
        return _FakeResult(result)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return False


class _Report:
    def __init__(self):
        self.report_metadata = {}  # no artifacts -> forces the fallback


class _ReportObject:
    def __init__(self, object_key):
        self.object_key = object_key


def test_valhalla_llm_formats_are_in_mcp_enum():
    values = {f.value for f in ReportFormat}
    assert {"valhalla_llm_xml", "valhalla_llm_manifest", "xml"} <= values
    # The download input accepts them.
    assert ReportDownloadInput(report_id="a" * 12, format="valhalla_llm_xml").format is (
        ReportFormat.VALHALLA_LLM_XML
    )


@pytest.mark.asyncio
async def test_download_falls_back_to_report_object(monkeypatch):
    object_key = "T1/S1/reports/valhalla/report-001.valhalla_llm_xml"
    session = _FakeSession([_Report(), _ReportObject(object_key)])

    monkeypatch.setattr(svc, "async_session_factory", lambda: session)

    async def _noop_set_tenant(*_args, **_kwargs):
        return None

    monkeypatch.setattr(svc, "set_session_tenant", _noop_set_tenant)
    monkeypatch.setattr(
        svc, "get_presigned_url_by_key", lambda key, **_k: f"https://minio.local/{key}"
    )

    result = await svc.get_report_download(
        tenant_id="T1", report_id="report-001", format=ReportFormat.VALHALLA_LLM_XML
    )
    assert result.presigned_url == f"https://minio.local/{object_key}"
    assert result.format is ReportFormat.VALHALLA_LLM_XML
