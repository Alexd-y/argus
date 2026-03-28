"""Bulk report generation: POST .../reports/generate-all, MinIO keys, Celery task wiring."""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.testclient import TestClient

from src.api.schemas import ReportGenerateAllRequest
from src.core.config import settings
from src.db.models import Finding as FindingModel
from src.db.models import Report as ReportModel
from src.db.models import ReportObject
from src.reports.report_pipeline import DEFAULT_REPORT_FORMATS, normalize_generation_formats
from src.storage.s3 import build_report_object_key

GENERATE_ALL_TIERS = ("midgard", "asgard", "valhalla")
DEFAULT_GENERATE_ALL_API = ("pdf", "html", "json", "csv")


def test_build_report_object_key_five_segments() -> None:
    k = build_report_object_key("t1", "s1", "asgard", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "json")
    assert k == "t1/s1/reports/asgard/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.json"
    assert len(k.split("/")) == 5


@pytest.mark.parametrize(
    ("left", "right"),
    [
        (
            ("t", "s", "midgard", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "json"),
            ("t", "s", "asgard", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "json"),
        ),
        (
            ("t", "s", "midgard", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "json"),
            ("t", "s", "midgard", "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "json"),
        ),
        (
            ("t", "s", "midgard", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "json"),
            ("t", "s", "midgard", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "pdf"),
        ),
    ],
)
def test_build_report_object_key_unique_per_tier_report_id_format(
    left: tuple[str, str, str, str, str],
    right: tuple[str, str, str, str, str],
) -> None:
    assert build_report_object_key(*left) != build_report_object_key(*right)


def test_build_report_object_keys_unique_for_generate_all_matrix() -> None:
    """One row per (tier, format) with distinct report_id → all MinIO keys distinct."""
    tenant_id = "00000000-0000-0000-0000-000000000001"
    scan_id = str(uuid.uuid4())
    keys: list[str] = []
    for tier in GENERATE_ALL_TIERS:
        for fmt in DEFAULT_GENERATE_ALL_API:
            rid = str(uuid.uuid4())
            keys.append(build_report_object_key(tenant_id, scan_id, tier, rid, fmt))
    assert len(keys) == 12
    assert len(set(keys)) == 12


def test_normalize_generation_formats_empty_explicit_defaults() -> None:
    """Explicit format list empty after whitelist → pipeline falls back to DEFAULT_REPORT_FORMATS."""
    want = list(DEFAULT_REPORT_FORMATS)
    assert normalize_generation_formats([], None) == want
    assert normalize_generation_formats(["not-a-real-format"], None) == want


def test_report_generate_all_request_resolved_formats_omitted_or_null() -> None:
    assert ReportGenerateAllRequest.model_validate({}).resolved_formats() == list(DEFAULT_GENERATE_ALL_API)
    assert ReportGenerateAllRequest.model_validate({"formats": None}).resolved_formats() == list(
        DEFAULT_GENERATE_ALL_API
    )


def test_report_generate_all_request_empty_formats_list_invalid() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        ReportGenerateAllRequest.model_validate({"formats": []})


def _session_factory_for_generate_all() -> tuple:
    scan_result = MagicMock()
    mock_scan = MagicMock()
    mock_scan.target_url = "https://example.com"
    mock_scan.options = None
    scan_result.scalar_one_or_none.return_value = mock_scan
    added: list[ReportModel] = []

    session = AsyncMock()

    def _add(obj: object) -> None:
        if isinstance(obj, ReportModel):
            added.append(obj)

    session.add = MagicMock(side_effect=_add)
    session.commit = AsyncMock()

    async def execute_mock(query: object, *args: object, **kwargs: object) -> MagicMock:
        qstr = str(query).lower()
        if "set local" in qstr or "app.current_tenant_id" in qstr:
            return MagicMock()
        return scan_result

    session.execute = AsyncMock(side_effect=execute_mock)
    session.__aenter__ = MagicMock(return_value=session)
    session.__aexit__ = MagicMock(return_value=None)

    @asynccontextmanager
    async def factory():
        yield session

    return factory, added


def test_post_generate_all_creates_twelve_rows_and_enqueues_task(client: TestClient) -> None:
    scan_id = str(uuid.uuid4())
    tenant_id = "00000000-0000-0000-0000-000000000001"
    factory, added = _session_factory_for_generate_all()
    celery_result = MagicMock()
    celery_result.id = "task-generate-all-1"

    with (
        patch("src.api.routers.scans.async_session_factory", factory),
        patch("src.api.routers.scans.generate_all_reports_task") as mock_task,
    ):
        mock_task.delay.return_value = celery_result
        resp = client.post(f"/api/v1/scans/{scan_id}/reports/generate-all", json={})

    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["count"] == 12
    assert len(body["report_ids"]) == 12
    assert len(added) == 12
    assert body.get("task_id") == "task-generate-all-1"
    bundle_ids = {row.report_metadata.get("bundle_id") for row in added if row.report_metadata}
    assert len(bundle_ids) == 1
    bundle_id = bundle_ids.pop()
    assert bundle_id == body["bundle_id"]
    assert all(row.report_metadata.get("generate_all") is True for row in added)
    tiers = {row.tier for row in added}
    assert tiers == {"midgard", "asgard", "valhalla"}
    fmt_lists = [tuple(row.requested_formats or []) for row in added]
    assert all(len(fl) == 1 for fl in fmt_lists)
    mock_task.delay.assert_called_once()
    a0, a1, a2, a3 = mock_task.delay.call_args[0]
    assert a0 == tenant_id
    assert a1 == scan_id
    assert a2 == bundle_id
    assert a3 == body["report_ids"]


def test_post_generate_all_custom_formats_count(client: TestClient) -> None:
    scan_id = str(uuid.uuid4())
    factory, added = _session_factory_for_generate_all()
    celery_result = MagicMock()
    celery_result.id = "t2"

    with (
        patch("src.api.routers.scans.async_session_factory", factory),
        patch("src.api.routers.scans.generate_all_reports_task") as mock_task,
    ):
        mock_task.delay.return_value = celery_result
        resp = client.post(
            f"/api/v1/scans/{scan_id}/reports/generate-all",
            json={"formats": ["pdf", "html"]},
        )

    assert resp.status_code == 202
    assert resp.json()["count"] == 6
    assert len(added) == 6


def test_post_generate_all_formats_null_uses_default_twelve(client: TestClient) -> None:
    scan_id = str(uuid.uuid4())
    factory, added = _session_factory_for_generate_all()
    celery_result = MagicMock()
    celery_result.id = "t-null"

    with (
        patch("src.api.routers.scans.async_session_factory", factory),
        patch("src.api.routers.scans.generate_all_reports_task") as mock_task,
    ):
        mock_task.delay.return_value = celery_result
        resp = client.post(
            f"/api/v1/scans/{scan_id}/reports/generate-all",
            json={"formats": None},
        )

    assert resp.status_code == 202, resp.text
    assert resp.json()["count"] == 12
    assert len(added) == 12


def test_post_generate_all_empty_formats_array_rejected(app) -> None:
    """formats: [] is rejected with 422 and validation detail (manual body parse → HTTPException)."""
    scan_id = str(uuid.uuid4())
    factory, _ = _session_factory_for_generate_all()
    safe_client = TestClient(app, raise_server_exceptions=False)

    with patch("src.api.routers.scans.async_session_factory", factory):
        resp = safe_client.post(
            f"/api/v1/scans/{scan_id}/reports/generate-all",
            json={"formats": []},
        )

    assert resp.status_code == 422, resp.text
    body = resp.json()
    # contract_http_exception_handler maps list detail → error/code/details
    assert body.get("error") == "Validation error"
    assert body.get("code") == "validation_error"
    details = body.get("details") or []
    assert isinstance(details, list) and details
    assert any(
        "formats" in (err.get("loc") or ())
        and "at least one" in (err.get("msg") or "").lower()
        for err in details
    )


def test_post_generate_all_task_payload_matches_created_bundle_and_ids(client: TestClient) -> None:
    """Celery receives exactly this request's bundle_id and report_ids (correlation / batch filter)."""
    scan_id = str(uuid.uuid4())
    factory, added = _session_factory_for_generate_all()
    celery_result = MagicMock()
    celery_result.id = "t-bundle"

    with (
        patch("src.api.routers.scans.async_session_factory", factory),
        patch("src.api.routers.scans.generate_all_reports_task") as mock_task,
    ):
        mock_task.delay.return_value = celery_result
        resp = client.post(f"/api/v1/scans/{scan_id}/reports/generate-all", json={})

    assert resp.status_code == 202
    body = resp.json()
    bundle_id = body["bundle_id"]
    assert all(row.report_metadata.get("bundle_id") == bundle_id for row in added)
    mock_task.delay.assert_called_once()
    t_id, s_id, b_id, r_ids = mock_task.delay.call_args[0]
    assert b_id == bundle_id
    assert r_ids == body["report_ids"]
    assert set(r_ids) == {row.id for row in added}


def test_post_generate_all_distinct_bundles_per_request(client: TestClient) -> None:
    scan_id = str(uuid.uuid4())
    celery_result = MagicMock()
    celery_result.id = "x"

    bundles: list[str] = []
    all_ids: list[str] = []

    for _ in range(2):
        factory, added = _session_factory_for_generate_all()
        with (
            patch("src.api.routers.scans.async_session_factory", factory),
            patch("src.api.routers.scans.generate_all_reports_task") as mock_task,
        ):
            mock_task.delay.return_value = celery_result
            resp = client.post(f"/api/v1/scans/{scan_id}/reports/generate-all", json={})
        assert resp.status_code == 202
        data = resp.json()
        bundles.append(data["bundle_id"])
        all_ids.extend(data["report_ids"])
        assert {row.report_metadata.get("bundle_id") for row in added} == {data["bundle_id"]}

    assert bundles[0] != bundles[1]
    assert len(set(all_ids)) == 24


def _session_factory_download_with_report_object(
    *,
    report: ReportModel,
    findings: list[FindingModel],
    report_object: ReportObject,
):
    async def execute_mock(query: object, *args: object, **kwargs: object) -> MagicMock:
        qstr = str(query).lower()
        if "set local" in qstr or "app.current_tenant_id" in qstr:
            return MagicMock()
        if "report_objects" in qstr:
            r = MagicMock()
            r.scalar_one_or_none.return_value = report_object
            return r
        if "findings" in qstr:
            r = MagicMock()
            r.scalars.return_value.all.return_value = findings
            r.scalar_one_or_none.return_value = None
            return r
        r = MagicMock()
        r.scalar_one_or_none.return_value = report
        return r

    session = MagicMock()
    session.execute = AsyncMock(side_effect=execute_mock)
    session.commit = AsyncMock()
    session.__aenter__ = MagicMock(return_value=session)
    session.__aexit__ = MagicMock(return_value=None)

    @asynccontextmanager
    async def factory():
        yield session

    return factory


def test_download_report_uses_report_object_key_not_legacy_path(client: TestClient) -> None:
    """When ReportObject.object_key is set, stream from download_by_key(ro.object_key); skip legacy storage_*."""
    tenant_id = settings.default_tenant_id
    report_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    scan_id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    tier_key = f"{tenant_id}/{scan_id}/reports/asgard/{report_id}.pdf"
    report = ReportModel(
        id=report_id,
        tenant_id=tenant_id,
        scan_id=scan_id,
        target="https://example.com",
        tier="asgard",
        generation_status="ready",
        requested_formats=["pdf"],
        summary={
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "technologies": [],
            "sslIssues": 0,
            "headerIssues": 0,
            "leaksFound": False,
        },
        technologies=[],
        created_at=datetime.now(UTC),
    )
    ro = ReportObject(
        tenant_id=tenant_id,
        scan_id=scan_id,
        report_id=report_id,
        format="pdf",
        object_key=tier_key,
        size_bytes=4,
    )
    factory = _session_factory_download_with_report_object(report=report, findings=[], report_object=ro)

    with (
        patch("src.api.routers.reports.async_session_factory", factory),
        patch("src.api.routers.reports.download_by_key", return_value=b"%PDF") as mock_dl,
        patch("src.api.routers.reports.storage_exists") as mock_exists,
        patch("src.api.routers.reports.storage_download") as mock_storage_dl,
        patch("src.api.routers.reports.upload_report_artifact") as mock_upload,
    ):
        resp = client.get(f"/api/v1/reports/{report_id}/download?format=pdf")

    assert resp.status_code == 200
    assert resp.content.startswith(b"%PDF")
    mock_dl.assert_called_once_with(tier_key)
    mock_exists.assert_not_called()
    mock_storage_dl.assert_not_called()
    mock_upload.assert_not_called()


class _ExecScalar:
    def __init__(self, scalar: object) -> None:
        self._scalar = scalar

    def scalar_one_or_none(self) -> object:
        return self._scalar


@pytest.mark.asyncio
async def test_pipeline_upload_fn_receives_distinct_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    import src.reports.report_pipeline as rp
    from src.reports.data_collector import ScanReportData
    from src.services.reporting import ReportContextBuildResult

    keys: list[str] = []

    def capture_upload(
        tenant_id: str,
        scan_id: str,
        tier: str,
        report_id: str,
        fmt: str,
        data: bytes,
        *,
        content_type: str,
    ) -> str:
        k = build_report_object_key(tenant_id, scan_id, tier, report_id, fmt)
        keys.append(k)
        return k

    built = ReportContextBuildResult(
        scan_report_data=ScanReportData(scan_id="scan-x", tenant_id="ten-x", findings=[]),
        template_context={},
        ai_section_results={"executive_summary": {"status": "ok", "text": "t"}},
    )

    async def fake_build_context(self, session, tenant_id, scan_id, tier, **kwargs):  # noqa: ANN001
        return built

    monkeypatch.setattr(rp.ReportGenerator, "build_context", fake_build_context)
    monkeypatch.setattr(rp, "generate_html", lambda *a, **k: b"<html/>")

    async def run_for_report(rid: str, tier: str) -> None:
        report = SimpleNamespace(
            id=rid,
            tenant_id="ten-x",
            scan_id="scan-x",
            tier=tier,
            requested_formats=["html"],
        )
        exec_results = [
            _ExecScalar(report),
            MagicMock(),
            _ExecScalar(None),
            MagicMock(),
        ]
        session = MagicMock()
        session.execute = AsyncMock(side_effect=exec_results)
        session.commit = AsyncMock()
        await rp.run_generate_report_pipeline(
            session,
            report_id=rid,
            tenant_id="ten-x",
            scan_id_hint="scan-x",
            formats=["html"],
            upload_fn=capture_upload,
            ensure_bucket_fn=lambda: True,
            redis_client=MagicMock(),
        )

    await run_for_report("11111111-1111-1111-1111-111111111111", "midgard")
    await run_for_report("22222222-2222-2222-2222-222222222222", "asgard")
    assert len(keys) == 2
    assert keys[0] != keys[1]
    assert "midgard" in keys[0] and "asgard" in keys[1]


def test_normalize_generation_formats_requested_formats_string_scalar() -> None:
    """JSONB or ORM edge: single format stored as string must not iterate characters."""
    assert normalize_generation_formats(None, "pdf") == ["pdf"]
    assert normalize_generation_formats(None, "PDF") == ["pdf"]


@pytest.mark.asyncio
async def test_enqueue_generate_all_bundle_creates_twelve_rows() -> None:
    """OWASP-006: 3 tiers × 4 formats = 12 Report rows (same as generate-all API default)."""
    from src.reports.bundle_enqueue import GENERATE_ALL_REPORT_TIERS, enqueue_generate_all_bundle

    assert len(GENERATE_ALL_REPORT_TIERS) * len(DEFAULT_GENERATE_ALL_API) == 12

    tenant_id = "00000000-0000-0000-0000-000000000001"
    scan_id = str(uuid.uuid4())
    factory, added = _session_factory_for_generate_all()
    async with factory() as session:
        out = await enqueue_generate_all_bundle(
            session,
            tenant_id,
            scan_id,
            list(DEFAULT_GENERATE_ALL_API),
            set_post_scan_idempotency_flag=False,
        )
    assert out is not None
    _bundle_id, rids = out
    assert len(rids) == 12
    assert len(added) == 12
    assert {row.tier for row in added} == {"midgard", "asgard", "valhalla"}
    assert all(len(row.requested_formats or []) == 1 for row in added)
    object_keys = [
        build_report_object_key(
            tenant_id,
            scan_id,
            row.tier,
            row.id,
            (row.requested_formats or ["json"])[0],
        )
        for row in added
    ]
    assert len(object_keys) == 12
    assert len(set(object_keys)) == 12
    for key in object_keys:
        assert key.startswith(f"{tenant_id}/{scan_id}/reports/")
        segs = key.split("/")
        assert len(segs) == 5
        assert segs[2] == "reports"
        assert segs[3] in GENERATE_ALL_TIERS


@pytest.mark.asyncio
async def test_enqueue_generate_all_bundle_post_scan_skips_if_already_flagged() -> None:
    from src.reports.bundle_enqueue import (
        POST_SCAN_GENERATE_ALL_BUNDLE_OPTION_KEY,
        enqueue_generate_all_bundle,
    )

    tenant_id = "00000000-0000-0000-0000-000000000001"
    scan_id = str(uuid.uuid4())
    scan_result = MagicMock()
    mock_scan = MagicMock()
    mock_scan.target_url = "https://example.com"
    mock_scan.options = {POST_SCAN_GENERATE_ALL_BUNDLE_OPTION_KEY: "existing-bundle"}
    scan_result.scalar_one_or_none.return_value = mock_scan
    added: list[ReportModel] = []

    session = AsyncMock()

    def _add(obj: object) -> None:
        if isinstance(obj, ReportModel):
            added.append(obj)

    session.add = MagicMock(side_effect=_add)

    async def execute_mock(query: object, *args: object, **kwargs: object) -> MagicMock:
        qstr = str(query).lower()
        if "set local" in qstr or "app.current_tenant_id" in qstr:
            return MagicMock()
        return scan_result

    session.execute = AsyncMock(side_effect=execute_mock)

    @asynccontextmanager
    async def factory():
        yield session

    async with factory() as sess:
        out = await enqueue_generate_all_bundle(
            sess,
            tenant_id,
            scan_id,
            list(DEFAULT_GENERATE_ALL_API),
            set_post_scan_idempotency_flag=True,
        )
    assert out is None
    assert len(added) == 0


def test_schedule_generate_all_reports_task_safe_invokes_celery(monkeypatch: pytest.MonkeyPatch) -> None:
    mock_task = MagicMock()
    mock_task.delay.return_value = MagicMock(id="celery-1")
    monkeypatch.setattr("src.tasks.generate_all_reports_task", mock_task)
    from src.reports.bundle_enqueue import schedule_generate_all_reports_task_safe

    schedule_generate_all_reports_task_safe("ten", "scan", "bundle", ["a", "b"])
    mock_task.delay.assert_called_once_with("ten", "scan", "bundle", ["a", "b"])
