"""RPT-003 — ReportDataCollector + ScanReportData (minimal)."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.engine import Result

from src.db.models import Scan as ScanModel
from src.recon.stage_object_download import StageObjectFetchError
from src.reports.data_collector import ReportDataCollector, ScanReportData


def _empty_result() -> MagicMock:
    r = MagicMock(spec=Result)
    r.scalars.return_value.all.return_value = []
    return r


def _single_scan_result(scan: ScanModel) -> MagicMock:
    r = MagicMock(spec=Result)
    r.scalar_one_or_none.return_value = scan
    return r


@pytest.fixture
def sample_scan() -> ScanModel:
    return ScanModel(
        id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        tenant_id="11111111-2222-3333-4444-555555555555",
        target_id=None,
        target_url="https://scan.example",
        status="completed",
        progress=100,
        phase="done",
        options=None,
    )


@pytest.mark.asyncio
async def test_collect_async_scan_only_no_minio(sample_scan: ScanModel) -> None:
    session = MagicMock()
    calls: list[str] = []

    async def execute_mock(stmt: object) -> MagicMock:
        calls.append("exec")
        # First call: Scan select
        if len(calls) == 1:
            return _single_scan_result(sample_scan)
        return _empty_result()

    session.execute = AsyncMock(side_effect=execute_mock)

    collector = ReportDataCollector()
    data = await collector.collect_async(
        session,
        tenant_id=sample_scan.tenant_id,
        scan_id=sample_scan.id,
        include_minio=False,
    )

    assert isinstance(data, ScanReportData)
    assert data.scan is not None
    assert data.scan.target_url == "https://scan.example"
    assert data.timeline == []
    assert data.phase_inputs == []
    assert data.phase_outputs == []
    assert data.findings == []
    assert data.stage1.items == []


@pytest.mark.asyncio
async def test_collect_async_missing_scan() -> None:
    session = MagicMock()

    async def execute_mock(_stmt: object) -> MagicMock:
        r = MagicMock(spec=Result)
        r.scalar_one_or_none.return_value = None
        return r

    session.execute = AsyncMock(side_effect=execute_mock)

    data = await ReportDataCollector().collect_async(
        session,
        tenant_id="11111111-2222-3333-4444-555555555555",
        scan_id="00000000-0000-0000-0000-000000000000",
        include_minio=False,
    )
    assert data.scan is None
    assert data.findings == []


@pytest.mark.asyncio
async def test_minio_missing_files_partial(sample_scan: ScanModel) -> None:
    session = MagicMock()
    n = {"i": 0}

    async def execute_mock(_stmt: object) -> MagicMock:
        n["i"] += 1
        if n["i"] == 1:
            return _single_scan_result(sample_scan)
        return _empty_result()

    session.execute = AsyncMock(side_effect=execute_mock)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "src.reports.data_collector.STAGE1_ROOT_FILES",
            ("recon_results.json",),
        )
        mp.setattr("src.reports.data_collector.STAGE2_ROOT_FILES", ())
        mp.setattr("src.reports.data_collector.get_stage3_root_files", lambda: ())
        mp.setattr("src.reports.data_collector.STAGE4_ROOT_FILES", ())

        def _none_download(_sid: str, _fn: str) -> None:
            return None

        mp.setattr(
            "src.reports.data_collector.download_stage1_artifact",
            _none_download,
        )

        data = await ReportDataCollector().collect_async(
            session,
            tenant_id=sample_scan.tenant_id,
            scan_id=sample_scan.id,
            include_minio=True,
        )

    assert len(data.stage1.items) == 1
    assert data.stage1.items[0].error == "not_found"
    assert data.stage1.items[0].fetched is False


@pytest.mark.asyncio
async def test_minio_storage_error_sets_code(sample_scan: ScanModel) -> None:
    session = MagicMock()
    n = {"i": 0}

    async def execute_mock(_stmt: object) -> MagicMock:
        n["i"] += 1
        if n["i"] == 1:
            return _single_scan_result(sample_scan)
        return _empty_result()

    session.execute = AsyncMock(side_effect=execute_mock)

    def _raise_storage(_sid: str, _fn: str) -> None:
        raise StageObjectFetchError("storage_error")

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "src.reports.data_collector.STAGE1_ROOT_FILES",
            ("recon_results.json",),
        )
        mp.setattr("src.reports.data_collector.STAGE2_ROOT_FILES", ())
        mp.setattr("src.reports.data_collector.get_stage3_root_files", lambda: ())
        mp.setattr("src.reports.data_collector.STAGE4_ROOT_FILES", ())
        mp.setattr("src.reports.data_collector.download_stage1_artifact", _raise_storage)

        data = await ReportDataCollector().collect_async(
            session,
            tenant_id=sample_scan.tenant_id,
            scan_id=sample_scan.id,
            include_minio=True,
        )

    assert data.stage1.items[0].error == "storage_error"
    assert data.stage1.items[0].fetched is False


@pytest.mark.asyncio
async def test_minio_fetch_failed_from_generic_exception(sample_scan: ScanModel) -> None:
    session = MagicMock()
    n = {"i": 0}

    async def execute_mock(_stmt: object) -> MagicMock:
        n["i"] += 1
        if n["i"] == 1:
            return _single_scan_result(sample_scan)
        return _empty_result()

    session.execute = AsyncMock(side_effect=execute_mock)

    def _raise_generic(_sid: str, _fn: str) -> None:
        raise RuntimeError("unexpected")

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "src.reports.data_collector.STAGE1_ROOT_FILES",
            ("recon_results.json",),
        )
        mp.setattr("src.reports.data_collector.STAGE2_ROOT_FILES", ())
        mp.setattr("src.reports.data_collector.get_stage3_root_files", lambda: ())
        mp.setattr("src.reports.data_collector.STAGE4_ROOT_FILES", ())
        mp.setattr("src.reports.data_collector.download_stage1_artifact", _raise_generic)

        data = await ReportDataCollector().collect_async(
            session,
            tenant_id=sample_scan.tenant_id,
            scan_id=sample_scan.id,
            include_minio=True,
        )

    assert data.stage1.items[0].error == "fetch_failed"
    assert data.stage1.items[0].fetched is False
