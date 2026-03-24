"""GET /api/v1/scans/{scan_id}/artifacts (RAW-004)."""

from contextlib import asynccontextmanager
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

from starlette.testclient import TestClient

SCAN_ID = "550e8400-e29b-41d4-a716-446655440000"


def _mock_session_factory(*, scan_exists: bool = True):
    scan_result = MagicMock()
    if scan_exists:
        mock_scan = MagicMock()
        mock_scan.id = SCAN_ID
        scan_result.scalar_one_or_none.return_value = mock_scan
    else:
        scan_result.scalar_one_or_none.return_value = None
    session = AsyncMock()

    async def execute_mock(query, *args, **kwargs):
        qstr = str(query).lower()
        if "set local" in qstr or "app.current_tenant_id" in qstr:
            return MagicMock()
        return scan_result

    session.execute = AsyncMock(side_effect=execute_mock)

    @asynccontextmanager
    async def _cm():
        yield session

    def factory():
        return _cm()

    return factory


def test_artifacts_404_when_scan_missing(client: TestClient) -> None:
    with patch("src.api.routers.scans.async_session_factory", _mock_session_factory(scan_exists=False)):
        r = client.get(f"/api/v1/scans/{SCAN_ID}/artifacts")
    assert r.status_code == 404


def test_artifacts_422_invalid_phase(client: TestClient) -> None:
    with patch("src.api.routers.scans.async_session_factory", _mock_session_factory(scan_exists=True)):
        r = client.get(f"/api/v1/scans/{SCAN_ID}/artifacts", params={"phase": "invalid_phase"})
    assert r.status_code == 422


def test_artifacts_200_with_mocked_list(client: TestClient) -> None:
    sample = [
        {
            "key": f"default/{SCAN_ID}/recon/raw/1_tool.txt",
            "size": 42,
            "last_modified": datetime(2026, 3, 23, 12, 0, 0, tzinfo=UTC),
            "content_type": "text/plain; charset=utf-8",
        }
    ]
    with (
        patch("src.api.routers.scans.async_session_factory", _mock_session_factory(scan_exists=True)),
        patch("src.api.routers.scans.list_scan_artifacts", return_value=sample),
        patch("src.api.routers.scans.get_presigned_url_by_key", return_value=None),
    ):
        r = client.get(f"/api/v1/scans/{SCAN_ID}/artifacts")
    assert r.status_code == 200
    data = r.json()
    assert len(data) == 1
    assert data[0]["key"] == sample[0]["key"]
    assert data[0]["size"] == 42
    assert data[0]["last_modified"].endswith("Z")
    assert data[0]["content_type"] == "text/plain; charset=utf-8"
    assert data[0]["download_url"] is None


def test_artifacts_presigned_query(client: TestClient) -> None:
    tenant_uuid = "11111111-1111-1111-1111-111111111111"
    sample = [
        {
            "key": f"{tenant_uuid}/{SCAN_ID}/raw/x.json",
            "size": 1,
            "last_modified": datetime(2026, 1, 1, tzinfo=UTC),
            "content_type": "application/json",
        }
    ]
    with (
        patch("src.api.routers.scans.async_session_factory", _mock_session_factory(scan_exists=True)),
        patch("src.api.routers.scans.list_scan_artifacts", return_value=sample),
        patch(
            "src.api.routers.scans.get_presigned_url_by_key",
            return_value="https://minio/presigned",
        ),
    ):
        r = client.get(
            f"/api/v1/scans/{SCAN_ID}/artifacts",
            params={"presigned": "true"},
            headers={"X-Tenant-ID": tenant_uuid},
        )
    assert r.status_code == 200
    assert r.json()[0]["download_url"] == "https://minio/presigned"


def test_openapi_lists_artifacts_endpoint(client: TestClient) -> None:
    r = client.get("/api/v1/openapi.json")
    assert r.status_code == 200
    paths = r.json().get("paths", {})
    entry = paths.get("/api/v1/scans/{scan_id}/artifacts")
    assert entry is not None, "OpenAPI must expose GET /scans/{scan_id}/artifacts"
    assert "get" in entry
    schema = entry["get"].get("responses", {}).get("200", {})
    ref = schema.get("content", {}).get("application/json", {}).get("schema", {})
    assert ref.get("type") == "array", ref


def test_artifacts_503_when_storage_unavailable(client: TestClient) -> None:
    with (
        patch("src.api.routers.scans.async_session_factory", _mock_session_factory(scan_exists=True)),
        patch("src.api.routers.scans.list_scan_artifacts", return_value=None),
    ):
        r = client.get(f"/api/v1/scans/{SCAN_ID}/artifacts")
    assert r.status_code == 503
