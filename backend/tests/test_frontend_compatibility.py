"""Frontend API contract compatibility (docs/frontend-api-contract-generated.md)."""

import json
import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.testclient import TestClient

FULL_SCAN_OPTIONS = {
    "scanType": "quick",
    "reportFormat": "pdf",
    "rateLimit": "normal",
    "ports": "80,443,8080,8443",
    "followRedirects": True,
    "vulnerabilities": {
        "xss": True,
        "sqli": True,
        "csrf": True,
        "ssrf": False,
        "lfi": False,
        "rce": False,
    },
    "authentication": {
        "enabled": False,
        "type": "basic",
        "username": "",
        "password": "",
        "token": "",
    },
    "scope": {
        "maxDepth": 3,
        "includeSubs": False,
        "excludePatterns": "",
    },
    "advanced": {
        "timeout": 30,
        "userAgent": "chrome",
        "proxy": "",
        "customHeaders": "",
    },
}


def _mock_db_session_create():
    tenant_result = MagicMock()
    tenant_result.scalar_one_or_none.return_value = None
    session = AsyncMock()
    session.add = MagicMock()
    session.commit = AsyncMock()
    session.flush = AsyncMock()
    session.execute = AsyncMock(return_value=tenant_result)

    @asynccontextmanager
    async def _cm():
        yield session

    def factory():
        return _cm()

    return factory


def _mock_db_scan_get(scan_id: str, *, exists: bool = True):
    scan_result = MagicMock()
    if exists:
        mock_scan = MagicMock()
        mock_scan.id = scan_id
        mock_scan.status = "running"
        mock_scan.progress = 50
        mock_scan.phase = "scanning"
        mock_scan.target_url = "https://example.com"
        mock_scan.created_at = datetime(2025, 3, 8, 12, 0, 0, tzinfo=UTC)
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


def _mock_db_reports_empty():
    session = AsyncMock()

    async def execute_mock(query, *args, **kwargs):
        r = MagicMock()
        qstr = str(query).lower()
        if "set local" in qstr or "app.current_tenant_id" in qstr:
            return MagicMock()
        r.scalars.return_value.all.return_value = []
        return r

    session.execute = AsyncMock(side_effect=execute_mock)

    @asynccontextmanager
    async def _cm():
        yield session

    def factory():
        return _cm()

    return factory


@pytest.fixture
def client():
    from main import app

    with TestClient(app) as c:
        yield c


def test_post_scans_full_options_body(client: TestClient) -> None:
    with (
        patch("src.api.routers.scans.async_session_factory", _mock_db_session_create()),
        patch("src.api.routers.scans.scan_phase_task"),
    ):
        r = client.post(
            "/api/v1/scans",
            json={
                "target": "https://example.com",
                "email": "user@example.com",
                "options": FULL_SCAN_OPTIONS,
            },
        )
    assert r.status_code == 201
    data = r.json()
    assert "scan_id" in data and data["status"] == "queued"


def test_get_scan_detail_contract_fields(client: TestClient) -> None:
    scan_id = str(uuid.uuid4())
    with patch("src.api.routers.scans.async_session_factory", _mock_db_scan_get(scan_id)):
        r = client.get(f"/api/v1/scans/{scan_id}")
    assert r.status_code == 200
    data = r.json()
    for k in ("id", "status", "progress", "phase", "target", "created_at"):
        assert k in data
    assert data["id"] == scan_id
    assert data["created_at"].endswith("Z")


def test_get_reports_target_returns_empty_array(client: TestClient) -> None:
    with patch("src.api.routers.reports.async_session_factory", _mock_db_reports_empty()):
        r = client.get(
            "/api/v1/reports",
            params={"target": "https://nobody.example.com"},
            headers={"Content-Type": "application/json"},
        )
    assert r.status_code == 200
    assert r.json() == []


def test_error_shape_404_scan(client: TestClient) -> None:
    scan_id = str(uuid.uuid4())
    with patch("src.api.routers.scans.async_session_factory", _mock_db_scan_get(scan_id, exists=False)):
        r = client.get(f"/api/v1/scans/{scan_id}")
    assert r.status_code == 404
    body = r.json()
    assert set(body.keys()) <= {"error", "code", "details"}
    assert body["error"] == "Scan not found"


def test_error_shape_422_validation(client: TestClient) -> None:
    r = client.post(
        "/api/v1/scans",
        json={"email": "a@b.com"},
    )
    assert r.status_code == 422
    body = r.json()
    assert body.get("error")
    assert body.get("code") == "validation_error"
    assert body.get("details") is not None


def test_error_shape_400_report_download(client: TestClient) -> None:
    # format validated before DB — no session mock needed
    r = client.get("/api/v1/reports/00000000-0000-0000-0000-000000000099/download?format=xml")
    assert r.status_code == 400
    body = r.json()
    assert "error" in body


def _mock_db_reports_download(report_id: str):
    """Minimal session mock for GET /reports/{id}/download."""
    from src.db.models import Finding as FindingModel
    from src.db.models import Report

    report = Report(
        id=report_id,
        tenant_id="00000000-0000-0000-0000-000000000001",
        scan_id=report_id,
        target="https://filtered.com",
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
    findings = [
        FindingModel(
            id="f-001",
            tenant_id="00000000-0000-0000-0000-000000000001",
            scan_id=report_id,
            report_id=report_id,
            severity="high",
            title="Test",
            description="Desc",
            cwe="CWE-79",
            cvss=7.5,
        ),
    ]
    findings_result = MagicMock()
    findings_result.scalar_one_or_none.return_value = None
    findings_result.scalars.return_value.all.return_value = findings
    report_result = MagicMock()
    report_result.scalar_one_or_none.return_value = report
    report_result.scalars.return_value.all.return_value = [report]

    async def execute_mock(query, *args, **kwargs):
        qstr = str(query).lower()
        if "set local" in qstr or "app.current_tenant_id" in qstr:
            return MagicMock()
        if "findings" in qstr:
            return findings_result
        if "reports" in qstr:
            return report_result
        empty = MagicMock()
        empty.scalar_one_or_none.return_value = None
        empty.scalars.return_value.all.return_value = []
        return empty

    session = AsyncMock()
    session.add = MagicMock()
    session.commit = AsyncMock(return_value=None)
    session.rollback = AsyncMock(return_value=None)
    session.execute = AsyncMock(side_effect=execute_mock)

    @asynccontextmanager
    async def _cm():
        yield session

    def factory():
        return _cm()

    return factory


def test_sse_smoke_first_event_json_shape(client: TestClient) -> None:
    """Completed scan ends the SSE generator so the response body finishes (no infinite stream)."""
    scan_id = str(uuid.uuid4())

    async def exec_sse(query, *args, **kwargs):
        qstr = str(query).lower()
        if "set local" in qstr or "app.current_tenant_id" in qstr:
            return MagicMock()
        if "scan_events" in qstr:
            r = MagicMock()
            r.scalars.return_value.all.return_value = []
            return r
        r = MagicMock()
        mock_scan = MagicMock()
        mock_scan.status = "completed"
        mock_scan.phase = "scanning"
        mock_scan.progress = 100
        r.scalar_one_or_none.return_value = mock_scan
        return r

    session = MagicMock()
    session.execute = AsyncMock(side_effect=exec_sse)
    session.__aenter__ = MagicMock(return_value=session)
    session.__aexit__ = MagicMock(return_value=None)

    @asynccontextmanager
    async def _factory():
        yield session

    with patch("src.api.routers.scans.async_session_factory", _factory):
        r = client.get(
            f"/api/v1/scans/{scan_id}/events",
            headers={"Accept": "text/event-stream"},
        )
    assert r.status_code == 200
    assert "text/event-stream" in (r.headers.get("content-type") or "")
    text = r.text
    assert "data:" in text
    line = [ln for ln in text.splitlines() if ln.startswith("data:")][0]
    payload = json.loads(line[len("data:") :].strip())
    assert "event" in payload
    for key in ("phase", "progress", "message"):
        assert key in payload


def test_download_content_disposition_headers(client: TestClient) -> None:
    report_id = "00000000-0000-0000-0000-000000000001"
    for fmt in ("pdf", "json"):
        with (
            patch(
                "src.api.routers.reports.async_session_factory",
                _mock_db_reports_download(report_id),
            ),
            patch("src.api.routers.reports.storage_exists", return_value=False),
            patch("src.api.routers.reports.upload_report_artifact"),
            patch(
                "src.api.routers.reports.generate_pdf",
                return_value=b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n",
            ),
        ):
            r = client.get(f"/api/v1/reports/{report_id}/download?format={fmt}")
        assert r.status_code == 200, fmt
        cd = r.headers.get("content-disposition") or ""
        assert "attachment" in cd.lower()
        assert report_id in cd or "report-" in cd
