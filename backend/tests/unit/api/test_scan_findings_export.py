"""Router tests: SARIF/JUnit scan findings export (T04, tenant opt-in)."""

from __future__ import annotations

import json
import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock
from xml.etree import ElementTree as ET

import pytest
from starlette.testclient import TestClient

from src.core.config import settings


def _scalar_result(val: object) -> MagicMock:
    r = MagicMock()
    r.scalar_one_or_none.return_value = val
    return r


def _findings_result(rows: list) -> MagicMock:
    r = MagicMock()
    scal = MagicMock()
    scal.all.return_value = rows
    r.scalars.return_value = scal
    return r


def _session_with_execute_sequence(results: list) -> AsyncMock:
    session = AsyncMock()
    session.execute = AsyncMock(side_effect=results)

    @asynccontextmanager
    async def _cm():
        yield session

    def factory():
        return _cm()

    return factory


@pytest.fixture
def mock_scan() -> MagicMock:
    s = MagicMock()
    s.id = str(uuid.uuid4())
    s.tenant_id = settings.default_tenant_id
    s.target_url = "https://example.com"
    s.created_at = datetime.now(UTC)
    return s


@pytest.fixture
def mock_finding(mock_scan: MagicMock) -> MagicMock:
    f = MagicMock()
    f.severity = "medium"
    f.title = "Issue"
    f.description = "Desc"
    f.cwe = "CWE-79"
    f.cvss = 5.0
    f.owasp_category = "A03"
    f.proof_of_concept = None
    f.confidence = "likely"
    f.evidence_type = None
    f.evidence_refs = []
    f.reproducible_steps = None
    f.applicability_notes = None
    f.scan_id = mock_scan.id
    f.tenant_id = mock_scan.tenant_id
    return f


class TestScanFindingsExport:
    def test_export_flag_off_returns_404(
        self, client: TestClient, mock_scan: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        results = [
            MagicMock(),
            _scalar_result(mock_scan),
            _scalar_result(False),
        ]
        factory = _session_with_execute_sequence(results)
        monkeypatch.setattr("src.api.routers.scans.async_session_factory", factory)
        r = client.get(
            f"/api/v1/scans/{mock_scan.id}/findings/export",
            params={"format": "sarif"},
        )
        assert r.status_code == 404
        # Contract paths use { "error": "..." } (see exception_handlers.contract_http_exception_handler).
        assert r.json().get("error") == "Not found"

    def test_export_scan_missing_returns_404(
        self, client: TestClient, mock_scan: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        results = [
            MagicMock(),
            _scalar_result(None),
        ]
        factory = _session_with_execute_sequence(results)
        monkeypatch.setattr("src.api.routers.scans.async_session_factory", factory)
        r = client.get(
            f"/api/v1/scans/{mock_scan.id}/findings/export",
            params={"format": "junit"},
        )
        assert r.status_code == 404

    def test_export_sarif_when_enabled(
        self,
        client: TestClient,
        mock_scan: MagicMock,
        mock_finding: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        results = [
            MagicMock(),
            _scalar_result(mock_scan),
            _scalar_result(True),
            _findings_result([mock_finding]),
        ]
        factory = _session_with_execute_sequence(results)
        monkeypatch.setattr("src.api.routers.scans.async_session_factory", factory)
        r = client.get(
            f"/api/v1/scans/{mock_scan.id}/findings/export.sarif",
        )
        assert r.status_code == 200
        assert "sarif" in r.headers.get("content-type", "").lower()
        payload = json.loads(r.content)
        assert payload.get("version") == "2.1.0"
        assert payload.get("$schema")

    def test_export_junit_path_when_enabled(
        self,
        client: TestClient,
        mock_scan: MagicMock,
        mock_finding: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        results = [
            MagicMock(),
            _scalar_result(mock_scan),
            _scalar_result(True),
            _findings_result([mock_finding]),
        ]
        factory = _session_with_execute_sequence(results)
        monkeypatch.setattr("src.api.routers.scans.async_session_factory", factory)
        r = client.get(
            f"/api/v1/scans/{mock_scan.id}/findings/export.junit.xml",
        )
        assert r.status_code == 200
        root = ET.fromstring(r.content)
        assert root.tag == "testsuites"
        assert root.find("testsuite") is not None
