"""ARGUS-009 Phase 7 — Reports & Object Storage.

Tests for storage (mocked S3/MinIO), generators, and reports router.
"""

import json
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from src.api.schemas import Finding, ReportSummary
from src.reports.generators import (
    ReportData,
    generate_csv,
    generate_html,
    generate_json,
    generate_pdf,
)
from starlette.testclient import TestClient

from tests.weasyprint_skips import WSP_REASON, WSP_SKIP


# --- Generators (no mocks) ---
class TestReportGenerators:
    """Report generators produce valid output."""

    @pytest.fixture
    def sample_data(self) -> ReportData:
        return ReportData(
            report_id="r-001",
            target="https://example.com",
            summary=ReportSummary(
                critical=1,
                high=2,
                medium=3,
                low=0,
                info=1,
                technologies=["nginx", "php"],
                sslIssues=0,
                headerIssues=1,
                leaksFound=False,
            ),
            findings=[
                Finding(
                    severity="critical",
                    title="SQL Injection",
                    description="Found in /login",
                    cwe="CWE-89",
                    cvss=9.8,
                ),
                Finding(
                    severity="high",
                    title="XSS",
                    description="Reflected",
                    cwe="CWE-79",
                    cvss=6.1,
                ),
            ],
            technologies=["nginx", "php"],
            created_at="2026-03-08T12:00:00Z",
            scan_id="s-001",
            ai_insights=["Prioritize SQLi remediation.", "Review auth flow."],
        )

    def test_generate_json(self, sample_data: ReportData) -> None:
        content = generate_json(sample_data)
        assert isinstance(content, bytes)
        data = json.loads(content.decode("utf-8"))
        assert data["report_id"] == "r-001"
        assert data["target"] == "https://example.com"
        assert len(data["findings"]) == 2
        assert data["findings"][0]["severity"] == "critical"
        assert len(data["ai_conclusions"]) == 2
        assert "ai_sections" in data
        assert data["scan_artifacts"]["status"] == "skipped"
        assert "active_web_scan" in data
        assert data["active_web_scan"] == {}

    def test_generate_csv(self, sample_data: ReportData) -> None:
        content = generate_csv(sample_data)
        assert isinstance(content, bytes)
        text = content.decode("utf-8")
        assert "Severity" in text
        assert "SQL Injection" in text
        assert "critical" in text

    def test_generate_html(self, sample_data: ReportData) -> None:
        content = generate_html(sample_data)
        assert isinstance(content, bytes)
        text = content.decode("utf-8")
        assert "<!DOCTYPE html>" in text
        assert "ARGUS Security Report" in text
        assert "AI Conclusions" in text
        assert "Prioritize SQLi" in text

    @pytest.mark.weasyprint_pdf
    @pytest.mark.skipif(WSP_SKIP, reason=WSP_REASON)
    def test_generate_pdf(self, sample_data: ReportData) -> None:
        content = generate_pdf(sample_data)
        assert isinstance(content, bytes)
        assert content[:4] == b"%PDF"

    def test_generate_json_empty_findings(self) -> None:
        """Generators handle report with no findings."""
        data = ReportData(
            report_id="r-empty",
            target="https://empty.example.com",
            summary=ReportSummary(
                critical=0,
                high=0,
                medium=0,
                low=0,
                info=0,
                technologies=[],
                sslIssues=0,
                headerIssues=0,
                leaksFound=False,
            ),
            findings=[],
            technologies=[],
            created_at="2026-03-08T12:00:00Z",
            scan_id="s-empty",
            ai_insights=[],
        )
        content = generate_json(data)
        assert isinstance(content, bytes)
        parsed = json.loads(content.decode("utf-8"))
        assert parsed["report_id"] == "r-empty"
        assert parsed["findings"] == []
        assert parsed["ai_conclusions"] == []

    def test_generate_csv_empty_findings(self) -> None:
        """CSV has header only when no findings."""
        data = ReportData(
            report_id="r-empty",
            target="https://empty.example.com",
            summary=ReportSummary(
                critical=0, high=0, medium=0, low=0, info=0,
                technologies=[], sslIssues=0, headerIssues=0, leaksFound=False,
            ),
            findings=[],
            technologies=[],
        )
        content = generate_csv(data)
        text = content.decode("utf-8")
        assert "Severity" in text
        assert "Title" in text
        lines = text.strip().split("\n")
        assert lines[0].startswith("Severity")
        assert "# ai_sections" in text
        assert "# scan_artifacts" in text

    def test_generate_html_empty_findings(self) -> None:
        """HTML renders with empty findings table."""
        data = ReportData(
            report_id="r-empty",
            target="https://empty.example.com",
            summary=ReportSummary(
                critical=0, high=0, medium=0, low=0, info=0,
                technologies=[], sslIssues=0, headerIssues=0, leaksFound=False,
            ),
            findings=[],
            technologies=[],
        )
        content = generate_html(data)
        assert b"ARGUS Security Report" in content
        assert b"Findings" in content
        assert b"<tbody>" in content

    @pytest.mark.weasyprint_pdf
    @pytest.mark.skipif(WSP_SKIP, reason=WSP_REASON)
    def test_generate_pdf_empty_findings(self) -> None:
        """PDF generates with empty findings table."""
        data = ReportData(
            report_id="r-empty",
            target="https://empty.example.com",
            summary=ReportSummary(
                critical=0, high=0, medium=0, low=0, info=0,
                technologies=[], sslIssues=0, headerIssues=0, leaksFound=False,
            ),
            findings=[],
            technologies=[],
        )
        content = generate_pdf(data)
        assert isinstance(content, bytes)
        assert content[:4] == b"%PDF"

    def test_generate_json_large_report(self) -> None:
        """Generators handle report with many findings."""
        findings = [
            Finding(
                severity="medium",
                title=f"Finding {i}",
                description=f"Description {i}",
                cwe="CWE-79",
                cvss=5.0,
            )
            for i in range(500)
        ]
        data = ReportData(
            report_id="r-large",
            target="https://large.example.com",
            summary=ReportSummary(
                critical=0,
                high=0,
                medium=500,
                low=0,
                info=0,
                technologies=[],
                sslIssues=0,
                headerIssues=0,
                leaksFound=False,
            ),
            findings=findings,
            technologies=[],
        )
        content = generate_json(data)
        assert isinstance(content, bytes)
        parsed = json.loads(content.decode("utf-8"))
        assert len(parsed["findings"]) == 500
        assert parsed["findings"][0]["title"] == "Finding 0"

    @pytest.mark.weasyprint_pdf
    @pytest.mark.skipif(WSP_SKIP, reason=WSP_REASON)
    def test_generate_pdf_large_report(self) -> None:
        """PDF generates for large report (500 findings)."""
        findings = [
            Finding(
                severity="info",
                title=f"Issue {i}",
                description="x",
                cwe="CWE-200",
                cvss=3.0,
            )
            for i in range(500)
        ]
        data = ReportData(
            report_id="r-large",
            target="https://large.example.com",
            summary=ReportSummary(
                critical=0, high=0, medium=0, low=0, info=500,
                technologies=[], sslIssues=0, headerIssues=0, leaksFound=False,
            ),
            findings=findings,
            technologies=[],
        )
        content = generate_pdf(data)
        assert isinstance(content, bytes)
        assert content[:4] == b"%PDF"
        assert len(content) > 1000


# --- RPT-002: Settings default for dedicated reports bucket ---
class TestRpt002MinioReportsBucketSettings:
    """MINIO_REPORTS_BUCKET / minio_reports_bucket defaults (RPT-002)."""

    def test_minio_reports_bucket_field_exists(self) -> None:
        from src.core.config import Settings

        assert "minio_reports_bucket" in Settings.model_fields

    def test_minio_reports_bucket_default_is_argus_reports(self) -> None:
        from src.core.config import Settings

        default = Settings.model_fields["minio_reports_bucket"].default
        assert default == "argus-reports"


# --- Storage (mocked boto3) ---
class TestReportStorage:
    """S3/MinIO storage with mocked boto3."""

    @pytest.fixture
    def mock_s3_client(self):
        client = MagicMock()
        client.exceptions.ClientError = type("ClientError", (Exception,), {})
        client.exceptions.NoSuchKey = type("NoSuchKey", (Exception,), {})

        def head_object(**_kwargs):
            raise client.exceptions.ClientError(
                {"Error": {"Code": "404", "Message": "Not Found"}},
                "HeadObject",
            )

        def get_object(**_kwargs):
            raise client.exceptions.NoSuchKey

        client.head_object = MagicMock(side_effect=head_object)
        client.get_object = MagicMock(side_effect=get_object)
        client.put_object = MagicMock(return_value={})
        return client

    def test_upload_returns_key(self, mock_s3_client) -> None:
        with patch("src.storage.s3._get_client", return_value=mock_s3_client):
            import src.reports.storage as storage
            from src.core.config import settings

            key = storage.upload(
                "tenant-1",
                "scan-1",
                "reports",
                "report.pdf",
                b"fake-pdf-content",
                "application/pdf",
            )
            assert key == "tenant-1/scan-1/reports/report.pdf"
            mock_s3_client.put_object.assert_called_once()
            _call = mock_s3_client.put_object.call_args
            assert _call.kwargs.get("Bucket") == settings.minio_reports_bucket

    def test_upload_report_artifact_returns_five_segment_key(self, mock_s3_client) -> None:
        with patch("src.storage.s3._get_client", return_value=mock_s3_client):
            from src.core.config import settings
            from src.storage.s3 import upload_report_artifact

            mock_s3_client.put_object.reset_mock()
            key = upload_report_artifact(
                "tenant-1",
                "scan-1",
                "valhalla",
                "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "pdf",
                b"x",
                content_type="application/pdf",
            )
            assert key == "tenant-1/scan-1/reports/valhalla/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.pdf"
            mock_s3_client.put_object.assert_called_once()
            assert (
                mock_s3_client.put_object.call_args.kwargs.get("Bucket")
                == settings.minio_reports_bucket
            )

    @pytest.mark.parametrize(
        "object_type",
        ["raw", "screenshots", "evidence", "attachments"],
    )
    def test_upload_uses_minio_bucket_for_non_reports_object_type(
        self, mock_s3_client, object_type: str
    ) -> None:
        """RPT-002: only object_type ``reports`` targets minio_reports_bucket."""
        with patch("src.storage.s3._get_client", return_value=mock_s3_client):
            from src.core.config import settings
            from src.storage.s3 import upload as s3_upload

            mock_s3_client.put_object.reset_mock()
            key = s3_upload(
                "tenant-1",
                "scan-1",
                object_type,
                "artifact.bin",
                b"x",
                "application/octet-stream",
            )
            assert key == f"tenant-1/scan-1/{object_type}/artifact.bin"
            mock_s3_client.put_object.assert_called_once()
            assert (
                mock_s3_client.put_object.call_args.kwargs.get("Bucket")
                == settings.minio_bucket
            )

    def test_download_by_key_uses_reports_bucket_when_path_segment_reports(
        self, mock_s3_client
    ) -> None:
        """Full key with .../reports/... selects minio_reports_bucket."""
        body = MagicMock()
        body.read.return_value = b"pdf-bytes"
        mock_s3_client.get_object = MagicMock(return_value={"Body": body})
        with patch("src.storage.s3._get_client", return_value=mock_s3_client):
            from src.core.config import settings
            from src.storage.s3 import download_by_key

            out = download_by_key("tenant-1/scan-1/reports/export.pdf")
            assert out == b"pdf-bytes"
            mock_s3_client.get_object.assert_called_once_with(
                Bucket=settings.minio_reports_bucket,
                Key="tenant-1/scan-1/reports/export.pdf",
            )

    def test_download_by_key_five_segment_reports_key_uses_reports_bucket(
        self, mock_s3_client
    ) -> None:
        body = MagicMock()
        body.read.return_value = b"tier-pdf"
        mock_s3_client.get_object = MagicMock(return_value={"Body": body})
        with patch("src.storage.s3._get_client", return_value=mock_s3_client):
            from src.core.config import settings
            from src.storage.s3 import download_by_key

            key = "tenant-1/scan-1/reports/midgard/report-uuid.pdf"
            out = download_by_key(key)
            assert out == b"tier-pdf"
            mock_s3_client.get_object.assert_called_once_with(
                Bucket=settings.minio_reports_bucket,
                Key=key,
            )

    def test_download_by_key_uses_minio_bucket_for_raw_segment(
        self, mock_s3_client
    ) -> None:
        body = MagicMock()
        body.read.return_value = b"raw-bytes"
        mock_s3_client.get_object = MagicMock(return_value={"Body": body})
        with patch("src.storage.s3._get_client", return_value=mock_s3_client):
            from src.core.config import settings
            from src.storage.s3 import download_by_key

            out = download_by_key("tenant-1/scan-1/raw/output.txt")
            assert out == b"raw-bytes"
            mock_s3_client.get_object.assert_called_once_with(
                Bucket=settings.minio_bucket,
                Key="tenant-1/scan-1/raw/output.txt",
            )

    def test_exists_non_reports_uses_minio_bucket(self, mock_s3_client) -> None:
        mock_s3_client.head_object = MagicMock(return_value={})
        with patch("src.storage.s3._get_client", return_value=mock_s3_client):
            from src.core.config import settings
            from src.storage.s3 import exists as s3_exists

            ok = s3_exists("t1", "s1", "evidence", "shot.png")
            assert ok is True
            mock_s3_client.head_object.assert_called_once_with(
                Bucket=settings.minio_bucket,
                Key="t1/s1/evidence/shot.png",
            )

    def test_download_returns_none_when_not_found(self, mock_s3_client) -> None:
        with patch("src.storage.s3._get_client", return_value=mock_s3_client):
            import src.reports.storage as storage

            data = storage.download("tenant-1", "scan-1", "reports", "report.pdf")
            assert data is None

    def test_exists_returns_false_when_404(self, mock_s3_client) -> None:
        err = type("ClientError", (Exception,), {})(
            {"Error": {"Code": "404"}},
            "HeadObject",
        )
        err.response = {"Error": {"Code": "404"}}
        mock_s3_client.head_object = MagicMock(side_effect=err)
        with patch("src.storage.s3._get_client", return_value=mock_s3_client):
            import src.reports.storage as storage

            ok = storage.exists("tenant-1", "scan-1", "reports", "report.pdf")
            assert ok is False


# --- Reports router (mocked DB + storage) ---
class TestReportsRouter:
    """Reports API with mocked DB and storage."""

    @pytest.fixture
    def mock_report_and_findings(self):
        from src.core.config import settings
        from src.db.models import Finding as FindingModel
        from src.db.models import Report

        report = Report(
            id="rep-001",
            tenant_id=settings.default_tenant_id,
            scan_id="scan-001",
            target="https://target.example.com",
            summary={
                "critical": 0,
                "high": 1,
                "medium": 0,
                "low": 0,
                "info": 0,
                "technologies": [],
                "sslIssues": 0,
                "headerIssues": 0,
                "leaksFound": False,
                "ai_insights": ["AI conclusion"],
            },
            technologies=["nginx"],
            created_at=datetime.now(UTC),
        )
        findings = [
            FindingModel(
                id="f-001",
                tenant_id=settings.default_tenant_id,
                scan_id="scan-001",
                report_id="rep-001",
                severity="high",
                title="XSS",
                description="Reflected XSS",
                cwe="CWE-79",
                cvss=6.1,
            ),
        ]
        return report, findings

    @pytest.fixture
    def mock_db_reports(self, mock_report_and_findings):
        report, findings = mock_report_and_findings
        async def execute(query, *args, **kwargs):
            result = MagicMock()
            qstr = str(query).lower()
            if "findings" in qstr:
                result.scalars.return_value.all.return_value = findings
                result.scalar_one_or_none.return_value = None
            elif "reports" in qstr:
                result.scalars.return_value.all.return_value = [report]
                result.scalar_one_or_none.return_value = report
            else:
                result.scalars.return_value.all.return_value = []
                result.scalar_one_or_none.return_value = None
            return result

        session = MagicMock()
        session.execute = AsyncMock(side_effect=execute)
        session.commit = AsyncMock(return_value=None)
        session.rollback = AsyncMock(return_value=None)
        session.__aenter__ = MagicMock(return_value=session)
        session.__aexit__ = MagicMock(return_value=None)

        @asynccontextmanager
        async def _factory():
            yield session

        return _factory

    def test_list_reports_empty(self, client: TestClient) -> None:
        async def empty_execute(_query, *args, **kwargs):
            r = MagicMock()
            r.scalars.return_value.all.return_value = []
            return r

        session = MagicMock()
        session.execute = AsyncMock(side_effect=empty_execute)
        session.__aenter__ = MagicMock(return_value=session)
        session.__aexit__ = MagicMock(return_value=None)

        @asynccontextmanager
        async def _factory():
            yield session

        with patch("src.api.routers.reports.async_session_factory", _factory):
            resp = client.get("/api/v1/reports")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_list_reports_with_target(self, client: TestClient, mock_db_reports) -> None:
        with patch("src.api.routers.reports.async_session_factory", mock_db_reports):
            resp = client.get("/api/v1/reports?target=https://target.example.com")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        if data:
            assert data[0]["report_id"] == "rep-001"
            assert data[0]["target"] == "https://target.example.com"

    def test_get_report_404(self, client: TestClient) -> None:
        async def none_execute(_query, *args, **kwargs):
            r = MagicMock()
            r.scalar_one_or_none.return_value = None
            return r

        session = MagicMock()
        session.execute = AsyncMock(side_effect=none_execute)
        session.__aenter__ = MagicMock(return_value=session)
        session.__aexit__ = MagicMock(return_value=None)

        @asynccontextmanager
        async def _factory():
            yield session

        with patch("src.api.routers.reports.async_session_factory", _factory):
            resp = client.get("/api/v1/reports/nonexistent")
        assert resp.status_code == 404

    def test_download_report_json(self, client: TestClient, mock_db_reports) -> None:
        with (
            patch("src.api.routers.reports.async_session_factory", mock_db_reports),
            patch("src.api.routers.reports.storage_exists", return_value=False),
            patch("src.api.routers.reports.upload_report_artifact"),
        ):
            resp = client.get("/api/v1/reports/rep-001/download?format=json")
        assert resp.status_code == 200, f"Got {resp.status_code}: {resp.text}"
        assert resp.headers["content-type"].startswith("application/json")
        data = json.loads(resp.content.decode("utf-8"))
        assert data["report_id"] == "rep-001"
        assert data["target"] == "https://target.example.com"

    def test_download_report_invalid_format(self, client: TestClient, mock_db_reports) -> None:
        """Invalid format returns 400."""
        with patch("src.api.routers.reports.async_session_factory", mock_db_reports):
            resp = client.get("/api/v1/reports/rep-001/download?format=xml")
        assert resp.status_code == 400

    def test_download_report_invalid_format_empty(self, client: TestClient, mock_db_reports) -> None:
        """Empty format string returns 400."""
        with patch("src.api.routers.reports.async_session_factory", mock_db_reports):
            resp = client.get("/api/v1/reports/rep-001/download?format=")
        assert resp.status_code == 400

    def test_download_report_invalid_format_unknown(self, client: TestClient, mock_db_reports) -> None:
        """Unknown format (docx) returns 400."""
        with patch("src.api.routers.reports.async_session_factory", mock_db_reports):
            resp = client.get("/api/v1/reports/rep-001/download?format=docx")
        assert resp.status_code == 400

    def test_download_report_storage_404_regenerates(
        self, client: TestClient, mock_db_reports
    ) -> None:
        """When storage says exists but download returns None (404), report is regenerated."""
        with (
            patch("src.api.routers.reports.async_session_factory", mock_db_reports),
            patch("src.api.routers.reports.storage_exists", return_value=True),
            patch("src.api.routers.reports.storage_download", return_value=None),
            patch("src.api.routers.reports.upload_report_artifact"),
        ):
            resp = client.get("/api/v1/reports/rep-001/download?format=json")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("application/json")
        data = json.loads(resp.content.decode("utf-8"))
        assert data["report_id"] == "rep-001"
        assert data["target"] == "https://target.example.com"

    def test_download_report_empty_findings(self, client: TestClient) -> None:
        """Download works when report has no findings."""
        from src.core.config import settings
        from src.db.models import Finding as FindingModel
        from src.db.models import Report

        report = Report(
            id="rep-empty",
            tenant_id=settings.default_tenant_id,
            scan_id="scan-empty",
            target="https://empty.example.com",
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
                "ai_insights": [],
            },
            technologies=[],
            created_at=datetime.now(UTC),
        )
        findings: list[FindingModel] = []

        async def empty_execute(query, *args, **kwargs):
            result = MagicMock()
            qstr = str(query).lower()
            if "findings" in qstr:
                result.scalars.return_value.all.return_value = findings
                result.scalar_one_or_none.return_value = None
            elif "reports" in qstr:
                result.scalars.return_value.all.return_value = [report]
                result.scalar_one_or_none.return_value = report
            else:
                result.scalars.return_value.all.return_value = []
                result.scalar_one_or_none.return_value = None
            return result

        session = MagicMock()
        session.execute = AsyncMock(side_effect=empty_execute)
        session.commit = AsyncMock(return_value=None)
        session.rollback = AsyncMock(return_value=None)
        session.__aenter__ = MagicMock(return_value=session)
        session.__aexit__ = MagicMock(return_value=None)

        @asynccontextmanager
        async def _factory():
            yield session

        with (
            patch("src.api.routers.reports.async_session_factory", _factory),
            patch("src.api.routers.reports.storage_exists", return_value=False),
            patch("src.api.routers.reports.upload_report_artifact"),
        ):
            resp = client.get("/api/v1/reports/rep-empty/download?format=json")
        assert resp.status_code == 200
        data = json.loads(resp.content.decode("utf-8"))
        assert data["report_id"] == "rep-empty"
        assert data["findings"] == []
