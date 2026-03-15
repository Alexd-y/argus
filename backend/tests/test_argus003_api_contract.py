"""API contract tests for ARGUS-003 (Phase 2: Core Backend).

TestClient: GET /health 200, POST /scans returns scan_id, GET /scans/:id, GET /reports.
Contract test: OpenAPI schema matches api-contracts.md expectations.
Uses mocks for DB-dependent tests so they pass without PostgreSQL.
"""

import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

from starlette.testclient import TestClient

REQUIRED_OPENAPI_PATHS = [
    "/api/v1/health",
    "/api/v1/scans",
    "/api/v1/reports",
]


def _resolve_schema(spec: dict, schema: dict) -> dict:
    """Resolve $ref in OpenAPI schema to get actual properties."""
    if not schema:
        return {}
    ref = schema.get("$ref")
    if ref and ref.startswith("#/components/schemas/"):
        name = ref.split("/")[-1]
        return spec.get("components", {}).get("schemas", {}).get(name, {})
    return schema


def _validate_openapi_contract(spec: dict, required_paths: list[str] | None = None) -> list[str]:
    """Validate OpenAPI spec structure and required paths. Returns list of error messages."""
    errors: list[str] = []
    paths_req = required_paths or REQUIRED_OPENAPI_PATHS

    if not spec or not isinstance(spec, dict):
        return ["OpenAPI spec must be a non-empty dict"]

    if "paths" not in spec:
        return ["OpenAPI spec must have 'paths' key"]

    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return ["OpenAPI 'paths' must be a dict"]

    for path in paths_req:
        if path not in paths:
            errors.append(f"Missing path: {path}")

    return errors


class TestHealthEndpoint:
    """GET /api/v1/health."""

    def test_health_returns_200(self, client: TestClient) -> None:
        """GET /health returns 200."""
        response = client.get("/api/v1/health")
        assert response.status_code == 200

    def test_health_response_structure(self, client: TestClient) -> None:
        """Response has status and version."""
        response = client.get("/api/v1/health")
        data = response.json()
        assert data["status"] == "ok"
        assert "version" in data
        assert data["version"] == "0.1.0"

    def test_health_content_type_json(self, client: TestClient) -> None:
        """Health returns application/json."""
        response = client.get("/api/v1/health")
        assert response.headers.get("content-type", "").startswith("application/json")


def _mock_db_session_create():
    """Mock async_session_factory for create_scan."""
    tenant_result = MagicMock()
    tenant_result.scalar_one_or_none.return_value = None
    session = AsyncMock()
    session.add = MagicMock()
    session.commit = AsyncMock()
    session.flush = AsyncMock()
    session.execute = AsyncMock(return_value=tenant_result)  # SET LOCAL + select Tenant

    @asynccontextmanager
    async def _cm():
        yield session

    def factory():
        return _cm()
    return factory


def _mock_db_scan_get(scan_id: str, exists: bool = True):
    """Mock async_session_factory for get_scan."""
    scan_result = MagicMock()
    if exists:
        mock_scan = MagicMock()
        mock_scan.id = scan_id
        mock_scan.status = "running"
        mock_scan.progress = 50
        mock_scan.phase = "vuln_analysis"
        mock_scan.target_url = "https://example.com"
        mock_scan.created_at = datetime.now(UTC)
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


def _mock_db_reports(
    report_id: str = "00000000-0000-0000-0000-000000000001",
    has_reports: bool = True,
):
    """Mock async_session_factory for reports endpoints. Uses real ORM objects for JSON serialization."""
    from src.db.models import Finding as FindingModel
    from src.db.models import Report

    report = Report(
        id=report_id,
        tenant_id="00000000-0000-0000-0000-000000000001",
        scan_id=report_id,
        target="https://filtered.com",
        summary={
            "critical": 0, "high": 1, "medium": 2, "low": 0, "info": 0,
            "technologies": ["nginx"], "sslIssues": 0, "headerIssues": 0, "leaksFound": False,
        },
        technologies=["nginx", "php"],
        created_at=datetime.now(UTC),
    ) if has_reports else None

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
    ] if has_reports else []

    empty_result = MagicMock()
    empty_result.scalar_one_or_none.return_value = None
    empty_result.scalars.return_value.all.return_value = []

    report_result = MagicMock()
    report_result.scalar_one_or_none.return_value = report
    report_result.scalars.return_value.all.return_value = [report] if report else []

    findings_result = MagicMock()
    findings_result.scalar_one_or_none.return_value = None
    findings_result.scalars.return_value.all.return_value = findings

    async def execute_mock(query, *args, **kwargs):
        qstr = str(query).lower()
        if "set local" in qstr or "app.current_tenant_id" in qstr:
            return MagicMock()
        if "findings" in qstr:
            return findings_result
        if "reports" in qstr:
            return report_result
        return empty_result

    session = AsyncMock()
    session.execute = AsyncMock(side_effect=execute_mock)

    @asynccontextmanager
    async def _cm():
        yield session

    def factory():
        return _cm()
    return factory


class TestScansEndpoint:
    """POST /scans, GET /scans/:id. Uses mocks for DB independence."""

    def test_post_scans_returns_201_and_scan_id(self, client: TestClient) -> None:
        """POST /scans returns 201 and scan_id."""
        with (
            patch("src.api.routers.scans.async_session_factory", _mock_db_session_create()),
            patch("src.api.routers.scans.scan_phase_task"),
        ):
            response = client.post(
                "/api/v1/scans",
                json={"target": "https://example.com", "email": "user@example.com"},
            )
        assert response.status_code == 201
        data = response.json()
        assert "scan_id" in data
        assert data["status"] == "queued"
        assert data["message"] == "Scan queued successfully"
        uuid.UUID(data["scan_id"])

    def test_post_scans_with_options(self, client: TestClient) -> None:
        """POST /scans accepts optional options."""
        with (
            patch("src.api.routers.scans.async_session_factory", _mock_db_session_create()),
            patch("src.api.routers.scans.scan_phase_task"),
        ):
            response = client.post(
                "/api/v1/scans",
                json={
                    "target": "https://target.com",
                    "email": "admin@test.com",
                    "options": {
                        "scanType": "deep",
                        "reportFormat": "pdf",
                        "vulnerabilities": {"xss": True, "sqli": True},
                    },
                },
            )
        assert response.status_code == 201
        assert "scan_id" in response.json()

    def test_post_scans_missing_target_returns_422(self, client: TestClient) -> None:
        """POST /scans without target returns 422."""
        response = client.post(
            "/api/v1/scans",
            json={"email": "user@example.com"},
        )
        assert response.status_code == 422

    def test_post_scans_missing_email_returns_422(self, client: TestClient) -> None:
        """POST /scans without email returns 422."""
        response = client.post(
            "/api/v1/scans",
            json={"target": "https://example.com"},
        )
        assert response.status_code == 422

    def test_get_scan_by_id_returns_200(self, client: TestClient) -> None:
        """GET /scans/:id returns scan detail."""
        scan_id = str(uuid.uuid4())
        with patch(
            "src.api.routers.scans.async_session_factory",
            _mock_db_scan_get(scan_id, exists=True),
        ):
            response = client.get(f"/api/v1/scans/{scan_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == scan_id
        assert "status" in data
        assert "progress" in data
        assert "phase" in data
        assert "target" in data
        assert "created_at" in data

    def test_get_scan_nonexistent_returns_404(self, client: TestClient) -> None:
        """GET /scans/:id with non-existent ID returns 404."""
        scan_id = str(uuid.uuid4())
        with patch(
            "src.api.routers.scans.async_session_factory",
            _mock_db_scan_get(scan_id, exists=False),
        ):
            response = client.get(f"/api/v1/scans/{scan_id}")
        assert response.status_code == 404
        assert response.json().get("detail") == "Scan not found"

    def test_get_scan_events_returns_sse(self, client: TestClient) -> None:
        """GET /scans/:id/events returns SSE stream."""
        scan_id = str(uuid.uuid4())
        response = client.get(
            f"/api/v1/scans/{scan_id}/events",
            headers={"Accept": "text/event-stream"},
        )
        assert response.status_code == 200
        assert "text/event-stream" in response.headers.get("content-type", "")


class TestReportsEndpoint:
    """GET /reports, GET /reports/:id. Uses mocks for DB independence."""

    def test_get_reports_returns_200(self, client: TestClient) -> None:
        """GET /reports returns 200 and list of reports."""
        with patch(
            "src.api.routers.reports.async_session_factory",
            _mock_db_reports(has_reports=True),
        ):
            response = client.get("/api/v1/reports")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        if data:
            item = data[0]
            assert "report_id" in item
            assert "target" in item
            assert "summary" in item
            assert "findings" in item
            assert "technologies" in item

    def test_get_reports_with_target_filter(self, client: TestClient) -> None:
        """GET /reports?target=... returns filtered list."""
        with patch(
            "src.api.routers.reports.async_session_factory",
            _mock_db_reports(has_reports=True),
        ):
            response = client.get("/api/v1/reports?target=https://filtered.com")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        if data:
            assert data[0]["target"] == "https://filtered.com"

    def test_get_report_by_id_returns_200(self, client: TestClient) -> None:
        """GET /reports/:id returns report detail."""
        report_id = "00000000-0000-0000-0000-000000000001"
        with patch(
            "src.api.routers.reports.async_session_factory",
            _mock_db_reports(report_id=report_id, has_reports=True),
        ):
            response = client.get(f"/api/v1/reports/{report_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["report_id"] == report_id
        assert "summary" in data
        assert "findings" in data

    def test_get_report_download_returns_stream(self, client: TestClient) -> None:
        """GET /reports/:id/download returns file stream."""
        report_id = "00000000-0000-0000-0000-000000000001"
        with (
            patch(
                "src.api.routers.reports.async_session_factory",
                _mock_db_reports(report_id=report_id, has_reports=True),
            ),
            patch("src.api.routers.reports.storage_exists", return_value=False),
        ):
            response = client.get(f"/api/v1/reports/{report_id}/download?format=pdf")
        assert response.status_code == 200
        assert "attachment" in response.headers.get("Content-Disposition", "")
        assert "report-" in response.headers.get("Content-Disposition", "")


class TestOpenAPIContract:
    """Validate OpenAPI schema matches api-contracts.md (Frontend expectations)."""

    def test_openapi_json_available(self, client: TestClient) -> None:
        """GET /api/v1/openapi.json returns 200."""
        response = client.get("/api/v1/openapi.json")
        assert response.status_code == 200
        assert response.headers.get("content-type", "").startswith("application/json")

    def test_openapi_spec_has_valid_structure(self, client: TestClient) -> None:
        """Live OpenAPI response has required top-level keys (openapi, info, paths)."""
        response = client.get("/api/v1/openapi.json")
        assert response.status_code == 200
        spec = response.json()
        assert "openapi" in spec
        assert "info" in spec
        assert "paths" in spec
        assert isinstance(spec["paths"], dict)

    def test_openapi_has_required_paths(self, client: TestClient) -> None:
        """OpenAPI documents all endpoints from api-contracts."""
        response = client.get("/api/v1/openapi.json")
        assert response.status_code == 200
        spec = response.json()
        errors = _validate_openapi_contract(spec)
        assert not errors, "; ".join(errors)

    def test_openapi_health_schema(self, client: TestClient) -> None:
        """GET /health response schema: status, version (optional)."""
        response = client.get("/api/v1/openapi.json")
        spec = response.json()
        health = spec.get("paths", {}).get("/api/v1/health", {})
        get_op = health.get("get", {})
        assert "responses" in get_op
        raw_schema = (
            get_op.get("responses", {})
            .get("200", {})
            .get("content", {})
            .get("application/json", {})
            .get("schema", {})
        )
        schema = _resolve_schema(spec, raw_schema)
        props = schema.get("properties", {})
        assert "status" in props
        assert "version" in props

    def test_openapi_post_scans_schema(self, client: TestClient) -> None:
        """POST /scans request: target, email; response: scan_id, status, message?."""
        response = client.get("/api/v1/openapi.json")
        spec = response.json()
        scans = spec.get("paths", {}).get("/api/v1/scans", {})
        post_op = scans.get("post", {})
        raw_req = (
            post_op.get("requestBody", {})
            .get("content", {})
            .get("application/json", {})
            .get("schema", {})
        )
        req_schema = _resolve_schema(spec, raw_req)
        assert "target" in req_schema.get("properties", {})
        assert "email" in req_schema.get("properties", {})

        raw_resp = (
            post_op.get("responses", {})
            .get("201", {})
            .get("content", {})
            .get("application/json", {})
            .get("schema", {})
        )
        resp_schema = _resolve_schema(spec, raw_resp)
        assert "scan_id" in resp_schema.get("properties", {})
        assert "status" in resp_schema.get("properties", {})

    def test_openapi_get_scan_by_id_schema(self, client: TestClient) -> None:
        """GET /scans/:id response: id, status, progress, phase, target, created_at."""
        response = client.get("/api/v1/openapi.json")
        spec = response.json()
        scan_path = spec.get("paths", {}).get("/api/v1/scans/{scan_id}")
        assert scan_path, "GET /scans/:id path not found"
        get_op = scan_path.get("get", {})
        raw_schema = (
            get_op.get("responses", {})
            .get("200", {})
            .get("content", {})
            .get("application/json", {})
            .get("schema", {})
        )
        schema = _resolve_schema(spec, raw_schema)
        props = schema.get("properties", {})
        required = ["id", "status", "progress", "phase", "target", "created_at"]
        for r in required:
            assert r in props, f"Missing property in GET /scans/:id: {r}"

    def test_openapi_get_reports_schema(self, client: TestClient) -> None:
        """GET /reports response: list of report_id, target, summary, findings, technologies."""
        response = client.get("/api/v1/openapi.json")
        spec = response.json()
        reports = spec.get("paths", {}).get("/api/v1/reports", {})
        get_op = reports.get("get", {})
        raw_schema = (
            get_op.get("responses", {})
            .get("200", {})
            .get("content", {})
            .get("application/json", {})
            .get("schema", {})
        )
        assert raw_schema
        schema = _resolve_schema(spec, raw_schema)
        if schema.get("type") == "array":
            item_ref = schema.get("items", {})
            item = _resolve_schema(spec, item_ref)
            props = item.get("properties", {})
        else:
            props = schema.get("properties", {})
        required = ["report_id", "target", "summary", "findings", "technologies"]
        for r in required:
            assert r in props, f"Missing property in GET /reports: {r}"

    def test_openapi_validation_invalid_schema_fails(self) -> None:
        """Validation rejects invalid or malformed OpenAPI spec structure."""
        assert _validate_openapi_contract(None)
        assert _validate_openapi_contract({})
        assert "paths" in str(_validate_openapi_contract({"info": {}}))
        assert _validate_openapi_contract({"paths": "not-a-dict"})
        assert _validate_openapi_contract({"paths": []})

    def test_openapi_validation_missing_paths_fails(self) -> None:
        """Validation fails when required paths are missing."""
        spec_partial = {
            "paths": {
                "/api/v1/health": {"get": {}},
            },
        }
        errors = _validate_openapi_contract(spec_partial)
        assert errors
        assert any("scans" in e for e in errors)
        assert any("reports" in e for e in errors)

        spec_empty_paths = {"paths": {}}
        errors_empty = _validate_openapi_contract(spec_empty_paths)
        assert len(errors_empty) == len(REQUIRED_OPENAPI_PATHS)


class TestFrontendApiContract:
    """CONTRACT-001: Backend API responses match schemas from frontend-api-contract.md."""

    def test_create_scan_response_matches_contract(self, client: TestClient) -> None:
        """POST /scans returns CreateScanResponse: scan_id, status, message?."""
        with (
            patch("src.api.routers.scans.async_session_factory", _mock_db_session_create()),
            patch("src.api.routers.scans.scan_phase_task"),
        ):
            response = client.post(
                "/api/v1/scans",
                json={"target": "https://example.com", "email": "user@example.com"},
            )
        assert response.status_code == 201
        data = response.json()
        assert "scan_id" in data
        assert "status" in data
        assert isinstance(data["scan_id"], str)
        assert isinstance(data["status"], str)
        if "message" in data:
            assert isinstance(data["message"], str)

    def test_scan_status_response_matches_contract(self, client: TestClient) -> None:
        """GET /scans/:id returns ScanStatus: id, status, progress, phase, target, created_at."""
        scan_id = str(uuid.uuid4())
        with patch(
            "src.api.routers.scans.async_session_factory",
            _mock_db_scan_get(scan_id, exists=True),
        ):
            response = client.get(f"/api/v1/scans/{scan_id}")
        assert response.status_code == 200
        data = response.json()
        required = ["id", "status", "progress", "phase", "target", "created_at"]
        for key in required:
            assert key in data, f"ScanStatus missing field: {key}"
        assert isinstance(data["progress"], (int, float))
        assert isinstance(data["created_at"], str)

    def test_report_list_response_matches_contract(self, client: TestClient) -> None:
        """GET /reports returns Report[]: report_id, target, summary, findings, technologies."""
        with patch(
            "src.api.routers.reports.async_session_factory",
            _mock_db_reports(has_reports=True),
        ):
            response = client.get("/api/v1/reports")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        if data:
            item = data[0]
            for key in ["report_id", "target", "summary", "findings", "technologies"]:
                assert key in item, f"Report missing field: {key}"
            summary = item["summary"]
            for k in ["critical", "high", "medium", "low", "info", "technologies",
                      "sslIssues", "headerIssues", "leaksFound"]:
                assert k in summary, f"ReportSummary missing field: {k}"
            for f in item["findings"]:
                assert "severity" in f and "title" in f and "description" in f

    def test_report_detail_response_matches_contract(self, client: TestClient) -> None:
        """GET /reports/:id returns Report: report_id, target, summary, findings, technologies."""
        report_id = "00000000-0000-0000-0000-000000000001"
        with patch(
            "src.api.routers.reports.async_session_factory",
            _mock_db_reports(report_id=report_id, has_reports=True),
        ):
            response = client.get(f"/api/v1/reports/{report_id}")
        assert response.status_code == 200
        data = response.json()
        for key in ["report_id", "target", "summary", "findings", "technologies"]:
            assert key in data, f"Report missing field: {key}"
        assert "critical" in data["summary"]
        assert "high" in data["summary"]

    def test_sse_events_content_type(self, client: TestClient) -> None:
        """GET /scans/:id/events returns text/event-stream per contract."""
        scan_id = str(uuid.uuid4())
        response = client.get(
            f"/api/v1/scans/{scan_id}/events",
            headers={"Accept": "text/event-stream"},
        )
        assert response.status_code == 200
        assert "text/event-stream" in response.headers.get("content-type", "")

    def test_report_download_formats_per_contract(self, client: TestClient) -> None:
        """Report download supports pdf, html, json, csv per frontend-api-contract."""
        report_id = "00000000-0000-0000-0000-000000000001"
        for fmt in ("pdf", "html", "json", "csv"):
            with (
                patch(
                    "src.api.routers.reports.async_session_factory",
                    _mock_db_reports(report_id=report_id, has_reports=True),
                ),
                patch("src.api.routers.reports.storage_exists", return_value=False),
                patch("src.api.routers.reports.upload"),
            ):
                response = client.get(f"/api/v1/reports/{report_id}/download?format={fmt}")
            assert response.status_code == 200, f"Format {fmt} should be valid"

    def test_error_response_has_user_message(self, client: TestClient) -> None:
        """404/400 responses have error or detail for user-facing message (ApiError)."""
        scan_id = str(uuid.uuid4())
        with patch(
            "src.api.routers.scans.async_session_factory",
            _mock_db_scan_get(scan_id, exists=False),
        ):
            response = client.get(f"/api/v1/scans/{scan_id}")
        assert response.status_code == 404
        body = response.json()
        assert "detail" in body or "error" in body
        msg = body.get("detail") or body.get("error")
        assert isinstance(msg, str)
        assert len(msg) > 0
