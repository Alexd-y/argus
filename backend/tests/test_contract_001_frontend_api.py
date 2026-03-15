"""CONTRACT-001: Frontend API contract document structure tests.

Verifies that docs/frontend-api-contract.md exists and contains required sections:
- Endpoints table (section 2)
- Full schemas (section 4)
"""

from pathlib import Path

import pytest

# Contract doc path: ARGUS/docs/frontend-api-contract.md (relative to backend root)
CONTRACT_DOC = Path(__file__).resolve().parent.parent.parent / "docs" / "frontend-api-contract.md"

REQUIRED_SCHEMAS = [
    "ApiError",
    "CreateScanRequest",
    "CreateScanResponse",
    "ScanStatus",
    "SSEEventPayload",
    "ReportSummary",
    "Finding",
    "Report",
]


class TestContractDocExists:
    """Contract document exists at expected path."""

    def test_contract_doc_exists(self) -> None:
        """docs/frontend-api-contract.md exists."""
        assert CONTRACT_DOC.exists(), f"Contract doc not found: {CONTRACT_DOC}"
        assert CONTRACT_DOC.is_file()

    def test_contract_doc_not_empty(self) -> None:
        """Contract doc has content."""
        content = CONTRACT_DOC.read_text(encoding="utf-8")
        assert len(content.strip()) > 100


class TestContractDocStructure:
    """Contract document contains required sections per frontend-api-contract.md."""

    @pytest.fixture
    def contract_content(self) -> str:
        """Load contract document content."""
        return CONTRACT_DOC.read_text(encoding="utf-8")

    def test_contract_has_endpoints_section(self, contract_content: str) -> None:
        """Section 2 REST API Endpoints is present."""
        assert "## 2. REST API Endpoints" in contract_content or "## 2. REST API" in contract_content

    def test_contract_has_scans_endpoints_table(self, contract_content: str) -> None:
        """Scans endpoints table (POST /scans, GET /scans/:id, etc.) is documented."""
        assert "POST /scans" in contract_content
        assert "GET /scans/:id" in contract_content or "/scans/:id" in contract_content
        assert "CreateScanRequest" in contract_content or "CreateScanResponse" in contract_content

    def test_contract_has_reports_endpoints_table(self, contract_content: str) -> None:
        """Reports endpoints table is documented."""
        assert "GET /reports" in contract_content
        assert "GET /reports/:id" in contract_content or "/reports/:id" in contract_content
        assert "Report" in contract_content or "Report[]" in contract_content

    def test_contract_has_schemas_section(self, contract_content: str) -> None:
        """Section 4 Full Schemas is present."""
        assert "## 4. Full Schemas" in contract_content or "## 4." in contract_content

    def test_contract_has_required_schemas(self, contract_content: str) -> None:
        """All required schema names are documented."""
        missing = [s for s in REQUIRED_SCHEMAS if s not in contract_content]
        assert not missing, f"Missing schemas in contract doc: {missing}"

    def test_contract_has_api_error_schema(self, contract_content: str) -> None:
        """ApiError schema with error field is documented."""
        assert "ApiError" in contract_content
        assert "error" in contract_content

    def test_contract_has_scan_status_schema(self, contract_content: str) -> None:
        """ScanStatus schema (id, status, progress, phase, target, created_at) is documented."""
        assert "ScanStatus" in contract_content
        assert "id" in contract_content and "status" in contract_content
        assert "progress" in contract_content and "phase" in contract_content

    def test_contract_has_report_schema(self, contract_content: str) -> None:
        """Report schema (report_id, target, summary, findings) is documented."""
        assert "Report" in contract_content
        assert "report_id" in contract_content
        assert "summary" in contract_content and "findings" in contract_content
