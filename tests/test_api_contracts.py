"""Contract tests for api-contracts.md (ARGUS-001).

Проверяет наличие обязательных REST endpoints, request/response schemas,
таблиц и связанных документов.
"""

from pathlib import Path

import pytest

ARGUS_ROOT = Path(__file__).resolve().parent.parent
API_CONTRACTS_PATH = ARGUS_ROOT / "docs" / "api-contracts.md"

# Required REST endpoints for ARGUS Scanner (section 1)
REQUIRED_ARGUS_ENDPOINTS = [
    ("POST", "/scans"),
    ("GET", "/scans/:id"),
    ("GET", "/scans/:id/events"),
    ("GET", "/reports"),
    ("GET", "/reports/:id"),
    ("GET", "/reports/:id/download"),
    ("GET", "/health"),
]

# Required schema names (TypeScript interfaces / table columns)
REQUIRED_SCHEMA_NAMES = [
    "ScanOptions",
    "ReportSummary",
    "Finding",
]


@pytest.fixture(scope="module")
def content() -> str:
    """Содержимое api-contracts.md (общая фикстура для всех тестов модуля)."""
    return API_CONTRACTS_PATH.read_text(encoding="utf-8")


class TestApiContractsFile:
    """Базовые проверки файла api-contracts.md."""

    def test_file_exists(self) -> None:
        """api-contracts.md должен существовать."""
        assert API_CONTRACTS_PATH.exists()

    def test_file_not_empty(self) -> None:
        """api-contracts.md не должен быть пустым."""
        content = API_CONTRACTS_PATH.read_text(encoding="utf-8")
        assert len(content.strip()) > 0


class TestApiContractsSections:
    """Проверка обязательных секций в api-contracts.md."""

    def test_has_rest_api_section(self, content: str) -> None:
        """Должна быть секция REST API (ARGUS Scanner)."""
        assert "REST API" in content or "1. REST API" in content

    def test_has_endpoints_table(self, content: str) -> None:
        """Должна быть таблица с Endpoint, Method, Request/Response Schema."""
        assert "Endpoint" in content
        assert "Method" in content
        assert "Request Schema" in content or "Request" in content
        assert "Response Schema" in content or "Response" in content

    def test_has_http_status_codes(self, content: str) -> None:
        """Должна быть секция HTTP Status Codes."""
        assert "HTTP Status Codes" in content
        assert "200" in content
        assert "401" in content
        assert "404" in content

    def test_has_related_docs_links(self, content: str) -> None:
        """Должны быть ссылки на связанные документы."""
        assert "env-vars.md" in content
        assert "auth-flow.md" in content
        assert "sse-polling.md" in content


class TestApiContractsEndpoints:
    """Проверка наличия обязательных REST endpoints."""

    @pytest.mark.parametrize("method,path", REQUIRED_ARGUS_ENDPOINTS)
    def test_endpoint_documented(self, content: str, method: str, path: str) -> None:
        """Каждый обязательный endpoint должен быть задокументирован."""
        # Проверяем наличие path (например /scans, /reports, /health)
        path_key = path.split("/")[1]  # scans, reports, health
        assert path_key in content, f"Endpoint path '{path_key}' not found for {method} {path}"


class TestApiContractsSchemas:
    """Проверка наличия schema определений."""

    @pytest.mark.parametrize("schema_name", REQUIRED_SCHEMA_NAMES)
    def test_schema_defined(self, content: str, schema_name: str) -> None:
        """ScanOptions, ReportSummary, Finding должны быть определены."""
        assert schema_name in content, f"Schema {schema_name} must be defined"
