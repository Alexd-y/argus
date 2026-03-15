"""RUNNING guide document structure tests.

Verifies that docs/RUNNING.md exists and contains required sections:
- Docker (docker compose)
- Backend
- Frontend
- API keys table
"""

from pathlib import Path

import pytest

# Path: ARGUS/docs/RUNNING.md (relative to ARGUS root; tests live in backend/tests/)
RUNNING_DOC = Path(__file__).resolve().parent.parent.parent / "docs" / "RUNNING.md"


class TestRunningGuideExists:
    """RUNNING.md exists at expected path."""

    def test_running_doc_exists(self) -> None:
        """docs/RUNNING.md exists."""
        assert RUNNING_DOC.exists(), f"RUNNING guide not found: {RUNNING_DOC}"
        assert RUNNING_DOC.is_file()

    def test_running_doc_not_empty(self) -> None:
        """RUNNING guide has content."""
        content = RUNNING_DOC.read_text(encoding="utf-8")
        assert len(content.strip()) > 100


class TestRunningGuideContent:
    """RUNNING guide contains required keywords and sections."""

    @pytest.fixture
    def content(self) -> str:
        """Load RUNNING guide content."""
        return RUNNING_DOC.read_text(encoding="utf-8")

    def test_has_docker_compose(self, content: str) -> None:
        """Document mentions docker compose."""
        assert "docker compose" in content.lower()

    def test_has_backend(self, content: str) -> None:
        """Document mentions backend."""
        assert "backend" in content.lower()

    def test_has_frontend(self, content: str) -> None:
        """Document mentions frontend."""
        assert "frontend" in content.lower()

    def test_has_api(self, content: str) -> None:
        """Document mentions API."""
        assert "api" in content.lower()

    def test_has_key_or_kluch(self, content: str) -> None:
        """Document mentions API keys (KEY or ключ)."""
        has_key = "key" in content.lower() or "ключ" in content.lower()
        assert has_key, "RUNNING.md must mention API keys (KEY or ключ)"


class TestRunningGuideSections:
    """RUNNING guide contains required sections: Docker, Backend, Frontend, API keys table."""

    @pytest.fixture
    def content(self) -> str:
        """Load RUNNING guide content."""
        return RUNNING_DOC.read_text(encoding="utf-8")

    def test_has_docker_section(self, content: str) -> None:
        """Section about Docker / docker compose is present."""
        has_docker = (
            "docker" in content.lower()
            and ("compose" in content.lower() or "docker-compose" in content.lower())
        )
        assert has_docker, "RUNNING.md must document Docker/docker compose"

    def test_has_backend_section(self, content: str) -> None:
        """Section about Backend is present."""
        has_backend_section = (
            "### 3.2 Backend" in content
            or "### 3.2 backend" in content
            or "## 3." in content
            and "backend" in content.lower()
        )
        assert has_backend_section or (
            "backend" in content.lower() and "uvicorn" in content.lower()
        ), "RUNNING.md must document Backend setup"

    def test_has_frontend_section(self, content: str) -> None:
        """Section about Frontend is present."""
        has_frontend_section = (
            "### 3.4 Frontend" in content
            or "### 3.4 frontend" in content
            or "### 4.2 Frontend" in content
        )
        assert has_frontend_section or (
            "frontend" in content.lower() and "npm run dev" in content
        ), "RUNNING.md must document Frontend setup"

    def test_has_api_keys_table(self, content: str) -> None:
        """API keys table (Файл/место, Переменная, etc.) is present."""
        has_table_header = (
            "Файл/место" in content
            or "Переменная" in content
            or "OPENAI_API_KEY" in content
            or "API ключ" in content
            or "API ключи" in content
        )
        assert has_table_header, (
            "RUNNING.md must contain API keys table "
            "(Файл/место, Переменная, or OPENAI_API_KEY)"
        )
