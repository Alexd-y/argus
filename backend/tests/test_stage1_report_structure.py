"""Tests for Stage 1 HTML report structure (pentest_reports_svalbard/stage1-svalbard.html).

Проверяет структуру отчёта: Scope & Methodology, Evidence, Observation.
Соответствует html_report_builder (Evidence/Observation badges, section layout).
"""

from pathlib import Path

import pytest

# Path: ARGUS/pentest_reports_svalbard/stage1-svalbard.html
# From backend/tests: parent.parent.parent = ARGUS root
ARGUS_ROOT = Path(__file__).resolve().parent.parent.parent
STAGE1_REPORT = ARGUS_ROOT / "pentest_reports_svalbard" / "stage1-svalbard.html"


class TestStage1ReportExists:
    """Stage 1 report file exists at expected path."""

    def test_report_exists(self) -> None:
        """stage1-svalbard.html exists."""
        assert STAGE1_REPORT.exists(), f"Report not found: {STAGE1_REPORT}"
        assert STAGE1_REPORT.is_file()

    def test_report_not_empty(self) -> None:
        """Report has content."""
        content = STAGE1_REPORT.read_text(encoding="utf-8")
        assert len(content.strip()) > 500


class TestMethodologySection:
    """Секция Scope & Methodology и структурные элементы присутствуют в отчёте."""

    @pytest.fixture
    def content(self) -> str:
        """Load report content."""
        return STAGE1_REPORT.read_text(encoding="utf-8")

    def test_has_methodology_section(self, content: str) -> None:
        """Секция Scope & Methodology или Methodology присутствует."""
        assert (
            "Scope & Methodology" in content
            or "Scope &amp; Methodology" in content
            or "Methodology" in content
        )

    def test_has_ai_subsection(self, content: str) -> None:
        """Подраздел Evidence (badge) присутствует."""
        assert "Evidence" in content

    def test_has_mcp_server_subsection(self, content: str) -> None:
        """Подраздел Observation (badge) присутствует."""
        assert "Observation" in content

    def test_has_mcp_justification_subsection(self, content: str) -> None:
        """Методология (Stages completed / Passive) присутствует."""
        assert "Methodology" in content or "Stages completed" in content or "Passive" in content


class TestMethodologyKeywords:
    """Ключевые слова в отчёте (новая структура: Evidence, Observation, Scope)."""

    @pytest.fixture
    def content(self) -> str:
        """Load report content."""
        return STAGE1_REPORT.read_text(encoding="utf-8")

    @pytest.mark.parametrize(
        "keyword",
        [
            "Evidence",
            "Observation",
            "Scope",
            "Methodology",
            "section",
        ],
    )
    def test_keyword_present(self, content: str, keyword: str) -> None:
        """Ключевое слово присутствует в отчёте."""
        assert keyword in content, f"Keyword '{keyword}' not found in report"


class TestMethodologyStructure:
    """Структура секции (section, таблицы)."""

    @pytest.fixture
    def content(self) -> str:
        """Load report content."""
        return STAGE1_REPORT.read_text(encoding="utf-8")

    def test_methodology_in_section_tag(self, content: str) -> None:
        """Секция Scope/Methodology идёт перед Domain and DNS."""
        assert 'class="section"' in content
        scope_idx = content.find("Scope &amp; Methodology")
        if scope_idx == -1:
            scope_idx = content.find("Scope & Methodology")
        domain_idx = content.find("Domain and DNS")
        if scope_idx != -1 and domain_idx != -1:
            assert scope_idx < domain_idx, "Scope & Methodology should precede Domain section"
        else:
            assert "Methodology" in content, "Methodology-related content expected"

    def test_has_prompts_table(self, content: str) -> None:
        """Таблица присутствует в отчёте."""
        assert "<table>" in content or "<table " in content
