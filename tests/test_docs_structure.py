"""Tests for ARGUS documentation structure (ARGUS-001, ARGUS-012).

Проверяет наличие всех документов Phase 0, обязательных секций,
валидность ссылок и наличие Cursor rules.
"""

import re
from pathlib import Path

import pytest

# Path to ARGUS docs (relative to this file)
ARGUS_ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = ARGUS_ROOT / "docs"
CURSOR_RULES_DIR = ARGUS_ROOT / ".cursor" / "rules"

# Required documents from Phase 0 + ARGUS-012
REQUIRED_DOCS = [
    "api-contracts.md",
    "env-vars.md",
    "auth-flow.md",
    "sse-polling.md",
    "api-contract-rule.md",
    "architecture-decisions.md",
]

# Required sections per document: { filename: [section_headers_or_keywords] }
REQUIRED_SECTIONS = {
    "api-contracts.md": [
        "REST API",
        "Endpoint",
        "Request Schema",
        "Response Schema",
        "Error Schema",
        "HTTP Status Codes",
    ],
    "env-vars.md": [
        "Frontend",
        "Backend",
        "ARGUS",
    ],
    "auth-flow.md": [
        "ARGUS Scanner",
        "pentagi Auth",
        "Login Flow",
        "Безопасность",
    ],
    "sse-polling.md": [
        "SSE",
        "Server-Sent Events",
        "Polling Fallback",
        "Event Types",
    ],
    "api-contract-rule.md": [
        "Основное правило",
        "Применение",
        "api-contracts.md",
    ],
    "architecture-decisions.md": [
        "ADR-001",
        "Frontend",
        "api-contracts.md",
        "Связанные документы",
    ],
}

# Cursor rules required for ARGUS-012
REQUIRED_CURSOR_RULES = [
    "api-contract.mdc",
]


class TestDocsExistence:
    """Проверка наличия всех документов Phase 0."""

    @pytest.mark.parametrize("doc", REQUIRED_DOCS)
    def test_doc_file_exists(self, doc: str) -> None:
        """Каждый документ Phase 0 должен существовать."""
        path = DOCS_DIR / doc
        assert path.exists(), f"Expected {path} to exist"

    def test_docs_dir_exists(self) -> None:
        """Директория docs должна существовать."""
        assert DOCS_DIR.exists(), f"Expected {DOCS_DIR} to exist"
        assert DOCS_DIR.is_dir(), f"Expected {DOCS_DIR} to be a directory"


class TestDocsContent:
    """Проверка содержимого документов."""

    @pytest.mark.parametrize("doc", REQUIRED_DOCS)
    def test_doc_not_empty(self, doc: str) -> None:
        """Документ не должен быть пустым."""
        path = DOCS_DIR / doc
        content = path.read_text(encoding="utf-8")
        assert len(content.strip()) > 0, f"Document {doc} must not be empty"

    @pytest.mark.parametrize("doc", REQUIRED_DOCS)
    def test_doc_contains_required_sections(self, doc: str) -> None:
        """Документ должен содержать обязательные секции/ключевые слова."""
        sections = REQUIRED_SECTIONS.get(doc, [])
        if not sections:
            pytest.skip(f"No required sections defined for {doc}")

        path = DOCS_DIR / doc
        content = path.read_text(encoding="utf-8")

        for section in sections:
            assert section in content, (
                f"Document {doc} must contain section/keyword: {section}"
            )


class TestCursorRules:
    """Проверка наличия Cursor rules (ARGUS-012)."""

    def test_cursor_rules_dir_exists(self) -> None:
        """Директория .cursor/rules должна существовать."""
        assert CURSOR_RULES_DIR.exists(), f"Expected {CURSOR_RULES_DIR} to exist"
        assert CURSOR_RULES_DIR.is_dir()

    @pytest.mark.parametrize("rule_file", REQUIRED_CURSOR_RULES)
    def test_rule_file_exists(self, rule_file: str) -> None:
        """Каждый обязательный Cursor rule должен существовать."""
        path = CURSOR_RULES_DIR / rule_file
        assert path.exists(), f"Expected {path} to exist"
        assert path.is_file()

    @pytest.mark.parametrize("rule_file", REQUIRED_CURSOR_RULES)
    def test_rule_not_empty(self, rule_file: str) -> None:
        """Cursor rule не должен быть пустым."""
        path = CURSOR_RULES_DIR / rule_file
        content = path.read_text(encoding="utf-8")
        assert len(content.strip()) > 0, f"Rule {rule_file} must not be empty"


class TestDocsLinks:
    """Проверка валидности ссылок в документации."""

    # Markdown link pattern: [text](url) — captures relative url (./ or ../)
    _LINK_PATTERN = re.compile(r"\]\s*\(\s*((?:\./|\.\./)[^)]+)\s*\)")

    @staticmethod
    def _extract_doc_links(doc_path: Path) -> list[tuple[str, Path]]:
        """Извлекает относительные ссылки ./file или ../path из markdown."""
        content = doc_path.read_text(encoding="utf-8")
        links: list[tuple[str, Path]] = []
        for match in TestDocsLinks._LINK_PATTERN.finditer(content):
            url = match.group(1).strip()
            if "://" in url or url.startswith("./http"):
                continue
            target = (doc_path.parent / url).resolve()
            links.append((url, target))
        return links

    def test_readme_links_valid(self) -> None:
        """Все ссылки в README.md должны вести на существующие файлы."""
        readme = DOCS_DIR / "README.md"
        if not readme.exists():
            pytest.skip("README.md not found")
        for url, target in self._extract_doc_links(readme):
            assert target.exists(), f"README link {url} -> {target} does not exist"

    @pytest.mark.parametrize("doc", REQUIRED_DOCS)
    def test_doc_internal_links_valid(self, doc: str) -> None:
        """Внутренние ссылки ./file в каждом документе должны быть валидны."""
        path = DOCS_DIR / doc
        if not path.exists():
            pytest.skip(f"{doc} not found")
        for url, target in self._extract_doc_links(path):
            assert target.exists(), (
                f"Document {doc} link {url} -> {target} does not exist"
            )

    def test_cursor_rule_links_valid(self) -> None:
        """Ссылки в Cursor rules должны вести на существующие файлы."""
        for rule_file in REQUIRED_CURSOR_RULES:
            rule_path = CURSOR_RULES_DIR / rule_file
            if not rule_path.exists():
                continue
            for url, target in self._extract_doc_links(rule_path):
                assert target.exists(), (
                    f"Rule {rule_file} link {url} -> {target} does not exist"
                )
