"""JSON validation tests for ARGUS documentation (ARGUS-001).

Извлекает JSON блоки из markdown и проверяет их валидность.
JSON Schema в docs нет — проверяем только парсинг JSON примеров.
"""

import json
import re
from pathlib import Path

import pytest

ARGUS_ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = ARGUS_ROOT / "docs"


def extract_json_blocks(content: str) -> list[str]:
    """Извлекает содержимое блоков ```json ... ``` из markdown."""
    pattern = r"```json\s*\n(.*?)```"
    matches = re.findall(pattern, content, re.DOTALL)
    return [m.strip() for m in matches if m.strip()]


class TestJsonExamplesInDocs:
    """Проверка валидности JSON примеров в документации."""

    @pytest.fixture
    def docs_with_json(self) -> list[tuple[Path, str]]:
        """Список (path, content) для документов, где могут быть JSON блоки."""
        candidates = ["api-contracts.md", "sse-polling.md", "env-vars.md", "auth-flow.md"]
        result = []
        for name in candidates:
            path = DOCS_DIR / name
            if path.exists():
                result.append((path, path.read_text(encoding="utf-8")))
        return result

    def test_sse_polling_has_valid_json_example(self) -> None:
        """sse-polling.md содержит валидный JSON пример payload."""
        path = DOCS_DIR / "sse-polling.md"
        content = path.read_text(encoding="utf-8")
        blocks = extract_json_blocks(content)
        assert len(blocks) >= 1, "sse-polling.md should have at least one JSON example"

        for i, block in enumerate(blocks):
            try:
                parsed = json.loads(block)
                assert isinstance(parsed, dict), f"Block {i}: expected object"
            except json.JSONDecodeError as e:
                pytest.fail(f"Invalid JSON in {path.name} block {i}: {e}")

    @pytest.mark.parametrize("doc_name", ["api-contracts.md", "sse-polling.md"])
    def test_all_json_blocks_parseable(self, doc_name: str) -> None:
        """Все JSON блоки в документе должны парситься."""
        path = DOCS_DIR / doc_name
        if not path.exists():
            pytest.skip(f"{doc_name} not found")

        content = path.read_text(encoding="utf-8")
        blocks = extract_json_blocks(content)

        for i, block in enumerate(blocks):
            try:
                json.loads(block)
            except json.JSONDecodeError as e:
                pytest.fail(f"Invalid JSON in {path.name} block {i}: {e}")


class TestSsePayloadStructure:
    """Проверка структуры JSON payload из sse-polling.md."""

    def test_sse_example_has_expected_fields(self) -> None:
        """Пример SSE payload должен содержать event или phase (phase_start или любой блок)."""
        path = DOCS_DIR / "sse-polling.md"
        content = path.read_text(encoding="utf-8")
        blocks = extract_json_blocks(content)

        if not blocks:
            pytest.skip("No JSON blocks in sse-polling.md")

        # Хотя бы один блок должен содержать event или phase (в т.ч. phase_start)
        found = any(
            "event" in (p := json.loads(block)) or "phase" in p
            for block in blocks
        )
        assert found, "SSE example should have block with event or phase"
