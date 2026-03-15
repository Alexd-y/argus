"""Requirements tests for ARGUS-002 (Phase 1: Project Structure & Infra).

Проверяет, что requirements.txt содержит fastapi и uvicorn.
"""

from pathlib import Path

import pytest

ARGUS_ROOT = Path(__file__).resolve().parent.parent

# Case-insensitive backend path
_backend_candidates = ["backend", "Backend"]
REQUIREMENTS_PATH = next(
    (ARGUS_ROOT / n / "requirements.txt" for n in _backend_candidates if (ARGUS_ROOT / n / "requirements.txt").exists()),
    ARGUS_ROOT / "backend" / "requirements.txt",
)

REQUIRED_PACKAGES = ["fastapi", "uvicorn"]


class TestRequirementsFile:
    """Проверка requirements.txt."""

    def test_file_exists(self) -> None:
        """requirements.txt должен существовать в backend."""
        assert REQUIREMENTS_PATH.exists(), f"Expected {REQUIREMENTS_PATH} to exist"
        assert REQUIREMENTS_PATH.is_file()

    def test_file_not_empty(self) -> None:
        """requirements.txt не должен быть пустым."""
        content = REQUIREMENTS_PATH.read_text(encoding="utf-8")
        assert len(content.strip()) > 0

    @pytest.mark.parametrize("package", REQUIRED_PACKAGES)
    def test_contains_package(self, package: str) -> None:
        """requirements.txt должен содержать fastapi и uvicorn."""
        content = REQUIREMENTS_PATH.read_text(encoding="utf-8").lower()
        assert package in content, f"requirements.txt must contain '{package}'"

    def test_uvicorn_has_standard_extra(self) -> None:
        """uvicorn должен иметь [standard] для production use."""
        content = REQUIREMENTS_PATH.read_text(encoding="utf-8")
        assert "uvicorn" in content.lower()
        assert "[standard]" in content or "uvicorn[standard]" in content.lower()
