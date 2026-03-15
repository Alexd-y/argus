"""Structure tests for ARGUS-002 (Phase 1: Project Structure & Infra).

Проверяет наличие директорий и ключевых файлов Phase 1.
"""

from pathlib import Path

import pytest

ARGUS_ROOT = Path(__file__).resolve().parent.parent

# Phase 1 required directories (case-insensitive on Windows)
REQUIRED_DIRS = [
    "backend",
    "mcp-server",
    "infra",
    "sandbox",
    "plugins",
    "admin-frontend",
]

# Key files for Phase 1
REQUIRED_FILES = [
    "backend/main.py",
    "backend/requirements.txt",
    "backend/Dockerfile",
    "mcp-server/main.py",
    "mcp-server/Dockerfile",
    "infra/docker-compose.yml",
    "sandbox/Dockerfile",
]


def _resolve_path(name: str) -> Path:
    """Resolve path case-insensitively (Windows)."""
    base = ARGUS_ROOT
    for part in name.replace("\\", "/").split("/"):
        if not part:
            continue
        found = next((p for p in base.iterdir() if p.name.lower() == part.lower()), None)
        if found is None:
            return base / part  # Return expected path for clearer error
        base = found
    return base


class TestStructureDirs:
    """Проверка наличия обязательных директорий."""

    @pytest.mark.parametrize("dir_name", REQUIRED_DIRS)
    def test_dir_exists(self, dir_name: str) -> None:
        """Каждая обязательная директория Phase 1 должна существовать."""
        path = _resolve_path(dir_name)
        assert path.exists(), f"Expected directory {dir_name} to exist at {path}"
        assert path.is_dir(), f"Expected {path} to be a directory"


class TestStructureFiles:
    """Проверка наличия ключевых файлов."""

    @pytest.mark.parametrize("file_path", REQUIRED_FILES)
    def test_file_exists(self, file_path: str) -> None:
        """Каждый ключевой файл Phase 1 должен существовать."""
        path = _resolve_path(file_path)
        assert path.exists(), f"Expected file {file_path} to exist at {path}"
        assert path.is_file(), f"Expected {path} to be a file"
