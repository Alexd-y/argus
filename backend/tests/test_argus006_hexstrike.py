"""Tests for ARGUS-006 — codebase hygiene.

Verify no mentions of hexstrike in ARGUS code (grep-style test).
"""

from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
ARGUS_ROOT = BACKEND_DIR.parent

# Directories to scan for hexstrike
SCAN_DIRS = [
    BACKEND_DIR / "src",
    BACKEND_DIR / "api",
    ARGUS_ROOT / "mcp-server",
]
# Extensions to check
SCAN_EXTENSIONS = {".py", ".ts", ".js", ".json", ".yml", ".yaml", ".md", ".txt"}


def _collect_files() -> list[Path]:
    """Collect all relevant source files."""
    files = []
    for base in SCAN_DIRS:
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if path.is_file() and path.suffix.lower() in SCAN_EXTENSIONS:
                files.append(path)
    return files


class TestNoHexstrikeInCodebase:
    """Grep-style test: no hexstrike in ARGUS code."""

    def test_no_hexstrike_in_source_files(self) -> None:
        """No file in backend/src, backend/api, mcp-server contains 'hexstrike'."""
        forbidden = "hexstrike"
        matches: list[tuple[Path, int, str]] = []

        for path in _collect_files():
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
                for i, line in enumerate(content.splitlines(), start=1):
                    if forbidden.lower() in line.lower():
                        matches.append((path, i, line.strip()[:80]))
            except (OSError, UnicodeDecodeError):
                continue

        assert not matches, (
            f"Found '{forbidden}' in codebase:\n"
            + "\n".join(
                f"  {p.relative_to(ARGUS_ROOT)}:{ln}: {preview}"
                for p, ln, preview in matches
            )
        )
