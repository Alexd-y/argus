"""M-11, M-12, M-14: Error handling improvements."""

from __future__ import annotations

import ast
from pathlib import Path

BACKEND_SRC = Path(__file__).resolve().parent.parent / "src"


def _file_has_bare_except_pass(filepath: Path) -> bool:
    """Check if file has 'except ...: pass' patterns (no logging)."""
    source = filepath.read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                return True
    return False


class TestErrorHandling:
    """Exception handlers must not silently swallow errors."""

    def test_ai_text_generation_no_bare_except_pass(self) -> None:
        f = BACKEND_SRC / "reports" / "ai_text_generation.py"
        if f.exists():
            assert not _file_has_bare_except_pass(f), (
                "ai_text_generation.py must not have bare 'except: pass'"
            )

    def test_exploitation_pipeline_no_bare_except_pass(self) -> None:
        f = BACKEND_SRC / "recon" / "exploitation" / "pipeline.py"
        if f.exists():
            assert not _file_has_bare_except_pass(f), (
                "exploitation pipeline must not have bare 'except: pass'"
            )

    def test_va_pipeline_no_bare_except_pass(self) -> None:
        f = BACKEND_SRC / "recon" / "vulnerability_analysis" / "pipeline.py"
        if f.exists():
            assert not _file_has_bare_except_pass(f), (
                "VA pipeline must not have bare 'except: pass'"
            )

    def test_report_pipeline_no_bare_except_pass(self) -> None:
        f = BACKEND_SRC / "reports" / "report_pipeline.py"
        if f.exists():
            assert not _file_has_bare_except_pass(f), (
                "report_pipeline must not have bare 'except: pass'"
            )
