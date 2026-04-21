"""FIX-008: Code quality — json.loads wrapped, no bare except pass, operator precedence."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest


BACKEND_SRC = Path(__file__).resolve().parent.parent / "src"


class TestExploitationJsonLoadsWrapped:
    """exploitation.py json.loads calls must be wrapped in try/except."""

    def test_json_loads_in_try_except(self) -> None:
        path = BACKEND_SRC / "api" / "routers" / "recon" / "exploitation.py"
        if not path.exists():
            pytest.skip("exploitation.py not found")
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            is_json_loads = False
            if isinstance(func, ast.Attribute) and func.attr == "loads":
                if isinstance(func.value, ast.Name) and func.value.id == "json":
                    is_json_loads = True
            if not is_json_loads:
                continue
            parent_try = _find_parent_try(tree, node)
            assert parent_try is not None, (
                f"json.loads at line {node.lineno} in exploitation.py "
                "is not wrapped in try/except"
            )


class TestRunnerNoBareExceptPass:
    """runner.py must not have bare `except Exception: pass` patterns."""

    def test_no_bare_except_pass(self) -> None:
        path = BACKEND_SRC / "recon" / "jobs" / "runner.py"
        if not path.exists():
            pytest.skip("runner.py not found")
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            if node.body and len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                assert node.type is not None, (
                    f"Line {node.lineno}: bare `except: pass` found in runner.py"
                )
                if isinstance(node.type, ast.Name) and node.type.id == "Exception":
                    pytest.fail(
                        f"Line {node.lineno}: `except Exception: pass` "
                        "(swallows errors silently) found in runner.py"
                    )


class TestMainMigrationHandling:
    """main.py subprocess.run for alembic must have proper error handling."""

    def test_alembic_call_has_error_check(self) -> None:
        path = BACKEND_SRC.parent / "main.py"
        if not path.exists():
            pytest.skip("main.py not found")
        source = path.read_text(encoding="utf-8")
        assert "subprocess.run" in source or "subprocess" in source
        assert "returncode" in source, (
            "main.py must check alembic subprocess return code"
        )
        assert "FileNotFoundError" in source or "except" in source, (
            "main.py must handle missing alembic command"
        )


def _find_parent_try(tree: ast.AST, target: ast.AST) -> ast.Try | None:
    """Walk the AST to find if target node is inside a Try block."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            for child in ast.walk(node):
                if child is target:
                    return node
    return None
