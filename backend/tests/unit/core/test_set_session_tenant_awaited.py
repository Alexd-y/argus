"""SEC-006 regression guard.

set_session_tenant() is an async coroutine that applies the RLS tenant context.
Calling it without ``await`` silently discards the coroutine, so tenant scoping
is never applied. This test parses every API router and asserts that each
set_session_tenant(...) call is directly awaited — catching a dropped await
anywhere in the router layer without needing a live database.
"""

import ast
from pathlib import Path

import pytest

_ROUTERS_DIR = Path(__file__).resolve().parents[3] / "src" / "api" / "routers"
_TARGET = "set_session_tenant"


def _router_files() -> list[Path]:
    return sorted(p for p in _ROUTERS_DIR.rglob("*.py") if p.is_file())


def _target_calls(tree: ast.AST) -> tuple[list[ast.Call], set[int]]:
    """Return all set_session_tenant call nodes and the ids of awaited ones."""
    all_calls: list[ast.Call] = []
    awaited_ids: set[int] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Await) and isinstance(node.value, ast.Call):
            awaited_ids.add(id(node.value))
        if isinstance(node, ast.Call):
            func = node.func
            name = (
                func.attr
                if isinstance(func, ast.Attribute)
                else func.id
                if isinstance(func, ast.Name)
                else None
            )
            if name == _TARGET:
                all_calls.append(node)

    return all_calls, awaited_ids


@pytest.mark.parametrize("path", _router_files(), ids=lambda p: p.name)
def test_set_session_tenant_calls_are_awaited(path: Path) -> None:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    calls, awaited_ids = _target_calls(tree)
    unawaited = [c.lineno for c in calls if id(c) not in awaited_ids]
    assert not unawaited, (
        f"{path.name}: set_session_tenant called without await at lines {unawaited} "
        "(coroutine discarded -> RLS tenant context never set, SEC-006)"
    )


def test_guard_sees_the_known_call_sites() -> None:
    # Sanity: the guard actually finds set_session_tenant usage (so a future
    # refactor that renames the helper does not make this test vacuously pass).
    total = 0
    for path in _router_files():
        calls, _ = _target_calls(ast.parse(path.read_text(encoding="utf-8")))
        total += len(calls)
    assert total >= 4, f"expected >=4 set_session_tenant call sites, found {total}"
