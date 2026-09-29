"""F-H01 Stage 3 — AST guard: the Docker access chokepoint must be the only door.

Walks every ``backend/src/**/*.py`` file and fails if any module other than the
gateway (``src/sandbox/docker_gateway.py``) either:

  * imports the ``docker`` SDK (``import docker`` / ``from docker ...``), or
  * hands a ``subprocess.*`` / ``asyncio.create_subprocess_*`` call an argv whose
    first element is the string literal ``"docker"``.

``_DOCKER_GATEWAY_EXEMPT`` lists modules not yet migrated. Every entry is
visible, reviewable technical debt; the goal is to drive this list to empty.
Newly-written code that reaches Docker directly (without being added here) will
fail this test — which is the point.
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parents[1] / "src"
GATEWAY_REL = "sandbox/docker_gateway.py"

# F-H01 Stage 3 (completed): the exempt list is EMPTY. Every module in
# backend/src reaches Docker exclusively through src.sandbox.docker_gateway
# (exec_in / exec_in_sync / exec_in_sync_bytes for exec, docker_client for SDK
# container lifecycle, inspect_format / copy_to_container for non-exec verbs).
# DO NOT add entries — route new code through the gateway instead.
_DOCKER_GATEWAY_EXEMPT: frozenset[str] = frozenset()

_SUBPROCESS_CALLEES = {
    # subprocess.*
    "run",
    "call",
    "check_call",
    "check_output",
    "Popen",
    # asyncio.create_subprocess_exec / _shell
    "create_subprocess_exec",
    "create_subprocess_shell",
}


def _iter_src_files() -> list[Path]:
    return [p for p in SRC_ROOT.rglob("*.py") if p.is_file()]


def _rel(path: Path) -> str:
    return path.relative_to(SRC_ROOT).as_posix()


def _imports_docker_sdk(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "docker" or alias.name.startswith("docker."):
                    return True
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod == "docker" or mod.startswith("docker."):
                return True
    return False


def _first_argv_literal_is_docker(node: ast.Call) -> bool:
    """True if a subprocess-family call's first positional arg is a list/tuple
    whose first element is the string literal ``"docker"``."""
    func = node.func
    name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
    if name not in _SUBPROCESS_CALLEES:
        return False
    if not node.args:
        return False
    first = node.args[0]
    if isinstance(first, ast.List | ast.Tuple) and first.elts:
        head = first.elts[0]
        if isinstance(head, ast.Constant) and head.value == "docker":
            return True
    return False


def _calls_docker_subprocess(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _first_argv_literal_is_docker(node):
            return True
    return False


def test_only_gateway_touches_docker() -> None:
    offenders: dict[str, list[str]] = {}
    for path in _iter_src_files():
        rel = _rel(path)
        if rel == GATEWAY_REL:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        reasons: list[str] = []
        if _imports_docker_sdk(tree):
            reasons.append("imports docker SDK")
        if _calls_docker_subprocess(tree):
            reasons.append('subprocess argv[0] == "docker"')
        if reasons and rel not in _DOCKER_GATEWAY_EXEMPT:
            offenders[rel] = reasons

    assert not offenders, (
        "These modules reach Docker directly instead of via "
        "src.sandbox.docker_gateway. Route them through the gateway or (only if "
        "unavoidable) add them to _DOCKER_GATEWAY_EXEMPT with justification:\n"
        + "\n".join(f"  - {m}: {', '.join(r)}" for m, r in sorted(offenders.items()))
    )


def test_exempt_list_has_no_stale_entries() -> None:
    """Every exempt module must still exist and still actually touch Docker —
    otherwise it should be removed from the list (keeps the debt honest)."""
    stale: list[str] = []
    for rel in _DOCKER_GATEWAY_EXEMPT:
        path = SRC_ROOT / rel
        if not path.exists():
            stale.append(f"{rel} (missing)")
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        if not (_imports_docker_sdk(tree) or _calls_docker_subprocess(tree)):
            stale.append(f"{rel} (no longer touches docker — remove from exempt)")
    assert not stale, "Stale _DOCKER_GATEWAY_EXEMPT entries:\n" + "\n".join(
        f"  - {s}" for s in stale
    )
