"""Regenerate ``backend/requirements.txt`` from ``backend/pyproject.toml``.

``pyproject.toml`` (PEP 621 ``[project.dependencies]``) is the single source of
truth for runtime dependencies. The Docker build (``infra/backend/Dockerfile``)
installs deps directly from ``pyproject.toml``; ``requirements.txt`` is kept in
the repo only as a *generated mirror* for legacy CI / SCA tooling
(``pip-audit``, ``safety``, dependabot) and for tests that assert its presence.

Usage (Windows PowerShell):
    python backend\\scripts\\sync_requirements.py
    python backend\\scripts\\sync_requirements.py --check        # CI-friendly: exit 1 on drift
    python backend\\scripts\\sync_requirements.py --include-dev   # also write requirements-dev.txt

Exit codes:
* ``0`` — file regenerated successfully (or already in sync with ``--check``).
* ``1`` — drift detected with ``--check``, or pyproject.toml is malformed.
"""

from __future__ import annotations

import argparse
import sys
import tomllib
from collections.abc import Iterable
from pathlib import Path

_BACKEND_ROOT = Path(__file__).resolve().parent.parent
_PYPROJECT = _BACKEND_ROOT / "pyproject.toml"
_REQUIREMENTS = _BACKEND_ROOT / "requirements.txt"
_REQUIREMENTS_DEV = _BACKEND_ROOT / "requirements-dev.txt"

_HEADER_RUNTIME = (
    "# AUTO-GENERATED from backend/pyproject.toml. DO NOT EDIT MANUALLY.\n"
    "# Source of truth: [project.dependencies] in pyproject.toml.\n"
    "# Regenerate: python backend/scripts/sync_requirements.py\n"
    "# CI check:   python backend/scripts/sync_requirements.py --check\n"
)
_HEADER_DEV = (
    "# AUTO-GENERATED from backend/pyproject.toml. DO NOT EDIT MANUALLY.\n"
    "# Source of truth: [project.optional-dependencies.dev] in pyproject.toml.\n"
    "# Install: pip install -r requirements.txt -r requirements-dev.txt\n"
    "# Regenerate: python backend/scripts/sync_requirements.py --include-dev\n"
)


def _render(deps: Iterable[str], header: str) -> str:
    body = "\n".join(sorted(deps, key=str.lower))
    return f"{header}\n{body}\n"


def _load_project() -> dict:
    if not _PYPROJECT.is_file():
        raise SystemExit(f"error: not found: {_PYPROJECT}")
    try:
        data = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise SystemExit(f"error: invalid pyproject.toml: {exc}") from exc
    project = data.get("project")
    if not isinstance(project, dict):
        raise SystemExit("error: [project] table missing in pyproject.toml")
    return project


def _runtime_deps(project: dict) -> list[str]:
    deps = project.get("dependencies", [])
    if not isinstance(deps, list) or not all(isinstance(d, str) for d in deps):
        raise SystemExit("error: [project.dependencies] must be a list of strings")
    return list(deps)


def _dev_deps(project: dict) -> list[str]:
    optional = project.get("optional-dependencies", {})
    dev = optional.get("dev", []) if isinstance(optional, dict) else []
    if not isinstance(dev, list) or not all(isinstance(d, str) for d in dev):
        raise SystemExit("error: [project.optional-dependencies.dev] must be a list of strings")
    return list(dev)


def _write_or_check(target: Path, rendered: str, *, check: bool) -> bool:
    """Return True when target matches *rendered*; write otherwise (unless --check)."""
    current = target.read_text(encoding="utf-8") if target.is_file() else ""
    if current == rendered:
        return True
    if check:
        return False
    target.write_text(rendered, encoding="utf-8")
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit 1 if requirements files are out of sync (no writes). For CI.",
    )
    parser.add_argument(
        "--include-dev",
        action="store_true",
        help="Also regenerate requirements-dev.txt from [project.optional-dependencies.dev].",
    )
    args = parser.parse_args(argv)

    project = _load_project()
    runtime = _render(_runtime_deps(project), _HEADER_RUNTIME)
    runtime_ok = _write_or_check(_REQUIREMENTS, runtime, check=args.check)

    dev_ok = True
    if args.include_dev:
        dev = _render(_dev_deps(project), _HEADER_DEV)
        dev_ok = _write_or_check(_REQUIREMENTS_DEV, dev, check=args.check)

    if args.check and not (runtime_ok and dev_ok):
        sys.stderr.write(
            "drift detected: requirements files do not match pyproject.toml. "
            "Run: python backend/scripts/sync_requirements.py\n"
        )
        return 1

    action = "checked" if args.check else "wrote"
    print(f"{action} {_REQUIREMENTS.name}" + (f", {_REQUIREMENTS_DEV.name}" if args.include_dev else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
