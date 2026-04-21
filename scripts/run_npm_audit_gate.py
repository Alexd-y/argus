#!/usr/bin/env python3
"""Advisory gate helper (T08): run `npm audit --audit-level=high --json` per Node project.

Invoked as a single subprocess from :mod:`scripts.argus_validate` gate ``npm_audit``.
Projects are discovered under the repo root: ``Frontend/``, ``admin-frontend/``,
``mcp-server/`` — only directories that contain ``package.json`` are audited.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_NODE_PROJECT_DIRS = ("Frontend", "admin-frontend", "mcp-server")


def _projects() -> list[Path]:
    found: list[Path] = []
    for rel in _NODE_PROJECT_DIRS:
        root = _REPO_ROOT / rel
        if (root / "package.json").is_file():
            found.append(root)
    return found


def main() -> int:
    projects = _projects()
    if not projects:
        print("npm_audit_gate: no package.json projects found — nothing to audit", file=sys.stderr)
        return 0

    worst = 0
    for proj in projects:
        completed = subprocess.run(
            ["npm", "audit", "--audit-level=high", "--json"],
            cwd=proj,
            check=False,
            shell=False,
        )
        if completed.returncode != 0:
            worst = 1
    return worst


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
