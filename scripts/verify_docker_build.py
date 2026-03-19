#!/usr/bin/env python3
"""Verify Docker images build successfully (argus-backend, argus-worker).

Usage:
  From ARGUS root:
    python scripts/verify_docker_build.py
  Or:
    cd ARGUS && python scripts/verify_docker_build.py

Exits 0 on success, non-zero on failure.
Uses docker compose build — deterministic, respects compose build order.
"""

import subprocess
import sys
from pathlib import Path

# ARGUS root: scripts/ -> parent
ARGUS_ROOT = Path(__file__).resolve().parent.parent
COMPOSE_FILE = ARGUS_ROOT / "infra" / "docker-compose.yml"


def main() -> int:
    if not COMPOSE_FILE.exists():
        print(f"Error: {COMPOSE_FILE} not found. Run from ARGUS root.", file=sys.stderr)
        return 1

    cmd = [
        "docker",
        "compose",
        "-f",
        str(COMPOSE_FILE),
        "build",
        "backend",
        "worker",
    ]

    result = subprocess.run(
        cmd,
        cwd=ARGUS_ROOT,
        capture_output=False,
        text=True,
    )

    if result.returncode != 0:
        print(
            f"Docker build failed (exit code {result.returncode}). "
            "Check output above.",
            file=sys.stderr,
        )
        return result.returncode

    print("Docker build succeeded: argus-backend, argus-worker")
    return 0


if __name__ == "__main__":
    sys.exit(main())
