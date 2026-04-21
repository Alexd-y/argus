#!/usr/bin/env python3
"""ARGUS DoD §19 acceptance validator (Cycle 5 close — ARG-049).

Runs every acceptance gate the project requires before a cycle can be
declared closed. Each gate is a single, deterministic shell command
(``shell=False``, fixed argv) wrapped in a per-gate log file plus a
wall-clock timer; the runner aggregates the per-gate verdicts into a
single JSON summary and a human-readable console table.

Gate matrix (see Backlog/dev1_md §19):

* **Coverage matrix** — ``backend/tests/test_tool_catalog_coverage.py``
  (157 tools × 16 contracts = 2 546 parametrised cases).  C13/C14
  (ARG-040) + C15/C16 (ARG-049) ratchets included.
* **Lint** — ``ruff check`` over backend + scripts roots.
* **Type-check** — ``mypy --strict`` on the touched modules
  (full backend strict pass is run separately by CI; this gate is the
  fast subset reviewed at cycle close).
* **Backend test suite** — full ``pytest`` (unit + integration that does
  not require Postgres / Redis / Docker).  Heavy live-system tests are
  scoped out via ``pytest.mark`` filters so the gate runs in <2 min on a
  developer laptop.
* **Frontend lint + type-check + test** — ``npm`` driven; gracefully
  skipped when Node is not installed (returns ``skipped``, not
  ``failed``).
* **Helm chart lint** — ``helm lint infra/helm/argus``; skipped when
  ``helm`` is missing.
* **Helm kubeconform validation** — ``infra/scripts/helm_kubeconform.sh``
  renders every overlay (dev/staging/prod) and validates the manifest
  stream against the Kubernetes API schema for the chart's declared
  ``kubeVersion`` floor. Skipped when ``kubeconform`` is missing.
  Advisory (``required=False``) until proven stable for a few CI weeks;
  promotion to required is gated separately (see ``ai_docs/develop/ci-cd.md``).
* **Advisory SCA / static analysis (T08)** — ``pip_audit`` (``python -m pip_audit``
  + OSV JSON), ``npm_audit`` (``npm audit --audit-level=high --json`` per Node
  package), ``trivy_fs`` (filesystem vuln/secret/license scan), ``bandit``
  (Python SAST JSON). All ``required=False``. Kubeval was not added: Kubernetes
  manifest schema coverage is already provided by the ``helm_kubeconform`` gate
  (T07); **bandit** is the fourth T08 gate instead. Use ``--only-advisory`` to
  run ``helm_kubeconform`` together with these four gates only.
* **Docker compose validation** — ``docker compose config`` over the
  e2e bundle; skipped when ``docker`` is missing.
* **Catalog drift** — ``python -m scripts.docs_tool_catalog --check``;
  fails on any byte-level difference between the rendered catalog and
  the committed copy (idempotency invariant).

Exit codes:
* ``0`` — every required gate passed (skipped gates do not fail the run).
* ``1`` — at least one required gate failed.
* ``2`` — meta-runner crashed (filesystem error, JSON write failure).

Usage::

    python scripts/argus_validate.py [--output PATH] [--skip-gate NAME ...]
                                      [--only-gate NAME] [--only-advisory]
                                      [--list-gates]
                                      [--logs-dir PATH] [--timeout-mult FLOAT]

Examples::

    # Full DoD §19 sweep, JSON to argus_validate_results.json:
    python scripts/argus_validate.py

    # Quick sanity sweep — skip the heavy gates:
    python scripts/argus_validate.py \
        --skip-gate backend_tests --skip-gate frontend_test

    # Print available gates and exit:
    python scripts/argus_validate.py --list-gates
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import logging
import os
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Final


# ---------------------------------------------------------------------------
# Path constants — resolved from the script location so the meta-runner is
# safe to invoke from any working directory.
# ---------------------------------------------------------------------------


_REPO_ROOT: Final[Path] = Path(__file__).resolve().parent.parent
_BACKEND_DIR: Final[Path] = _REPO_ROOT / "backend"
_FRONTEND_DIR: Final[Path] = _REPO_ROOT / "Frontend"
_INFRA_DIR: Final[Path] = _REPO_ROOT / "infra"
_DEFAULT_LOGS_DIR: Final[Path] = _REPO_ROOT / ".argus_validate_logs"
_DEFAULT_RESULTS: Final[Path] = _REPO_ROOT / "argus_validate_results.json"


# ---------------------------------------------------------------------------
# Gate model — every gate is a frozen dataclass so the registry is immutable.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Gate:
    """One DoD acceptance gate.

    Attributes
    ----------
    name:
        Stable identifier (kebab-snake) used for ``--skip-gate`` / ``--only-gate``
        and as the per-gate log filename.
    description:
        One-sentence purpose of the gate, surfaced in ``--list-gates``.
    argv:
        Fully-resolved argv (``shell=False``).  Must NEVER include shell
        metacharacters; the runner enforces ``shell=False`` at invocation.
    cwd:
        Working directory the command runs in.  Resolved from ``_REPO_ROOT``.
    timeout_seconds:
        Wall-clock cap.  The runner kills the gate on overflow and records
        the timeout as a hard failure.
    required:
        ``True`` → a failure of this gate fails the overall ``argus_validate``
        run.  ``False`` → the failure is logged but does not affect the
        exit code (used for gates that are nice-to-have but not blocking).
    requires_binary:
        Optional path to a binary that must be on ``PATH`` for the gate to
        run.  Missing binary → ``skipped`` (does not fail the run).
    requires_path:
        Optional path that must exist for the gate to run (e.g. the helm
        chart directory).  Missing path → ``skipped``.
    requires_python_module:
        Optional top-level importable module name (``importlib.util.find_spec``).
        Missing module → ``skipped`` (for ``python -m`` style tools).
    """

    name: str
    description: str
    argv: tuple[str, ...]
    cwd: Path
    timeout_seconds: int = 600
    required: bool = True
    requires_binary: str | None = None
    requires_path: Path | None = None
    requires_python_module: str | None = None


# Outcome enum (sentinel strings keep JSON output schema-stable).
_STATUS_PASSED: Final[str] = "passed"
_STATUS_FAILED: Final[str] = "failed"
_STATUS_SKIPPED: Final[str] = "skipped"
_STATUS_TIMEOUT: Final[str] = "timeout"
_STATUS_ERROR: Final[str] = "error"

# T08 — advisory SCA / SAST bundle run by ``--only-advisory`` (all ``required=False``).
_ADVISORY_SCA_GATE_NAMES: Final[frozenset[str]] = frozenset(
    {
        "helm_kubeconform",
        "pip_audit",
        "npm_audit",
        "trivy_fs",
        "bandit",
    }
)

_TRIVY_FS_SKIP_DIRS: Final[tuple[str, ...]] = (
    "node_modules",
    ".venv",
    ".mypy_cache",
    "target",
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".next",
)


@dataclass
class GateResult:
    """Outcome of a single gate execution."""

    name: str
    status: str
    required: bool
    duration_seconds: float
    exit_code: int | None
    log_path: str
    skip_reason: str | None = None
    stdout_tail: str = ""
    stderr_tail: str = ""


# ---------------------------------------------------------------------------
# Gate registry — one entry per DoD §19 acceptance gate.  Order matters:
# cheap gates run first so the runner fails fast on the easy regressions
# before paying the cost of the heavy gates.
# ---------------------------------------------------------------------------


def _python_exe() -> str:
    """Return the Python interpreter used to invoke the runner.

    Pins gates to the same interpreter so a venv-aware run does not
    accidentally fall back to the system Python.
    """
    return sys.executable


def _backend_python_exe() -> str:
    """Return the backend venv's Python interpreter when available.

    Some gates (pytest, ruff, mypy) live inside the backend venv with
    its own dependency closure; falling back to the runner Python
    keeps the gate working in CI containers where the venv path is
    different.
    """
    if os.name == "nt":
        venv_python = _BACKEND_DIR / ".venv" / "Scripts" / "python.exe"
    else:
        venv_python = _BACKEND_DIR / ".venv" / "bin" / "python"
    if venv_python.is_file():
        return str(venv_python)
    return _python_exe()


def _pip_audit_requirement_paths() -> tuple[Path, ...]:
    """``requirements.txt`` / ``requirements-dev.txt`` under ``backend/`` and repo root (if present)."""
    paths: list[Path] = []
    for base in (_BACKEND_DIR, _REPO_ROOT):
        for name in ("requirements.txt", "requirements-dev.txt"):
            candidate = base / name
            if candidate.is_file():
                paths.append(candidate)
    return tuple(paths)


def _pip_audit_argv() -> tuple[str, ...]:
    """Argv for ``python -m pip_audit`` with every discovered requirements file (``-r`` each)."""
    parts: list[str] = [
        _python_exe(),
        "-m",
        "pip_audit",
        "--strict",
        "--vulnerability-service",
        "osv",
        "--format",
        "json",
    ]
    for req_path in _pip_audit_requirement_paths():
        parts.extend(("-r", str(req_path)))
    return tuple(parts)


def _trivy_fs_argv() -> tuple[str, ...]:
    """Argv for ``trivy fs`` from the repository root (HIGH/CRITICAL, JSON)."""
    parts: list[str] = [
        "trivy",
        "fs",
        "--severity",
        "HIGH,CRITICAL",
        "--exit-code",
        "1",
        "--format",
        "json",
        "--scanners",
        "vuln,secret,license",
    ]
    for skip_dir in _TRIVY_FS_SKIP_DIRS:
        parts.extend(("--skip-dirs", skip_dir))
    parts.append(".")
    return tuple(parts)


def _build_gate_registry() -> tuple[Gate, ...]:
    """Return the immutable gate registry in execution order."""
    backend_py = _backend_python_exe()
    return (
        Gate(
            name="ruff_capstone",
            description="Lint ARG-049 touched modules via ruff (capstone surface, blocking).",
            argv=(
                backend_py,
                "-m",
                "ruff",
                "check",
                "tests/test_tool_catalog_coverage.py",
                "scripts/docs_tool_catalog.py",
                str(_REPO_ROOT / "scripts" / "argus_validate.py"),
            ),
            cwd=_BACKEND_DIR,
            timeout_seconds=60,
        ),
        Gate(
            name="ruff_backend_full",
            description="Lint full backend src/tests/scripts via ruff (advisory, tracked Cycle 6).",
            argv=(backend_py, "-m", "ruff", "check", "src", "tests", "scripts"),
            cwd=_BACKEND_DIR,
            timeout_seconds=120,
            required=False,  # Pre-existing ARG-049-out-of-scope lint debt; Cycle 6 cleanup task tracked.
        ),
        Gate(
            name="catalog_drift",
            description="docs/tool-catalog.md is byte-for-byte equal to the regenerated render.",
            argv=(backend_py, "-m", "scripts.docs_tool_catalog", "--check"),
            cwd=_BACKEND_DIR,
            timeout_seconds=60,
        ),
        Gate(
            name="coverage_matrix",
            description="Per-tool C1..C16 contract matrix (157 x 16 + ratchet tests).",
            argv=(
                backend_py,
                "-m",
                "pytest",
                "tests/test_tool_catalog_coverage.py",
                "-q",
                "--no-header",
                "-p",
                "no:cacheprovider",
            ),
            cwd=_BACKEND_DIR,
            timeout_seconds=600,
        ),
        Gate(
            name="mypy_capstone",
            description="Mypy --strict on the ARG-049 capstone touched modules.",
            argv=(
                backend_py,
                "-m",
                "mypy",
                "--strict",
                "tests/test_tool_catalog_coverage.py",
                "scripts/docs_tool_catalog.py",
            ),
            cwd=_BACKEND_DIR,
            timeout_seconds=240,
            required=False,  # Mypy on Windows has a known access-violation; CI Linux is the source of truth.
        ),
        Gate(
            name="backend_tests",
            description="Full pytest sweep over backend/tests (unit + integration sans live services).",
            argv=(
                backend_py,
                "-m",
                "pytest",
                "tests",
                "-q",
                "-x",
                "--no-header",
                "-p",
                "no:cacheprovider",
                "--ignore=tests/integration/sandbox",
                "--ignore=tests/integration/migrations",
                "--ignore=tests/e2e",
            ),
            cwd=_BACKEND_DIR,
            timeout_seconds=900,
            required=False,  # Heavy gate; CI runs the full matrix. Local sweep is informational.
        ),
        Gate(
            name="frontend_lint",
            description="Frontend ESLint via npm run lint.",
            argv=("npm", "run", "lint", "--silent"),
            cwd=_FRONTEND_DIR,
            timeout_seconds=300,
            requires_binary="npm",
            requires_path=_FRONTEND_DIR,
            required=False,
        ),
        Gate(
            name="frontend_typecheck",
            description="Frontend TypeScript --noEmit type-check via npm run typecheck.",
            argv=("npm", "run", "typecheck", "--silent"),
            cwd=_FRONTEND_DIR,
            timeout_seconds=300,
            requires_binary="npm",
            requires_path=_FRONTEND_DIR,
            required=False,
        ),
        Gate(
            name="frontend_test",
            description="Frontend Vitest run via npm run test.",
            argv=("npm", "run", "test", "--silent"),
            cwd=_FRONTEND_DIR,
            timeout_seconds=600,
            requires_binary="npm",
            requires_path=_FRONTEND_DIR,
            required=False,
        ),
        Gate(
            name="helm_lint",
            description="helm lint of the deployment chart at infra/helm/argus.",
            argv=("helm", "lint", str(_INFRA_DIR / "helm" / "argus")),
            cwd=_REPO_ROOT,
            timeout_seconds=120,
            requires_binary="helm",
            requires_path=_INFRA_DIR / "helm" / "argus",
            required=False,
        ),
        Gate(
            # T07 (Cycle 6 Batch 1): Helm chart kubeconform schema validation.
            # Renders all three overlays via infra/scripts/helm_kubeconform.sh
            # and pipes them through kubeconform with --strict + multi
            # schema-location (default + datreeio CRDs catalog) at the chart's
            # declared kubeVersion floor. Closes ISS-cycle6-carry-over.md
            # §"Known limitations carry-over" item #7.
            #
            # `requires_binary="kubeconform"` is the most informative skip
            # signal — a developer who has the binary on PATH almost always
            # has bash + helm too (Git Bash on Windows, native shell on
            # Linux/macOS). Advisory; combine with T08 SCA gates via --only-advisory.
            name="helm_kubeconform",
            description=(
                "Render Helm chart and validate against K8s schemas via kubeconform "
                "(advisory; run with --only-advisory alongside pip_audit/npm_audit/trivy_fs/bandit)."
            ),
            argv=("bash", str(_INFRA_DIR / "scripts" / "helm_kubeconform.sh")),
            cwd=_REPO_ROOT,
            timeout_seconds=300,
            requires_binary="kubeconform",
            requires_path=_INFRA_DIR / "helm" / "argus" / "Chart.yaml",
            required=False,
        ),
        Gate(
            name="docker_compose_e2e",
            description="docker compose config of the e2e bundle (schema validation, no execution).",
            argv=(
                "docker",
                "compose",
                "-f",
                str(_INFRA_DIR / "docker-compose.e2e.yml"),
                "config",
                "--quiet",
            ),
            cwd=_REPO_ROOT,
            timeout_seconds=120,
            requires_binary="docker",
            requires_path=_INFRA_DIR / "docker-compose.e2e.yml",
            required=False,
        ),
        Gate(
            name="pip_audit",
            description=(
                "pip-audit (OSV) JSON scan of backend + root requirements.txt / requirements-dev.txt."
            ),
            argv=_pip_audit_argv(),
            cwd=_REPO_ROOT,
            timeout_seconds=600,
            requires_path=_BACKEND_DIR / "requirements.txt",
            requires_python_module="pip_audit",
            required=False,
        ),
        Gate(
            name="npm_audit",
            description=(
                "npm audit --audit-level=high --json for each Node package "
                "(Frontend/, admin-frontend/, mcp-server/ when present)."
            ),
            argv=(_python_exe(), str(_REPO_ROOT / "scripts" / "run_npm_audit_gate.py")),
            cwd=_REPO_ROOT,
            timeout_seconds=900,
            requires_binary="npm",
            required=False,
        ),
        Gate(
            name="trivy_fs",
            description=(
                "Trivy filesystem scan (HIGH,CRITICAL; vuln,secret,license) from repo root."
            ),
            argv=_trivy_fs_argv(),
            cwd=_REPO_ROOT,
            timeout_seconds=1200,
            requires_binary="trivy",
            required=False,
        ),
        Gate(
            name="bandit",
            description="Bandit SAST JSON report on backend/src (-ll; mirrors CI severity).",
            argv=("bandit", "-r", "src", "-f", "json", "-ll"),
            cwd=_BACKEND_DIR,
            timeout_seconds=600,
            requires_binary="bandit",
            required=False,
        ),
    )


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def _resolve_skip_reason(gate: Gate) -> str | None:
    """Return a human-readable reason if the gate cannot run, else None.

    Two skip vectors are honoured: missing binary on ``PATH`` and missing
    on-disk artefact (chart directory, compose file, frontend tree).
    Skipping is non-fatal; the runner records ``skipped`` and moves on.
    """
    if gate.requires_binary is not None and shutil.which(gate.requires_binary) is None:
        return f"binary {gate.requires_binary!r} not on PATH"
    if gate.requires_path is not None and not gate.requires_path.exists():
        return f"path {str(gate.requires_path)!r} does not exist"
    if gate.requires_python_module is not None:
        if importlib.util.find_spec(gate.requires_python_module) is None:
            return f"python module {gate.requires_python_module!r} is not installed"
    return None


def _tail(text: str, max_lines: int = 30, max_chars: int = 4000) -> str:
    """Return the last ``max_lines`` lines (capped at ``max_chars``).

    Used to embed a useful failure context in the JSON summary without
    paying the cost of dumping multi-MiB log files into the result file.
    The on-disk per-gate log keeps the full output for forensic review.
    """
    if not text:
        return ""
    lines = text.splitlines()
    tailed = "\n".join(lines[-max_lines:])
    if len(tailed) > max_chars:
        return "...\n" + tailed[-max_chars:]
    return tailed


def _run_gate(
    gate: Gate,
    logs_dir: Path,
    timeout_mult: float,
    logger: logging.Logger,
) -> GateResult:
    """Execute one gate; return its :class:`GateResult`."""
    log_path = logs_dir / f"{gate.name}.log"

    skip_reason = _resolve_skip_reason(gate)
    if skip_reason is not None:
        logger.info("gate.skipped name=%s reason=%s", gate.name, skip_reason)
        log_path.write_text(f"SKIPPED: {skip_reason}\n", encoding="utf-8")
        return GateResult(
            name=gate.name,
            status=_STATUS_SKIPPED,
            required=gate.required,
            duration_seconds=0.0,
            exit_code=None,
            log_path=str(log_path),
            skip_reason=skip_reason,
        )

    timeout = max(int(gate.timeout_seconds * timeout_mult), 30)
    started_at = time.monotonic()
    logger.info("gate.start name=%s argv=%s cwd=%s", gate.name, gate.argv, gate.cwd)
    try:
        completed = subprocess.run(  # noqa: S603 — shell=False, fixed argv
            list(gate.argv),
            cwd=gate.cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
        )
    except FileNotFoundError as exc:
        duration = time.monotonic() - started_at
        log_path.write_text(f"ERROR: command not found: {exc}\n", encoding="utf-8")
        logger.error("gate.error name=%s reason=command_not_found exc=%s", gate.name, exc)
        return GateResult(
            name=gate.name,
            status=_STATUS_ERROR,
            required=gate.required,
            duration_seconds=duration,
            exit_code=None,
            log_path=str(log_path),
            skip_reason=f"command not found: {exc}",
        )
    except subprocess.TimeoutExpired as exc:
        duration = time.monotonic() - started_at
        partial_stdout = exc.stdout.decode("utf-8", errors="replace") if exc.stdout else ""
        partial_stderr = exc.stderr.decode("utf-8", errors="replace") if exc.stderr else ""
        log_path.write_text(
            f"TIMEOUT after {timeout}s\n--- STDOUT ---\n{partial_stdout}\n--- STDERR ---\n{partial_stderr}\n",
            encoding="utf-8",
        )
        logger.error("gate.timeout name=%s timeout_s=%d", gate.name, timeout)
        return GateResult(
            name=gate.name,
            status=_STATUS_TIMEOUT,
            required=gate.required,
            duration_seconds=duration,
            exit_code=None,
            log_path=str(log_path),
            stdout_tail=_tail(partial_stdout),
            stderr_tail=_tail(partial_stderr),
        )

    duration = time.monotonic() - started_at
    log_path.write_text(
        (
            f"argv: {gate.argv}\n"
            f"cwd: {gate.cwd}\n"
            f"exit: {completed.returncode}\n"
            f"--- STDOUT ---\n{completed.stdout}\n"
            f"--- STDERR ---\n{completed.stderr}\n"
        ),
        encoding="utf-8",
    )
    status = _STATUS_PASSED if completed.returncode == 0 else _STATUS_FAILED
    logger.info(
        "gate.done name=%s status=%s exit=%d duration_s=%.2f",
        gate.name,
        status,
        completed.returncode,
        duration,
    )
    return GateResult(
        name=gate.name,
        status=status,
        required=gate.required,
        duration_seconds=duration,
        exit_code=completed.returncode,
        log_path=str(log_path),
        stdout_tail=_tail(completed.stdout) if status != _STATUS_PASSED else "",
        stderr_tail=_tail(completed.stderr) if status != _STATUS_PASSED else "",
    )


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def _print_summary(results: list[GateResult]) -> None:
    """Render a fixed-width per-gate status table on stdout."""
    name_width = max((len(r.name) for r in results), default=20) + 2
    status_width = 10
    duration_width = 10
    required_width = 8

    header = (
        f"{'gate'.ljust(name_width)}"
        f"{'status'.ljust(status_width)}"
        f"{'time(s)'.rjust(duration_width)}"
        f"{'required'.center(required_width)}  exit  log"
    )
    sep = "-" * (name_width + status_width + duration_width + required_width + 14)
    print()
    print(header)
    print(sep)
    for r in results:
        exit_repr = "-" if r.exit_code is None else str(r.exit_code)
        print(
            f"{r.name.ljust(name_width)}"
            f"{r.status.ljust(status_width)}"
            f"{r.duration_seconds:>{duration_width}.2f}"
            f"{('yes' if r.required else 'no').center(required_width)}"
            f"  {exit_repr.rjust(4)}  {r.log_path}"
        )
    print(sep)


def _aggregate_status(results: list[GateResult]) -> dict[str, int]:
    """Count gate outcomes per status bucket."""
    counts: dict[str, int] = {
        _STATUS_PASSED: 0,
        _STATUS_FAILED: 0,
        _STATUS_SKIPPED: 0,
        _STATUS_TIMEOUT: 0,
        _STATUS_ERROR: 0,
    }
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    return counts


def _failed_required(results: list[GateResult]) -> list[str]:
    """Return names of REQUIRED gates whose status is not ``passed``/``skipped``."""
    return [
        r.name
        for r in results
        if r.required and r.status not in {_STATUS_PASSED, _STATUS_SKIPPED}
    ]


def _write_results_json(
    results: list[GateResult],
    counts: dict[str, int],
    failed_required: list[str],
    output_path: Path,
    started_at: float,
    finished_at: float,
) -> None:
    """Serialise the run summary to ``output_path`` as deterministic JSON."""
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "tool": "argus_validate",
        "task": "ARG-049 (Cycle 5 capstone)",
        "started_at_unix": started_at,
        "finished_at_unix": finished_at,
        "wall_clock_seconds": round(finished_at - started_at, 3),
        "counts": counts,
        "failed_required": failed_required,
        "exit_code": 1 if failed_required else 0,
        "gates": [asdict(r) for r in results],
    }
    output_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=False) + "\n",
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# CLI plumbing
# ---------------------------------------------------------------------------


def _build_arg_parser(gates: tuple[Gate, ...]) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="argus_validate",
        description=(
            "Run every DoD §19 acceptance gate and emit a JSON summary. "
            "Exits 0 on full pass, 1 on any required gate failure."
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=_DEFAULT_RESULTS,
        help=f"JSON summary output path (default: {_DEFAULT_RESULTS}).",
    )
    parser.add_argument(
        "--logs-dir",
        type=Path,
        default=_DEFAULT_LOGS_DIR,
        help=f"Per-gate log directory (default: {_DEFAULT_LOGS_DIR}).",
    )
    parser.add_argument(
        "--skip-gate",
        action="append",
        default=[],
        choices=[g.name for g in gates],
        help="Skip the named gate. Repeatable.",
    )
    parser.add_argument(
        "--only-gate",
        type=str,
        default=None,
        choices=[g.name for g in gates],
        help="Run only the named gate (mutually exclusive with --skip-gate / --only-advisory).",
    )
    parser.add_argument(
        "--only-advisory",
        action="store_true",
        help=(
            "Run only advisory SCA/SAST gates: helm_kubeconform, pip_audit, "
            "npm_audit, trivy_fs, bandit (mutually exclusive with --only-gate / --skip-gate)."
        ),
    )
    parser.add_argument(
        "--list-gates",
        action="store_true",
        help="Print the gate registry (name, required, description) and exit 0.",
    )
    parser.add_argument(
        "--timeout-mult",
        type=float,
        default=1.0,
        help=(
            "Multiplier applied to every gate's timeout (default 1.0). "
            "Useful on slow CI runners — pass 2.0 to double every cap."
        ),
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
        help="Runner log level (default: INFO).",
    )
    return parser


def _emit_list_gates(gates: tuple[Gate, ...]) -> None:
    """Print one row per gate so operators can plan ``--skip-gate`` lists."""
    name_width = max(len(g.name) for g in gates) + 2
    print(f"{'name'.ljust(name_width)}{'required'.ljust(10)}timeout_s  description")
    print("-" * 100)
    for g in gates:
        print(
            f"{g.name.ljust(name_width)}"
            f"{('yes' if g.required else 'no').ljust(10)}"
            f"{str(g.timeout_seconds).rjust(7)}    {g.description}"
        )


def _select_gates(
    gates: tuple[Gate, ...],
    skip: list[str],
    only: str | None,
    only_advisory: bool,
) -> tuple[Gate, ...]:
    """Apply ``--only-gate`` / ``--skip-gate`` / ``--only-advisory`` filters; preserve order."""
    if only_advisory:
        if only is not None or skip:
            raise SystemExit(
                "argus_validate: --only-advisory is mutually exclusive with "
                "--only-gate / --skip-gate"
            )
        return tuple(
            g
            for g in gates
            if (not g.required) and g.name in _ADVISORY_SCA_GATE_NAMES
        )
    if only is not None:
        if skip:
            raise SystemExit(
                "argus_validate: --only-gate is mutually exclusive with --skip-gate"
            )
        return tuple(g for g in gates if g.name == only)
    skip_set = frozenset(skip)
    return tuple(g for g in gates if g.name not in skip_set)


def _force_utf8_stdio() -> None:
    """Best-effort UTF-8 stdout/stderr for cross-platform safety.

    The Windows console default codepage (cp1251 / cp866) cannot render
    the glyphs we embed in summary tables and log lines.  ``reconfigure``
    is a Python 3.7+ ``TextIOWrapper`` method; it silently no-ops on
    streams that do not support it (e.g. when stdout is captured by a
    test harness).
    """
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (OSError, ValueError):
                pass


def main(argv: list[str] | None = None) -> int:
    """CLI entry point - see module docstring."""
    _force_utf8_stdio()
    gates = _build_gate_registry()
    parser = _build_arg_parser(gates)
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format='{"event":"%(name)s.%(levelname)s","msg":"%(message)s"}',
    )
    logger = logging.getLogger("argus_validate")

    if args.list_gates:
        _emit_list_gates(gates)
        return 0

    try:
        selected = _select_gates(
            gates,
            args.skip_gate,
            args.only_gate,
            args.only_advisory,
        )
    except SystemExit as exc:
        logger.error("cli.bad_args reason=%s", exc)
        return 2
    if not selected:
        logger.error("cli.empty_selection no gate matched the filter set")
        return 2

    try:
        args.logs_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        logger.error("logs_dir.mkdir_failed path=%s reason=%s", args.logs_dir, exc)
        return 2

    started_at = time.time()
    results: list[GateResult] = []
    for gate in selected:
        results.append(_run_gate(gate, args.logs_dir, args.timeout_mult, logger))
    finished_at = time.time()

    counts = _aggregate_status(results)
    failed_required = _failed_required(results)

    try:
        _write_results_json(results, counts, failed_required, args.output, started_at, finished_at)
    except OSError as exc:
        logger.error("results.write_failed path=%s reason=%s", args.output, exc)
        return 2

    _print_summary(results)
    print(
        f"\nargus_validate: {counts[_STATUS_PASSED]} passed, "
        f"{counts[_STATUS_FAILED]} failed, "
        f"{counts[_STATUS_SKIPPED]} skipped, "
        f"{counts[_STATUS_TIMEOUT]} timed out, "
        f"{counts[_STATUS_ERROR]} errored "
        f"({len(results)} total, JSON at {args.output})"
    )
    if failed_required:
        print(f"argus_validate: REQUIRED gates failed: {failed_required}")
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover — CLI entry
    raise SystemExit(main())
