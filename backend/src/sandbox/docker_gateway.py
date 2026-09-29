"""F-H01 Stage 3 — the single Docker access chokepoint.

This is the **only** module in ``backend/src/`` that is allowed to construct a
Docker invocation (a ``docker`` CLI ``subprocess`` call) or import the ``docker``
SDK. Every other module must route container execution through
:func:`exec_in` / :func:`exec_in_sync`.

Why a single chokepoint: you cannot broker, audit, or lock down what you cannot
intercept. Before this module ARGUS reached the daemon from ~15 independent call
sites (see ``docs/docker-socket-hardening.md`` §2), so no policy, allowlist, or
transport swap could be enforced in one place. This gateway is the precondition
for the Stage 4 exec broker.

Design invariants:

* **List argv only.** The signatures make a shell string unrepresentable — you
  cannot pass ``shell=True`` or an interpolated command. This structurally kills
  the class of bug fixed in Stage 1.
* **Transport aware.** ``socket`` and ``proxy`` both use the ``docker`` CLI
  (which honours ``DOCKER_HOST``); ``broker`` (Stage 4) posts to the exec broker.
* **Container name validated.** Names are re-checked here even though
  ``Settings`` validates the configured one, because callers may pass ephemeral
  names.
* **Audited.** Every call emits a structured log event with a redacted argv, so
  the Stage 4 broker has a comparable audit trail.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import subprocess
import time
from collections.abc import Mapping
from dataclasses import dataclass

from src.core.config import settings
from src.sandbox.templating import redact_argv_for_logging

logger = logging.getLogger(__name__)

# Docker container / name reference: first char alnum, then alnum plus _ . -
# (Docker's own rule). Mirrors the Settings validator so ephemeral names passed
# straight to the gateway are held to the same bar.
_CONTAINER_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$")


class DockerGatewayError(RuntimeError):
    """Raised when a Docker invocation cannot be constructed or executed."""


@dataclass(frozen=True)
class ExecResult:
    """Outcome of a container exec. Mirrors the shape callers already expect."""

    exit_code: int
    stdout: str
    stderr: str
    duration_s: float

    @property
    def success(self) -> bool:
        return self.exit_code == 0


def _validate_container(container: str) -> None:
    if not container or not _CONTAINER_NAME_RE.match(container):
        raise DockerGatewayError(
            f"invalid container name {container!r}: must match "
            r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$"
        )


def _validate_argv(argv: list[str]) -> None:
    if not isinstance(argv, list) or not argv:
        raise DockerGatewayError("argv must be a non-empty list of strings")
    if not all(isinstance(a, str) for a in argv):
        raise DockerGatewayError("argv must contain only strings (no shell string)")


def build_exec_argv(
    container: str,
    argv: list[str],
    *,
    workdir: str | None = None,
    env: Mapping[str, str] | None = None,
) -> list[str]:
    """Build the ``docker exec`` argv for *argv* inside *container*.

    Pure/deterministic and side-effect free so it can be unit-tested and reused
    by the availability probe. Never returns a shell string.
    """
    _validate_container(container)
    _validate_argv(argv)
    parts: list[str] = ["docker", "exec"]
    wd = (workdir or "").strip()
    if wd:
        parts.extend(["-w", wd])
    if env:
        for key, value in env.items():
            parts.extend(["-e", f"{key}={value}"])
    parts.append(container)
    parts.extend(argv)
    return parts


def _log_call(container: str, argv: list[str], transport: str) -> None:
    logger.info(
        "docker_gateway_exec",
        extra={
            "event": "docker_gateway_exec",
            "container": container,
            "tool": argv[0] if argv else "",
            "argv": redact_argv_for_logging(argv),
            "transport": transport,
        },
    )


def _subprocess_env() -> dict[str, str] | None:
    """Return the env overlay for the docker CLI (DOCKER_HOST for the proxy)."""
    host = getattr(settings, "docker_host", None)
    if not host:
        return None
    overlay = dict(os.environ)
    overlay["DOCKER_HOST"] = host
    return overlay


def exec_in_sync(
    container: str,
    argv: list[str],
    *,
    workdir: str | None = None,
    timeout: float,
    env: Mapping[str, str] | None = None,
) -> ExecResult:
    """Execute *argv* inside *container* synchronously and capture output.

    ``env`` is injected into the target container (``docker exec -e``), not the
    local docker CLI process. Transport is selected by ``settings.docker_transport``.
    """
    transport = getattr(settings, "docker_transport", "socket")
    if transport == "broker":
        # Wired up in Stage 4 (argus-exec-broker). Until then, callers must run
        # under socket/proxy transport.
        raise DockerGatewayError(
            "docker_transport='broker' requires the Stage 4 exec broker "
            "(infra/docker-compose.broker.yml); not yet available"
        )

    exec_argv = build_exec_argv(container, argv, workdir=workdir, env=env)
    _log_call(container, argv, transport)

    start = time.perf_counter()
    try:
        proc = subprocess.run(  # noqa: S603 - argv list, shell=False, gateway-owned
            exec_argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            env=_subprocess_env(),
        )
    except subprocess.TimeoutExpired:
        elapsed = time.perf_counter() - start
        logger.warning(
            "docker_gateway_timeout",
            extra={"event": "docker_gateway_timeout", "container": container, "timeout": timeout},
        )
        return ExecResult(-1, "", "Command timed out", elapsed)
    except OSError as exc:
        elapsed = time.perf_counter() - start
        logger.warning(
            "docker_gateway_os_error",
            extra={"event": "docker_gateway_os_error", "container": container, "error": str(exc)},
        )
        return ExecResult(-1, "", "Execution failed", elapsed)

    elapsed = time.perf_counter() - start
    return ExecResult(proc.returncode, proc.stdout or "", proc.stderr or "", elapsed)


async def exec_in(
    container: str,
    argv: list[str],
    *,
    workdir: str | None = None,
    timeout: float,
    env: Mapping[str, str] | None = None,
) -> ExecResult:
    """Async wrapper around :func:`exec_in_sync` (runs it in a worker thread)."""
    return await asyncio.to_thread(
        exec_in_sync,
        container,
        argv,
        workdir=workdir,
        timeout=timeout,
        env=env,
    )
