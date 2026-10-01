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

import httpx

from src.core.config import settings
from src.sandbox.templating import redact_argv_for_logging

# The docker SDK is an optional dependency (absent in offline/dev installs). This
# module is the ONE place in backend/src allowed to import it (F-H01 Stage 3).
try:  # pragma: no cover - trivial import guard
    import docker as _docker_sdk
except ImportError:  # pragma: no cover - exercised only where docker is absent
    _docker_sdk = None  # type: ignore[assignment]

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


def docker_sdk_available() -> bool:
    """True if the ``docker`` Python SDK is importable."""
    return _docker_sdk is not None


def docker_client() -> object:
    """Return a ``docker.from_env()`` client — the single SDK entry point.

    SDK-based callers (container lifecycle: run / get / stop / remove /
    get_archive / list / exec_run) obtain their client here instead of importing
    ``docker`` themselves, so the gateway stays the only module bound to the SDK.
    Raises :class:`DockerGatewayError` when the SDK is unavailable so callers can
    fail closed (or fall back to mock mode) without an ``ImportError`` of their own.
    """
    if _docker_sdk is None:
        raise DockerGatewayError("docker SDK not installed")
    return _docker_sdk.from_env()


def copy_to_container(
    src_path: str, container: str, dest_path: str, *, timeout: float = 10.0
) -> ExecResult:
    """Run ``docker cp <src_path> <container>:<dest_path>`` — a non-exec verb.

    Kept in the gateway so callers do not construct a raw ``docker`` argv. Honours
    ``DOCKER_HOST``.
    """
    _validate_container(container)
    argv = ["docker", "cp", src_path, f"{container}:{dest_path}"]
    start = time.perf_counter()
    try:
        proc = subprocess.run(  # noqa: S603 - argv list, shell=False, gateway-owned
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            env=_subprocess_env(),
        )
    except subprocess.TimeoutExpired:
        return ExecResult(-1, "", "docker cp timed out", time.perf_counter() - start)
    except OSError as exc:
        return ExecResult(-1, "", f"docker cp failed: {exc}", time.perf_counter() - start)
    return ExecResult(
        proc.returncode, proc.stdout or "", proc.stderr or "", time.perf_counter() - start
    )


def inspect_format(container: str, fmt: str, *, timeout: float = 10.0) -> ExecResult:
    """Run ``docker inspect -f <fmt> <container>`` — a non-exec daemon query.

    Kept in the gateway so callers needing ``docker inspect`` (e.g. lab/runner)
    do not construct a raw ``docker`` argv themselves. Honours ``DOCKER_HOST``.
    """
    _validate_container(container)
    argv = ["docker", "inspect", "-f", fmt, container]
    start = time.perf_counter()
    try:
        proc = subprocess.run(  # noqa: S603 - argv list, shell=False, gateway-owned
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            env=_subprocess_env(),
        )
    except subprocess.TimeoutExpired:
        return ExecResult(-1, "", "docker inspect timed out", time.perf_counter() - start)
    except OSError as exc:
        return ExecResult(-1, "", f"docker inspect failed: {exc}", time.perf_counter() - start)
    return ExecResult(
        proc.returncode, proc.stdout or "", proc.stderr or "", time.perf_counter() - start
    )


def build_exec_argv(
    container: str,
    argv: list[str],
    *,
    workdir: str | None = None,
    env: Mapping[str, str] | None = None,
    interactive: bool = False,
) -> list[str]:
    """Build the ``docker exec`` argv for *argv* inside *container*.

    Pure/deterministic and side-effect free so it can be unit-tested and reused
    by the availability probe and by callers that must run the exec themselves
    (e.g. stdin-piping). Never returns a shell string. ``interactive`` adds
    ``-i`` so the caller can pipe stdin into the exec'd process.
    """
    _validate_container(container)
    _validate_argv(argv)
    parts: list[str] = ["docker", "exec"]
    if interactive:
        parts.append("-i")
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


def _exec_via_broker(
    container: str,
    argv: list[str],
    *,
    workdir: str | None,
    timeout: float,
    env: Mapping[str, str] | None,
) -> ExecResult:
    """POST the exec request to the argus-exec-broker and adapt its response.

    Validation still happens client-side (fail fast) and again server-side (the
    broker never trusts the client). ``httpx`` is imported here-at-top of module.
    """
    _validate_container(container)
    _validate_argv(argv)
    _log_call(container, argv, "broker")

    url = getattr(settings, "exec_broker_url", "http://argus-exec-broker:8080").rstrip("/")
    payload: dict[str, object] = {"container": container, "argv": argv, "timeout": timeout}
    if workdir:
        payload["workdir"] = workdir
    if env:
        payload["env"] = dict(env)

    start = time.perf_counter()
    try:
        resp = httpx.post(f"{url}/v1/exec", json=payload, timeout=timeout + 15.0)
    except httpx.HTTPError as exc:
        elapsed = time.perf_counter() - start
        logger.warning(
            "docker_gateway_broker_error",
            extra={"event": "docker_gateway_broker_error", "error": str(exc)},
        )
        return ExecResult(-1, "", f"exec broker unreachable: {exc}", elapsed)

    elapsed = time.perf_counter() - start
    if resp.status_code != 200:
        return ExecResult(
            -1,
            "",
            f"exec broker rejected request: HTTP {resp.status_code} {resp.text[:500]}",
            elapsed,
        )
    data = resp.json()
    return ExecResult(
        int(data.get("exit_code", -1)),
        str(data.get("stdout", "")),
        str(data.get("stderr", "")),
        float(data.get("duration_s", elapsed)),
    )


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
        # Stage 4: delegate to the argus-exec-broker over HTTP. The broker holds
        # the socket and re-validates server-side; it exposes no raw Docker API.
        return _exec_via_broker(container, argv, workdir=workdir, timeout=timeout, env=env)

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


def exec_in_sync_bytes(
    container: str,
    argv: list[str],
    *,
    workdir: str | None = None,
    timeout: float,
    env: Mapping[str, str] | None = None,
) -> tuple[int, bytes, bytes]:
    """Like :func:`exec_in_sync` but captures **raw bytes** (no UTF-8 decode).

    For tools whose output is binary (e.g. ``head -c`` reading a file). Returns
    ``(exit_code, stdout, stderr)``. Socket/proxy transports only — binary
    capture is not representable over the text/JSON broker transport.
    """
    transport = getattr(settings, "docker_transport", "socket")
    if transport == "broker":
        raise DockerGatewayError("binary capture is not supported over the broker transport")
    exec_argv = build_exec_argv(container, argv, workdir=workdir, env=env)
    _log_call(container, argv, transport)
    try:
        proc = subprocess.run(  # noqa: S603 - argv list, shell=False, gateway-owned
            exec_argv,
            capture_output=True,
            timeout=timeout,
            shell=False,
            env=_subprocess_env(),
        )
    except subprocess.TimeoutExpired:
        return -1, b"", b"Command timed out"
    except OSError as exc:
        return -1, b"", f"Execution failed: {exc}".encode()
    return proc.returncode, proc.stdout or b"", proc.stderr or b""


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
