"""Isolated LAB runner — docker exec into argus-lab-runner, never production sandbox.

After a verified lease the script/artifact actually runs. Missing lab-runner
falls back to local subprocess. Production ``argus-sandbox`` is never used.
"""

from __future__ import annotations

import logging
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from uuid import uuid4

from src.core.config import settings
from src.lab.languages import (
    interpreter_argv,
    is_nuclei_language,
    normalize_language,
    normalize_local_command_argv,
)
from src.nuclei.profile_compiler import NucleiProfileCompiler

logger = logging.getLogger(__name__)

_DOCKER_INSPECT_TIMEOUT_SEC = 5.0
_LAB_NAMESPACE_LABEL = "argus.dev/lab-namespace"
_PRODUCTION_SANDBOX_FORBIDDEN = "argus-sandbox"


@dataclass(frozen=True)
class LabRunRequest:
    language: str
    source: str = ""
    argv: tuple[str, ...] = ()
    lease_id: str = ""
    k8s_namespace: str | None = None
    capture_full: bool = False
    timeout_sec: float | None = None
    target_url: str = "http://127.0.0.1"
    yaml_content: str | None = None


@dataclass(frozen=True)
class LabRunResult:
    status: str
    return_code: int
    stdout: str
    stderr: str
    runner: str
    execution_time_sec: float
    argv: tuple[str, ...] = ()
    error_code: str | None = None


class LabRunner(Protocol):
    def execute(self, request: LabRunRequest) -> LabRunResult: ...


def _clip(text: str, *, max_bytes: int, capture_full: bool) -> str:
    if capture_full or max_bytes <= 0:
        return text
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text
    return encoded[:max_bytes].decode("utf-8", errors="ignore")


def _timeout_sec(request: LabRunRequest) -> float:
    if request.timeout_sec is not None and request.timeout_sec > 0:
        return float(request.timeout_sec)
    return float(settings.lab_runner_timeout_sec)


def _docker_inspect(container: str, format_expr: str) -> str | None:
    try:
        proc = subprocess.run(
            ["docker", "inspect", "-f", format_expr, container],
            capture_output=True,
            text=True,
            timeout=_DOCKER_INSPECT_TIMEOUT_SEC,
            shell=False,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return (proc.stdout or "").strip()


def lab_runner_container_running(container: str) -> bool:
    state = _docker_inspect(container, "{{.State.Running}}")
    return state == "true"


def read_lab_namespace(container: str) -> str:
    label = _docker_inspect(container, f'{{{{index .Config.Labels "{_LAB_NAMESPACE_LABEL}"}}}}')
    if label:
        return label
    try:
        proc = subprocess.run(
            ["docker", "exec", container, "printenv", "ARGUS_LAB_NAMESPACE"],
            capture_output=True,
            text=True,
            timeout=_DOCKER_INSPECT_TIMEOUT_SEC,
            shell=False,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    if proc.returncode != 0:
        return ""
    return (proc.stdout or "").strip()


def assert_lab_namespace(container: str, lease_namespace: str | None) -> None:
    """Refuse execution when the lease binds a namespace the runner does not own."""
    wanted = (lease_namespace or "").strip()
    if not wanted:
        return
    actual = read_lab_namespace(container)
    if actual != wanted:
        raise PermissionError("lab_namespace_mismatch")


def _target_from_argv(argv: tuple[str, ...], fallback: str) -> str:
    for item in argv:
        raw = item.strip()
        if raw.startswith(("http://", "https://")):
            return raw
    return fallback or "http://127.0.0.1"


class IsolatedLabRunner:
    """Production runner: lab-runner container, else local subprocess. Never sandbox."""

    def execute(self, request: LabRunRequest) -> LabRunResult:
        container = (settings.lab_runner_container_name or "").strip()
        if container == _PRODUCTION_SANDBOX_FORBIDDEN:
            return LabRunResult(
                status="failed",
                return_code=-1,
                stdout="",
                stderr="",
                runner="refused",
                execution_time_sec=0.0,
                error_code="lab_runner_must_not_be_production_sandbox",
            )
        if container and lab_runner_container_running(container):
            try:
                assert_lab_namespace(container, request.k8s_namespace)
            except PermissionError:
                return LabRunResult(
                    status="failed",
                    return_code=-1,
                    stdout="",
                    stderr="",
                    runner="docker",
                    execution_time_sec=0.0,
                    error_code="lab_namespace_mismatch",
                )
            return self._execute_docker(container, request)
        if settings.sandbox_enabled:
            logger.warning(
                "lab_runner_local_fallback",
                extra={
                    "event": "lab_runner_local_fallback",
                    "container": container,
                    "lease_id": request.lease_id,
                },
            )
        return self._execute_local(request)

    def _execute_docker(self, container: str, request: LabRunRequest) -> LabRunResult:
        lang = normalize_language(request.language)
        if is_nuclei_language(lang) or request.yaml_content:
            return self._execute_nuclei(request, container=container)
        if request.argv and not request.source:
            argv = ["docker", "exec", container, *request.argv]
            return self._run(argv, input_text=None, request=request, runner="docker")
        try:
            interp = interpreter_argv(lang, local=False)
        except ValueError:
            return LabRunResult(
                status="failed",
                return_code=-1,
                stdout="",
                stderr="",
                runner="docker",
                execution_time_sec=0.0,
                error_code="unsupported_lab_language",
            )
        argv = ["docker", "exec", "-i", container, *interp]
        return self._run(argv, input_text=request.source, request=request, runner="docker")

    def _execute_local(self, request: LabRunRequest) -> LabRunResult:
        lang = normalize_language(request.language)
        if is_nuclei_language(lang) or request.yaml_content:
            return self._execute_nuclei(request, container=None)
        if request.argv and not request.source:
            argv = normalize_local_command_argv(list(request.argv))
            return self._run(argv, input_text=None, request=request, runner="local")
        try:
            interp = interpreter_argv(lang, local=True)
        except ValueError:
            return LabRunResult(
                status="failed",
                return_code=-1,
                stdout="",
                stderr="",
                runner="local",
                execution_time_sec=0.0,
                error_code="unsupported_lab_language",
            )
        return self._run(interp, input_text=request.source, request=request, runner="local")

    def _execute_nuclei(self, request: LabRunRequest, *, container: str | None) -> LabRunResult:
        yaml_text = request.yaml_content or request.source
        if not yaml_text.strip():
            return LabRunResult(
                status="failed",
                return_code=-1,
                stdout="",
                stderr="",
                runner="docker" if container else "local",
                execution_time_sec=0.0,
                error_code="nuclei_yaml_missing",
            )
        target = _target_from_argv(request.argv, request.target_url)
        template_path = self._materialize_yaml(yaml_text, container=container)
        if template_path is None:
            return LabRunResult(
                status="failed",
                return_code=-1,
                stdout="",
                stderr="",
                runner="docker" if container else "local",
                execution_time_sec=0.0,
                error_code="nuclei_template_write_failed",
            )
        argv = NucleiProfileCompiler.compile(
            "lab_unrestricted",
            "lab_unrestricted",
            target,
            templates=[template_path],
            allow_code=True,
            allow_headless=True,
            allow_javascript=True,
        )
        if not argv:
            return LabRunResult(
                status="failed",
                return_code=-1,
                stdout="",
                stderr="",
                runner="docker" if container else "local",
                execution_time_sec=0.0,
                argv=(),
                error_code="nuclei_compile_failed",
            )
        if container:
            run_argv = ["docker", "exec", container, *argv]
            runner = "docker"
        else:
            run_argv = argv
            runner = "local"
        return self._run(run_argv, input_text=None, request=request, runner=runner, compiled=argv)

    def _materialize_yaml(self, yaml_text: str, *, container: str | None) -> str | None:
        suffix = f"{uuid4().hex}.yaml"
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".yaml",
                prefix="argus-lab-nuclei-",
                delete=False,
                encoding="utf-8",
            ) as handle:
                handle.write(yaml_text)
                host_path = handle.name
        except OSError:
            logger.warning(
                "lab_nuclei_template_write_failed",
                extra={"event": "lab_nuclei_template_write_failed"},
            )
            return None
        if not container:
            return host_path
        remote = f"/tmp/argus-lab-{suffix}"
        try:
            proc = subprocess.run(
                ["docker", "cp", host_path, f"{container}:{remote}"],
                capture_output=True,
                text=True,
                timeout=_DOCKER_INSPECT_TIMEOUT_SEC,
                shell=False,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            Path(host_path).unlink(missing_ok=True)
            return None
        Path(host_path).unlink(missing_ok=True)
        if proc.returncode != 0:
            return None
        return remote

    def _run(
        self,
        argv: list[str],
        *,
        input_text: str | None,
        request: LabRunRequest,
        runner: str,
        compiled: list[str] | None = None,
    ) -> LabRunResult:
        timeout = _timeout_sec(request)
        start = time.perf_counter()
        recorded_argv = tuple(compiled or argv)
        try:
            proc = subprocess.run(
                argv,
                input=input_text,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False,
                check=False,
            )
        except subprocess.TimeoutExpired:
            elapsed = time.perf_counter() - start
            logger.warning(
                "lab_runner_timeout",
                extra={
                    "event": "lab_runner_timeout",
                    "lease_id": request.lease_id,
                    "runner": runner,
                    "timeout_sec": timeout,
                },
            )
            return LabRunResult(
                status="failed",
                return_code=-1,
                stdout="",
                stderr="",
                runner=runner,
                execution_time_sec=elapsed,
                argv=recorded_argv,
                error_code="timeout",
            )
        except OSError:
            elapsed = time.perf_counter() - start
            logger.warning(
                "lab_runner_os_error",
                extra={
                    "event": "lab_runner_os_error",
                    "lease_id": request.lease_id,
                    "runner": runner,
                },
            )
            return LabRunResult(
                status="failed",
                return_code=-1,
                stdout="",
                stderr="",
                runner=runner,
                execution_time_sec=elapsed,
                argv=recorded_argv,
                error_code="execution_failed",
            )
        elapsed = time.perf_counter() - start
        max_bytes = int(settings.lab_script_capture_max_bytes)
        stdout = _clip(proc.stdout or "", max_bytes=max_bytes, capture_full=request.capture_full)
        stderr = _clip(proc.stderr or "", max_bytes=max_bytes, capture_full=request.capture_full)
        status = "completed" if proc.returncode == 0 else "failed"
        logger.info(
            "lab_runner_executed",
            extra={
                "event": "lab_runner_executed",
                "lease_id": request.lease_id,
                "runner": runner,
                "return_code": proc.returncode,
                "status": status,
                "language": normalize_language(request.language),
            },
        )
        return LabRunResult(
            status=status,
            return_code=proc.returncode,
            stdout=stdout,
            stderr=stderr,
            runner=runner,
            execution_time_sec=elapsed,
            argv=recorded_argv,
        )


_LAB_RUNNER: LabRunner | None = None


def get_lab_runner() -> LabRunner:
    global _LAB_RUNNER
    if _LAB_RUNNER is None:
        _LAB_RUNNER = IsolatedLabRunner()
    return _LAB_RUNNER


def set_lab_runner(runner: LabRunner | None) -> None:
    global _LAB_RUNNER
    _LAB_RUNNER = runner


def reset_lab_runner() -> None:
    set_lab_runner(None)
