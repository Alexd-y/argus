"""DockerSandboxAdapter — transitional local runner mirroring the K8s adapter.

This adapter is the docker-daemon counterpart of
:class:`~src.sandbox.k8s_adapter.KubernetesSandboxAdapter`. It exposes the SAME
public contract — ``async run(tool_job, descriptor) -> SandboxRunResult`` plus
the shared error taxonomy (:class:`SandboxConfigError`,
:class:`ApprovalRequiredError`, :class:`SandboxClusterError`) and the closed
``failure_reason`` vocabulary — so it is a drop-in for
:class:`~src.sandbox.runner.SandboxRunner` (which is duck-typed on ``run``).

It exists to unblock the "single control plane" migration (Backlog §3 /
orchestrator prompt task #1) on a plain Docker host, WITHOUT a Kubernetes
cluster: the exploitation executor and recon pipeline can dispatch signed
:class:`ToolJob`s through one code path, and the K8s adapter can later be
swapped back in unchanged.

Execution model — ephemeral, security-hardened, one-shot (mirrors a K8s Job):

* ``docker run --rm`` — a fresh container per job; never a long-lived
  ``docker exec`` into a shared box, so a runaway tool cannot poison siblings.
* Hardening mirrors the K8s ``securityContext`` invariants (§5/§18):
  non-root UID (65532), ``--read-only`` rootfs, ``--cap-drop ALL``,
  ``--security-opt no-new-privileges``, ``--pids-limit`` / ``--memory`` /
  ``--cpus`` from the descriptor, a memory-backed ``/tmp`` tmpfs, and a
  writable ``/out`` bind mount for artifacts. No ``docker.sock`` mount, no
  host-path other than the per-job ``/out`` dir.
* The tool argv is rendered by the SAME safe templating layer
  (:func:`src.sandbox.manifest.build_argv` → ``render_argv``) and passed via
  ``--entrypoint`` + positional args, matching the K8s ``command:`` override.
* Egress control is delegated to a caller-supplied docker ``--network`` (an
  operator-provisioned egress-restricted network is the docker analogue of a
  NetworkPolicy). The descriptor's ``network_policy`` name is still validated
  against the registered templates so a misconfigured descriptor fails closed.

Two modes: :attr:`DockerRunMode.DRY_RUN` (render + persist the command plan,
never execute) and :attr:`DockerRunMode.DOCKER` (execute via the daemon and
capture stdout/stderr/exit code).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
import tempfile
import time
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import yaml

from src.pipeline.contracts.tool_job import ToolJob
from src.sandbox import manifest as manifest_helpers
from src.sandbox.adapter_base import ToolDescriptor
from src.sandbox.k8s_adapter import (
    FAILURE_REASONS,
    ApprovalRequiredError,
    SandboxConfigError,
    SandboxRunResult,
)
from src.sandbox.network_policies import NETWORK_POLICY_NAMES
from src.sandbox.templating import redact_argv_for_logging

if TYPE_CHECKING:
    from src.policy.preflight import PreflightChecker, PreflightDecision

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants — hardening + defaults (mirror the K8s adapter where meaningful).
# ---------------------------------------------------------------------------

_NON_ROOT_UID: Final[int] = 65_532
_NON_ROOT_GID: Final[int] = 65_532
_DEFAULT_NAMESPACE: Final[str] = "argus-sandbox"
_DEFAULT_RUN_TIMEOUT_S: Final[int] = 1_200
_LOG_TAIL_BYTES: Final[int] = 10_240
_TERM_GRACE_S: Final[int] = 10

# ``failure_reason`` values, reusing the closed taxonomy shared with the K8s
# adapter / runner. A local-docker daemon failure maps onto the same
# ``cluster_apply_failed`` catch-all so downstream consumers need no new
# vocabulary. Every constant is asserted to be a member of the shared set.
_FR_DRY_RUN: Final[str] = "dry_run"
_FR_JOB_FAILED: Final[str] = "job_failed"
_FR_TIMEOUT: Final[str] = "cluster_timeout"
_FR_DOCKER_UNAVAILABLE: Final[str] = "cluster_apply_failed"
_FR_PREFLIGHT_DENIED: Final[str] = "preflight_denied"

assert {
    _FR_DRY_RUN,
    _FR_JOB_FAILED,
    _FR_TIMEOUT,
    _FR_DOCKER_UNAVAILABLE,
    _FR_PREFLIGHT_DENIED,
}.issubset(FAILURE_REASONS), "DockerSandboxAdapter failure_reasons must be in the closed taxonomy"

# K8s binary units (Mi/Gi) → docker size suffixes (m/g). Docker has no Ti/Pi;
# collapse them to ``g`` so an over-large descriptor still renders a valid flag.
_MEM_RE: Final[re.Pattern[str]] = re.compile(r"^(\d+)(Ki|Mi|Gi|Ti|K|M|G|T)?$")
_MEM_UNIT: Final[dict[str, str]] = {
    "Ki": "k",
    "Mi": "m",
    "Gi": "g",
    "Ti": "g",
    "K": "k",
    "M": "m",
    "G": "g",
    "T": "g",
}


def _memory_to_docker(mem: str) -> str:
    """Translate a K8s memory quantity (``256Mi``, ``2Gi``) to a docker size.

    Docker's ``--memory`` accepts ``b/k/m/g`` suffixes; K8s uses the binary
    ``Ki/Mi/Gi``. A bare integer is treated as bytes and passed through. An
    unrecognised quantity is passed through verbatim so docker (not this
    helper) is the single source of truth for rejecting a bad value.
    """
    match = _MEM_RE.fullmatch(mem.strip())
    if match is None:
        return mem
    value, unit = match.group(1), match.group(2)
    if unit is None:
        return value
    mapped = _MEM_UNIT.get(unit)
    return f"{value}{mapped}" if mapped is not None else mem


def _cpu_to_docker(cpu: str) -> str:
    """Translate a K8s CPU quantity (``500m``, ``2``) to a docker ``--cpus`` value.

    Millicores (``500m``) become fractional cores (``0.5``); whole / decimal
    core counts pass through unchanged.
    """
    cpu = cpu.strip()
    if cpu.endswith("m"):
        try:
            return str(int(cpu[:-1]) / 1000)
        except ValueError:
            return cpu
    return cpu


class DockerRunMode(StrEnum):
    """How :class:`DockerSandboxAdapter` should execute a job."""

    DRY_RUN = "dry_run"
    DOCKER = "docker"


class DockerSandboxAdapter:
    """Render and (optionally) execute sandbox jobs as ephemeral docker containers.

    Stateless across calls — every :meth:`run` materialises a fresh
    ``docker run`` command and a fresh per-job ``/out`` directory, so sharing
    one adapter across many jobs is safe.

    Parameters
    ----------
    registry
        Loaded :class:`~src.sandbox.tool_registry.ToolRegistry`. Used to surface
        the descriptor-declared artifact paths and (defence-in-depth) confirm
        the descriptor passed to :meth:`run` matches the indexed one.
    mode
        :attr:`DockerRunMode.DRY_RUN` (default) or :attr:`DockerRunMode.DOCKER`.
    namespace
        Logical namespace label (kept for parity with the K8s adapter /
        :class:`SandboxRunResult.namespace`; not a real docker construct).
    dry_run_artifact_dir
        Required when ``mode == DRY_RUN``: the rendered docker command + argv
        are written under ``<dir>/<scan_id>/<job_short>.docker.json``.
    out_dir_root
        Host directory under which per-job ``/out`` mounts are created
        (``<root>/<scan_id>/<job_short>``). Defaults to a temp dir.
    network
        Optional docker network name applied via ``--network`` for egress
        control (the docker analogue of a NetworkPolicy). ``None`` uses the
        docker default bridge — acceptable for lab use only.
    docker_binary
        Path / name of the docker CLI (default ``docker``); injectable for tests.
    default_run_timeout_s
        Hard ceiling; the effective per-run timeout is
        ``min(descriptor.default_timeout_s, default_run_timeout_s)``.
    preflight_checker
        Optional policy checker re-run defence-in-depth before execution.
    """

    def __init__(
        self,
        registry: Any,
        *,
        mode: DockerRunMode = DockerRunMode.DRY_RUN,
        namespace: str = _DEFAULT_NAMESPACE,
        dry_run_artifact_dir: Path | None = None,
        out_dir_root: Path | None = None,
        network: str | None = None,
        docker_binary: str = "docker",
        default_run_timeout_s: int = _DEFAULT_RUN_TIMEOUT_S,
        preflight_checker: PreflightChecker | None = None,
    ) -> None:
        if not isinstance(mode, DockerRunMode):
            raise SandboxConfigError(f"mode must be a DockerRunMode, got {type(mode)!r}")
        if mode is DockerRunMode.DRY_RUN and dry_run_artifact_dir is None:
            raise SandboxConfigError("dry_run_artifact_dir is required when mode=DRY_RUN")
        if default_run_timeout_s <= 0:
            raise SandboxConfigError("default_run_timeout_s must be > 0")
        if not namespace:
            raise SandboxConfigError("namespace must be non-empty")

        self._registry = registry
        self._mode = mode
        self._namespace = namespace
        self._dry_run_artifact_dir = dry_run_artifact_dir
        self._out_dir_root = out_dir_root
        self._network = network
        self._docker_binary = docker_binary
        self._default_run_timeout_s = default_run_timeout_s
        self._preflight_checker = preflight_checker

    # -- public properties ---------------------------------------------------

    @property
    def mode(self) -> DockerRunMode:
        return self._mode

    @property
    def namespace(self) -> str:
        return self._namespace

    @property
    def default_run_timeout_s(self) -> int:
        return self._default_run_timeout_s

    # -- command building (pure) --------------------------------------------

    def build_docker_command(
        self,
        tool_job: ToolJob,
        descriptor: ToolDescriptor,
        *,
        host_out_dir: Path,
        auth_argv: list[str] | None = None,
    ) -> list[str]:
        """Build (but do not execute) the hardened ``docker run`` argv.

        ``auth_argv`` is an OPTIONAL, caller-validated execution-context fragment
        (authenticated-session flags such as ``["-H", "Cookie: ..."]``) appended
        AFTER the descriptor-rendered tool argv. It is NOT part of the signed
        template — its FLAG tokens are chosen by trusted caller code and its
        VALUE tokens carry the session secret. Two guarantees make this safe and
        equivalent to a signed ``{auth_header}`` placeholder: (1) each value is
        strict-validated by the caller (no CR/LF/NUL/control → no header/argv
        injection; it is a single argv token, never shell-split), and (2) values
        are redacted from the persisted plan / dry-run artefacts. The session
        secret itself originates from the trusted ``SessionStore``, never the LLM.

        Raises
        ------
        SandboxConfigError
            On a tool_id mismatch or an unknown NetworkPolicy reference.
        ApprovalRequiredError
            When the descriptor requires approval but the job carries none.
        TemplateRenderError
            (Re-raised from the templating layer) for missing / invalid
            placeholder values.
        """
        self._validate_pair(tool_job, descriptor)
        self._validate_network_policy(descriptor)

        argv = manifest_helpers.build_argv(descriptor, tool_job)
        image = manifest_helpers.resolve_image(descriptor)

        docker_cmd: list[str] = [
            self._docker_binary,
            "run",
            "--rm",
            "--user",
            f"{_NON_ROOT_UID}:{_NON_ROOT_GID}",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            str(descriptor.pids_limit),
            "--memory",
            _memory_to_docker(descriptor.memory_limit),
            "--cpus",
            _cpu_to_docker(descriptor.cpu_limit),
            "--tmpfs",
            "/tmp",
            "-v",
            f"{host_out_dir}:/out:rw",
            "-w",
            "/out",
            "-e",
            f"ARGUS_TOOL_ID={descriptor.tool_id}",
            "-e",
            "ARGUS_OUT_DIR=/out",
            "-e",
            "ARGUS_TMP_DIR=/tmp",
        ]
        if self._network is not None:
            docker_cmd += ["--network", self._network]
        # ``--entrypoint`` + positional args mirror the K8s ``command:`` override
        # (the descriptor argv is authoritative regardless of the image default).
        docker_cmd += ["--entrypoint", argv[0], image, *argv[1:]]
        if auth_argv:
            docker_cmd += list(auth_argv)
        return docker_cmd

    # -- run -----------------------------------------------------------------

    async def run(
        self,
        tool_job: ToolJob,
        descriptor: ToolDescriptor,
        *,
        auth_argv: list[str] | None = None,
    ) -> SandboxRunResult:
        """Execute (or simulate) the job as a docker container and return a result.

        DRY_RUN persists the command plan and returns ``completed=False,
        failure_reason="dry_run"``. DOCKER runs the container, waits (bounded
        by ``min(descriptor.default_timeout_s, default_run_timeout_s)``),
        captures stdout/stderr, and maps the outcome onto the shared
        :class:`SandboxRunResult`.

        ``auth_argv`` (see :meth:`build_docker_command`) carries caller-validated
        authenticated-session flags; its secret value tokens are redacted from
        the persisted plan / dry-run artefacts.
        """
        start = time.monotonic()
        if self._preflight_checker is not None:
            decision = self._preflight_checker.check_tool_job(tool_job)
            if not decision.allowed:
                return self._preflight_denied_result(tool_job, decision, start)

        host_out_dir = self._prepare_out_dir(tool_job)
        docker_cmd = self.build_docker_command(
            tool_job, descriptor, host_out_dir=host_out_dir, auth_argv=auth_argv
        )
        # Value tokens of auth_argv (odd indices) are session secrets → redact
        # them from every persisted representation of the command.
        auth_values = (
            frozenset(auth_argv[i] for i in range(1, len(auth_argv), 2))
            if auth_argv
            else frozenset()
        )
        plan_yaml = self._render_plan_yaml(
            tool_job, descriptor, docker_cmd, auth_values=auth_values
        )
        job_name = manifest_helpers.build_job_name(tool_job)

        if self._mode is DockerRunMode.DRY_RUN:
            self._write_dry_run_artifacts(
                tool_job, descriptor, docker_cmd, plan_yaml, auth_values=auth_values
            )
            duration = time.monotonic() - start
            _logger.info(
                "sandbox.docker.dry_run",
                extra={
                    "tool_id": tool_job.tool_id,
                    "scan_id": str(tool_job.scan_id),
                    "job_id": str(tool_job.id),
                    "job_name": job_name,
                    "duration_s": duration,
                },
            )
            return SandboxRunResult(
                job_name=job_name,
                namespace=self._namespace,
                exit_code=None,
                duration_seconds=duration,
                artifacts=[],
                logs_excerpt="",
                completed=False,
                failure_reason=_FR_DRY_RUN,
                manifest_yaml=plan_yaml,
            )

        return await self._run_container(
            tool_job=tool_job,
            descriptor=descriptor,
            docker_cmd=docker_cmd,
            plan_yaml=plan_yaml,
            job_name=job_name,
            host_out_dir=host_out_dir,
            start_monotonic=start,
        )

    # -- private: validation -------------------------------------------------

    def _validate_pair(self, tool_job: ToolJob, descriptor: ToolDescriptor) -> None:
        if tool_job.tool_id != descriptor.tool_id:
            raise SandboxConfigError(
                f"tool_job.tool_id={tool_job.tool_id!r} mismatches "
                f"descriptor.tool_id={descriptor.tool_id!r}"
            )
        if descriptor.requires_approval and tool_job.approval_id is None:
            raise ApprovalRequiredError(
                f"tool_id={descriptor.tool_id!r} requires approval but "
                f"tool_job.approval_id is None"
            )

    @staticmethod
    def _validate_network_policy(descriptor: ToolDescriptor) -> None:
        """Fail closed on an unknown NetworkPolicy reference (parity with K8s)."""
        name = descriptor.network_policy.name
        if name not in NETWORK_POLICY_NAMES:
            raise SandboxConfigError(
                f"NetworkPolicy template {name!r} is not registered. "
                f"Known templates: {sorted(NETWORK_POLICY_NAMES)}"
            )

    # -- private: execution --------------------------------------------------

    def _prepare_out_dir(self, tool_job: ToolJob) -> Path:
        root = self._out_dir_root or Path(tempfile.gettempdir()) / "argus-docker-out"
        out_dir = root / str(tool_job.scan_id) / tool_job.id.hex[:8]
        out_dir.mkdir(parents=True, exist_ok=True)
        return out_dir

    async def _run_container(
        self,
        *,
        tool_job: ToolJob,
        descriptor: ToolDescriptor,
        docker_cmd: list[str],
        plan_yaml: str,
        job_name: str,
        host_out_dir: Path,
        start_monotonic: float,
    ) -> SandboxRunResult:
        deadline_s = min(descriptor.default_timeout_s, self._default_run_timeout_s)
        try:
            proc = await asyncio.create_subprocess_exec(
                *docker_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            return self._failure_result(
                job_name=job_name,
                start_monotonic=start_monotonic,
                failure_reason=_FR_DOCKER_UNAVAILABLE,
                plan_yaml=plan_yaml,
                logs_excerpt="docker binary not found on PATH",
            )

        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(), timeout=deadline_s + _TERM_GRACE_S
            )
        except TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            with contextlib.suppress(Exception):
                await proc.wait()
            _logger.warning(
                "sandbox.docker.timeout",
                extra={
                    "tool_id": tool_job.tool_id,
                    "scan_id": str(tool_job.scan_id),
                    "job_id": str(tool_job.id),
                    "job_name": job_name,
                    "timeout_s": deadline_s,
                },
            )
            return self._failure_result(
                job_name=job_name,
                start_monotonic=start_monotonic,
                failure_reason=_FR_TIMEOUT,
                plan_yaml=plan_yaml,
                logs_excerpt="",
            )

        exit_code = proc.returncode
        completed = exit_code == 0
        logs_excerpt = self._tail_logs(stdout_b, stderr_b)
        duration = time.monotonic() - start_monotonic
        _logger.info(
            "sandbox.docker.completed",
            extra={
                "tool_id": tool_job.tool_id,
                "scan_id": str(tool_job.scan_id),
                "job_id": str(tool_job.id),
                "job_name": job_name,
                "exit_code": exit_code,
                "completed": completed,
                "duration_s": duration,
            },
        )
        return SandboxRunResult(
            job_name=job_name,
            namespace=self._namespace,
            exit_code=exit_code,
            duration_seconds=duration,
            artifacts=self._collect_artifacts(descriptor, host_out_dir),
            logs_excerpt=logs_excerpt,
            completed=completed,
            failure_reason=None if completed else _FR_JOB_FAILED,
            manifest_yaml=plan_yaml,
        )

    def _failure_result(
        self,
        *,
        job_name: str,
        start_monotonic: float,
        failure_reason: str,
        plan_yaml: str,
        logs_excerpt: str,
    ) -> SandboxRunResult:
        return SandboxRunResult(
            job_name=job_name,
            namespace=self._namespace,
            exit_code=None,
            duration_seconds=max(0.0, time.monotonic() - start_monotonic),
            artifacts=[],
            logs_excerpt=logs_excerpt,
            completed=False,
            failure_reason=failure_reason,
            manifest_yaml=plan_yaml,
        )

    @staticmethod
    def _tail_logs(stdout_b: bytes | None, stderr_b: bytes | None) -> str:
        stdout = (stdout_b or b"").decode("utf-8", errors="replace")
        stderr = (stderr_b or b"").decode("utf-8", errors="replace")
        combined = stdout if not stderr else f"{stdout}\n{stderr}"
        if len(combined.encode("utf-8")) > _LOG_TAIL_BYTES:
            return combined[-_LOG_TAIL_BYTES:]
        return combined

    def _collect_artifacts(self, descriptor: ToolDescriptor, host_out_dir: Path) -> list[str]:
        """Return host paths of descriptor-declared artifacts that were produced.

        Unlike the K8s adapter (which cannot read the pod FS pre-sidecar), the
        docker adapter bind-mounts ``/out`` so it CAN surface the real files.
        A declared ``/out/x`` or ``x`` maps to ``<host_out_dir>/x``.
        """
        found: list[str] = []
        for artifact in descriptor.evidence_artifacts:
            relative = (
                artifact[len("/out/") :] if artifact.startswith("/out/") else artifact.lstrip("/")
            )
            candidate = host_out_dir / relative
            if candidate.exists():
                found.append(str(candidate))
        return found

    # -- private: plan rendering + dry-run artefacts ------------------------

    def _render_plan_yaml(
        self,
        tool_job: ToolJob,
        descriptor: ToolDescriptor,
        docker_cmd: list[str],
        *,
        auth_values: frozenset[str] = frozenset(),
    ) -> str:
        """Render the docker invocation plan as YAML (credentials redacted).

        Populates :class:`SandboxRunResult.manifest_yaml` — the docker analogue
        of the K8s Job manifest. Credential placeholder values are scrubbed via
        :func:`redact_argv_for_logging`; ``auth_values`` (authenticated-session
        secret tokens) are additionally replaced with ``[REDACTED]`` so the plan
        is safe to log / persist.
        """
        redacted = redact_argv_for_logging(docker_cmd, tool_job.parameters)
        if auth_values:
            redacted = ["[REDACTED]" if tok in auth_values else tok for tok in redacted]
        plan = {
            "kind": "DockerRunPlan",
            "tool_id": descriptor.tool_id,
            "namespace": self._namespace,
            "image": manifest_helpers.resolve_image(descriptor),
            "network": self._network,
            "network_policy": descriptor.network_policy.name,
            "security": {
                "user": f"{_NON_ROOT_UID}:{_NON_ROOT_GID}",
                "read_only_root_fs": True,
                "cap_drop": ["ALL"],
                "no_new_privileges": True,
                "pids_limit": descriptor.pids_limit,
                "memory": _memory_to_docker(descriptor.memory_limit),
                "cpus": _cpu_to_docker(descriptor.cpu_limit),
            },
            "command": redacted,
        }
        return str(yaml.safe_dump(plan, sort_keys=True, default_flow_style=False))

    def _write_dry_run_artifacts(
        self,
        tool_job: ToolJob,
        descriptor: ToolDescriptor,
        docker_cmd: list[str],
        plan_yaml: str,
        *,
        auth_values: frozenset[str] = frozenset(),
    ) -> None:
        if self._dry_run_artifact_dir is None:
            raise SandboxConfigError("dry_run_artifact_dir is not configured")
        scan_dir = self._dry_run_artifact_dir / str(tool_job.scan_id)
        scan_dir.mkdir(parents=True, exist_ok=True)
        short = tool_job.id.hex[:8]
        redacted = redact_argv_for_logging(docker_cmd, tool_job.parameters)
        if auth_values:
            redacted = ["[REDACTED]" if tok in auth_values else tok for tok in redacted]
        (scan_dir / f"{short}.plan.yaml").write_text(plan_yaml, encoding="utf-8")
        (scan_dir / f"{short}.docker.json").write_text(
            json.dumps(
                {
                    "tool_id": tool_job.tool_id,
                    "scan_id": str(tool_job.scan_id),
                    "job_id": str(tool_job.id),
                    "image": manifest_helpers.resolve_image(descriptor),
                    "namespace": self._namespace,
                    "network": self._network,
                    "network_policy": descriptor.network_policy.name,
                    "command": redacted,
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )

    def _preflight_denied_result(
        self,
        tool_job: ToolJob,
        decision: PreflightDecision,
        start_monotonic: float,
    ) -> SandboxRunResult:
        job_short = f"argus-{tool_job.tool_id.replace('_', '-')}-{tool_job.id.hex[:8]}"
        _logger.warning(
            "sandbox.docker.preflight_denied",
            extra={
                "tool_id": tool_job.tool_id,
                "scan_id": str(tool_job.scan_id),
                "job_id": str(tool_job.id),
                "decision_id": str(decision.decision_id),
                "summary": decision.failure_summary,
            },
        )
        return SandboxRunResult(
            job_name=job_short,
            namespace=self._namespace,
            exit_code=None,
            duration_seconds=max(0.0, time.monotonic() - start_monotonic),
            artifacts=[],
            logs_excerpt="",
            completed=False,
            failure_reason=_FR_PREFLIGHT_DENIED,
            manifest_yaml="# job rejected by preflight checker before command rendering\n",
        )


__all__ = [
    "DockerRunMode",
    "DockerSandboxAdapter",
]
