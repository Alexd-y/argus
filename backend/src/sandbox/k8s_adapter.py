"""KubernetesSandboxAdapter — materialises and (optionally) submits sandbox Jobs.

Two run modes (Backlog/dev1_md §3, §5):

* :attr:`SandboxRunMode.DRY_RUN` — pure rendering. Builds the Job manifest +
  NetworkPolicy manifest, writes them to ``dry_run_artifact_dir`` so tests
  / CI can diff them, and returns immediately with ``completed=False``,
  ``failure_reason="dry_run"``. **Never** imports the Kubernetes SDK.

* :attr:`SandboxRunMode.CLUSTER` — submits the Job to the cluster, polls
  status, captures pod logs (best-effort artifact source until the sidecar
  uploader from ARG-007+ ships), and returns the run result.

Hard guarantees enforced for every rendered manifest (see Backlog §5/§18):

#. ``securityContext.runAsNonRoot=True``, non-zero UID/GID.
#. ``securityContext.allowPrivilegeEscalation=False``.
#. ``securityContext.readOnlyRootFilesystem=True``.
#. ``securityContext.capabilities.drop=["ALL"]``.
#. ``securityContext.privileged=False``.
#. ``seccompProfile.type=RuntimeDefault``.
#. **No** hostPath volumes anywhere.
#. **No** docker.sock mount.
#. ``automountServiceAccountToken=False``.
#. ``restartPolicy=Never``, ``backoffLimit=0`` — sandbox jobs do not retry.
#. ``activeDeadlineSeconds`` bounded by the smaller of descriptor /adapter
   timeout — a runaway tool can never burn cluster resources beyond the
   declared envelope.

This module never calls ``subprocess`` / ``os.system``; it never sets
``shell=True``. All cluster I/O goes through the official ``kubernetes``
Python SDK, imported lazily only when CLUSTER mode is selected.
"""

from __future__ import annotations

import asyncio
import copy
import importlib
import json
import logging
import time
from collections.abc import Mapping
from enum import StrEnum
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING, Any, Final

import yaml
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr

from src.pipeline.contracts.tool_job import TargetKind, ToolJob
from src.sandbox import manifest as manifest_helpers
from src.sandbox.adapter_base import ToolDescriptor
from src.sandbox.network_policies import (
    NETWORK_POLICY_NAMES,
    NetworkPolicyTemplate,
    get_template,
)
from src.sandbox.templating import redact_argv_for_logging
from src.sandbox.tool_registry import ToolRegistry


if TYPE_CHECKING:
    # Lazy import to avoid the policy plane dragging k8s SDK paths into its
    # own module load. The runtime constructor accepts any object that
    # quacks like PreflightChecker; type-checkers see the real class.
    from src.policy.preflight import PreflightChecker, PreflightDecision


_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


_DEFAULT_NAMESPACE: Final[str] = "argus-sandbox"
_DEFAULT_POD_TIMEOUT_S: Final[int] = 1_200
_LOG_TAIL_BYTES: Final[int] = 10_240
_CLUSTER_POLL_INTERVAL_S: Final[float] = 2.0


# ---------------------------------------------------------------------------
# Closed taxonomy of `SandboxRunResult.failure_reason` values.
#
# Anything assigned to ``failure_reason`` MUST be one of these constants. Raw
# strings (especially ``str(ApiException)``) are forbidden because the
# Kubernetes ApiException str representation embeds the HTTP body, response
# headers, and the API server version banner — direct information leak per
# the project's "never expose error details to the end user" rule. Verbose
# detail belongs in structured logs (``error_class``, ``status``), never in
# user-facing fields.
# ---------------------------------------------------------------------------


_FAILURE_REASON_CLUSTER_APPLY: Final[str] = "cluster_apply_failed"
_FAILURE_REASON_CLUSTER_STATUS: Final[str] = "cluster_status_unavailable"
_FAILURE_REASON_CLUSTER_TIMEOUT: Final[str] = "cluster_timeout"
_FAILURE_REASON_CLUSTER_LOG_READ: Final[str] = "cluster_log_read_failed"
_FAILURE_REASON_JOB_FAILED: Final[str] = "job_failed"
_FAILURE_REASON_OOM: Final[str] = "oom_killed"
_FAILURE_REASON_IMAGE_PULL: Final[str] = "image_pull_failed"
_FAILURE_REASON_DRY_RUN: Final[str] = "dry_run"
_FAILURE_REASON_UNEXPECTED: Final[str] = "unexpected_error"
_FAILURE_REASON_PREFLIGHT_DENIED: Final[str] = "preflight_denied"


FAILURE_REASONS: Final[frozenset[str]] = frozenset(
    {
        _FAILURE_REASON_CLUSTER_APPLY,
        _FAILURE_REASON_CLUSTER_STATUS,
        _FAILURE_REASON_CLUSTER_TIMEOUT,
        _FAILURE_REASON_CLUSTER_LOG_READ,
        _FAILURE_REASON_JOB_FAILED,
        _FAILURE_REASON_OOM,
        _FAILURE_REASON_IMAGE_PULL,
        _FAILURE_REASON_DRY_RUN,
        _FAILURE_REASON_UNEXPECTED,
        _FAILURE_REASON_PREFLIGHT_DENIED,
    }
)
"""Public, immutable set of every value the closed taxonomy admits.

Other modules (runner, audit, API serialisers) MUST use this set when
validating ``failure_reason`` values rather than hard-coding string literals.
"""


# Map raw Kubernetes status reasons (Job ``conditions[].reason`` and pod
# ``container_statuses[].state.terminated.reason``) into the closed taxonomy.
# Anything not listed here falls back to :data:`_FAILURE_REASON_JOB_FAILED`,
# so a malicious / spoofed apiserver response can never inject a free-form
# string into ``SandboxRunResult.failure_reason``.
_K8S_REASON_TO_FAILURE: Final[Mapping[str, str]] = {
    "OOMKilled": _FAILURE_REASON_OOM,
    "Evicted": _FAILURE_REASON_OOM,
    "ImagePullBackOff": _FAILURE_REASON_IMAGE_PULL,
    "ErrImagePull": _FAILURE_REASON_IMAGE_PULL,
    "InvalidImageName": _FAILURE_REASON_IMAGE_PULL,
    "DeadlineExceeded": _FAILURE_REASON_CLUSTER_TIMEOUT,
    "BackoffLimitExceeded": _FAILURE_REASON_JOB_FAILED,
    "Error": _FAILURE_REASON_JOB_FAILED,
    "ContainerCannotRun": _FAILURE_REASON_JOB_FAILED,
}


# ---------------------------------------------------------------------------
# Enums + result models
# ---------------------------------------------------------------------------


class SandboxRunMode(StrEnum):
    """How the adapter should execute a job."""

    DRY_RUN = "dry_run"
    CLUSTER = "cluster"


class SandboxRunResult(BaseModel):
    """Outcome of a single sandbox run.

    All fields are required so callers always get a complete snapshot. For
    DRY_RUN the runtime-only fields (``exit_code``, ``failure_reason``,
    ``logs_excerpt``) carry sentinel values documented in
    :meth:`KubernetesSandboxAdapter.run`.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    job_name: StrictStr = Field(min_length=1, max_length=128)
    namespace: StrictStr = Field(min_length=1, max_length=64)
    exit_code: StrictInt | None
    duration_seconds: float = Field(ge=0)
    artifacts: list[StrictStr] = Field(default_factory=list)
    logs_excerpt: StrictStr = ""
    completed: StrictBool
    failure_reason: StrictStr | None = Field(default=None, max_length=128)
    manifest_yaml: StrictStr = Field(min_length=1)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class SandboxConfigError(Exception):
    """Raised for misconfigured descriptors / unknown NetworkPolicy refs."""


class ApprovalRequiredError(Exception):
    """Raised when a descriptor demands approval but the job has none."""


class SandboxClusterError(Exception):
    """Raised when the live cluster surface fails (auth, API, timeout).

    The optional ``failure_reason`` carries one of the closed-taxonomy
    constants from this module (see :data:`FAILURE_REASONS`) so the caller
    can surface a stable, vocabulary-controlled identifier via
    :class:`SandboxRunResult.failure_reason` instead of leaking the
    underlying ``ApiException`` body / HTTP headers / API server version.

    Defaults to ``None`` so existing call sites (``raise SandboxClusterError("…")``)
    keep working; consumers MUST then treat the absence as
    :data:`_FAILURE_REASON_CLUSTER_APPLY` (the safe catch-all).
    """

    def __init__(self, message: str, *, failure_reason: str | None = None) -> None:
        super().__init__(message)
        self.failure_reason = failure_reason


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------


class KubernetesSandboxAdapter:
    """Render and (optionally) execute sandbox jobs as Kubernetes Jobs.

    The adapter is **stateless across calls**: every :meth:`run` invocation
    materialises a fresh manifest, applies a fresh NetworkPolicy, and
    streams the result. Sharing one adapter across many jobs is therefore
    safe (and recommended — the registry / kube-config are loaded once).

    Parameters
    ----------
    registry
        :class:`ToolRegistry` instance (already loaded). Used to validate
        that the descriptor passed to :meth:`run` is the one indexed by
        the registry — defence-in-depth against routing bugs.
    mode
        :attr:`SandboxRunMode.DRY_RUN` (default) or
        :attr:`SandboxRunMode.CLUSTER`. Only the latter requires the
        ``kubernetes`` Python SDK to be installed.
    namespace
        Kubernetes namespace used for both the Job and its NetworkPolicy.
    dry_run_artifact_dir
        Required when ``mode == DRY_RUN``. Manifest YAML and argv JSON files
        are written under ``<dir>/<scan_id>/<job_short>.yaml`` and
        ``<dir>/<scan_id>/<job_short>.argv.json``.
    kube_config_path
        Optional path to a kubeconfig file (CLUSTER mode only). If ``None``,
        in-cluster config is used (works inside a Pod with a service account).
    default_pod_timeout_s
        Hard ceiling on ``activeDeadlineSeconds``. The actual value used is
        ``min(descriptor.default_timeout_s, default_pod_timeout_s)``.
    """

    def __init__(
        self,
        registry: ToolRegistry,
        *,
        mode: SandboxRunMode = SandboxRunMode.DRY_RUN,
        namespace: str = _DEFAULT_NAMESPACE,
        dry_run_artifact_dir: Path | None = None,
        kube_config_path: Path | None = None,
        default_pod_timeout_s: int = _DEFAULT_POD_TIMEOUT_S,
        preflight_checker: "PreflightChecker | None" = None,
    ) -> None:
        if not isinstance(mode, SandboxRunMode):
            raise SandboxConfigError(
                f"mode must be a SandboxRunMode, got {type(mode)!r}"
            )
        if mode is SandboxRunMode.DRY_RUN and dry_run_artifact_dir is None:
            raise SandboxConfigError(
                "dry_run_artifact_dir is required when mode=DRY_RUN"
            )
        if default_pod_timeout_s <= 0:
            raise SandboxConfigError("default_pod_timeout_s must be > 0")
        if not namespace:
            raise SandboxConfigError("namespace must be non-empty")

        self._registry = registry
        self._mode = mode
        self._namespace = namespace
        self._dry_run_artifact_dir = dry_run_artifact_dir
        self._kube_config_path = kube_config_path
        self._default_pod_timeout_s = default_pod_timeout_s
        self._preflight_checker = preflight_checker
        # Lazily initialised in CLUSTER mode only — see _kube().
        self._kube_modules: dict[str, ModuleType] | None = None

    # ------------------------------------------------------------------
    # Public properties
    # ------------------------------------------------------------------

    @property
    def mode(self) -> SandboxRunMode:
        return self._mode

    @property
    def namespace(self) -> str:
        return self._namespace

    @property
    def default_pod_timeout_s(self) -> int:
        return self._default_pod_timeout_s

    # ------------------------------------------------------------------
    # Manifest building (pure)
    # ------------------------------------------------------------------

    def build_job_manifest(
        self,
        tool_job: ToolJob,
        descriptor: ToolDescriptor,
    ) -> dict[str, Any]:
        """Build (but do not apply) the Kubernetes Job manifest.

        Composes the manifest helpers from :mod:`src.sandbox.manifest`
        and validates the descriptor / job pair against the security
        invariants documented at module level.

        Raises
        ------
        SandboxConfigError
            If the descriptor's NetworkPolicy reference is unknown OR if
            tool_job.tool_id mismatches descriptor.tool_id.
        ApprovalRequiredError
            If descriptor.requires_approval is True and tool_job.approval_id
            is None.
        TemplateRenderError
            (Re-raised from the templating layer) for missing parameters or
            invalid placeholder values.
        """
        self._validate_pair(tool_job, descriptor)
        argv = manifest_helpers.build_argv(descriptor, tool_job)
        job_name = manifest_helpers.build_job_name(tool_job)
        labels = manifest_helpers.build_pod_labels(tool_job)
        active_deadline = min(descriptor.default_timeout_s, self._default_pod_timeout_s)

        manifest: dict[str, Any] = {
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": manifest_helpers.build_job_metadata(
                tool_job, namespace=self._namespace, job_name=job_name
            ),
            "spec": {
                # backoffLimit=0 — sandbox jobs are one-shot; never let k8s
                # silently re-run a destructive command.
                "backoffLimit": 0,
                "completions": 1,
                "parallelism": 1,
                "activeDeadlineSeconds": active_deadline,
                # ttlSecondsAfterFinished — k8s GC removes finished Jobs after
                # 10 minutes so their logs survive long enough to be ingested.
                "ttlSecondsAfterFinished": 600,
                "template": {
                    "metadata": {
                        "labels": labels,
                        "annotations": {
                            "argus.io/correlation-id": tool_job.correlation_id,
                        },
                    },
                    "spec": {
                        "restartPolicy": "Never",
                        "automountServiceAccountToken": False,
                        "securityContext": manifest_helpers.build_pod_security_context(),
                        "volumes": manifest_helpers.build_volumes(),
                        "containers": [
                            self._build_container_spec(descriptor, argv),
                        ],
                    },
                },
            },
        }

        self._assert_no_dangerous_volumes(manifest)
        return manifest

    def build_networkpolicy_manifest(
        self,
        tool_job: ToolJob,
        descriptor: ToolDescriptor,
    ) -> dict[str, Any]:
        """Build the NetworkPolicy manifest paired with the Job.

        Resolves the descriptor's :class:`NetworkPolicyRef` against the
        registered templates, derives the per-job target CIDR from
        ``tool_job.target`` when the template demands it, and returns a
        v1 NetworkPolicy manifest ready to apply.

        ARG-027: per-tool ``dns_resolvers`` / ``egress_allowlist``
        overrides on the descriptor's ``NetworkPolicyRef`` flow through
        :func:`src.sandbox.manifest.build_networkpolicy_for_job` so the
        renderer can validate them against the private-range / IMDS
        denylist before they widen the policy.
        """
        self._validate_pair(tool_job, descriptor)
        template = self._resolve_template(descriptor.network_policy.name)
        target_cidr = (
            self._derive_target_cidr(tool_job)
            if template.egress_target_dynamic
            else None
        )
        pod_labels = manifest_helpers.build_pod_labels(tool_job)
        try:
            return manifest_helpers.build_networkpolicy_for_job(
                descriptor.network_policy,
                template,
                namespace=self._namespace,
                pod_label_selector=pod_labels,
                target_cidr=target_cidr,
                name_suffix=tool_job.id.hex[:8],
            )
        except ValueError as exc:
            # Translate render-side validation failures into the sandbox's
            # domain error so the runner / API surface gets a stable
            # exception type to catch (and so the closed-taxonomy
            # ``failure_reason`` mapping in the cluster path keeps
            # working). Never echo ``str(exc)`` further than this — the
            # message names the offending CIDR, which is fine for
            # operator logs but not for the API response.
            raise SandboxConfigError(
                f"NetworkPolicy override rejected for tool_id="
                f"{descriptor.tool_id!r}: {exc}"
            ) from exc

    # ------------------------------------------------------------------
    # Run (DRY_RUN or CLUSTER)
    # ------------------------------------------------------------------

    async def run(
        self,
        tool_job: ToolJob,
        descriptor: ToolDescriptor,
    ) -> SandboxRunResult:
        """Execute (or simulate) the job and return a typed result.

        DRY_RUN mode writes manifests to disk and returns immediately with
        ``completed=False``, ``failure_reason="dry_run"``.

        CLUSTER mode applies the NetworkPolicy + Job, polls until the Job
        terminates (success / failure / timeout), captures the last 10 KB
        of pod logs, and returns the typed result.

        When the adapter was constructed with a ``preflight_checker`` the
        method performs a defense-in-depth re-check before any rendering /
        cluster I/O; on denial it returns a closed-taxonomy
        ``failure_reason="preflight_denied"`` result.
        """
        start = time.monotonic()
        if self._preflight_checker is not None:
            preflight_decision = self._preflight_checker.check_tool_job(tool_job)
            if not preflight_decision.allowed:
                return self._build_preflight_denied_result(
                    tool_job=tool_job,
                    decision=preflight_decision,
                    start_monotonic=start,
                )

        job_manifest = self.build_job_manifest(tool_job, descriptor)
        netpol_manifest = self.build_networkpolicy_manifest(tool_job, descriptor)
        manifest_yaml = self._render_manifest_yaml(job_manifest, netpol_manifest)
        job_name = job_manifest["metadata"]["name"]

        if self._mode is SandboxRunMode.DRY_RUN:
            self._write_dry_run_artifacts(
                tool_job=tool_job,
                descriptor=descriptor,
                job_manifest=job_manifest,
                netpol_manifest=netpol_manifest,
                manifest_yaml=manifest_yaml,
            )
            duration = time.monotonic() - start
            _logger.info(
                "sandbox.run.dry_run",
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
                failure_reason=_FAILURE_REASON_DRY_RUN,
                manifest_yaml=manifest_yaml,
            )

        # CLUSTER mode — submit the manifests and wait for completion.
        return await self._run_in_cluster(
            tool_job=tool_job,
            descriptor=descriptor,
            job_manifest=job_manifest,
            netpol_manifest=netpol_manifest,
            manifest_yaml=manifest_yaml,
            start_monotonic=start,
        )

    # ------------------------------------------------------------------
    # Private helpers — pure
    # ------------------------------------------------------------------

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

    def _resolve_template(self, name: str) -> NetworkPolicyTemplate:
        if name not in NETWORK_POLICY_NAMES:
            raise SandboxConfigError(
                f"NetworkPolicy template {name!r} is not registered. "
                f"Known templates: {sorted(NETWORK_POLICY_NAMES)}"
            )
        try:
            return get_template(name)
        except KeyError as exc:
            raise SandboxConfigError(str(exc)) from exc

    @staticmethod
    def _derive_target_cidr(tool_job: ToolJob) -> str | None:
        """Convert :class:`TargetSpec` into a CIDR for NetworkPolicy egress.

        Returns ``None`` for hostname / URL / domain targets — the caller
        (NetworkPolicy renderer) refuses these for ``egress_target_dynamic``
        templates with a clear error message.
        """
        target = tool_job.target
        if target.kind is TargetKind.IP:
            assert target.ip is not None
            return f"{target.ip}/32" if "." in target.ip else f"{target.ip}/128"
        if target.kind is TargetKind.CIDR:
            assert target.cidr is not None
            return target.cidr
        return None

    def _build_container_spec(
        self, descriptor: ToolDescriptor, argv: list[str]
    ) -> dict[str, Any]:
        return {
            "name": "tool",
            "image": manifest_helpers.resolve_image(descriptor),
            "imagePullPolicy": "IfNotPresent",
            # argv is rendered by the safe templating layer — pass directly,
            # no shell wrapping at the runner level. If the YAML uses
            # "sh -c <cmd>" the first two argv entries reflect that and
            # k8s will exec them as the container's command.
            "command": list(argv),
            "args": [],
            "workingDir": "/out",
            "securityContext": manifest_helpers.build_container_security_context(),
            "resources": manifest_helpers.build_resource_limits(descriptor),
            "volumeMounts": manifest_helpers.build_volume_mounts(),
            "env": [
                {"name": "ARGUS_TOOL_ID", "value": descriptor.tool_id},
                {"name": "ARGUS_OUT_DIR", "value": "/out"},
                {"name": "ARGUS_TMP_DIR", "value": "/tmp"},
            ],
        }

    @staticmethod
    def _assert_no_dangerous_volumes(manifest: Mapping[str, Any]) -> None:
        """Defence-in-depth: scan the rendered manifest for forbidden volumes.

        Any of these would imply a logic bug above — guard anyway because
        a single rogue YAML / future helper change must not silently expose
        the host filesystem or docker.sock to a tool.
        """
        spec = manifest.get("spec", {})
        template_spec = spec.get("template", {}).get("spec", {})
        for volume in template_spec.get("volumes", []):
            if "hostPath" in volume:
                raise SandboxConfigError(
                    "rendered manifest contains a hostPath volume — forbidden"
                )
        for container in template_spec.get("containers", []):
            for mount in container.get("volumeMounts", []):
                path = mount.get("mountPath", "")
                if "docker.sock" in path:
                    raise SandboxConfigError(
                        f"rendered manifest mounts docker.sock at {path!r} — forbidden"
                    )

    @staticmethod
    def _render_manifest_yaml(
        job_manifest: Mapping[str, Any],
        netpol_manifest: Mapping[str, Any],
    ) -> str:
        """Serialise (Job, NetworkPolicy) into a single YAML document stream."""
        rendered = yaml.safe_dump_all(
            [dict(netpol_manifest), dict(job_manifest)],
            sort_keys=True,
            default_flow_style=False,
        )
        return str(rendered)

    def _build_preflight_denied_result(
        self,
        *,
        tool_job: ToolJob,
        decision: "PreflightDecision",
        start_monotonic: float,
    ) -> SandboxRunResult:
        """Render a closed-taxonomy result for a preflight-denied job.

        The detailed sub-reason (scope, ownership, policy, approval) lives
        in the structured ``PreflightDecision`` consumed by the audit
        pipeline; the user-facing ``failure_reason`` is the deliberately
        opaque ``preflight_denied`` taxonomy entry so internal rule
        identifiers never escape the trust boundary.
        """
        job_short = f"argus-{tool_job.tool_id.replace('_', '-')}-{tool_job.id.hex[:8]}"
        duration = max(0.0, time.monotonic() - start_monotonic)
        _logger.warning(
            "sandbox.run.preflight_denied",
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
            duration_seconds=duration,
            artifacts=[],
            logs_excerpt="",
            completed=False,
            failure_reason=_FAILURE_REASON_PREFLIGHT_DENIED,
            manifest_yaml="# job rejected by preflight checker before manifest rendering\n",
        )

    def _write_dry_run_artifacts(
        self,
        *,
        tool_job: ToolJob,
        descriptor: ToolDescriptor,
        job_manifest: Mapping[str, Any],
        netpol_manifest: Mapping[str, Any],
        manifest_yaml: str,
    ) -> None:
        """Persist the rendered manifests + argv to ``dry_run_artifact_dir``.

        Credential placeholder values (``{user}`` / ``{pass}`` / ``{u}`` /
        ``{p}`` / ``{password}`` / ``{username}``) are redacted out of BOTH
        on-disk artefacts (``{short}.yaml`` and ``{short}.argv.json``)
        before they are written, per the contract documented in
        :func:`src.sandbox.templating.redact_argv_for_logging`.  The
        in-memory ``manifest_yaml`` parameter (passed back to the caller
        on the :class:`SandboxRunResult`) retains the unredacted command
        because the live cluster apply needs the real credential values
        to launch the Job; only the disk-resident copies are scrubbed.
        """
        if self._dry_run_artifact_dir is None:
            raise SandboxConfigError("dry_run_artifact_dir is not configured")
        scan_dir = self._dry_run_artifact_dir / str(tool_job.scan_id)
        scan_dir.mkdir(parents=True, exist_ok=True)
        short = tool_job.id.hex[:8]
        manifest_path = scan_dir / f"{short}.yaml"
        argv_path = scan_dir / f"{short}.argv.json"

        argv = manifest_helpers.build_argv(descriptor, tool_job)
        redacted_argv = redact_argv_for_logging(argv, tool_job.parameters)

        # Re-render the manifest YAML with the redacted argv so the
        # on-disk dump never echoes credential values via the container's
        # ``command:`` list.  The caller's in-memory ``manifest_yaml``
        # (which carries the unredacted command for cluster submission)
        # is left untouched.
        redacted_manifest = copy.deepcopy(dict(job_manifest))
        for container in (
            redacted_manifest.get("spec", {})
            .get("template", {})
            .get("spec", {})
            .get("containers", [])
        ):
            container["command"] = list(redacted_argv)
        redacted_manifest_yaml = self._render_manifest_yaml(
            redacted_manifest, netpol_manifest
        )

        manifest_path.write_text(redacted_manifest_yaml, encoding="utf-8")
        argv_payload = {
            "tool_id": tool_job.tool_id,
            "scan_id": str(tool_job.scan_id),
            "job_id": str(tool_job.id),
            "image": manifest_helpers.resolve_image(descriptor),
            "argv": redacted_argv,
            "namespace": self._namespace,
            "network_policy": descriptor.network_policy.name,
            "netpol_name": netpol_manifest.get("metadata", {}).get("name"),
        }
        argv_path.write_text(
            json.dumps(argv_payload, indent=2, sort_keys=True), encoding="utf-8"
        )

    # ------------------------------------------------------------------
    # Private helpers — cluster I/O
    # ------------------------------------------------------------------

    def _kube(self) -> dict[str, ModuleType]:
        """Lazily import the Kubernetes SDK + load configuration.

        Imported only inside CLUSTER-mode code paths so DRY_RUN consumers
        and tests never need the SDK on their PYTHONPATH.
        """
        if self._kube_modules is not None:
            return self._kube_modules

        try:
            client_mod = importlib.import_module("kubernetes.client")
            config_mod = importlib.import_module("kubernetes.config")
            watch_mod = importlib.import_module("kubernetes.watch")
        except ImportError as exc:
            raise SandboxClusterError(
                "kubernetes Python SDK is not installed; install "
                "'kubernetes>=29,<30' to use SandboxRunMode.CLUSTER",
                failure_reason=_FAILURE_REASON_CLUSTER_APPLY,
            ) from exc

        try:
            if self._kube_config_path is not None:
                config_mod.load_kube_config(config_file=str(self._kube_config_path))
            else:
                # Try in-cluster first (works inside a Pod), fall back to default kubeconfig.
                try:
                    config_mod.load_incluster_config()
                except config_mod.ConfigException:
                    config_mod.load_kube_config()
        except Exception as exc:  # noqa: BLE001 — wrap every kubeconfig error uniformly
            # Intentionally do NOT include str(exc) — kubeconfig parser errors
            # may echo file system paths, host names, or token fragments. The
            # exception class name + chained __cause__ are enough for ops.
            raise SandboxClusterError(
                f"failed to load kubeconfig ({exc.__class__.__name__})",
                failure_reason=_FAILURE_REASON_CLUSTER_APPLY,
            ) from exc

        self._kube_modules = {
            "client": client_mod,
            "config": config_mod,
            "watch": watch_mod,
        }
        return self._kube_modules

    async def _run_in_cluster(
        self,
        *,
        tool_job: ToolJob,
        descriptor: ToolDescriptor,
        job_manifest: Mapping[str, Any],
        netpol_manifest: Mapping[str, Any],
        manifest_yaml: str,
        start_monotonic: float,
    ) -> SandboxRunResult:
        """Submit Job + NetworkPolicy to the cluster and wait for completion.

        Artifact collection is intentionally best-effort: the adapter reads
        the pod's stdout (last 10 KB) and exposes it as ``logs_excerpt``.
        A future task (out of scope for ARG-004) introduces a sidecar that
        ships ``/out`` to S3 / MinIO; until then ``artifacts`` is populated
        only with the on-pod paths declared by the descriptor.
        """
        del descriptor  # reserved for future use (sidecar uploader hooks)

        loop = asyncio.get_running_loop()
        job_name: str = str(job_manifest["metadata"]["name"])
        networkpolicy_name: str = str(netpol_manifest["metadata"]["name"])
        deadline_s = float(job_manifest["spec"]["activeDeadlineSeconds"])
        # MED-1: track NP-applied state so we can clean it up if the Job-side
        # path fails. Job has ttlSecondsAfterFinished=600; NetworkPolicy has
        # no TTL primitive, so an orphaned NP would survive a partial failure
        # forever and accumulate per-job clutter in the namespace.
        networkpolicy_applied = False
        try:
            try:
                await loop.run_in_executor(
                    None,
                    self._apply_networkpolicy,
                    netpol_manifest,
                )
                networkpolicy_applied = True
                await loop.run_in_executor(
                    None,
                    self._apply_job,
                    job_manifest,
                )
                (
                    exit_code,
                    completed,
                    failure_reason,
                    logs_excerpt,
                ) = await loop.run_in_executor(
                    None,
                    self._wait_for_completion,
                    job_name,
                    deadline_s,
                )
            except Exception:
                # Anything raised after the NetworkPolicy was applied (Job
                # apply, status read, unexpected SDK bug) MUST trigger an
                # explicit NP cleanup before re-raising; the outer
                # ``except SandboxClusterError`` handler still maps the
                # failure to a closed-taxonomy result.
                if networkpolicy_applied:
                    try:
                        await loop.run_in_executor(
                            None,
                            self._delete_networkpolicy,
                            networkpolicy_name,
                        )
                    except Exception as cleanup_err:  # noqa: BLE001 — best-effort
                        # Use ``netpol_name`` (not ``name``) as the extras key
                        # because ``LogRecord.name`` is reserved and the
                        # logging library refuses to overwrite it. Cleanup
                        # noise stays in structured logs and never masks the
                        # original failure_reason returned to the caller.
                        _logger.warning(
                            "sandbox.networkpolicy_cleanup_failed",
                            extra={
                                "netpol_name": networkpolicy_name,
                                "error_class": type(cleanup_err).__name__,
                                "cleanup_status": getattr(cleanup_err, "status", None),
                            },
                        )
                raise
        except SandboxClusterError as exc:
            duration = time.monotonic() - start_monotonic
            cause = exc.__cause__
            _logger.error(
                "sandbox.run.cluster_error",
                extra={
                    "tool_id": tool_job.tool_id,
                    "scan_id": str(tool_job.scan_id),
                    "job_id": str(tool_job.id),
                    "job_name": job_name,
                    "error_class": type(exc).__name__,
                    # MED-2: log the underlying class + HTTP status only —
                    # NEVER ``str(cause)`` (echoes ApiException body).
                    "cause_class": type(cause).__name__ if cause is not None else None,
                    "status": getattr(cause, "status", None)
                    if cause is not None
                    else None,
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
                # MED-2: closed-taxonomy value only. ``str(exc)`` would leak
                # the rendered ApiException including HTTP body / headers.
                failure_reason=exc.failure_reason or _FAILURE_REASON_CLUSTER_APPLY,
                manifest_yaml=manifest_yaml,
            )

        duration = time.monotonic() - start_monotonic
        _logger.info(
            "sandbox.run.completed",
            extra={
                "tool_id": tool_job.tool_id,
                "scan_id": str(tool_job.scan_id),
                "job_id": str(tool_job.id),
                "job_name": job_name,
                "exit_code": exit_code,
                "completed": completed,
                "failure_reason": failure_reason,
                "duration_s": duration,
            },
        )
        return SandboxRunResult(
            job_name=job_name,
            namespace=self._namespace,
            exit_code=exit_code,
            duration_seconds=duration,
            artifacts=list(self._collected_artifact_paths(tool_job)),
            logs_excerpt=logs_excerpt,
            completed=completed,
            failure_reason=failure_reason,
            manifest_yaml=manifest_yaml,
        )

    def _apply_networkpolicy(self, manifest: Mapping[str, Any]) -> None:
        kube = self._kube()
        client = kube["client"]
        api = client.NetworkingV1Api()
        name = manifest["metadata"]["name"]
        try:
            api.delete_namespaced_network_policy(
                name=name,
                namespace=self._namespace,
                grace_period_seconds=0,
            )
        except client.exceptions.ApiException as exc:
            if getattr(exc, "status", None) != 404:
                raise SandboxClusterError(
                    f"failed to clean stale NetworkPolicy {name!r}",
                    failure_reason=_FAILURE_REASON_CLUSTER_APPLY,
                ) from exc
        try:
            api.create_namespaced_network_policy(
                namespace=self._namespace,
                body=dict(manifest),
            )
        except client.exceptions.ApiException as exc:
            raise SandboxClusterError(
                f"failed to apply NetworkPolicy {name!r}",
                failure_reason=_FAILURE_REASON_CLUSTER_APPLY,
            ) from exc

    def _delete_networkpolicy(self, name: str) -> None:
        """Best-effort delete of a NetworkPolicy; 404 (already gone) is swallowed.

        Invoked by the cleanup path in :meth:`_run_in_cluster` when the Job-side
        of the workflow fails after a NetworkPolicy was successfully applied.
        Job objects self-GC via ``ttlSecondsAfterFinished``; NetworkPolicies do
        not, so the adapter must drop them explicitly to keep the namespace
        from accumulating per-job clutter on partial failure.
        """
        kube = self._kube()
        client = kube["client"]
        api = client.NetworkingV1Api()
        try:
            api.delete_namespaced_network_policy(
                name=name,
                namespace=self._namespace,
                grace_period_seconds=0,
            )
        except client.exceptions.ApiException as exc:
            if getattr(exc, "status", None) == 404:
                return
            raise SandboxClusterError(
                f"failed to delete NetworkPolicy {name!r}",
                failure_reason=_FAILURE_REASON_CLUSTER_APPLY,
            ) from exc

    def _apply_job(self, manifest: Mapping[str, Any]) -> None:
        kube = self._kube()
        client = kube["client"]
        api = client.BatchV1Api()
        name = manifest["metadata"]["name"]
        try:
            api.create_namespaced_job(
                namespace=self._namespace,
                body=dict(manifest),
            )
        except client.exceptions.ApiException as exc:
            raise SandboxClusterError(
                f"failed to create Job {name!r}",
                failure_reason=_FAILURE_REASON_CLUSTER_APPLY,
            ) from exc

    def _wait_for_completion(
        self, job_name: str, deadline_s: float
    ) -> tuple[int | None, bool, str | None, str]:
        """Poll Job status until success / failure / wall-clock deadline.

        Returns ``(exit_code, completed, failure_reason, logs_excerpt)``.

        ``failure_reason`` is always either ``None`` (successful run) or one
        of the closed-taxonomy constants from :data:`FAILURE_REASONS` — raw
        Kubernetes ``conditions[].reason`` strings are normalised through
        :data:`_K8S_REASON_TO_FAILURE` so a malicious / spoofed apiserver
        response can never leak a free-form value into the API surface.
        """
        kube = self._kube()
        client = kube["client"]
        batch_api = client.BatchV1Api()
        core_api = client.CoreV1Api()

        deadline = time.monotonic() + deadline_s + 30.0  # allow grace for polling
        while time.monotonic() < deadline:
            try:
                job = batch_api.read_namespaced_job_status(
                    name=job_name, namespace=self._namespace
                )
            except client.exceptions.ApiException as exc:
                raise SandboxClusterError(
                    f"failed to read Job status {job_name!r}",
                    failure_reason=_FAILURE_REASON_CLUSTER_STATUS,
                ) from exc
            status = getattr(job, "status", None)
            if status is not None:
                if getattr(status, "succeeded", None):
                    logs = self._read_pod_logs(core_api, job_name)
                    return 0, True, None, logs
                if getattr(status, "failed", None):
                    conditions = getattr(status, "conditions", []) or []
                    raw_condition_reason = conditions[-1].reason if conditions else None
                    raw_pod_reason = self._pod_termination_reason(core_api, job_name)
                    failure_reason = self._normalise_failure_reason(
                        raw_pod_reason, raw_condition_reason
                    )
                    logs = self._read_pod_logs(core_api, job_name)
                    return (
                        self._exit_code_from_pod(core_api, job_name),
                        False,
                        failure_reason,
                        logs,
                    )
            time.sleep(_CLUSTER_POLL_INTERVAL_S)

        # Wall-clock timeout — try one last log capture so operators can see
        # what the tool was doing when we gave up.
        logs = self._read_pod_logs(core_api, job_name)
        return None, False, _FAILURE_REASON_CLUSTER_TIMEOUT, logs

    @staticmethod
    def _normalise_failure_reason(*raw_reasons: str | None) -> str:
        """Map raw K8s reasons (most-specific first) into the closed taxonomy.

        ``raw_reasons`` is consumed left-to-right: the first element that is a
        known K8s vocabulary term (per :data:`_K8S_REASON_TO_FAILURE`) wins.
        Pod-side ``container_statuses[].state.terminated.reason`` is more
        specific than Job-side ``conditions[].reason`` (e.g. OOMKilled appears
        only on the pod), so callers SHOULD pass it first.

        Anything not in the map collapses to :data:`_FAILURE_REASON_JOB_FAILED`
        — this is the closed-taxonomy guard that prevents a free-form K8s
        string from reaching :class:`SandboxRunResult.failure_reason`.
        """
        for raw in raw_reasons:
            if raw and raw in _K8S_REASON_TO_FAILURE:
                return _K8S_REASON_TO_FAILURE[raw]
        return _FAILURE_REASON_JOB_FAILED

    def _pod_termination_reason(self, core_api: Any, job_name: str) -> str | None:
        """Best-effort fetch of the failing container's terminated-state reason.

        Returns the raw K8s string (e.g. ``"OOMKilled"``) or ``None`` if no pod
        exists or no container has terminated yet. The caller normalises through
        :meth:`_normalise_failure_reason` — never expose the raw value directly.
        """
        try:
            pods = core_api.list_namespaced_pod(
                namespace=self._namespace,
                label_selector=f"job-name={job_name}",
            )
        except Exception:  # noqa: BLE001 — best-effort, swallow + return None
            return None
        items = getattr(pods, "items", []) or []
        for pod in items:
            statuses = (
                getattr(getattr(pod, "status", None), "container_statuses", []) or []
            )
            for status in statuses:
                terminated = getattr(getattr(status, "state", None), "terminated", None)
                if terminated is not None:
                    reason = getattr(terminated, "reason", None)
                    if reason:
                        return str(reason)
        return None

    def _read_pod_logs(self, core_api: Any, job_name: str) -> str:
        """Fetch the last :data:`_LOG_TAIL_BYTES` bytes of the Job's pod logs."""
        try:
            pods = core_api.list_namespaced_pod(
                namespace=self._namespace,
                label_selector=f"job-name={job_name}",
            )
        except Exception as exc:  # noqa: BLE001 — bound capture for log surfacing
            _logger.warning(
                "sandbox.run.pod_list_failed",
                extra={
                    "job_name": job_name,
                    # MED-2: never ``repr(exc)`` — ApiException repr embeds
                    # HTTP body / headers. Class + HTTP status is enough.
                    "error_class": type(exc).__name__,
                    "status": getattr(exc, "status", None),
                },
            )
            return ""
        items = getattr(pods, "items", []) or []
        if not items:
            return ""
        pod_name = items[0].metadata.name
        try:
            log_text = core_api.read_namespaced_pod_log(
                name=pod_name,
                namespace=self._namespace,
                limit_bytes=_LOG_TAIL_BYTES,
                tail_lines=200,
            )
        except Exception as exc:  # noqa: BLE001
            _logger.warning(
                "sandbox.run.pod_log_read_failed",
                extra={
                    "job_name": job_name,
                    "pod": pod_name,
                    "error_class": type(exc).__name__,
                    "status": getattr(exc, "status", None),
                },
            )
            return ""
        text = str(log_text or "")
        if len(text.encode("utf-8")) > _LOG_TAIL_BYTES:
            return text[-_LOG_TAIL_BYTES:]
        return text

    def _exit_code_from_pod(self, core_api: Any, job_name: str) -> int | None:
        """Best-effort exit code extraction from the failing pod's status."""
        try:
            pods = core_api.list_namespaced_pod(
                namespace=self._namespace,
                label_selector=f"job-name={job_name}",
            )
        except Exception:  # noqa: BLE001
            return None
        items = getattr(pods, "items", []) or []
        for pod in items:
            statuses = (
                getattr(getattr(pod, "status", None), "container_statuses", []) or []
            )
            for status in statuses:
                terminated = getattr(getattr(status, "state", None), "terminated", None)
                if terminated is not None:
                    code = getattr(terminated, "exit_code", None)
                    if code is not None:
                        return int(code)
        return None

    def _collected_artifact_paths(self, tool_job: ToolJob) -> list[str]:
        """Return descriptor-declared artifact paths (as in-pod paths).

        Until the sidecar uploader (out of scope) ships, the adapter cannot
        read the pod's filesystem. We surface the *declared* artifact paths
        so downstream consumers know what to expect under ``/out`` once the
        uploader runs.
        """
        registered = self._registry.get(tool_job.tool_id)
        if registered is None:
            return []
        return list(registered.evidence_artifacts)


__all__ = [
    "FAILURE_REASONS",
    "ApprovalRequiredError",
    "KubernetesSandboxAdapter",
    "SandboxClusterError",
    "SandboxConfigError",
    "SandboxRunMode",
    "SandboxRunResult",
]
