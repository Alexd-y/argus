"""Pure helper functions that build a Kubernetes ``Job`` manifest.

Every helper here is a pure function over the static :class:`ToolDescriptor`
plus the per-run :class:`ToolJob`; they do not touch the cluster, the
filesystem, or any global mutable state. The :class:`KubernetesSandboxAdapter`
composes them when materialising a manifest.

The hard guarantees encoded by these helpers map 1-to-1 onto Backlog/dev1_md
§5 sandbox guardrails:

* Pod-level security context: ``runAsNonRoot=True``, non-zero UID/GID,
  ``seccompProfile=RuntimeDefault``.
* Container-level security context: ``allowPrivilegeEscalation=False``,
  ``readOnlyRootFilesystem=True``, all capabilities dropped, ``privileged``
  always False.
* Volumes: emptyDir for ``/out`` and ``/tmp`` only. **No** hostPath, **no**
  docker.sock, **no** privileged-required mounts.
* Resource limits AND requests populated from the descriptor (k8s rejects
  pods that have only one of the two when LimitRange is enforced).

These are reusable across DRY_RUN and CLUSTER modes; only the rendered dict
shape is shared, never any cluster I/O.
"""

from __future__ import annotations

import re
from typing import Any, Final
from uuid import UUID

from src.pipeline.contracts.tool_job import ToolJob
from src.sandbox.adapter_base import NetworkPolicyRef, ToolDescriptor
from src.sandbox.network_policies import (
    NetworkPolicyTemplate,
    render_networkpolicy_manifest,
)
from src.sandbox.templating import render_argv


# ---------------------------------------------------------------------------
# Constants — non-root user/group used for every sandbox pod.
# ---------------------------------------------------------------------------


# 65532 == "nobody" in distroless / Alpine; conventional pick for non-root
# workloads on every base image we ship.
_NON_ROOT_UID: Final[int] = 65_532
_NON_ROOT_GID: Final[int] = 65_532
_TMP_VOLUME_SIZE: Final[str] = "256Mi"
_OUT_VOLUME_SIZE: Final[str] = "1Gi"

# Public registry prefix used when a descriptor's image is bare ("nmap:7.94"
# without a host). Centralised here so a future task can swap the registry
# without touching every adapter call site.
_DEFAULT_REGISTRY: Final[str] = "ghcr.io/argus"

# K8s memory units (binary IEC + decimal SI). Used by _quantity_to_request.
_MEM_QUANTITY_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?P<value>\d+(?:\.\d+)?)(?P<unit>(?:Ki|Mi|Gi|Ti|Pi|Ei|k|M|G|T|P|E)?)$"
)

# K8s CPU units: "500m", "2", "2.5". Matches integer + millicore + decimal.
_CPU_QUANTITY_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?P<value>\d+(?:\.\d+)?)(?P<suffix>m?)$"
)


# ---------------------------------------------------------------------------
# Security context helpers
# ---------------------------------------------------------------------------


def build_pod_security_context() -> dict[str, Any]:
    """Pod-level securityContext (applies to every container in the pod).

    Returns a dict suitable for ``Job.spec.template.spec.securityContext``.
    Pinned values:

    * ``runAsNonRoot=True`` — kubelet refuses to start the pod if the image's
      first process would run as UID 0.
    * ``runAsUser`` / ``runAsGroup`` / ``fsGroup`` = 65532 (the conventional
      "nobody" UID).
    * ``seccompProfile.type=RuntimeDefault`` — the container runtime's
      default seccomp filter (containerd / CRI-O ship a sane block-list).
    """
    return {
        "runAsNonRoot": True,
        "runAsUser": _NON_ROOT_UID,
        "runAsGroup": _NON_ROOT_GID,
        "fsGroup": _NON_ROOT_GID,
        "seccompProfile": {"type": "RuntimeDefault"},
    }


def build_container_security_context() -> dict[str, Any]:
    """Container-level securityContext (applies to ONE container).

    Pinned values (Backlog/dev1_md §5):

    * ``allowPrivilegeEscalation=False`` — disallow setuid/setgid binaries.
    * ``readOnlyRootFilesystem=True`` — only emptyDir volumes are writable.
    * ``capabilities.drop=["ALL"]`` — strip every Linux capability.
    * ``privileged=False`` — defence-in-depth (PSA already blocks this).
    """
    return {
        "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": True,
        "privileged": False,
        "capabilities": {"drop": ["ALL"]},
    }


# ---------------------------------------------------------------------------
# Resource limits
# ---------------------------------------------------------------------------


def _validate_cpu_quantity(value: str) -> None:
    if not _CPU_QUANTITY_RE.fullmatch(value):
        raise ValueError(
            f"cpu quantity {value!r} is not a valid k8s value "
            "(expected '500m', '1', '2.5')"
        )


def _validate_memory_quantity(value: str) -> None:
    if not _MEM_QUANTITY_RE.fullmatch(value):
        raise ValueError(
            f"memory quantity {value!r} is not a valid k8s value "
            "(expected '256Mi', '1Gi', '512M')"
        )


def build_resource_limits(descriptor: ToolDescriptor) -> dict[str, Any]:
    """Translate descriptor cpu/memory into a Container.resources block.

    Sets ``requests`` equal to ``limits`` (Guaranteed QoS class) — this is the
    safest default for batch sandbox jobs because it prevents the noisy
    neighbour effect on the host node.
    """
    cpu = descriptor.cpu_limit
    mem = descriptor.memory_limit
    _validate_cpu_quantity(cpu)
    _validate_memory_quantity(mem)
    return {
        "limits": {"cpu": cpu, "memory": mem},
        "requests": {"cpu": cpu, "memory": mem},
    }


# ---------------------------------------------------------------------------
# Volumes
# ---------------------------------------------------------------------------


def build_volumes() -> list[dict[str, Any]]:
    """Build the pod-level volume list.

    Two emptyDir volumes:

    * ``argus-out`` mounted at ``/out`` — collects tool artifacts. Has a
      ``sizeLimit`` to bound disk usage on the host node.
    * ``argus-tmp`` mounted at ``/tmp`` — workspace for tools that write
      intermediate files (Java tools, sqlmap, …). Memory-backed so it never
      survives the pod and is fast.

    NO ``hostPath`` volumes are EVER produced here. The ``/in`` mount for
    payloads / wordlists lands in ARG-005 as a CSI volume.
    """
    return [
        {
            "name": "argus-out",
            "emptyDir": {"sizeLimit": _OUT_VOLUME_SIZE},
        },
        {
            "name": "argus-tmp",
            "emptyDir": {"medium": "Memory", "sizeLimit": _TMP_VOLUME_SIZE},
        },
    ]


def build_volume_mounts() -> list[dict[str, Any]]:
    """Build the container-level volumeMounts pairing with :func:`build_volumes`."""
    return [
        {"name": "argus-out", "mountPath": "/out"},
        {"name": "argus-tmp", "mountPath": "/tmp"},
    ]


# ---------------------------------------------------------------------------
# Metadata + labels
# ---------------------------------------------------------------------------


def _short_uuid(value: UUID) -> str:
    """Return the first 8 hex chars of ``value`` — DNS-1123 friendly."""
    return value.hex[:8]


def build_job_metadata(
    tool_job: ToolJob,
    *,
    namespace: str,
    job_name: str,
) -> dict[str, Any]:
    """Build the Job's ``metadata`` block (name, namespace, labels, annotations).

    Labels follow the K8s recommended scheme so kubectl / dashboards group
    sandbox pods correctly. ``argus.io/*`` carry the per-run identifiers
    (used by the NetworkPolicy ``podSelector`` and by metrics labels).
    """
    return {
        "name": job_name,
        "namespace": namespace,
        "labels": {
            "app.kubernetes.io/name": "argus-sandbox",
            "app.kubernetes.io/component": "tool-runner",
            "app.kubernetes.io/managed-by": "argus-control-plane",
            "argus.io/tool-id": tool_job.tool_id,
            "argus.io/scan-id": str(tool_job.scan_id),
            "argus.io/tenant-id": str(tool_job.tenant_id),
            "argus.io/job-id": _short_uuid(tool_job.id),
            "argus.io/phase": tool_job.phase.value,
            "argus.io/risk-level": tool_job.risk_level.value,
        },
        "annotations": {
            "argus.io/correlation-id": tool_job.correlation_id,
            "argus.io/created-at": tool_job.created_at.isoformat(),
            "argus.io/job-uuid": str(tool_job.id),
        },
    }


def build_pod_labels(tool_job: ToolJob) -> dict[str, str]:
    """Per-pod labels used as the NetworkPolicy ``podSelector`` target.

    Returns the SAME labels as :func:`build_job_metadata` — they propagate
    onto the Pod via ``Job.spec.template.metadata.labels`` so the
    NetworkPolicy can match them.
    """
    return {
        "app.kubernetes.io/name": "argus-sandbox",
        "argus.io/tool-id": tool_job.tool_id,
        "argus.io/scan-id": str(tool_job.scan_id),
        "argus.io/job-id": _short_uuid(tool_job.id),
    }


# ---------------------------------------------------------------------------
# Image + argv
# ---------------------------------------------------------------------------


def resolve_image(descriptor: ToolDescriptor) -> str:
    """Return the fully-qualified image reference for ``descriptor``.

    If the descriptor's image already contains a registry host (``host/path``),
    it is returned verbatim. Bare references (``nmap:7.94``) get prefixed with
    :data:`_DEFAULT_REGISTRY`.
    """
    image = descriptor.image
    if "/" in image and (
        "." in image.split("/", 1)[0] or ":" in image.split("/", 1)[0]
    ):
        # Looks like "registry.example.com/path:tag" — use as-is.
        return image
    if "/" in image:
        # "argus/nmap:7.94" — registry-relative path, prepend default registry host.
        return f"{_DEFAULT_REGISTRY.rsplit('/', 1)[0]}/{image}"
    # Plain "nmap:7.94".
    return f"{_DEFAULT_REGISTRY}/{image}"


def build_argv(descriptor: ToolDescriptor, tool_job: ToolJob) -> list[str]:
    """Materialise the descriptor's command_template against ``tool_job.parameters``.

    Thin wrapper around :func:`src.sandbox.templating.render_argv` — kept
    here so the manifest builder has a single, well-named call site (and so
    a future task can post-process the argv, e.g. to inject ``--output-dir``).
    """
    return render_argv(list(descriptor.command_template), tool_job.parameters)


# ---------------------------------------------------------------------------
# Public utility
# ---------------------------------------------------------------------------


def build_job_name(tool_job: ToolJob) -> str:
    """Return a deterministic, DNS-1123-compliant Job name for ``tool_job``.

    Format: ``argus-{tool_id}-{short-uuid}``. K8s names are limited to 63
    chars; tool_id is constrained to <=64 by ToolDescriptor's regex but the
    leading prefix + short UUID keeps the total bounded.
    """
    short = _short_uuid(tool_job.id)
    base = f"argus-{tool_job.tool_id.replace('_', '-')}-{short}"
    if len(base) > 63:
        # Trim the tool_id portion, keep the suffix intact for traceability.
        max_tool = 63 - len("argus-") - len(short) - 1  # one dash separator
        truncated = tool_job.tool_id.replace("_", "-")[:max_tool]
        base = f"argus-{truncated}-{short}"
    return base


# ---------------------------------------------------------------------------
# NetworkPolicy manifest builder (ARG-027)
# ---------------------------------------------------------------------------


def build_networkpolicy_for_job(
    network_policy: NetworkPolicyRef,
    template: NetworkPolicyTemplate,
    *,
    namespace: str,
    pod_label_selector: dict[str, str],
    target_cidr: str | None = None,
    name_suffix: str | None = None,
) -> dict[str, Any]:
    """Render a per-job NetworkPolicy manifest, applying any tool overrides.

    Bridge between the descriptor surface (``NetworkPolicyRef`` carries the
    template name + per-tool ``dns_resolvers`` / ``egress_allowlist``
    overrides parsed from the YAML) and the pure renderer in
    :mod:`src.sandbox.network_policies` (which validates + applies the
    overrides). Centralising this wiring here means future call sites
    (CLI, audit tooling, ARG-027 integration tests) get the same
    validation guarantees as the live :class:`KubernetesSandboxAdapter`.

    The ``NetworkPolicyRef.name`` field MUST already match
    ``template.name``; the assertion below catches any mis-routed
    template lookup at render time.
    """
    if network_policy.name != template.name:
        raise ValueError(
            f"NetworkPolicyRef.name={network_policy.name!r} does not match "
            f"template.name={template.name!r} — refusing to render a "
            "policy under a mismatched template (defence in depth against "
            "template-resolution bugs upstream)."
        )
    return render_networkpolicy_manifest(
        template,
        namespace=namespace,
        pod_label_selector=pod_label_selector,
        target_cidr=target_cidr,
        name_suffix=name_suffix,
        dns_resolvers_override=network_policy.dns_resolvers,
        egress_allowlist_override=network_policy.egress_allowlist,
    )


__all__ = [
    "build_argv",
    "build_container_security_context",
    "build_job_metadata",
    "build_job_name",
    "build_networkpolicy_for_job",
    "build_pod_labels",
    "build_pod_security_context",
    "build_resource_limits",
    "build_volume_mounts",
    "build_volumes",
    "resolve_image",
]
