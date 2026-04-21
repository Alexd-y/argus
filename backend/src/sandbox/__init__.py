"""ARGUS sandbox package — typed contracts and helpers for the execution-plane.

Modules
-------
* :mod:`src.sandbox.signing`          — Ed25519 key management + ``SIGNATURES`` file model.
* :mod:`src.sandbox.templating`       — allow-listed, shell-safe command-template renderer.
* :mod:`src.sandbox.adapter_base`     — :class:`ToolAdapter` ``Protocol`` + :class:`ShellToolAdapter`
  base + value objects (``NetworkPolicyRef``, ``ResourceLimits``, ``ToolDescriptor``).
* :mod:`src.sandbox.tool_registry`    — discovers, signature-verifies, and indexes
  ``backend/config/tools/*.yaml`` descriptors at startup (fail-closed).
* :mod:`src.sandbox.network_policies` — strict NetworkPolicy templates (default-deny + per-tool egress).
* :mod:`src.sandbox.manifest`         — pure helpers that build the K8s ``Job`` manifest
  pieces (security context, volumes, resources, argv) without touching the cluster.
* :mod:`src.sandbox.k8s_adapter`      — :class:`KubernetesSandboxAdapter` (DRY_RUN / CLUSTER).
* :mod:`src.sandbox.runner`           — multi-job dispatch wrapper with bounded parallelism.

Imports follow the project convention ``from src.X import Y``; see
``backend/conftest.py`` and ``backend/pyproject.toml`` for the path layout.

The whole package is an *execution-plane* contract: nothing here imports
``src.db`` / FastAPI / Celery, so it is safe to use from CLIs, isolated
sandbox runners, and unit tests without dragging in the application stack.

The Kubernetes Python SDK (``kubernetes>=29``) is imported lazily *only* by
:mod:`src.sandbox.k8s_adapter` when running in CLUSTER mode, so DRY_RUN code
paths and unit tests stay free of cluster-side dependencies.
"""

from src.sandbox.adapter_base import (
    AdapterExecutionError,
    AdapterRegistrationError,
    NetworkPolicyRef,
    ParseStrategy,
    ResourceLimits,
    ShellToolAdapter,
    ToolAdapter,
    ToolCategory,
    ToolDescriptor,
)
from src.sandbox.k8s_adapter import (
    ApprovalRequiredError,
    KubernetesSandboxAdapter,
    SandboxClusterError,
    SandboxConfigError,
    SandboxRunMode,
    SandboxRunResult,
)
from src.sandbox.manifest import (
    build_argv,
    build_container_security_context,
    build_job_metadata,
    build_job_name,
    build_networkpolicy_for_job,
    build_pod_labels,
    build_pod_security_context,
    build_resource_limits,
    build_volume_mounts,
    build_volumes,
    resolve_image,
)
from src.sandbox.network_policies import (
    NETWORK_POLICY_NAMES,
    NetworkPolicyTemplate,
    get_template,
    list_templates,
    render_networkpolicy_manifest,
)
from src.sandbox.runner import SandboxRunner, dispatch_jobs
from src.sandbox.signing import (
    IntegrityError,
    KeyManager,
    KeyNotFoundError,
    SignatureError,
    SignaturesFile,
    SignatureRecord,
    compute_yaml_hash,
    sign_blob,
    verify_blob,
)
from src.sandbox.templating import (
    ALLOWED_PLACEHOLDERS,
    TemplateRenderError,
    extract_placeholders,
    render,
    render_argv,
    validate_template,
)
from src.sandbox.tool_registry import (
    RegistryLoadError,
    RegistrySummary,
    ToolRegistry,
)

__all__ = [
    "ALLOWED_PLACEHOLDERS",
    "AdapterExecutionError",
    "AdapterRegistrationError",
    "ApprovalRequiredError",
    "IntegrityError",
    "KeyManager",
    "KeyNotFoundError",
    "KubernetesSandboxAdapter",
    "NETWORK_POLICY_NAMES",
    "NetworkPolicyRef",
    "NetworkPolicyTemplate",
    "ParseStrategy",
    "RegistryLoadError",
    "RegistrySummary",
    "ResourceLimits",
    "SandboxClusterError",
    "SandboxConfigError",
    "SandboxRunMode",
    "SandboxRunResult",
    "SandboxRunner",
    "ShellToolAdapter",
    "SignatureError",
    "SignatureRecord",
    "SignaturesFile",
    "TemplateRenderError",
    "ToolAdapter",
    "ToolCategory",
    "ToolDescriptor",
    "ToolRegistry",
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
    "compute_yaml_hash",
    "dispatch_jobs",
    "extract_placeholders",
    "get_template",
    "list_templates",
    "render",
    "render_argv",
    "render_networkpolicy_manifest",
    "resolve_image",
    "sign_blob",
    "validate_template",
    "verify_blob",
]
