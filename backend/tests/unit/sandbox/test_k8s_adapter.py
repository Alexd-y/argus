"""Unit tests for :class:`src.sandbox.k8s_adapter.KubernetesSandboxAdapter`.

DRY_RUN mode is exercised end-to-end (no Kubernetes SDK required).
CLUSTER mode is exercised only at the *configuration* surface: the SDK is
asserted to load lazily (failure modes wrapped in ``SandboxClusterError``).

Backlog/dev1_md §5/§18 invariants are pinned via a deliberate "scan for
forbidden tokens" check on the rendered YAML.
"""

from __future__ import annotations

import ast
import asyncio
import copy
import importlib
import json
import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch
from uuid import UUID, uuid4

import pytest
import yaml

from src.pipeline.contracts.phase_io import ScanPhase
from src.pipeline.contracts.tool_job import RiskLevel, TargetKind, TargetSpec, ToolJob
from src.sandbox.adapter_base import (
    NetworkPolicyRef,
    ParseStrategy,
    ToolCategory,
    ToolDescriptor,
)
from src.sandbox.k8s_adapter import (
    ApprovalRequiredError,
    KubernetesSandboxAdapter,
    SandboxConfigError,
    SandboxRunMode,
    SandboxRunResult,
)


# ---------------------------------------------------------------------------
# Fake registry — no need to load real YAMLs for unit tests.
# ---------------------------------------------------------------------------


class _FakeRegistry:
    """Minimal in-memory registry stub used only in this test module."""

    def __init__(self, descriptors: list[ToolDescriptor]) -> None:
        self._by_id: dict[str, ToolDescriptor] = {d.tool_id: d for d in descriptors}

    def get(self, tool_id: str) -> ToolDescriptor | None:
        return self._by_id.get(tool_id)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def passive_descriptor() -> ToolDescriptor:
    return ToolDescriptor(
        tool_id="crt_sh",
        category=ToolCategory.RECON,
        phase=ScanPhase.RECON,
        risk_level=RiskLevel.PASSIVE,
        requires_approval=False,
        network_policy=NetworkPolicyRef(
            name="recon-passive",
            egress_allowlist=["0.0.0.0/0"],
            dns_resolvers=["1.1.1.1"],
        ),
        seccomp_profile="profiles/recon-default.json",
        default_timeout_s=120,
        cpu_limit="500m",
        memory_limit="256Mi",
        pids_limit=256,
        image="argus/crt_sh:1.0",
        command_template=["crt_sh", "{domain}"],
        parse_strategy=ParseStrategy.JSON_LINES,
        evidence_artifacts=["crt.json"],
        cwe_hints=[],
        owasp_wstg=[],
    )


@pytest.fixture()
def active_descriptor() -> ToolDescriptor:
    return ToolDescriptor(
        tool_id="nmap_tcp_top",
        category=ToolCategory.RECON,
        phase=ScanPhase.RECON,
        risk_level=RiskLevel.LOW,
        requires_approval=False,
        network_policy=NetworkPolicyRef(
            name="recon-active-tcp",
            egress_allowlist=[],
            dns_resolvers=["1.1.1.1"],
        ),
        seccomp_profile="profiles/recon-active.json",
        default_timeout_s=600,
        cpu_limit="1",
        memory_limit="512Mi",
        pids_limit=512,
        image="argus/nmap:7.94",
        command_template=["nmap", "-Pn", "{ip}", "-oX", "{out_dir}/nmap.xml"],
        parse_strategy=ParseStrategy.XML_NMAP,
        evidence_artifacts=["nmap.xml"],
        cwe_hints=[200],
        owasp_wstg=["WSTG-INFO-02"],
    )


@pytest.fixture()
def passive_job() -> ToolJob:
    return ToolJob(
        id=UUID("00000000-0000-0000-0000-000000000010"),
        tenant_id=uuid4(),
        scan_id=UUID("11111111-2222-3333-4444-555555555555"),
        tool_id="crt_sh",
        phase=ScanPhase.RECON,
        risk_level=RiskLevel.PASSIVE,
        target=TargetSpec(kind=TargetKind.DOMAIN, domain="example.com"),
        parameters={"domain": "example.com"},
        outputs_dir="/out",
        timeout_s=60,
        correlation_id="argus-test-1",
    )


@pytest.fixture()
def active_job() -> ToolJob:
    return ToolJob(
        id=UUID("00000000-0000-0000-0000-000000000020"),
        tenant_id=uuid4(),
        scan_id=UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
        tool_id="nmap_tcp_top",
        phase=ScanPhase.RECON,
        risk_level=RiskLevel.LOW,
        target=TargetSpec(kind=TargetKind.IP, ip="10.0.0.5"),
        parameters={"ip": "10.0.0.5", "out_dir": "/out/nmap"},
        outputs_dir="/out",
        timeout_s=120,
        correlation_id="argus-test-2",
    )


@pytest.fixture()
def adapter(
    tmp_path: Path,
    passive_descriptor: ToolDescriptor,
    active_descriptor: ToolDescriptor,
) -> KubernetesSandboxAdapter:
    registry = _FakeRegistry([passive_descriptor, active_descriptor])
    return KubernetesSandboxAdapter(
        registry,  # type: ignore[arg-type]
        mode=SandboxRunMode.DRY_RUN,
        dry_run_artifact_dir=tmp_path / "dryrun",
    )


# ---------------------------------------------------------------------------
# Constructor validation
# ---------------------------------------------------------------------------


def test_dry_run_requires_artifact_dir(passive_descriptor: ToolDescriptor) -> None:
    registry = _FakeRegistry([passive_descriptor])
    with pytest.raises(SandboxConfigError, match="dry_run_artifact_dir"):
        KubernetesSandboxAdapter(
            registry,
            mode=SandboxRunMode.DRY_RUN,
            dry_run_artifact_dir=None,  # type: ignore[arg-type]
        )


def test_invalid_default_pod_timeout_raises(
    tmp_path: Path, passive_descriptor: ToolDescriptor
) -> None:
    registry = _FakeRegistry([passive_descriptor])
    with pytest.raises(SandboxConfigError, match="default_pod_timeout_s"):
        KubernetesSandboxAdapter(
            registry,  # type: ignore[arg-type]
            mode=SandboxRunMode.DRY_RUN,
            dry_run_artifact_dir=tmp_path,
            default_pod_timeout_s=0,
        )


def test_empty_namespace_rejected(
    tmp_path: Path, passive_descriptor: ToolDescriptor
) -> None:
    registry = _FakeRegistry([passive_descriptor])
    with pytest.raises(SandboxConfigError, match="namespace"):
        KubernetesSandboxAdapter(
            registry,  # type: ignore[arg-type]
            mode=SandboxRunMode.DRY_RUN,
            dry_run_artifact_dir=tmp_path,
            namespace="",
        )


# ---------------------------------------------------------------------------
# Pair validation
# ---------------------------------------------------------------------------


def test_mismatched_tool_id_raises(
    adapter: KubernetesSandboxAdapter,
    active_descriptor: ToolDescriptor,
    passive_job: ToolJob,
) -> None:
    with pytest.raises(SandboxConfigError, match="mismatches"):
        adapter.build_job_manifest(passive_job, active_descriptor)


def test_unknown_network_policy_raises(
    tmp_path: Path,
    passive_descriptor: ToolDescriptor,
    passive_job: ToolJob,
) -> None:
    bogus = passive_descriptor.model_copy(
        update={"network_policy": NetworkPolicyRef(name="not-a-real-template")}
    )
    registry = _FakeRegistry([bogus])
    bad_adapter = KubernetesSandboxAdapter(
        registry,  # type: ignore[arg-type]
        mode=SandboxRunMode.DRY_RUN,
        dry_run_artifact_dir=tmp_path,
    )
    with pytest.raises(SandboxConfigError, match="not registered"):
        bad_adapter.build_networkpolicy_manifest(passive_job, bogus)


def test_approval_required_without_approval_raises(
    tmp_path: Path,
    active_descriptor: ToolDescriptor,
) -> None:
    descriptor = active_descriptor.model_copy(update={"requires_approval": True})
    registry = _FakeRegistry([descriptor])
    bad_adapter = KubernetesSandboxAdapter(
        registry,  # type: ignore[arg-type]
        mode=SandboxRunMode.DRY_RUN,
        dry_run_artifact_dir=tmp_path,
    )
    job_no_approval = ToolJob(
        id=uuid4(),
        tenant_id=uuid4(),
        scan_id=uuid4(),
        tool_id="nmap_tcp_top",
        phase=ScanPhase.RECON,
        risk_level=RiskLevel.LOW,
        target=TargetSpec(kind=TargetKind.IP, ip="10.0.0.5"),
        parameters={"ip": "10.0.0.5", "out_dir": "/out/nmap"},
        outputs_dir="/out",
        timeout_s=60,
        correlation_id="x",
        requires_approval=False,
        approval_id=None,
    )
    with pytest.raises(ApprovalRequiredError):
        bad_adapter.build_job_manifest(job_no_approval, descriptor)


# ---------------------------------------------------------------------------
# Job manifest invariants
# ---------------------------------------------------------------------------


def test_built_job_manifest_has_security_context(
    adapter: KubernetesSandboxAdapter,
    passive_descriptor: ToolDescriptor,
    passive_job: ToolJob,
) -> None:
    manifest = adapter.build_job_manifest(passive_job, passive_descriptor)
    pod_spec = manifest["spec"]["template"]["spec"]
    assert pod_spec["restartPolicy"] == "Never"
    assert pod_spec["automountServiceAccountToken"] is False
    sec_ctx = pod_spec["securityContext"]
    assert sec_ctx["runAsNonRoot"] is True
    assert sec_ctx["seccompProfile"]["type"] == "RuntimeDefault"


def test_built_job_manifest_container_security_locked_down(
    adapter: KubernetesSandboxAdapter,
    passive_descriptor: ToolDescriptor,
    passive_job: ToolJob,
) -> None:
    manifest = adapter.build_job_manifest(passive_job, passive_descriptor)
    container = manifest["spec"]["template"]["spec"]["containers"][0]
    sec = container["securityContext"]
    assert sec["allowPrivilegeEscalation"] is False
    assert sec["readOnlyRootFilesystem"] is True
    assert sec["privileged"] is False
    assert sec["capabilities"]["drop"] == ["ALL"]


def test_built_job_manifest_no_dangerous_volumes(
    adapter: KubernetesSandboxAdapter,
    passive_descriptor: ToolDescriptor,
    passive_job: ToolJob,
) -> None:
    manifest = adapter.build_job_manifest(passive_job, passive_descriptor)
    serialised = repr(manifest).lower()
    assert "hostpath" not in serialised
    assert "docker.sock" not in serialised


def test_built_job_manifest_uses_active_deadline_seconds(
    adapter: KubernetesSandboxAdapter,
    passive_descriptor: ToolDescriptor,
    passive_job: ToolJob,
) -> None:
    manifest = adapter.build_job_manifest(passive_job, passive_descriptor)
    spec = manifest["spec"]
    assert spec["backoffLimit"] == 0
    assert spec["activeDeadlineSeconds"] == passive_descriptor.default_timeout_s
    assert spec["ttlSecondsAfterFinished"] > 0


def test_built_job_manifest_carries_argv_in_command(
    adapter: KubernetesSandboxAdapter,
    passive_descriptor: ToolDescriptor,
    passive_job: ToolJob,
) -> None:
    manifest = adapter.build_job_manifest(passive_job, passive_descriptor)
    container = manifest["spec"]["template"]["spec"]["containers"][0]
    assert container["command"] == ["crt_sh", "example.com"]
    # No args field should ever embed shell metacharacters.
    for arg in container["command"]:
        for bad in (";", "|", "&", "$(", "`", "rm -rf"):
            assert bad not in arg


def test_built_job_manifest_overrides_long_descriptor_timeout(
    tmp_path: Path,
    passive_descriptor: ToolDescriptor,
    passive_job: ToolJob,
) -> None:
    """default_pod_timeout_s caps even longer descriptor timeouts."""
    descriptor = passive_descriptor.model_copy(update={"default_timeout_s": 9_999})
    registry = _FakeRegistry([descriptor])
    capped = KubernetesSandboxAdapter(
        registry,  # type: ignore[arg-type]
        mode=SandboxRunMode.DRY_RUN,
        dry_run_artifact_dir=tmp_path,
        default_pod_timeout_s=300,
    )
    manifest = capped.build_job_manifest(passive_job, descriptor)
    assert manifest["spec"]["activeDeadlineSeconds"] == 300


# ---------------------------------------------------------------------------
# NetworkPolicy manifest
# ---------------------------------------------------------------------------


def test_networkpolicy_manifest_has_ingress_blocked(
    adapter: KubernetesSandboxAdapter,
    passive_descriptor: ToolDescriptor,
    passive_job: ToolJob,
) -> None:
    np = adapter.build_networkpolicy_manifest(passive_job, passive_descriptor)
    assert np["spec"]["ingress"] == []
    assert "Ingress" in np["spec"]["policyTypes"]
    assert "Egress" in np["spec"]["policyTypes"]


def test_networkpolicy_dynamic_target_uses_job_target_cidr(
    adapter: KubernetesSandboxAdapter,
    active_descriptor: ToolDescriptor,
    active_job: ToolJob,
) -> None:
    np = adapter.build_networkpolicy_manifest(active_job, active_descriptor)
    payload_rule = np["spec"]["egress"][0]
    assert payload_rule["to"] == [{"ipBlock": {"cidr": "10.0.0.5/32"}}]


def test_networkpolicy_unique_name_per_job(
    adapter: KubernetesSandboxAdapter,
    passive_descriptor: ToolDescriptor,
    passive_job: ToolJob,
) -> None:
    np = adapter.build_networkpolicy_manifest(passive_job, passive_descriptor)
    short = passive_job.id.hex[:8]
    assert np["metadata"]["name"].endswith(short)


# ---------------------------------------------------------------------------
# DRY_RUN end-to-end
# ---------------------------------------------------------------------------


def test_dry_run_writes_manifest_and_argv(
    adapter: KubernetesSandboxAdapter,
    passive_descriptor: ToolDescriptor,
    passive_job: ToolJob,
    tmp_path: Path,
) -> None:
    result: SandboxRunResult = asyncio.run(adapter.run(passive_job, passive_descriptor))
    assert result.completed is False
    assert result.failure_reason == "dry_run"
    assert result.exit_code is None
    assert result.manifest_yaml.strip().startswith("apiVersion:")

    scan_dir = tmp_path / "dryrun" / str(passive_job.scan_id)
    short = passive_job.id.hex[:8]
    yaml_path = scan_dir / f"{short}.yaml"
    argv_path = scan_dir / f"{short}.argv.json"
    assert yaml_path.is_file()
    assert argv_path.is_file()

    docs = list(yaml.safe_load_all(yaml_path.read_text("utf-8")))
    kinds = sorted(doc["kind"] for doc in docs)
    assert kinds == ["Job", "NetworkPolicy"]

    argv_payload = json.loads(argv_path.read_text("utf-8"))
    assert argv_payload["argv"] == ["crt_sh", "example.com"]
    assert argv_payload["tool_id"] == "crt_sh"


def test_dry_run_yaml_passes_security_invariant_scan(
    adapter: KubernetesSandboxAdapter,
    active_descriptor: ToolDescriptor,
    active_job: ToolJob,
) -> None:
    result = asyncio.run(adapter.run(active_job, active_descriptor))
    text = result.manifest_yaml.lower()
    for forbidden in (
        "hostpath",
        "docker.sock",
        "privileged: true",
        "shell: true",
        "shell=true",
    ):
        assert forbidden not in text, f"{forbidden!r} leaked into manifest"
    # Required pinned values still present:
    assert "runasnonroot: true" in text
    assert "readonlyrootfilesystem: true" in text
    assert "runtimedefault" in text


def test_dry_run_manifest_contains_argv_substituted(
    adapter: KubernetesSandboxAdapter,
    active_descriptor: ToolDescriptor,
    active_job: ToolJob,
) -> None:
    result = asyncio.run(adapter.run(active_job, active_descriptor))
    assert "10.0.0.5" in result.manifest_yaml
    assert "/out/nmap" in result.manifest_yaml
    # No shell metas leaked through:
    for bad in (";", "&&", "|", "`", "$("):
        assert (
            bad not in "".join(active_job.parameters.values())
            or bad not in result.manifest_yaml
        )


# ---------------------------------------------------------------------------
# CLUSTER mode — lazy import path
# ---------------------------------------------------------------------------


def test_cluster_mode_does_not_import_kubernetes_until_run(
    tmp_path: Path,
    passive_descriptor: ToolDescriptor,
) -> None:
    """Constructing a CLUSTER-mode adapter must NOT import kubernetes."""
    registry = _FakeRegistry([passive_descriptor])
    sys.modules.pop("kubernetes", None)
    sys.modules.pop("kubernetes.client", None)
    KubernetesSandboxAdapter(
        registry,  # type: ignore[arg-type]
        mode=SandboxRunMode.CLUSTER,
        namespace="argus-sandbox",
        dry_run_artifact_dir=tmp_path,
    )
    assert "kubernetes" not in sys.modules
    assert "kubernetes.client" not in sys.modules


def test_cluster_mode_run_raises_clean_error_when_sdk_missing(
    tmp_path: Path,
    passive_descriptor: ToolDescriptor,
    passive_job: ToolJob,
) -> None:
    """If the kubernetes SDK is unavailable, CLUSTER mode wraps it cleanly."""
    registry = _FakeRegistry([passive_descriptor])
    cluster_adapter = KubernetesSandboxAdapter(
        registry,  # type: ignore[arg-type]
        mode=SandboxRunMode.CLUSTER,
        namespace="argus-sandbox",
        dry_run_artifact_dir=tmp_path,
    )

    real_import_module = importlib.import_module

    def _fail_kubernetes(name: str, *args: Any, **kwargs: Any) -> Any:
        if name.startswith("kubernetes"):
            raise ImportError(f"forced failure for {name!r}")
        return real_import_module(name, *args, **kwargs)

    with patch(
        "src.sandbox.k8s_adapter.importlib.import_module", side_effect=_fail_kubernetes
    ):
        result = asyncio.run(cluster_adapter.run(passive_job, passive_descriptor))
    assert result.completed is False
    # MED-2: closed taxonomy — SDK-missing collapses to cluster_apply_failed.
    # The verbose install hint stays in the chained SandboxClusterError /
    # structured logs and never reaches the user-facing field.
    assert result.failure_reason == "cluster_apply_failed"


# ---------------------------------------------------------------------------
# Anti-shell-injection static check
# ---------------------------------------------------------------------------


def _module_source(module_relpath: str) -> str:
    """Read a module's source from disk, resolved against ``src/sandbox`` regardless of cwd."""
    import src.sandbox as _sandbox_pkg

    pkg_dir = Path(_sandbox_pkg.__file__).resolve().parent
    return (pkg_dir / module_relpath).read_text(encoding="utf-8")


def test_module_source_does_not_use_shell_subprocess() -> None:
    """The adapter source must never call ``subprocess`` or ``shell=True``."""
    source = _module_source("k8s_adapter.py")

    # Hard tokens — these can never appear in code OR docstrings without raising
    # eyebrows during a security review. ``import`` lines are unambiguous.
    assert "import subprocess" not in source
    assert "from subprocess" not in source

    # For ``os.system`` / ``shell=True`` we must ignore docstrings & comments —
    # the module docstring legitimately *describes* what the module does NOT do.
    code_only = ast.unparse(_strip_docstrings(ast.parse(source)))
    assert "os.system(" not in code_only
    assert "shell=True" not in code_only


def _strip_docstrings(tree: ast.AST) -> ast.AST:
    """Return a copy of ``tree`` with leading-string docstrings removed."""
    stripped = copy.deepcopy(tree)
    for node in ast.walk(stripped):
        if isinstance(
            node,
            (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
        ):
            body = getattr(node, "body", None)
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                if len(body) == 1:
                    body[0] = ast.Pass()
                else:
                    body.pop(0)
    return stripped


def test_module_source_does_not_mount_docker_sock_or_hostpath() -> None:
    source = _module_source("manifest.py")
    # ``docker.sock`` and ``hostPath`` are only referenced from comments / guards.
    # They MUST NOT appear inside any returned dict literal.
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if '"hostPath"' in stripped or '"docker.sock"' in stripped:
            pytest.fail(f"manifest.py contains a forbidden literal: {stripped!r}")
