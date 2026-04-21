"""Unit tests for :mod:`src.sandbox.manifest`.

The manifest module is a set of pure helpers that compose the K8s ``Job``
manifest. Tests pin down every Backlog/dev1_md §5 invariant:

* runAsNonRoot=True, non-zero UID/GID, RuntimeDefault seccomp.
* allowPrivilegeEscalation=False, readOnlyRootFilesystem=True, drop ALL caps.
* Resource limits AND requests populated from the descriptor.
* No hostPath, no docker.sock anywhere.
* DNS-1123-compliant Job names with deterministic suffixes.
"""

from __future__ import annotations

import re
from typing import Any
from uuid import UUID, uuid4

import pytest

from src.pipeline.contracts.phase_io import ScanPhase
from src.pipeline.contracts.tool_job import RiskLevel, TargetKind, TargetSpec, ToolJob
from src.sandbox.adapter_base import (
    NetworkPolicyRef,
    ParseStrategy,
    ToolCategory,
    ToolDescriptor,
)
from src.sandbox.manifest import (
    build_argv,
    build_container_security_context,
    build_job_metadata,
    build_job_name,
    build_pod_labels,
    build_pod_security_context,
    build_resource_limits,
    build_volume_mounts,
    build_volumes,
    resolve_image,
)


_DNS_1123_LABEL = re.compile(r"^[a-z0-9][a-z0-9\-]{0,61}[a-z0-9]$|^[a-z0-9]$")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def descriptor() -> ToolDescriptor:
    return ToolDescriptor(
        tool_id="nmap_quick",
        category=ToolCategory.RECON,
        phase=ScanPhase.RECON,
        risk_level=RiskLevel.PASSIVE,
        requires_approval=False,
        network_policy=NetworkPolicyRef(
            name="recon-active-tcp",
            egress_allowlist=[],
            dns_resolvers=["1.1.1.1"],
        ),
        seccomp_profile="profiles/recon-default.json",
        default_timeout_s=300,
        cpu_limit="500m",
        memory_limit="256Mi",
        pids_limit=256,
        image="argus/nmap:7.94",
        command_template=["nmap", "-Pn", "-T4", "{host}", "-oX", "{out_dir}/nmap.xml"],
        parse_strategy=ParseStrategy.XML_NMAP,
        evidence_artifacts=["nmap.xml"],
        cwe_hints=[200],
        owasp_wstg=["WSTG-INFO-02"],
    )


@pytest.fixture()
def tool_job() -> ToolJob:
    return ToolJob(
        id=UUID("00000000-0000-0000-0000-000000000001"),
        tenant_id=uuid4(),
        scan_id=UUID("11111111-1111-1111-1111-111111111111"),
        tool_id="nmap_quick",
        phase=ScanPhase.RECON,
        risk_level=RiskLevel.PASSIVE,
        target=TargetSpec(kind=TargetKind.HOST, host="scanme.nmap.org"),
        parameters={"host": "scanme.nmap.org", "out_dir": "/out/job"},
        outputs_dir="/out",
        timeout_s=120,
        correlation_id="argus-test-correlation",
    )


# ---------------------------------------------------------------------------
# Pod security context (Backlog §5)
# ---------------------------------------------------------------------------


def test_pod_security_context_runs_as_non_root_with_seccomp() -> None:
    ctx = build_pod_security_context()
    assert ctx["runAsNonRoot"] is True
    assert ctx["runAsUser"] != 0
    assert ctx["runAsGroup"] != 0
    assert ctx["fsGroup"] != 0
    assert ctx["seccompProfile"]["type"] == "RuntimeDefault"


def test_pod_security_context_uses_consistent_uid_gid() -> None:
    ctx = build_pod_security_context()
    assert ctx["runAsUser"] == ctx["runAsGroup"] == ctx["fsGroup"] == 65_532


# ---------------------------------------------------------------------------
# Container security context (Backlog §5)
# ---------------------------------------------------------------------------


def test_container_security_context_disables_privilege_escalation() -> None:
    ctx = build_container_security_context()
    assert ctx["allowPrivilegeEscalation"] is False
    assert ctx["readOnlyRootFilesystem"] is True
    assert ctx["privileged"] is False
    assert ctx["capabilities"]["drop"] == ["ALL"]


def test_container_security_context_does_not_expose_extra_caps() -> None:
    """Ensure no ``add`` field accidentally restores capabilities."""
    ctx = build_container_security_context()
    caps = ctx.get("capabilities", {})
    assert "add" not in caps
    assert caps == {"drop": ["ALL"]}


# ---------------------------------------------------------------------------
# Resource limits
# ---------------------------------------------------------------------------


def test_resource_limits_match_descriptor(descriptor: ToolDescriptor) -> None:
    res = build_resource_limits(descriptor)
    assert res["limits"] == {"cpu": "500m", "memory": "256Mi"}
    assert res["requests"] == res["limits"]  # Guaranteed QoS


@pytest.mark.parametrize(
    ("cpu", "mem"),
    [
        ("not-a-cpu", "256Mi"),
        ("500m", "not-a-mem"),
        ("500x", "256Mi"),
        ("500m", "256Q"),
    ],
)
def test_invalid_resource_quantities_raise(
    cpu: str, mem: str, descriptor: ToolDescriptor
) -> None:
    bad = descriptor.model_copy(update={"cpu_limit": cpu, "memory_limit": mem})
    with pytest.raises(ValueError):
        build_resource_limits(bad)


# ---------------------------------------------------------------------------
# Volumes (no hostPath, no docker.sock)
# ---------------------------------------------------------------------------


def test_volumes_only_emptyDir() -> None:
    volumes = build_volumes()
    assert len(volumes) == 2
    for vol in volumes:
        assert "emptyDir" in vol
        assert "hostPath" not in vol


def test_volume_mounts_match_volumes() -> None:
    mounts = build_volume_mounts()
    paths = [m["mountPath"] for m in mounts]
    assert paths == ["/out", "/tmp"]


def test_no_docker_sock_in_mount_paths() -> None:
    mounts = build_volume_mounts()
    for mount in mounts:
        assert "docker.sock" not in mount["mountPath"]


def test_tmp_volume_uses_memory_backing() -> None:
    """``/tmp`` should be tmpfs so secrets / scratch never hit disk."""
    volumes = build_volumes()
    tmp = next(v for v in volumes if v["name"] == "argus-tmp")
    assert tmp["emptyDir"].get("medium") == "Memory"


# ---------------------------------------------------------------------------
# Metadata + labels
# ---------------------------------------------------------------------------


def test_job_metadata_carries_tool_scan_tenant_labels(
    descriptor: ToolDescriptor, tool_job: ToolJob
) -> None:
    del descriptor
    meta = build_job_metadata(
        tool_job, namespace="argus-sandbox", job_name="argus-nmap-quick-00000000"
    )
    labels = meta["labels"]
    assert labels["argus.io/tool-id"] == "nmap_quick"
    assert labels["argus.io/scan-id"] == str(tool_job.scan_id)
    assert labels["argus.io/tenant-id"] == str(tool_job.tenant_id)
    assert labels["argus.io/phase"] == "recon"
    assert labels["argus.io/risk-level"] == "passive"
    assert meta["annotations"]["argus.io/correlation-id"] == "argus-test-correlation"


def test_pod_labels_include_job_id(tool_job: ToolJob) -> None:
    labels = build_pod_labels(tool_job)
    assert labels["argus.io/job-id"] == tool_job.id.hex[:8]
    assert labels["argus.io/tool-id"] == "nmap_quick"
    assert labels["argus.io/scan-id"] == str(tool_job.scan_id)


# ---------------------------------------------------------------------------
# Image resolution
# ---------------------------------------------------------------------------


def test_resolve_image_prepends_default_registry_for_bare_image() -> None:
    desc = _make_descriptor("nmap:7.94")
    assert resolve_image(desc) == "ghcr.io/argus/nmap:7.94"


def test_resolve_image_keeps_registry_when_explicit() -> None:
    desc = _make_descriptor("registry.example.com/argus/nmap:7.94")
    assert resolve_image(desc) == "registry.example.com/argus/nmap:7.94"


def test_resolve_image_handles_path_only_reference() -> None:
    desc = _make_descriptor("argus/nmap:7.94")
    assert resolve_image(desc) == "ghcr.io/argus/nmap:7.94"


# ---------------------------------------------------------------------------
# Argv rendering (delegates to templating)
# ---------------------------------------------------------------------------


def test_build_argv_renders_template(
    descriptor: ToolDescriptor, tool_job: ToolJob
) -> None:
    argv = build_argv(descriptor, tool_job)
    assert argv == [
        "nmap",
        "-Pn",
        "-T4",
        "scanme.nmap.org",
        "-oX",
        "/out/job/nmap.xml",
    ]


def test_build_argv_rejects_shell_meta_in_parameters(
    descriptor: ToolDescriptor,
) -> None:
    """The templating layer must catch every shell-meta value."""
    bad = ToolJob(
        id=uuid4(),
        tenant_id=uuid4(),
        scan_id=uuid4(),
        tool_id="nmap_quick",
        phase=ScanPhase.RECON,
        risk_level=RiskLevel.PASSIVE,
        target=TargetSpec(kind=TargetKind.HOST, host="scanme.nmap.org"),
        parameters={"host": "scanme.nmap.org;rm -rf /", "out_dir": "/out/x"},
        outputs_dir="/out",
        timeout_s=60,
        correlation_id="abc",
    )
    with pytest.raises(Exception):
        build_argv(descriptor, bad)


# ---------------------------------------------------------------------------
# Job name (DNS-1123)
# ---------------------------------------------------------------------------


def test_build_job_name_is_dns1123_compliant(tool_job: ToolJob) -> None:
    name = build_job_name(tool_job)
    assert len(name) <= 63
    assert _DNS_1123_LABEL.fullmatch(name) is not None
    assert name.startswith("argus-nmap-quick-")
    assert name.endswith(tool_job.id.hex[:8])


def test_build_job_name_truncates_long_tool_ids() -> None:
    long_tool = "a" * 60
    job = ToolJob(
        id=uuid4(),
        tenant_id=uuid4(),
        scan_id=uuid4(),
        tool_id=long_tool,
        phase=ScanPhase.RECON,
        risk_level=RiskLevel.PASSIVE,
        target=TargetSpec(kind=TargetKind.HOST, host="x"),
        parameters={},
        outputs_dir="/out",
        timeout_s=60,
        correlation_id="c",
    )
    name = build_job_name(job)
    assert len(name) <= 63
    assert _DNS_1123_LABEL.fullmatch(name) is not None


def test_build_job_name_replaces_underscores_with_dashes() -> None:
    job = ToolJob(
        id=uuid4(),
        tenant_id=uuid4(),
        scan_id=uuid4(),
        tool_id="nmap_quick_test",
        phase=ScanPhase.RECON,
        risk_level=RiskLevel.PASSIVE,
        target=TargetSpec(kind=TargetKind.HOST, host="x"),
        parameters={},
        outputs_dir="/out",
        timeout_s=60,
        correlation_id="c",
    )
    name = build_job_name(job)
    assert "_" not in name
    assert "nmap-quick-test" in name


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_descriptor(image: str) -> ToolDescriptor:
    """Tiny factory used only for image-resolution tests."""
    return ToolDescriptor(
        tool_id="nmap_quick",
        category=ToolCategory.RECON,
        phase=ScanPhase.RECON,
        risk_level=RiskLevel.PASSIVE,
        requires_approval=False,
        network_policy=NetworkPolicyRef(name="recon-passive"),
        seccomp_profile="profiles/recon-default.json",
        default_timeout_s=300,
        cpu_limit="500m",
        memory_limit="256Mi",
        pids_limit=256,
        image=image,
        command_template=["nmap"],
        parse_strategy=ParseStrategy.JSON_LINES,
        evidence_artifacts=[],
        cwe_hints=[],
        owasp_wstg=[],
    )


# ---------------------------------------------------------------------------
# Cross-cutting: render the FULL set of helpers, ensure no dangerous strings
# ---------------------------------------------------------------------------


def test_full_helper_render_has_no_dangerous_volume_or_capability(
    descriptor: ToolDescriptor, tool_job: ToolJob
) -> None:
    pieces: list[Any] = [
        build_pod_security_context(),
        build_container_security_context(),
        build_resource_limits(descriptor),
        build_volumes(),
        build_volume_mounts(),
        build_job_metadata(tool_job, namespace="argus-sandbox", job_name="x-1"),
        build_pod_labels(tool_job),
    ]
    serialised = repr(pieces).lower()
    assert "hostpath" not in serialised
    assert "docker.sock" not in serialised
    assert "privileged': true" not in serialised
    assert '"privileged": true' not in serialised
    assert "shell=true" not in serialised
