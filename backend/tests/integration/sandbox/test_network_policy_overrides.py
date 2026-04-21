"""Integration test: ARG-027 NetworkPolicy override consumption end-to-end.

Closes the reviewer-flagged H2 gap from ARG-019: ``NetworkPolicyRef.dns_resolvers``
and ``NetworkPolicyRef.egress_allowlist`` were "dead config" — the values were
parsed from YAML but never reached the rendered manifest.

What this suite verifies (without spinning up a real cluster):

1. The :class:`KubernetesSandboxAdapter` builds the NetworkPolicy through
   :func:`src.sandbox.manifest.build_networkpolicy_for_job`, so per-tool
   overrides on ``descriptor.network_policy`` actually propagate into the
   rendered manifest the cluster would receive.
2. ``dns_resolvers`` overrides REPLACE the template defaults (the new resolver
   IPs end up in the DNS egress block; the template defaults are absent).
3. ``egress_allowlist`` overrides UNION with the template's static allow-list
   (template peers stay; override peers are appended; FQDN-style entries land
   in the ``argus.io/egress-fqdns`` annotation, never in ``ipBlock.cidr``).
4. Validation is enforced at render time: a private IP in either override
   field aborts manifest rendering with :class:`SandboxConfigError` (the
   adapter's domain-specific wrapper around the renderer's ``ValueError``).
5. The full DRY_RUN flow (Job + NetworkPolicy YAML serialisation) works
   end-to-end with overrides applied — the rendered NetworkPolicy round-trips
   through ``yaml.safe_dump`` / ``yaml.safe_load`` without losing the override
   peers or annotations.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from uuid import uuid4

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
    KubernetesSandboxAdapter,
    SandboxConfigError,
    SandboxRunMode,
)
from src.sandbox.tool_registry import ToolRegistry


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_descriptor(
    *,
    tool_id: str,
    network_policy: NetworkPolicyRef,
    requires_approval: bool = False,
) -> ToolDescriptor:
    """Build a minimal-but-valid ToolDescriptor for the cloud-aws template.

    The descriptor uses a fixed safe shape (alpine image, ``echo`` template,
    BINARY_BLOB parser) so the only knob we vary across tests is the
    ``network_policy`` field.
    """
    return ToolDescriptor(
        tool_id=tool_id,
        category=ToolCategory.CLOUD,
        phase=ScanPhase.RECON,
        risk_level=RiskLevel.LOW,
        requires_approval=requires_approval,
        network_policy=network_policy,
        seccomp_profile="runtime/default",
        default_timeout_s=60,
        cpu_limit="500m",
        memory_limit="256Mi",
        image="alpine:3.20",
        command_template=["/bin/echo", "{out_dir}"],
        parse_strategy=ParseStrategy.BINARY_BLOB,
    )


def _make_tool_job(*, tool_id: str) -> ToolJob:
    return ToolJob(
        id=uuid4(),
        tenant_id=uuid4(),
        scan_id=uuid4(),
        tool_id=tool_id,
        phase=ScanPhase.RECON,
        risk_level=RiskLevel.LOW,
        target=TargetSpec(kind=TargetKind.DOMAIN, domain="example.com"),
        parameters={"out_dir": "/out/job"},
        outputs_dir="/out",
        timeout_s=30,
        correlation_id=f"argus-arg027-{tool_id}",
    )


@pytest.fixture()
def empty_registry(tmp_path: Path) -> ToolRegistry:
    """A loaded ToolRegistry with no tools — adapter ignores the catalog
    contents for the manifest-building path under test (the descriptor is
    passed in directly)."""
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    # Touch a .gitignore so the directory isn't empty (some loader code paths
    # are sensitive to that). The registry's `load()` is patched on the
    # adapter side via _validate_pair; we never actually invoke it here.
    (tools_dir / ".gitignore").write_text("*\n", encoding="utf-8")
    registry = ToolRegistry(tools_dir=tools_dir)
    return registry


@pytest.fixture()
def adapter(empty_registry: ToolRegistry, tmp_path: Path) -> KubernetesSandboxAdapter:
    out = tmp_path / "dryrun"
    out.mkdir()
    return KubernetesSandboxAdapter(
        empty_registry,
        mode=SandboxRunMode.DRY_RUN,
        dry_run_artifact_dir=out,
    )


# ---------------------------------------------------------------------------
# 1) dns_resolvers override propagates end-to-end
# ---------------------------------------------------------------------------


def test_descriptor_with_dns_resolver_override_renders_custom_resolver(
    adapter: KubernetesSandboxAdapter,
) -> None:
    descriptor = _make_descriptor(
        tool_id="prowler_with_custom_dns",
        network_policy=NetworkPolicyRef(
            name="cloud-aws",
            dns_resolvers=["8.8.4.4"],
        ),
    )
    job = _make_tool_job(tool_id=descriptor.tool_id)

    manifest = adapter.build_networkpolicy_manifest(job, descriptor)

    # DNS rule is the second egress block (payload + DNS).
    dns_rule = manifest["spec"]["egress"][1]
    cidrs = {peer["ipBlock"]["cidr"] for peer in dns_rule["to"]}
    assert "8.8.4.4/32" in cidrs
    # Cloudflare / Quad9 defaults are absent — the override REPLACES them.
    assert "1.1.1.1/32" not in cidrs
    assert "9.9.9.9/32" not in cidrs


def test_descriptor_without_dns_resolver_override_keeps_template_defaults(
    adapter: KubernetesSandboxAdapter,
) -> None:
    descriptor = _make_descriptor(
        tool_id="prowler_default_dns",
        network_policy=NetworkPolicyRef(name="cloud-aws"),
    )
    job = _make_tool_job(tool_id=descriptor.tool_id)

    manifest = adapter.build_networkpolicy_manifest(job, descriptor)

    dns_rule = manifest["spec"]["egress"][1]
    cidrs = {peer["ipBlock"]["cidr"] for peer in dns_rule["to"]}
    assert "1.1.1.1/32" in cidrs
    assert "9.9.9.9/32" in cidrs


# ---------------------------------------------------------------------------
# 2) egress_allowlist override unions with template static peers
# ---------------------------------------------------------------------------


def test_descriptor_with_cidr_egress_override_unions_with_template_static(
    adapter: KubernetesSandboxAdapter,
) -> None:
    descriptor = _make_descriptor(
        tool_id="prowler_with_extra_subnet",
        network_policy=NetworkPolicyRef(
            name="cloud-aws",
            egress_allowlist=["198.51.100.0/24"],
        ),
    )
    job = _make_tool_job(tool_id=descriptor.tool_id)

    manifest = adapter.build_networkpolicy_manifest(job, descriptor)

    payload_rule = manifest["spec"]["egress"][0]
    cidrs = [peer["ipBlock"]["cidr"] for peer in payload_rule["to"]]
    # Template static (0.0.0.0/0) MUST still be present (additive).
    assert "0.0.0.0/0" in cidrs
    # Override entry appended.
    assert "198.51.100.0/24" in cidrs


def test_descriptor_with_fqdn_egress_override_lands_in_annotation(
    adapter: KubernetesSandboxAdapter,
) -> None:
    descriptor = _make_descriptor(
        tool_id="prowler_with_extra_fqdn",
        network_policy=NetworkPolicyRef(
            name="cloud-aws",
            egress_allowlist=["api.example.com"],
        ),
    )
    job = _make_tool_job(tool_id=descriptor.tool_id)

    manifest = adapter.build_networkpolicy_manifest(job, descriptor)

    payload_rule = manifest["spec"]["egress"][0]
    for peer in payload_rule["to"]:
        # The CIDR field must remain a syntactically valid IP literal.
        assert "example.com" not in peer["ipBlock"]["cidr"]
    annotations = manifest["metadata"]["annotations"]["argus.io/egress-fqdns"]
    # Both the template's documented FQDNs and the override land here.
    assert "*.amazonaws.com" in annotations
    assert "api.example.com" in annotations


def test_descriptor_with_mixed_cidr_and_fqdn_override(
    adapter: KubernetesSandboxAdapter,
) -> None:
    descriptor = _make_descriptor(
        tool_id="prowler_with_mixed_override",
        network_policy=NetworkPolicyRef(
            name="cloud-aws",
            egress_allowlist=["198.51.100.0/24", "api.example.com"],
        ),
    )
    job = _make_tool_job(tool_id=descriptor.tool_id)

    manifest = adapter.build_networkpolicy_manifest(job, descriptor)

    payload_rule = manifest["spec"]["egress"][0]
    cidrs = {peer["ipBlock"]["cidr"] for peer in payload_rule["to"]}
    assert "198.51.100.0/24" in cidrs
    assert "0.0.0.0/0" in cidrs
    annotations = manifest["metadata"]["annotations"]["argus.io/egress-fqdns"]
    assert "api.example.com" in annotations


# ---------------------------------------------------------------------------
# 3) Validation: private / IMDS overrides are rejected at render time
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_dns",
    [
        "10.0.0.5",
        "172.16.5.5",
        "192.168.1.1",
        "169.254.169.254",
    ],
)
def test_descriptor_with_private_dns_override_raises_sandbox_config_error(
    adapter: KubernetesSandboxAdapter,
    bad_dns: str,
) -> None:
    descriptor = _make_descriptor(
        tool_id="prowler_with_private_dns",
        network_policy=NetworkPolicyRef(
            name="cloud-aws",
            dns_resolvers=[bad_dns],
        ),
    )
    job = _make_tool_job(tool_id=descriptor.tool_id)

    with pytest.raises(SandboxConfigError, match="NetworkPolicy override rejected"):
        adapter.build_networkpolicy_manifest(job, descriptor)


@pytest.mark.parametrize(
    "bad_egress",
    [
        "10.0.0.0/8",
        "10.0.0.5",
        "172.16.0.0/12",
        "192.168.1.0/24",
        "169.254.169.254",
        "169.254.169.254/32",
    ],
)
def test_descriptor_with_private_egress_override_raises_sandbox_config_error(
    adapter: KubernetesSandboxAdapter,
    bad_egress: str,
) -> None:
    descriptor = _make_descriptor(
        tool_id="prowler_with_private_egress",
        network_policy=NetworkPolicyRef(
            name="cloud-aws",
            egress_allowlist=[bad_egress],
        ),
    )
    job = _make_tool_job(tool_id=descriptor.tool_id)

    with pytest.raises(SandboxConfigError, match="NetworkPolicy override rejected"):
        adapter.build_networkpolicy_manifest(job, descriptor)


def test_descriptor_with_zero_zero_egress_override_carries_mandatory_excepts(
    adapter: KubernetesSandboxAdapter,
) -> None:
    """0.0.0.0/0 is the canonical "permit internet" intent used by 40+ tools.

    It must render successfully BUT the wildcard peer must always carry the
    private + IMDS deny exceptions injected by the renderer
    (defence-in-depth — strictly safer than the pre-ARG-027 behaviour
    that emitted a naked 0.0.0.0/0 with no exceptions at all).
    """
    descriptor = _make_descriptor(
        tool_id="prowler_with_zero_zero",
        network_policy=NetworkPolicyRef(
            name="cloud-aws",
            egress_allowlist=["0.0.0.0/0"],
        ),
    )
    job = _make_tool_job(tool_id=descriptor.tool_id)

    manifest = adapter.build_networkpolicy_manifest(job, descriptor)
    payload_rule = manifest["spec"]["egress"][0]
    wildcard_peers = [
        peer for peer in payload_rule["to"] if peer["ipBlock"]["cidr"] == "0.0.0.0/0"
    ]
    assert wildcard_peers, "expected the wildcard peer to be rendered"
    excepts = wildcard_peers[0]["ipBlock"].get("except", [])
    for must_block in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.169.254/32",
        "169.254.0.0/16",
    ):
        assert must_block in excepts


# ---------------------------------------------------------------------------
# 4) Cloud-template parity: cloud-gcp and cloud-azure render correctly
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("template_name", "expected_fqdn"),
    [
        ("cloud-gcp", "*.googleapis.com"),
        ("cloud-azure", "*.azure.com"),
    ],
)
def test_cloud_gcp_and_azure_descriptors_render_through_adapter(
    adapter: KubernetesSandboxAdapter,
    template_name: str,
    expected_fqdn: str,
) -> None:
    descriptor = _make_descriptor(
        tool_id=f"smoke_{template_name.replace('-', '_')}",
        network_policy=NetworkPolicyRef(name=template_name),
    )
    job = _make_tool_job(tool_id=descriptor.tool_id)

    manifest = adapter.build_networkpolicy_manifest(job, descriptor)

    # Ingress denied for every template.
    assert manifest["spec"]["ingress"] == []
    payload_rule = manifest["spec"]["egress"][0]
    peer = payload_rule["to"][0]
    assert peer["ipBlock"]["cidr"] == "0.0.0.0/0"
    # IMDS + private blocks denied via except-list.
    assert "169.254.0.0/16" in peer["ipBlock"]["except"]
    annotations = manifest["metadata"]["annotations"]
    assert expected_fqdn in annotations["argus.io/egress-fqdns"]


# ---------------------------------------------------------------------------
# 5) Full DRY_RUN flow: overrides survive YAML round-trip
# ---------------------------------------------------------------------------


def test_dry_run_yaml_preserves_dns_resolver_override(
    adapter: KubernetesSandboxAdapter,
) -> None:
    """End-to-end DRY_RUN flow: the rendered YAML on disk carries the override."""
    descriptor = _make_descriptor(
        tool_id="prowler_dryrun_dns",
        network_policy=NetworkPolicyRef(
            name="cloud-aws",
            dns_resolvers=["8.8.4.4"],
        ),
    )
    job = _make_tool_job(tool_id=descriptor.tool_id)

    result = asyncio.run(adapter.run(job, descriptor))

    assert result.failure_reason == "dry_run"
    docs: list[dict[str, Any]] = list(yaml.safe_load_all(result.manifest_yaml))
    np_doc = next(doc for doc in docs if doc["kind"] == "NetworkPolicy")
    dns_rule = np_doc["spec"]["egress"][1]
    cidrs = {peer["ipBlock"]["cidr"] for peer in dns_rule["to"]}
    assert "8.8.4.4/32" in cidrs
    assert "1.1.1.1/32" not in cidrs
    assert "9.9.9.9/32" not in cidrs


def test_dry_run_yaml_preserves_egress_allowlist_override(
    adapter: KubernetesSandboxAdapter,
) -> None:
    descriptor = _make_descriptor(
        tool_id="prowler_dryrun_egress",
        network_policy=NetworkPolicyRef(
            name="cloud-aws",
            egress_allowlist=["198.51.100.0/24", "api.example.com"],
        ),
    )
    job = _make_tool_job(tool_id=descriptor.tool_id)

    result = asyncio.run(adapter.run(job, descriptor))

    docs: list[dict[str, Any]] = list(yaml.safe_load_all(result.manifest_yaml))
    np_doc = next(doc for doc in docs if doc["kind"] == "NetworkPolicy")
    payload_rule = np_doc["spec"]["egress"][0]
    cidrs = {peer["ipBlock"]["cidr"] for peer in payload_rule["to"]}
    assert "0.0.0.0/0" in cidrs
    assert "198.51.100.0/24" in cidrs
    assert (
        "api.example.com" in np_doc["metadata"]["annotations"]["argus.io/egress-fqdns"]
    )
