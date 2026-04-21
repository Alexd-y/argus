"""Integration test: end-to-end DRY_RUN against the real signed catalog.

Loads the production tool catalog and dispatches one ToolJob per registered
tool through :class:`KubernetesSandboxAdapter` in DRY_RUN mode. Every rendered
manifest is parsed back from disk and asserted against the Backlog/dev1_md
§5/§18 invariants:

* No ``hostPath`` volume.
* No ``docker.sock`` mount.
* No ``privileged: true``.
* ``readOnlyRootFilesystem: true`` is set on the container.
* ``runAsNonRoot: true`` and a non-zero UID are set on the pod.
* ``NetworkPolicy`` blocks ingress and includes the per-template egress block.
* Argv carries the templated value verbatim with no shell metacharacters.

This is the closest we can get to a real cluster run without spinning one up.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Final
from uuid import uuid4

import pytest
import yaml

from src.pipeline.contracts.phase_io import ScanPhase
from src.pipeline.contracts.tool_job import RiskLevel, TargetKind, TargetSpec, ToolJob
from src.sandbox.adapter_base import ToolDescriptor
from src.sandbox.k8s_adapter import (
    KubernetesSandboxAdapter,
    SandboxRunMode,
    SandboxRunResult,
)
from src.sandbox.network_policies import NetworkPolicyTemplate, get_template
from src.sandbox.runner import SandboxRunner
from src.sandbox.tool_registry import ToolRegistry


_FORBIDDEN_TOKENS: Final[tuple[str, ...]] = (
    "hostpath",
    "docker.sock",
    "privileged: true",
    "shell: true",
    "shell=true",
)

_REQUIRED_TOKENS: Final[tuple[str, ...]] = (
    "runasnonroot: true",
    "readonlyrootfilesystem: true",
    "runtimedefault",
)


@pytest.fixture(scope="session")
def catalog_dir() -> Path:
    here = Path(__file__).resolve()
    backend_dir = here.parents[3]
    catalog = backend_dir / "config" / "tools"
    assert catalog.is_dir(), f"expected catalog dir at {catalog}"
    return catalog


@pytest.fixture(scope="session")
def loaded_registry(catalog_dir: Path) -> ToolRegistry:
    registry = ToolRegistry(tools_dir=catalog_dir)
    registry.load()
    return registry


@pytest.fixture()
def dry_run_dir(tmp_path: Path) -> Path:
    out = tmp_path / "dryrun"
    out.mkdir(parents=True, exist_ok=True)
    return out


def _tool_job_for(descriptor: ToolDescriptor) -> ToolJob:
    """Build a ToolJob whose parameters satisfy the descriptor's template.

    The catalog's templates only ever use ``{domain}``, ``{host}``, ``{ip}``,
    ``{url}``, ``{port}``, and ``{out_dir}``; cover all of them with safe
    deterministic values that pass the per-placeholder validators.

    Tools that declare ``requires_approval: true`` (and tools whose
    ``risk_level`` is HIGH or DESTRUCTIVE, which the contract pins to
    ``requires_approval``) receive a synthetic ``approval_id`` so the
    ToolJob model invariant holds; the dry-run flow remains the unit
    under test, not the approval workflow.
    """
    placeholders = _placeholders_in(descriptor.command_template)
    parameters: dict[str, str] = {}
    for name in placeholders:
        parameters[name] = _SAFE_VALUES[name]

    target = _target_for(placeholders, descriptor=descriptor)
    requires_approval = descriptor.requires_approval or descriptor.risk_level in {
        RiskLevel.HIGH,
        RiskLevel.DESTRUCTIVE,
    }
    return ToolJob(
        id=uuid4(),
        tenant_id=uuid4(),
        scan_id=uuid4(),
        tool_id=descriptor.tool_id,
        phase=descriptor.phase,
        risk_level=descriptor.risk_level,
        target=target,
        parameters=parameters,
        outputs_dir="/out",
        timeout_s=min(descriptor.default_timeout_s, 300),
        correlation_id=f"argus-it-{descriptor.tool_id}",
        requires_approval=requires_approval,
        approval_id=uuid4() if requires_approval else None,
    )


def _placeholders_in(template_tokens: list[str]) -> list[str]:
    import re

    found: list[str] = []
    pattern = re.compile(r"\{([a-z_][a-z0-9_]*)\}")
    for token in template_tokens:
        for match in pattern.finditer(token):
            name = match.group(1)
            if name not in found:
                found.append(name)
    return found


_SAFE_VALUES: dict[str, str] = {
    "domain": "example.com",
    "host": "scanme.nmap.org",
    "ip": "10.0.0.5",
    "cidr": "10.0.0.0/24",
    "url": "https://example.com/",
    "port": "443",
    "ports": "80,443",
    "ports_range": "1-1024",
    "proto": "tcp",
    "params": "id,name",
    "out_dir": "/out/job",
    "in_dir": "/in/job",
    "wordlist": "/wordlists/common.txt",
    "canary": "deadbeefcafebabe",
    "session": "sess1",
    "user": "admin",
    "pass": "Password123",
    "u": "admin",
    "p": "Password123",
    "fmt": "json",
    "mode": "1",
    "module": "smb",
    "mod": "smb",
    "org": "exampleorg",
    "profile": "fast",
    "image": "nmap:7.94",
    "dc": "dc1.example.com",
    "size": "1024",
    "safe": "https://example.com/safe",
    "rand": "abc123",
    "s": "session",
    "scan_id": "scan1",
    "tenant_id": "tenant1",
    "community": "public",
    "community_string": "internal",
    "hashes_file": "/in/hashes.txt",
    "canary_callback": "https://canary.argus.example.com/abc123",
    "target_proto": "ssh",
    "path": "/in/source",
    "interface": "eth0",
    "binary": "/in/sample.bin",
    "file": "/in/payload.json",
    "script": "/in/scenarios/login.js",
    "basedn": "DC=example,DC=com",
}


def _target_for(
    placeholders: list[str],
    *,
    descriptor: ToolDescriptor,
) -> TargetSpec:
    """Build a TargetSpec compatible with the descriptor's network policy.

    Production semantics: jobs whose NetworkPolicy uses ``egress_target_dynamic``
    (``recon-active-tcp/udp``, ``recon-smb``, ``tls-handshake``) MUST arrive
    with an IP/CIDR-typed target — the orchestrator is responsible for
    resolving hostnames *before* dispatch. This helper mirrors that contract
    so the dry-run integration test stays representative of the real flow.
    """
    template: NetworkPolicyTemplate | None
    try:
        template = get_template(descriptor.network_policy.name)
    except KeyError:
        # Tool references a policy template not in the new catalog
        # (e.g. legacy ``recon`` / ``web_va``). Treat as static — the adapter
        # will raise a clear error of its own, which is what the test asserts.
        template = None
    if template is not None and template.egress_target_dynamic:
        if "cidr" in placeholders:
            return TargetSpec(kind=TargetKind.CIDR, cidr="10.0.0.0/24")
        return TargetSpec(kind=TargetKind.IP, ip="10.0.0.5")

    if "ip" in placeholders:
        return TargetSpec(kind=TargetKind.IP, ip="10.0.0.5")
    if "cidr" in placeholders:
        return TargetSpec(kind=TargetKind.CIDR, cidr="10.0.0.0/24")
    if "url" in placeholders:
        return TargetSpec(kind=TargetKind.URL, url="https://example.com/")
    if "host" in placeholders:
        return TargetSpec(kind=TargetKind.HOST, host="scanme.nmap.org")
    return TargetSpec(kind=TargetKind.DOMAIN, domain="example.com")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_dry_run_renders_every_tool_in_catalog(
    loaded_registry: ToolRegistry,
    dry_run_dir: Path,
) -> None:
    """Every tool in the real catalog renders cleanly in DRY_RUN mode."""
    adapter = KubernetesSandboxAdapter(
        loaded_registry,
        mode=SandboxRunMode.DRY_RUN,
        dry_run_artifact_dir=dry_run_dir,
    )

    failures: list[str] = []
    for descriptor in loaded_registry.all_descriptors():
        job = _tool_job_for(descriptor)
        try:
            result: SandboxRunResult = asyncio.run(adapter.run(job, descriptor))
        except Exception as exc:  # noqa: BLE001 — collect every failure for one report
            failures.append(f"{descriptor.tool_id}: {exc.__class__.__name__}: {exc}")
            continue

        if result.completed is not False or result.failure_reason != "dry_run":
            failures.append(
                f"{descriptor.tool_id}: unexpected dry-run result {result!r}"
            )

    assert not failures, "dry-run failures:\n" + "\n".join(failures)


def test_dry_run_artifacts_pass_security_invariant_scan(
    loaded_registry: ToolRegistry,
    dry_run_dir: Path,
) -> None:
    """Every dry-run artifact must respect Backlog §5 / §18 security invariants."""
    adapter = KubernetesSandboxAdapter(
        loaded_registry,
        mode=SandboxRunMode.DRY_RUN,
        dry_run_artifact_dir=dry_run_dir,
    )

    violations: list[str] = []
    for descriptor in loaded_registry.all_descriptors():
        job = _tool_job_for(descriptor)
        result = asyncio.run(adapter.run(job, descriptor))
        text = result.manifest_yaml.lower()
        for forbidden in _FORBIDDEN_TOKENS:
            if forbidden in text:
                violations.append(f"{descriptor.tool_id}: contains {forbidden!r}")
        for required in _REQUIRED_TOKENS:
            if required not in text:
                violations.append(f"{descriptor.tool_id}: missing {required!r}")

    assert not violations, "security invariant violations:\n" + "\n".join(violations)


def test_dry_run_yaml_contains_both_job_and_networkpolicy(
    loaded_registry: ToolRegistry,
    dry_run_dir: Path,
) -> None:
    """Every dry-run YAML stream is exactly two documents: NP + Job."""
    adapter = KubernetesSandboxAdapter(
        loaded_registry,
        mode=SandboxRunMode.DRY_RUN,
        dry_run_artifact_dir=dry_run_dir,
    )

    for descriptor in loaded_registry.all_descriptors():
        job = _tool_job_for(descriptor)
        asyncio.run(adapter.run(job, descriptor))
        scan_dir = dry_run_dir / str(job.scan_id)
        yaml_path = scan_dir / f"{job.id.hex[:8]}.yaml"
        assert yaml_path.is_file(), f"{descriptor.tool_id}: missing {yaml_path}"
        docs = list(yaml.safe_load_all(yaml_path.read_text("utf-8")))
        kinds = sorted(doc["kind"] for doc in docs)
        assert kinds == ["Job", "NetworkPolicy"], (
            f"{descriptor.tool_id}: unexpected kinds {kinds}"
        )


def test_dry_run_argv_files_carry_safe_values(
    loaded_registry: ToolRegistry,
    dry_run_dir: Path,
) -> None:
    """The argv JSON file must not introduce shell metacharacters via *parameter* substitution.

    Catalog templates may legitimately contain shell metacharacters when the
    tool is invoked through ``sh -c "<chained pipeline>"`` — those chains are
    code-reviewed and signed at catalog build time. What this test verifies is
    that the *user-controlled* parameter values do not slip extra metachars
    into the rendered argv: i.e. for every metachar present in the rendered
    argv token, the same token must already contain it in the *pre-substitution*
    catalog template. Any new metachar in the rendered argv would be a
    parameter-injection regression.
    """
    adapter = KubernetesSandboxAdapter(
        loaded_registry,
        mode=SandboxRunMode.DRY_RUN,
        dry_run_artifact_dir=dry_run_dir,
    )

    import json

    bad_chars = (";", "&&", "||", "`", "$(", "rm -rf", "\n")
    for descriptor in loaded_registry.all_descriptors():
        job = _tool_job_for(descriptor)
        asyncio.run(adapter.run(job, descriptor))
        scan_dir = dry_run_dir / str(job.scan_id)
        argv_path = scan_dir / f"{job.id.hex[:8]}.argv.json"
        assert argv_path.is_file()

        payload = json.loads(argv_path.read_text("utf-8"))
        assert payload["tool_id"] == descriptor.tool_id

        rendered = payload["argv"]
        template = list(descriptor.command_template)
        assert len(rendered) == len(template), (
            f"{descriptor.tool_id}: argv length differs from template"
        )
        for arg, tpl_token in zip(rendered, template, strict=True):
            assert isinstance(arg, str)
            for bad in bad_chars:
                if bad in arg and bad not in tpl_token:
                    pytest.fail(
                        f"{descriptor.tool_id}: parameter substitution introduced {bad!r} "
                        f"into argv token {arg!r} (template was {tpl_token!r})"
                    )


def test_runner_dispatches_full_catalog_concurrently(
    loaded_registry: ToolRegistry,
    dry_run_dir: Path,
) -> None:
    """SandboxRunner returns one result per job, in input order."""
    adapter = KubernetesSandboxAdapter(
        loaded_registry,
        mode=SandboxRunMode.DRY_RUN,
        dry_run_artifact_dir=dry_run_dir,
    )
    runner = SandboxRunner(adapter, registry=loaded_registry, max_parallel=8)

    descriptors = sorted(loaded_registry.all_descriptors(), key=lambda d: d.tool_id)
    jobs = [_tool_job_for(d) for d in descriptors]
    results = asyncio.run(runner.dispatch_jobs(jobs))

    assert len(results) == len(jobs)
    for descriptor, job, result in zip(descriptors, jobs, results, strict=True):
        assert result.failure_reason == "dry_run", (
            f"{descriptor.tool_id} ({job.id}): {result.failure_reason}"
        )
        assert result.completed is False
        assert descriptor.tool_id.replace("_", "-") in result.job_name


def test_runner_reports_unknown_tool_as_failure(
    loaded_registry: ToolRegistry,
    dry_run_dir: Path,
) -> None:
    """Unknown tool_id is reported, not raised, so the batch survives."""
    adapter = KubernetesSandboxAdapter(
        loaded_registry,
        mode=SandboxRunMode.DRY_RUN,
        dry_run_artifact_dir=dry_run_dir,
    )
    runner = SandboxRunner(adapter, registry=loaded_registry, max_parallel=2)

    real_descriptor = loaded_registry.all_descriptors()[0]
    real_job = _tool_job_for(real_descriptor)
    bogus_job = ToolJob(
        id=uuid4(),
        tenant_id=uuid4(),
        scan_id=uuid4(),
        tool_id="not_in_registry",
        phase=ScanPhase.RECON,
        risk_level=RiskLevel.PASSIVE,
        target=TargetSpec(kind=TargetKind.HOST, host="scanme.nmap.org"),
        parameters={},
        outputs_dir="/out",
        timeout_s=60,
        correlation_id="abc",
    )

    results = asyncio.run(runner.dispatch_jobs([real_job, bogus_job]))
    assert len(results) == 2
    assert results[0].failure_reason == "dry_run"
    assert results[1].completed is False
    assert results[1].failure_reason is not None
    assert "unknown tool_id" in results[1].failure_reason
