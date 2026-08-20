"""End-to-end smoke for :class:`DockerSandboxAdapter` against a REAL docker daemon.

Marked ``requires_docker`` → **skipped by default** (dev/CI default addopts is
``-m "not requires_docker"``). Run explicitly with a working daemon:

    cd backend && pytest -m requires_docker tests/integration/sandbox/test_docker_adapter_e2e.py -v

Validates the hardened ``docker run`` mechanics of the adapter (security flags,
``--entrypoint`` argv override, exit-code capture, log capture, ``/out`` bind)
against a tiny public image — decoupled from the ``argus-kali-*`` catalog so it
runs anywhere Docker + ``docker.io/library/alpine`` are reachable.
"""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest

from src.pipeline.contracts.phase_io import ScanPhase
from src.pipeline.contracts.tool_job import RiskLevel, TargetKind, TargetSpec, ToolJob
from src.sandbox.adapter_base import (
    NetworkPolicyRef,
    ParseStrategy,
    ToolCategory,
    ToolDescriptor,
)
from src.sandbox.docker_adapter import DockerRunMode, DockerSandboxAdapter

pytestmark = pytest.mark.requires_docker

_ALPINE = "docker.io/library/alpine:3.20"
_CANARY = "a1b2c3d4e5f60718"  # 16 lowercase hex — satisfies the {canary} validator


class _FakeRegistry:
    def __init__(self, descriptors: list[ToolDescriptor]) -> None:
        self._by_id = {d.tool_id: d for d in descriptors}

    def get(self, tool_id: str) -> ToolDescriptor | None:
        return self._by_id.get(tool_id)


def _echo_descriptor() -> ToolDescriptor:
    # Synthetic descriptor: alpine `echo {canary}`. The image carries a registry
    # host ("docker.io") so resolve_image() returns it verbatim (no ghcr prefix).
    return ToolDescriptor(
        tool_id="echo_probe",
        category=ToolCategory.MISC,
        phase=ScanPhase.RECON,
        risk_level=RiskLevel.LOW,
        requires_approval=False,
        network_policy=NetworkPolicyRef(name="recon-passive"),
        seccomp_profile="runtime/default",
        default_timeout_s=60,
        cpu_limit="500m",
        memory_limit="256Mi",
        pids_limit=128,
        image=_ALPINE,
        command_template=["echo", "{canary}"],
        parse_strategy=ParseStrategy.TEXT_LINES,
        evidence_artifacts=[],
    )


def _echo_job() -> ToolJob:
    return ToolJob(
        id=uuid4(),
        tenant_id=uuid4(),
        scan_id=uuid4(),
        tool_id="echo_probe",
        phase=ScanPhase.RECON,
        risk_level=RiskLevel.LOW,
        target=TargetSpec(kind=TargetKind.URL, url="http://example.test/"),
        parameters={"canary": _CANARY},
        outputs_dir="/out",
        timeout_s=60,
        correlation_id="argus-docker-e2e",
    )


async def test_docker_run_executes_and_captures_output(tmp_path: Path) -> None:
    descriptor = _echo_descriptor()
    adapter = DockerSandboxAdapter(
        _FakeRegistry([descriptor]),
        mode=DockerRunMode.DOCKER,
        out_dir_root=tmp_path / "out",
    )
    result = await adapter.run(_echo_job(), descriptor)
    assert (
        result.completed is True
    ), f"docker run failed: {result.failure_reason}: {result.logs_excerpt}"
    assert result.exit_code == 0
    assert _CANARY in result.logs_excerpt


async def test_auth_argv_reaches_real_docker_and_is_redacted(tmp_path: Path) -> None:
    descriptor = _echo_descriptor()
    adapter = DockerSandboxAdapter(
        _FakeRegistry([descriptor]),
        mode=DockerRunMode.DOCKER,
        out_dir_root=tmp_path / "out",
    )
    result = await adapter.run(_echo_job(), descriptor, auth_argv=["-H", "Cookie: sid=E2ESECRET"])
    assert result.completed is True
    # ``echo`` prints the appended auth flags → proves they reached real docker.
    assert "Cookie: sid=E2ESECRET" in result.logs_excerpt
    # …but the persisted plan redacts the secret value.
    assert "sid=E2ESECRET" not in result.manifest_yaml
    assert "[REDACTED]" in result.manifest_yaml


async def test_dry_run_matches_docker_command_plan(tmp_path: Path) -> None:
    descriptor = _echo_descriptor()
    adapter = DockerSandboxAdapter(
        _FakeRegistry([descriptor]),
        mode=DockerRunMode.DRY_RUN,
        dry_run_artifact_dir=tmp_path / "dry",
        out_dir_root=tmp_path / "out",
    )
    result = await adapter.run(_echo_job(), descriptor)
    assert result.completed is False
    assert result.failure_reason == "dry_run"
    assert _ALPINE in result.manifest_yaml
