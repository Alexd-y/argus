"""Unit tests for :class:`src.sandbox.docker_adapter.DockerSandboxAdapter`.

DRY_RUN is exercised end-to-end (no docker daemon). DOCKER mode is exercised
with a mocked ``asyncio.create_subprocess_exec`` so success / non-zero /
timeout / docker-missing paths are covered without a real daemon. The adapter
is asserted to be a drop-in for :class:`~src.sandbox.runner.SandboxRunner`.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
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
from src.sandbox.docker_adapter import (
    DockerRunMode,
    DockerSandboxAdapter,
    _cpu_to_docker,
    _memory_to_docker,
)
from src.sandbox.k8s_adapter import (
    ApprovalRequiredError,
    SandboxConfigError,
    SandboxRunResult,
)


class _FakeRegistry:
    def __init__(self, descriptors: list[ToolDescriptor]) -> None:
        self._by_id = {d.tool_id: d for d in descriptors}

    def get(self, tool_id: str) -> ToolDescriptor | None:
        return self._by_id.get(tool_id)


@pytest.fixture()
def descriptor() -> ToolDescriptor:
    return ToolDescriptor(
        tool_id="nuclei",
        category=ToolCategory.WEB_VA,
        phase=ScanPhase.VULN_ANALYSIS,
        risk_level=RiskLevel.LOW,
        requires_approval=False,
        network_policy=NetworkPolicyRef(name="recon-active-tcp"),
        seccomp_profile="runtime/default",
        default_timeout_s=600,
        cpu_limit="2",
        memory_limit="2Gi",
        pids_limit=256,
        image="argus-kali-web:latest",
        command_template=["nuclei", "-target", "{url}", "-output", "{out_dir}/nuclei.jsonl"],
        parse_strategy=ParseStrategy.NUCLEI_JSONL,
        evidence_artifacts=["/out/nuclei.jsonl"],
    )


@pytest.fixture()
def approval_descriptor() -> ToolDescriptor:
    return ToolDescriptor(
        tool_id="commix",
        category=ToolCategory.WEB_VA,
        phase=ScanPhase.VULN_ANALYSIS,
        risk_level=RiskLevel.HIGH,
        requires_approval=True,
        network_policy=NetworkPolicyRef(name="recon-active-tcp"),
        seccomp_profile="runtime/default",
        default_timeout_s=600,
        cpu_limit="1",
        memory_limit="1Gi",
        pids_limit=256,
        image="argus-kali-web:latest",
        command_template=["commix", "--url", "{url}"],
        parse_strategy=ParseStrategy.TEXT_LINES,
        evidence_artifacts=[],
    )


def _job(tool_id: str = "nuclei", *, approval: UUID | None = None) -> ToolJob:
    return ToolJob(
        id=UUID("aabbccdd-1111-2222-3333-444444444444"),
        tenant_id=uuid4(),
        scan_id=UUID("11111111-2222-3333-4444-555555555555"),
        tool_id=tool_id,
        phase=ScanPhase.VULN_ANALYSIS,
        risk_level=RiskLevel.HIGH if approval is not None else RiskLevel.LOW,
        target=TargetSpec(kind=TargetKind.URL, url="http://target.example/app"),
        parameters={"url": "http://target.example/app", "out_dir": "/out"},
        outputs_dir="/out",
        timeout_s=120,
        requires_approval=approval is not None,
        approval_id=approval,
        correlation_id="argus-docker-test",
    )


def _proc_mock(returncode: int = 0, stdout: bytes = b"", stderr: bytes = b"") -> MagicMock:
    proc = MagicMock()
    proc.returncode = returncode
    proc.communicate = AsyncMock(return_value=(stdout, stderr))
    proc.wait = AsyncMock()
    return proc


# ---------------------------------------------------------------------------
# Quantity conversion helpers
# ---------------------------------------------------------------------------


class TestQuantityConversion:
    def test_memory_binary_units(self) -> None:
        assert _memory_to_docker("2Gi") == "2g"
        assert _memory_to_docker("256Mi") == "256m"
        assert _memory_to_docker("512Ki") == "512k"

    def test_memory_decimal_and_bytes(self) -> None:
        assert _memory_to_docker("512M") == "512m"
        assert _memory_to_docker("268435456") == "268435456"

    def test_cpu_millicores_and_cores(self) -> None:
        assert _cpu_to_docker("500m") == "0.5"
        assert _cpu_to_docker("1500m") == "1.5"
        assert _cpu_to_docker("2") == "2"


# ---------------------------------------------------------------------------
# build_docker_command
# ---------------------------------------------------------------------------


class TestBuildCommand:
    def test_hardening_flags_present(self, tmp_path: Path, descriptor: ToolDescriptor) -> None:
        adapter = DockerSandboxAdapter(
            _FakeRegistry([descriptor]), mode=DockerRunMode.DRY_RUN, dry_run_artifact_dir=tmp_path
        )
        cmd = adapter.build_docker_command(_job(), descriptor, host_out_dir=tmp_path / "out")
        assert cmd[:3] == ["docker", "run", "--rm"]
        assert "--read-only" in cmd
        assert "--cap-drop" in cmd and "ALL" in cmd
        assert "no-new-privileges" in cmd
        assert "--user" in cmd and "65532:65532" in cmd
        assert "--pids-limit" in cmd and "256" in cmd
        assert "--memory" in cmd and "2g" in cmd
        assert "--cpus" in cmd and "2" in cmd

    def test_entrypoint_and_argv(self, tmp_path: Path, descriptor: ToolDescriptor) -> None:
        adapter = DockerSandboxAdapter(
            _FakeRegistry([descriptor]), mode=DockerRunMode.DRY_RUN, dry_run_artifact_dir=tmp_path
        )
        cmd = adapter.build_docker_command(_job(), descriptor, host_out_dir=tmp_path / "out")
        # --entrypoint = argv[0]; image (registry-resolved) precedes the tool args.
        assert "--entrypoint" in cmd
        assert cmd[cmd.index("--entrypoint") + 1] == "nuclei"
        assert cmd[-4:] == [
            "-target",
            "http://target.example/app",
            "-output",
            "/out/nuclei.jsonl",
        ]
        assert "argus-kali-web:latest" in cmd[-5]  # resolved image sits before argv[1:]

    def test_network_flag_when_configured(self, tmp_path: Path, descriptor: ToolDescriptor) -> None:
        adapter = DockerSandboxAdapter(
            _FakeRegistry([descriptor]),
            mode=DockerRunMode.DRY_RUN,
            dry_run_artifact_dir=tmp_path,
            network="argus-egress",
        )
        cmd = adapter.build_docker_command(_job(), descriptor, host_out_dir=tmp_path / "out")
        assert "--network" in cmd and "argus-egress" in cmd

    def test_tool_id_mismatch_raises(self, tmp_path: Path, descriptor: ToolDescriptor) -> None:
        adapter = DockerSandboxAdapter(
            _FakeRegistry([descriptor]), mode=DockerRunMode.DRY_RUN, dry_run_artifact_dir=tmp_path
        )
        with pytest.raises(SandboxConfigError):
            adapter.build_docker_command(
                _job(tool_id="ffuf"), descriptor, host_out_dir=tmp_path / "out"
            )

    def test_unknown_network_policy_raises(self, tmp_path: Path) -> None:
        bad = ToolDescriptor(
            tool_id="nuclei",
            category=ToolCategory.WEB_VA,
            phase=ScanPhase.VULN_ANALYSIS,
            risk_level=RiskLevel.LOW,
            requires_approval=False,
            network_policy=NetworkPolicyRef(name="totally-unknown-policy"),
            seccomp_profile="runtime/default",
            default_timeout_s=600,
            cpu_limit="1",
            memory_limit="1Gi",
            pids_limit=256,
            image="argus-kali-web:latest",
            command_template=["nuclei", "-target", "{url}"],
            parse_strategy=ParseStrategy.NUCLEI_JSONL,
        )
        adapter = DockerSandboxAdapter(
            _FakeRegistry([bad]), mode=DockerRunMode.DRY_RUN, dry_run_artifact_dir=tmp_path
        )
        with pytest.raises(SandboxConfigError):
            adapter.build_docker_command(_job(), bad, host_out_dir=tmp_path / "out")


# ---------------------------------------------------------------------------
# run — DRY_RUN
# ---------------------------------------------------------------------------


class TestDryRun:
    async def test_dry_run_returns_result_and_writes_artifacts(
        self, tmp_path: Path, descriptor: ToolDescriptor
    ) -> None:
        adapter = DockerSandboxAdapter(
            _FakeRegistry([descriptor]),
            mode=DockerRunMode.DRY_RUN,
            dry_run_artifact_dir=tmp_path,
            out_dir_root=tmp_path / "run",
        )
        result = await adapter.run(_job(), descriptor)
        assert isinstance(result, SandboxRunResult)
        assert result.completed is False
        assert result.failure_reason == "dry_run"
        assert result.exit_code is None
        assert result.manifest_yaml.strip()
        scan_dir = tmp_path / "11111111-2222-3333-4444-555555555555"
        assert (scan_dir / "aabbccdd.docker.json").is_file()
        payload = json.loads((scan_dir / "aabbccdd.docker.json").read_text(encoding="utf-8"))
        assert payload["tool_id"] == "nuclei"
        assert payload["command"][0] == "docker"

    def test_dry_run_requires_artifact_dir(self, descriptor: ToolDescriptor) -> None:
        with pytest.raises(SandboxConfigError):
            DockerSandboxAdapter(_FakeRegistry([descriptor]), mode=DockerRunMode.DRY_RUN)

    async def test_approval_required_without_id(
        self, tmp_path: Path, approval_descriptor: ToolDescriptor
    ) -> None:
        adapter = DockerSandboxAdapter(
            _FakeRegistry([approval_descriptor]),
            mode=DockerRunMode.DRY_RUN,
            dry_run_artifact_dir=tmp_path,
        )
        with pytest.raises(ApprovalRequiredError):
            await adapter.run(_job(tool_id="commix"), approval_descriptor)


# ---------------------------------------------------------------------------
# run — DOCKER (mocked subprocess)
# ---------------------------------------------------------------------------


class TestDockerExec:
    async def test_success(self, tmp_path: Path, descriptor: ToolDescriptor) -> None:
        adapter = DockerSandboxAdapter(
            _FakeRegistry([descriptor]),
            mode=DockerRunMode.DOCKER,
            out_dir_root=tmp_path / "run",
        )
        proc = _proc_mock(returncode=0, stdout=b'{"template":"cve"}')
        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=proc):
            result = await adapter.run(_job(), descriptor)
        assert result.completed is True
        assert result.exit_code == 0
        assert result.failure_reason is None
        assert "cve" in result.logs_excerpt

    async def test_nonzero_exit_is_job_failed(
        self, tmp_path: Path, descriptor: ToolDescriptor
    ) -> None:
        adapter = DockerSandboxAdapter(
            _FakeRegistry([descriptor]),
            mode=DockerRunMode.DOCKER,
            out_dir_root=tmp_path / "run",
        )
        proc = _proc_mock(returncode=2, stderr=b"boom")
        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=proc):
            result = await adapter.run(_job(), descriptor)
        assert result.completed is False
        assert result.exit_code == 2
        assert result.failure_reason == "job_failed"

    async def test_docker_missing_is_cluster_apply_failed(
        self, tmp_path: Path, descriptor: ToolDescriptor
    ) -> None:
        adapter = DockerSandboxAdapter(
            _FakeRegistry([descriptor]),
            mode=DockerRunMode.DOCKER,
            out_dir_root=tmp_path / "run",
        )
        with patch(
            "asyncio.create_subprocess_exec",
            new_callable=AsyncMock,
            side_effect=FileNotFoundError("docker"),
        ):
            result = await adapter.run(_job(), descriptor)
        assert result.completed is False
        assert result.failure_reason == "cluster_apply_failed"

    async def test_timeout_is_cluster_timeout(
        self, tmp_path: Path, descriptor: ToolDescriptor
    ) -> None:
        adapter = DockerSandboxAdapter(
            _FakeRegistry([descriptor]),
            mode=DockerRunMode.DOCKER,
            out_dir_root=tmp_path / "run",
        )
        proc = MagicMock()
        proc.communicate = MagicMock()  # non-coroutine: wait_for is mocked below
        proc.kill = MagicMock()
        proc.wait = AsyncMock()
        with (
            patch("asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=proc),
            patch("asyncio.wait_for", new_callable=AsyncMock, side_effect=TimeoutError),
        ):
            result = await adapter.run(_job(), descriptor)
        assert result.completed is False
        assert result.failure_reason == "cluster_timeout"
        proc.kill.assert_called_once()

    async def test_declared_artifacts_are_collected(
        self, tmp_path: Path, descriptor: ToolDescriptor
    ) -> None:
        adapter = DockerSandboxAdapter(
            _FakeRegistry([descriptor]),
            mode=DockerRunMode.DOCKER,
            out_dir_root=tmp_path / "run",
        )
        # Pre-create the artifact the descriptor declares under the per-job /out.
        out_dir = tmp_path / "run" / "11111111-2222-3333-4444-555555555555" / "aabbccdd"
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "nuclei.jsonl").write_text("{}", encoding="utf-8")
        proc = _proc_mock(returncode=0)
        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=proc):
            result = await adapter.run(_job(), descriptor)
        assert any(a.endswith("nuclei.jsonl") for a in result.artifacts)


# ---------------------------------------------------------------------------
# Interchangeability with SandboxRunner (duck-typed drop-in)
# ---------------------------------------------------------------------------


class TestAuthArgv:
    def test_auth_argv_appended_after_tool_args(
        self, tmp_path: Path, descriptor: ToolDescriptor
    ) -> None:
        adapter = DockerSandboxAdapter(
            _FakeRegistry([descriptor]), mode=DockerRunMode.DRY_RUN, dry_run_artifact_dir=tmp_path
        )
        cmd = adapter.build_docker_command(
            _job(),
            descriptor,
            host_out_dir=tmp_path / "out",
            auth_argv=["-H", "Cookie: sid=SECRET"],
        )
        assert cmd[-2:] == ["-H", "Cookie: sid=SECRET"]

    async def test_auth_secret_redacted_in_plan(
        self, tmp_path: Path, descriptor: ToolDescriptor
    ) -> None:
        adapter = DockerSandboxAdapter(
            _FakeRegistry([descriptor]),
            mode=DockerRunMode.DRY_RUN,
            dry_run_artifact_dir=tmp_path,
            out_dir_root=tmp_path / "out",
        )
        result = await adapter.run(_job(), descriptor, auth_argv=["-H", "Cookie: sid=SECRET"])
        assert "sid=SECRET" not in result.manifest_yaml
        assert "[REDACTED]" in result.manifest_yaml


class TestRunnerInterop:
    async def test_dispatch_via_sandbox_runner_dry_run(
        self, tmp_path: Path, descriptor: ToolDescriptor
    ) -> None:
        from src.sandbox.runner import SandboxRunner

        registry = _FakeRegistry([descriptor])
        adapter = DockerSandboxAdapter(
            registry,
            mode=DockerRunMode.DRY_RUN,
            dry_run_artifact_dir=tmp_path,
            out_dir_root=tmp_path / "run",
        )
        runner = SandboxRunner(adapter, registry=registry)  # type: ignore[arg-type]
        results = await runner.dispatch_jobs([_job()])
        assert len(results) == 1
        assert results[0].failure_reason == "dry_run"
