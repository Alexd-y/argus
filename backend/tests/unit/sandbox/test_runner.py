"""Unit tests for :class:`src.sandbox.runner.SandboxRunner`.

Cover constructor validation, dispatch ordering, concurrency bounding via the
internal semaphore, per-job timeout, the empty-input fast path, the
convenience :func:`dispatch_jobs` wrapper, and every documented failure path
(unknown tool, ApprovalRequiredError, SandboxConfigError, SandboxClusterError,
TemplateRenderError, ``asyncio.TimeoutError``).
"""

from __future__ import annotations

import asyncio
from pathlib import Path
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
from src.sandbox.k8s_adapter import (
    ApprovalRequiredError,
    KubernetesSandboxAdapter,
    SandboxClusterError,
    SandboxConfigError,
    SandboxRunMode,
    SandboxRunResult,
)
from src.sandbox.runner import SandboxRunner, dispatch_jobs
from src.sandbox.templating import TemplateRenderError


# ---------------------------------------------------------------------------
# Fakes — keep dependencies minimal so the runner is the unit under test.
# ---------------------------------------------------------------------------


class _FakeRegistry:
    def __init__(self, descriptors: list[ToolDescriptor]) -> None:
        self._by_id: dict[str, ToolDescriptor] = {d.tool_id: d for d in descriptors}

    def get(self, tool_id: str) -> ToolDescriptor | None:
        return self._by_id.get(tool_id)


class _FakeAdapter:
    """Adapter stub usable in place of :class:`KubernetesSandboxAdapter`.

    Records every ``(tool_job, descriptor)`` pair, can be configured to raise
    a specific exception or sleep for a configurable duration before returning
    a synthesised :class:`SandboxRunResult`.
    """

    def __init__(
        self,
        *,
        sleep_s: float = 0.0,
        raises: type[BaseException] | None = None,
        raise_kwargs: dict[str, Any] | None = None,
    ) -> None:
        self.sleep_s = sleep_s
        self.raises = raises
        self.raise_kwargs = raise_kwargs or {}
        self.calls: list[tuple[ToolJob, ToolDescriptor]] = []
        self.concurrent: int = 0
        self.peak_concurrent: int = 0

    async def run(
        self, tool_job: ToolJob, descriptor: ToolDescriptor
    ) -> SandboxRunResult:
        self.calls.append((tool_job, descriptor))
        self.concurrent += 1
        self.peak_concurrent = max(self.peak_concurrent, self.concurrent)
        try:
            if self.raises is not None:
                if self.raises is TemplateRenderError:
                    raise TemplateRenderError(
                        self.raise_kwargs.get("reason", "template-fail"),
                        placeholder=self.raise_kwargs.get("placeholder"),
                    )
                raise self.raises(self.raise_kwargs.get("message", "boom"))
            if self.sleep_s > 0:
                await asyncio.sleep(self.sleep_s)
            return SandboxRunResult(
                job_name=f"argus-{tool_job.tool_id.replace('_', '-')}-{tool_job.id.hex[:8]}",
                namespace="ns",
                exit_code=0,
                duration_seconds=self.sleep_s,
                artifacts=list(descriptor.evidence_artifacts),
                logs_excerpt="",
                completed=True,
                failure_reason=None,
                manifest_yaml="apiVersion: v1\nkind: Job\n",
            )
        finally:
            self.concurrent -= 1


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def descriptor() -> ToolDescriptor:
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


def _make_job(tool_id: str = "crt_sh", *, job_id: UUID | None = None) -> ToolJob:
    return ToolJob(
        id=job_id or uuid4(),
        tenant_id=uuid4(),
        scan_id=uuid4(),
        tool_id=tool_id,
        phase=ScanPhase.RECON,
        risk_level=RiskLevel.PASSIVE,
        target=TargetSpec(kind=TargetKind.DOMAIN, domain="example.com"),
        parameters={"domain": "example.com"},
        outputs_dir="/out",
        timeout_s=60,
        correlation_id="argus-runner-test",
    )


@pytest.fixture()
def registry(descriptor: ToolDescriptor) -> _FakeRegistry:
    return _FakeRegistry([descriptor])


# ---------------------------------------------------------------------------
# Constructor validation
# ---------------------------------------------------------------------------


def test_max_parallel_must_be_positive(registry: _FakeRegistry) -> None:
    adapter = _FakeAdapter()
    with pytest.raises(ValueError, match="max_parallel"):
        SandboxRunner(adapter, registry=registry, max_parallel=0)  # type: ignore[arg-type]


def test_per_job_timeout_must_be_positive_or_none(registry: _FakeRegistry) -> None:
    adapter = _FakeAdapter()
    with pytest.raises(ValueError, match="per_job_timeout_s"):
        SandboxRunner(
            adapter,
            registry=registry,
            per_job_timeout_s=0,  # type: ignore[arg-type]
        )


# ---------------------------------------------------------------------------
# Dispatch behaviour
# ---------------------------------------------------------------------------


def test_empty_jobs_iterable_returns_empty_list(registry: _FakeRegistry) -> None:
    adapter = _FakeAdapter()
    runner = SandboxRunner(adapter, registry=registry)  # type: ignore[arg-type]
    results = asyncio.run(runner.dispatch_jobs([]))
    assert results == []


def test_dispatch_preserves_input_order(
    registry: _FakeRegistry, descriptor: ToolDescriptor
) -> None:
    adapter = _FakeAdapter()
    runner = SandboxRunner(adapter, registry=registry, max_parallel=4)  # type: ignore[arg-type]

    jobs = [_make_job() for _ in range(6)]
    results = asyncio.run(runner.dispatch_jobs(jobs))
    assert len(results) == len(jobs)
    for job, result in zip(jobs, results, strict=True):
        assert job.id.hex[:8] in result.job_name
        assert result.completed is True
        assert result.artifacts == list(descriptor.evidence_artifacts)


def test_dispatch_bounds_concurrency_to_max_parallel(
    registry: _FakeRegistry,
) -> None:
    adapter = _FakeAdapter(sleep_s=0.05)
    runner = SandboxRunner(adapter, registry=registry, max_parallel=2)  # type: ignore[arg-type]

    jobs = [_make_job() for _ in range(8)]
    asyncio.run(runner.dispatch_jobs(jobs))
    assert adapter.peak_concurrent <= 2
    assert adapter.peak_concurrent >= 1
    assert len(adapter.calls) == len(jobs)


def test_unknown_tool_id_returns_failure_without_calling_adapter(
    registry: _FakeRegistry,
) -> None:
    adapter = _FakeAdapter()
    runner = SandboxRunner(adapter, registry=registry, max_parallel=2)  # type: ignore[arg-type]

    bogus = _make_job(tool_id="not_in_registry")
    results = asyncio.run(runner.dispatch_jobs([bogus]))
    assert len(results) == 1
    assert results[0].completed is False
    assert results[0].failure_reason is not None
    assert "unknown tool_id" in results[0].failure_reason
    assert results[0].namespace == "(unscheduled)"
    assert adapter.calls == []


# ---------------------------------------------------------------------------
# Per-job error mapping
# ---------------------------------------------------------------------------


def test_approval_required_error_is_translated(registry: _FakeRegistry) -> None:
    adapter = _FakeAdapter(
        raises=ApprovalRequiredError, raise_kwargs={"message": "needs approval"}
    )
    runner = SandboxRunner(adapter, registry=registry)  # type: ignore[arg-type]

    results = asyncio.run(runner.dispatch_jobs([_make_job()]))
    assert results[0].completed is False
    assert results[0].failure_reason is not None
    assert results[0].failure_reason.startswith("approval:")


def test_sandbox_config_error_is_translated(registry: _FakeRegistry) -> None:
    adapter = _FakeAdapter(
        raises=SandboxConfigError, raise_kwargs={"message": "bad cfg"}
    )
    runner = SandboxRunner(adapter, registry=registry)  # type: ignore[arg-type]

    results = asyncio.run(runner.dispatch_jobs([_make_job()]))
    assert results[0].completed is False
    assert results[0].failure_reason is not None
    assert results[0].failure_reason.startswith("config:")


def test_sandbox_cluster_error_is_translated(registry: _FakeRegistry) -> None:
    adapter = _FakeAdapter(
        raises=SandboxClusterError, raise_kwargs={"message": "kube down"}
    )
    runner = SandboxRunner(adapter, registry=registry)  # type: ignore[arg-type]

    results = asyncio.run(runner.dispatch_jobs([_make_job()]))
    assert results[0].completed is False
    assert results[0].failure_reason is not None
    assert results[0].failure_reason.startswith("cluster:")


def test_template_render_error_is_translated(registry: _FakeRegistry) -> None:
    adapter = _FakeAdapter(
        raises=TemplateRenderError,
        raise_kwargs={"reason": "missing placeholder", "placeholder": "domain"},
    )
    runner = SandboxRunner(adapter, registry=registry)  # type: ignore[arg-type]

    results = asyncio.run(runner.dispatch_jobs([_make_job()]))
    assert results[0].completed is False
    assert results[0].failure_reason is not None
    assert results[0].failure_reason.startswith("template:")
    assert "missing placeholder" in results[0].failure_reason


def test_failure_reason_is_truncated_to_128_chars(registry: _FakeRegistry) -> None:
    long_msg = "x" * 500
    adapter = _FakeAdapter(
        raises=SandboxConfigError, raise_kwargs={"message": long_msg}
    )
    runner = SandboxRunner(adapter, registry=registry)  # type: ignore[arg-type]

    results = asyncio.run(runner.dispatch_jobs([_make_job()]))
    assert results[0].failure_reason is not None
    assert len(results[0].failure_reason) <= 128


# ---------------------------------------------------------------------------
# Per-job timeout
# ---------------------------------------------------------------------------


def test_per_job_timeout_aborts_long_running_job(registry: _FakeRegistry) -> None:
    adapter = _FakeAdapter(sleep_s=1.0)
    runner = SandboxRunner(
        adapter,  # type: ignore[arg-type]
        registry=registry,
        max_parallel=2,
        per_job_timeout_s=1,
    )

    async def _drive() -> list[SandboxRunResult]:
        # Patch wait_for to simulate immediate timeout regardless of clock skew.
        # We close the in-flight coroutine to avoid "never awaited" warnings.
        original = asyncio.wait_for

        async def _instant_timeout(coro: Any, *_args: Any, **_kwargs: Any) -> Any:
            try:
                coro.close()
            except Exception:  # noqa: BLE001 — best-effort cleanup
                pass
            raise asyncio.TimeoutError

        asyncio.wait_for = _instant_timeout  # type: ignore[assignment]
        try:
            return await runner.dispatch_jobs([_make_job()])
        finally:
            asyncio.wait_for = original  # type: ignore[assignment]

    results = asyncio.run(_drive())
    assert results[0].completed is False
    assert results[0].failure_reason == "runner-timeout"


def test_no_per_job_timeout_allows_run_to_complete(registry: _FakeRegistry) -> None:
    adapter = _FakeAdapter(sleep_s=0.01)
    runner = SandboxRunner(
        adapter,  # type: ignore[arg-type]
        registry=registry,
        per_job_timeout_s=None,
    )
    results = asyncio.run(runner.dispatch_jobs([_make_job()]))
    assert results[0].completed is True
    assert results[0].failure_reason is None


# ---------------------------------------------------------------------------
# Convenience wrapper
# ---------------------------------------------------------------------------


def test_dispatch_jobs_wrapper_returns_results(
    registry: _FakeRegistry, descriptor: ToolDescriptor
) -> None:
    adapter = _FakeAdapter()
    jobs = [_make_job() for _ in range(3)]
    results = asyncio.run(
        dispatch_jobs(
            jobs,
            adapter=adapter,  # type: ignore[arg-type]
            registry=registry,  # type: ignore[arg-type]
            max_parallel=2,
            per_job_timeout_s=10,
        )
    )
    assert len(results) == len(jobs)
    assert all(r.completed for r in results)
    assert all(r.artifacts == descriptor.evidence_artifacts for r in results)


def test_dispatch_jobs_wrapper_handles_empty_input(registry: _FakeRegistry) -> None:
    adapter = _FakeAdapter()
    results = asyncio.run(
        dispatch_jobs(
            [],
            adapter=adapter,  # type: ignore[arg-type]
            registry=registry,  # type: ignore[arg-type]
        )
    )
    assert results == []


# ---------------------------------------------------------------------------
# Real adapter smoke test (DRY_RUN) — ensures our fakes match behaviour.
# ---------------------------------------------------------------------------


def test_runner_with_real_adapter_dry_run(
    tmp_path: Path, registry: _FakeRegistry, descriptor: ToolDescriptor
) -> None:
    adapter = KubernetesSandboxAdapter(
        registry,  # type: ignore[arg-type]
        mode=SandboxRunMode.DRY_RUN,
        dry_run_artifact_dir=tmp_path / "dryrun",
    )
    runner = SandboxRunner(adapter, registry=registry, max_parallel=2)  # type: ignore[arg-type]
    job = _make_job()
    results = asyncio.run(runner.dispatch_jobs([job]))

    assert len(results) == 1
    assert results[0].completed is False
    assert results[0].failure_reason == "dry_run"
    # Artifacts list is empty in DRY_RUN — confirm we did not synthesise any.
    assert results[0].artifacts == []
    # Job name carries the descriptor's tool_id transformed to DNS-1123.
    assert descriptor.tool_id.replace("_", "-") in results[0].job_name


# ---------------------------------------------------------------------------
# MED-3: unexpected exceptions MUST NOT abort the batch
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "exception_class",
    [ValueError, KeyError, RuntimeError, TypeError],
)
def test_unexpected_exception_in_adapter_does_not_abort_batch(
    registry: _FakeRegistry,
    exception_class: type[BaseException],
) -> None:
    """MED-3: any exception class NOT in the per-job ``except`` ladder must
    still produce a per-job failure result — never propagate up through
    ``asyncio.gather`` and cancel sibling jobs.
    """
    adapter = _FakeAdapter(
        raises=exception_class,
        raise_kwargs={"message": "leaked secret token AKIAIOSFODNN7EXAMPLE"},
    )
    runner = SandboxRunner(adapter, registry=registry)  # type: ignore[arg-type]

    results = asyncio.run(runner.dispatch_jobs([_make_job()]))

    assert len(results) == 1
    assert results[0].completed is False
    # Closed taxonomy: must be exactly the runner's unexpected_error sentinel.
    assert results[0].failure_reason == "unexpected_error"
    # MED-3 guarantee: the original exception's str() (which may carry
    # secrets, paths, or PII) MUST NOT leak into the user-facing field.
    assert "AKIAIOSFODNN7EXAMPLE" not in (results[0].failure_reason or "")
    assert "secret" not in (results[0].failure_reason or "").lower()


def test_unexpected_exception_in_one_job_does_not_block_siblings(
    registry: _FakeRegistry,
) -> None:
    """MED-3: a batch containing a job that raises an unexpected exception
    still returns results for ALL jobs (the contract is per-job isolation,
    not all-or-nothing)."""

    class _MixedAdapter:
        """Adapter that raises ValueError on the first job and succeeds on the rest."""

        def __init__(self) -> None:
            self.calls: int = 0

        async def run(
            self, tool_job: ToolJob, descriptor: ToolDescriptor
        ) -> SandboxRunResult:
            self.calls += 1
            if self.calls == 1:
                raise ValueError("simulated SDK bug: list index out of range")
            return SandboxRunResult(
                job_name=f"argus-ok-{tool_job.id.hex[:8]}",
                namespace="ns",
                exit_code=0,
                duration_seconds=0.0,
                artifacts=list(descriptor.evidence_artifacts),
                logs_excerpt="",
                completed=True,
                failure_reason=None,
                manifest_yaml="apiVersion: v1\nkind: Job\n",
            )

    adapter = _MixedAdapter()
    runner = SandboxRunner(adapter, registry=registry, max_parallel=1)  # type: ignore[arg-type]

    jobs = [_make_job() for _ in range(3)]
    results = asyncio.run(runner.dispatch_jobs(jobs))

    assert len(results) == len(jobs), "every job must produce a result"
    # First job hit the catch-all; the other two succeeded.
    assert results[0].completed is False
    assert results[0].failure_reason == "unexpected_error"
    assert all(r.completed for r in results[1:])
    assert all(r.failure_reason is None for r in results[1:])


def test_runner_logs_unexpected_failure_with_class_only(
    registry: _FakeRegistry,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """MED-3: structured log records the exception *class* (so SREs can
    recognise the bug) but never the rendered message string (which may
    embed secrets / paths / PII)."""
    adapter = _FakeAdapter(
        raises=ValueError,
        raise_kwargs={"message": "do-not-log-this-secret-9f2a"},
    )
    runner = SandboxRunner(adapter, registry=registry)  # type: ignore[arg-type]

    with caplog.at_level("ERROR", logger="src.sandbox.runner"):
        asyncio.run(runner.dispatch_jobs([_make_job()]))

    matching = [
        rec
        for rec in caplog.records
        if rec.getMessage() == "sandbox.runner.unexpected_failure"
    ]
    assert matching, "MED-3 unexpected-failure log record must be emitted"
    rec = matching[0]
    # Class IS in the structured payload (via ``extra``).
    assert getattr(rec, "error_class", None) == "ValueError"
    # Message MUST NOT carry the rendered exception text.
    for log_field in (rec.message, getattr(rec, "msg", "")):
        assert "do-not-log-this-secret-9f2a" not in str(log_field)


def test_runner_unexpected_constant_matches_adapter_taxonomy() -> None:
    """MED-3 + MED-2: the runner's local taxonomy constant MUST be one of the
    closed-taxonomy values exported by :mod:`src.sandbox.k8s_adapter`. This
    is an executable invariant — if anyone renames the adapter constant
    without touching the runner, this test breaks the build."""
    from src.sandbox.k8s_adapter import FAILURE_REASONS
    from src.sandbox.runner import _FAILURE_REASON_UNEXPECTED

    assert _FAILURE_REASON_UNEXPECTED == "unexpected_error"
    assert _FAILURE_REASON_UNEXPECTED in FAILURE_REASONS
