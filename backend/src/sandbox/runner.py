"""Multi-job dispatch wrapper around :class:`KubernetesSandboxAdapter`.

Implements concurrent execution with bounded parallelism + per-job timeout
handling so the control-plane can dispatch a phase's tool jobs in one
``await``. The runner does not own the adapter — callers pass an
already-configured :class:`KubernetesSandboxAdapter` so they can switch
between DRY_RUN and CLUSTER without re-wiring.

Single-purpose: this module is just an asyncio orchestration layer (gather +
semaphore + per-job try/except). All security guarantees live one layer down
in :mod:`src.sandbox.k8s_adapter`.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Iterable, Sequence
from typing import Final

from src.core.observability import (
    get_tracer,
    record_sandbox_run,
    safe_set_span_attribute,
)
from src.pipeline.contracts.tool_job import ToolJob
from src.sandbox.k8s_adapter import (
    ApprovalRequiredError,
    KubernetesSandboxAdapter,
    SandboxClusterError,
    SandboxConfigError,
    SandboxRunResult,
)
from src.sandbox.templating import TemplateRenderError
from src.sandbox.tool_registry import ToolRegistry


_logger = logging.getLogger(__name__)
_tracer = get_tracer("argus.sandbox")

#: Profile label used by ``argus_sandbox_runs_total``. K8s adapter is the
#: only production sandbox today; if other profiles (docker / local) ever
#: dispatch through this runner, switch to a per-adapter attribute.
_SANDBOX_PROFILE: Final[str] = "kubernetes"


def _result_status(result: SandboxRunResult, *, timed_out: bool) -> str:
    """Map a :class:`SandboxRunResult` into the sandbox metric status enum."""
    if timed_out:
        return "timeout"
    if not result.completed:
        return "error"
    if result.exit_code is not None and result.exit_code != 0:
        return "error"
    return "success"


_DEFAULT_MAX_PARALLEL: int = 4

# Closed-taxonomy failure_reason value used when an unexpected exception
# escapes the per-job try/except in :meth:`SandboxRunner._guarded_run`.
# MUST match :data:`src.sandbox.k8s_adapter._FAILURE_REASON_UNEXPECTED`;
# the test suite asserts both stay in sync.
_FAILURE_REASON_UNEXPECTED: Final[str] = "unexpected_error"


class SandboxRunner:
    """Dispatch many :class:`ToolJob` s through a single adapter.

    Parameters
    ----------
    adapter
        Configured :class:`KubernetesSandboxAdapter`. The runner reuses the
        adapter's mode / namespace / dry-run dir verbatim.
    registry
        :class:`ToolRegistry` used to resolve ``tool_id`` → descriptor.
        Passed separately so the control plane can pre-validate jobs
        without coupling to the adapter's internals.
    max_parallel
        Maximum number of jobs running concurrently. Defaults to 4 — keep
        it low because each job is a full Kubernetes Job + NetworkPolicy
        round-trip.
    per_job_timeout_s
        Wall-clock ceiling for one ``adapter.run`` call. ``None`` means rely
        entirely on ``ToolJob.timeout_s`` (translated into
        ``activeDeadlineSeconds`` by the adapter).
    """

    def __init__(
        self,
        adapter: KubernetesSandboxAdapter,
        *,
        registry: ToolRegistry,
        max_parallel: int = _DEFAULT_MAX_PARALLEL,
        per_job_timeout_s: int | None = None,
    ) -> None:
        if max_parallel <= 0:
            raise ValueError("max_parallel must be > 0")
        if per_job_timeout_s is not None and per_job_timeout_s <= 0:
            raise ValueError("per_job_timeout_s must be > 0 or None")
        self._adapter = adapter
        self._registry = registry
        self._max_parallel = max_parallel
        self._per_job_timeout_s = per_job_timeout_s

    async def dispatch_jobs(
        self, tool_jobs: Iterable[ToolJob]
    ) -> list[SandboxRunResult]:
        """Run every job and return results in the same order as the input.

        A failed job (config error, missing approval, template rejection,
        cluster failure) does not abort the batch — its result is appended
        with ``completed=False`` and a populated ``failure_reason`` so the
        caller can correlate failures back to their tool / scan.
        """
        jobs: Sequence[ToolJob] = list(tool_jobs)
        if not jobs:
            return []

        sem = asyncio.Semaphore(self._max_parallel)
        coroutines = [self._guarded_run(sem, job) for job in jobs]
        return await asyncio.gather(*coroutines)

    async def _guarded_run(
        self, sem: asyncio.Semaphore, tool_job: ToolJob
    ) -> SandboxRunResult:
        async with sem:
            start = time.perf_counter()
            timed_out = False
            with _tracer.start_as_current_span("sandbox.run") as span:
                safe_set_span_attribute(span, "argus.tool_id", tool_job.tool_id)
                safe_set_span_attribute(span, "argus.scan_id", str(tool_job.scan_id))
                safe_set_span_attribute(span, "argus.job_id", str(tool_job.id))
                try:
                    descriptor = self._registry.get(tool_job.tool_id)
                    if descriptor is None:
                        result = self._build_failure(
                            tool_job,
                            failure_reason=f"unknown tool_id {tool_job.tool_id!r}",
                        )
                    else:
                        try:
                            if self._per_job_timeout_s is not None:
                                result = await asyncio.wait_for(
                                    self._adapter.run(tool_job, descriptor),
                                    timeout=self._per_job_timeout_s,
                                )
                            else:
                                result = await self._adapter.run(
                                    tool_job, descriptor
                                )
                        except asyncio.TimeoutError:
                            timed_out = True
                            _logger.warning(
                                "sandbox.runner.timeout",
                                extra={
                                    "tool_id": tool_job.tool_id,
                                    "scan_id": str(tool_job.scan_id),
                                    "job_id": str(tool_job.id),
                                    "timeout_s": self._per_job_timeout_s,
                                },
                            )
                            result = self._build_failure(
                                tool_job,
                                failure_reason="runner-timeout",
                            )
                        except ApprovalRequiredError as exc:
                            result = self._build_failure(
                                tool_job, failure_reason=f"approval: {exc}"
                            )
                        except SandboxConfigError as exc:
                            result = self._build_failure(
                                tool_job, failure_reason=f"config: {exc}"
                            )
                        except SandboxClusterError as exc:
                            result = self._build_failure(
                                tool_job, failure_reason=f"cluster: {exc}"
                            )
                        except TemplateRenderError as exc:
                            result = self._build_failure(
                                tool_job, failure_reason=f"template: {exc.reason}"
                            )
                except Exception as exc:  # noqa: BLE001 — last-line-of-defence
                    # MED-3: unexpected exceptions (ValueError from the K8s SDK,
                    # pydantic ValidationError, KeyError, …) MUST NOT abort the
                    # batch; ``asyncio.gather`` would otherwise re-raise and
                    # cancel sibling jobs. Convert to a closed-taxonomy failure
                    # result so the runner contract — "a failed job does not
                    # abort the batch" — holds for ALL exception types.
                    _logger.error(
                        "sandbox.runner.unexpected_failure",
                        extra={
                            "tool_id": tool_job.tool_id,
                            "scan_id": str(tool_job.scan_id),
                            "job_id": str(tool_job.id),
                            # Class name only — never str(exc) (may echo
                            # ApiException body / secrets / paths).
                            "error_class": type(exc).__name__,
                        },
                    )
                    result = self._build_failure(
                        tool_job, failure_reason=_FAILURE_REASON_UNEXPECTED
                    )
                duration_seconds = max(0.0, time.perf_counter() - start)
                status = _result_status(result, timed_out=timed_out)
                safe_set_span_attribute(span, "argus.status", status)
                safe_set_span_attribute(
                    span, "argus.duration_seconds", round(duration_seconds, 4)
                )
                try:
                    record_sandbox_run(
                        tool_id=tool_job.tool_id,
                        status=status,
                        profile=_SANDBOX_PROFILE,
                        duration_seconds=duration_seconds,
                    )
                except Exception:  # pragma: no cover — defensive
                    _logger.debug("sandbox.runner.metrics_emit_failed", exc_info=True)
                return result

    @staticmethod
    def _build_failure(tool_job: ToolJob, *, failure_reason: str) -> SandboxRunResult:
        """Construct a placeholder result for a job that never reached the adapter."""
        return SandboxRunResult(
            job_name=f"argus-{tool_job.tool_id.replace('_', '-')}-{tool_job.id.hex[:8]}",
            namespace="(unscheduled)",
            exit_code=None,
            duration_seconds=0.0,
            artifacts=[],
            logs_excerpt="",
            completed=False,
            failure_reason=failure_reason[:128],
            manifest_yaml="# job rejected before manifest rendering\n",
        )


async def dispatch_jobs(
    tool_jobs: Iterable[ToolJob],
    *,
    adapter: KubernetesSandboxAdapter,
    registry: ToolRegistry,
    max_parallel: int = _DEFAULT_MAX_PARALLEL,
    per_job_timeout_s: int | None = None,
) -> list[SandboxRunResult]:
    """Top-level convenience wrapper around :class:`SandboxRunner`.

    Useful for one-off CLIs where building the runner is more boilerplate
    than helpful — production code should hold the runner so the semaphore
    lifetime spans many dispatches.
    """
    start = time.monotonic()
    runner = SandboxRunner(
        adapter,
        registry=registry,
        max_parallel=max_parallel,
        per_job_timeout_s=per_job_timeout_s,
    )
    results = await runner.dispatch_jobs(tool_jobs)
    _logger.info(
        "sandbox.runner.batch_done",
        extra={
            "total": len(results),
            "completed": sum(1 for r in results if r.completed),
            "duration_s": time.monotonic() - start,
        },
    )
    return results


__all__ = [
    "SandboxRunner",
    "dispatch_jobs",
]
