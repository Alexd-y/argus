"""WrbAgentDriver — the primary Cairn driver (no upstream equivalent).

Instead of shelling out to an external CLI agent, this runs a
:class:`~src.orchestration.react_agent.ReActAgent` over ``call_llm_unified``
(WhiteRabbitNeo) with a sandbox-backed tool executor. The agent's final answer is
the raw JSON the Cairn contract validators parse.

Both dependencies are injected via :class:`CairnTaskContext` so the driver is
decoupled from the facade and unit-testable with mocks. If no ``llm_caller`` is
available the driver fails closed (``RuntimeError``) — never a mock fallback.

"Same session" (upstream D-13 conclude fallback): WRB has no server-side session,
so a conclude re-invokes a fresh ReActAgent with the conclude prompt (which
explicitly overrides "keep working"). The prior trace is carried on the task run.
Documented in ``docs/cairn_port_deviations.md``.
"""

from __future__ import annotations

import uuid
from typing import Any

from src.cairn.workers.base import CairnTaskContext, CairnWorkerConfig, DriverResult
from src.cairn.workers.health import HealthResult, http_ping, proxy_from_env
from src.core.config import settings
from src.orchestration.react_agent import ReActAgent, ReActStep


def _step_to_dict(step: ReActStep) -> dict[str, Any]:
    return {
        "type": step.step_type.value,
        "content": step.content,
        "tool_name": step.tool_name,
        "tool_args": step.tool_args,
    }


class WrbAgentDriver:
    """In-process driver backed by ReActAgent + WhiteRabbitNeo."""

    type_name = "wrb"

    def supports_conclude(self) -> bool:
        return True

    def local_binary(self) -> str | None:
        return None

    async def prepare_session(self) -> str | None:
        return str(uuid.uuid4())

    async def check_health(self, worker: CairnWorkerConfig, *, timeout: float) -> HealthResult:
        """Reachability ping to the WRB endpoint (fail-closed when unconfigured)."""
        base = (getattr(settings, "whiterabbitneo_url", "") or "").rstrip("/")
        if not base:
            return HealthResult(ok=False, status=None, detail="WHITERABBITNEO_URL not set")
        model = getattr(settings, "whiterabbitneo_model", None) or "whiterabbitneo"
        return await http_ping(
            f"{base}/v1/chat/completions",
            headers={"content-type": "application/json"},
            json_body={
                "model": model,
                "max_tokens": 1,
                "messages": [{"role": "user", "content": "ping"}],
            },
            timeout=timeout,
            proxy=proxy_from_env(worker.env),
        )

    def describe_health(self, _worker: CairnWorkerConfig) -> str:
        base = (getattr(settings, "whiterabbitneo_url", "") or "").rstrip("/")
        return f"POST {base}/v1/chat/completions (WhiteRabbitNeo)"

    async def _run_agent(
        self, ctx: CairnTaskContext, prompt: str, session: str | None
    ) -> DriverResult:
        if ctx.llm_caller is None:
            raise RuntimeError("WrbAgentDriver requires an llm_caller (WRB unavailable)")
        agent = ReActAgent(
            task_description=prompt,
            max_iterations=ctx.max_iterations,
            confidence_threshold=ctx.confidence_threshold,
        )
        result = await agent.run(
            system_prompt="",
            llm_caller=ctx.llm_caller,
            tool_executor=ctx.tool_executor,
            scan_id=ctx.scan_id,
            require_tools=ctx.tool_executor is not None,
        )
        return DriverResult(
            text=result.answer,
            session=session or str(uuid.uuid4()),
            trace=[_step_to_dict(s) for s in result.steps],
            evidence_backed=result.evidence_backed,
        )

    async def execute(
        self, ctx: CairnTaskContext, prompt: str, session: str | None
    ) -> DriverResult:
        return await self._run_agent(ctx, prompt, session)

    async def conclude(self, ctx: CairnTaskContext, prompt: str, session: str) -> DriverResult:
        # Re-invoke with the conclude prompt; the prompt itself overrides "keep working".
        return await self._run_agent(ctx, prompt, session)

    def extract_session(self, session: str | None, _stdout: str, _stderr: str) -> str | None:
        return session

    def extract_response_text(self, stdout: str, _stderr: str) -> str:
        # In-process driver already returns the answer in DriverResult.text.
        return stdout


__all__ = ["WrbAgentDriver"]
