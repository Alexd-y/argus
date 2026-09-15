"""Wire the remediation runner to the production LLM facade.

Kept separate from :mod:`runner` so unit tests can exercise the orchestration
with an injected callable without importing the (heavy) facade/provider stack.
The runner stays provider-agnostic; production code calls
:func:`build_facade_llm_callable` to obtain a concrete callable.
"""

from __future__ import annotations

from src.llm.facade import call_llm_sync
from src.llm.task_router import LLMTask
from src.reports.llm_remediation.prompts import CLOSURE_SCHEMA_ID, REMEDIATION_SCHEMA_ID
from src.reports.llm_remediation.runner import LlmCallable

_KIND_TASK: dict[str, LLMTask] = {
    "remediation": LLMTask.REMEDIATION_PLAN,
    "closure": LLMTask.CLOSURE_ASSESSMENT,
    "summary": LLMTask.EXECUTIVE_SUMMARY,
}

_KIND_SCHEMA: dict[str, str | None] = {
    "remediation": REMEDIATION_SCHEMA_ID,
    "closure": CLOSURE_SCHEMA_ID,
    "summary": None,
}


def build_facade_llm_callable(
    *,
    scan_id: str | None = None,
    tenant_id: str | None = None,
    use_schema: bool = False,
) -> LlmCallable:
    """Return an :data:`LlmCallable` backed by ``call_llm_sync``.

    ``use_schema`` opts into gateway JSON-schema enforcement where a schema id
    is registered; otherwise the model returns free-form JSON that the runner
    validates against the Pydantic contract.
    """

    def _call(system_prompt: str, user_prompt: str, kind: str) -> str:
        task = _KIND_TASK.get(kind, LLMTask.REPORT_SECTION)
        schema_id = _KIND_SCHEMA.get(kind) if use_schema else None
        return call_llm_sync(
            system_prompt,
            user_prompt,
            task=task,
            scan_id=scan_id,
            phase="reporting",
            response_schema_id=schema_id,
            tenant_id=tenant_id,
        )

    return _call


__all__ = ["build_facade_llm_callable"]
