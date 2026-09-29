"""Wire the remediation runner to the production LLM facade.

Kept separate from :mod:`runner` so unit tests can exercise the orchestration
with an injected callable without importing the (heavy) facade/provider stack.
The runner stays provider-agnostic; production code calls
:func:`build_facade_llm_callable` to obtain a concrete callable and
:func:`resolve_report_llm_identity` to record the *real* provider/model in
provenance instead of the ``report_writer`` alias (prompt §28.3, R-02).
"""

from __future__ import annotations

from dataclasses import dataclass

from src.core.config import settings
from src.llm.facade import _cloud_fallback_allowed, call_llm_sync
from src.llm.registry import get_unified_registry
from src.llm.task_router import LLMTask
from src.reports.llm_remediation.prompts import CLOSURE_SCHEMA_ID, REMEDIATION_SCHEMA_ID
from src.reports.llm_remediation.runner import LlmCallable, LlmNotInvokedError

REPORT_LLM_ALIAS = "report_writer"

_KIND_TASK: dict[str, LLMTask] = {
    "remediation": LLMTask.REMEDIATION_PLAN,
    "closure": LLMTask.CLOSURE_ASSESSMENT,
    "summary": LLMTask.EXECUTIVE_SUMMARY,
    "probe": LLMTask.REPORT_SECTION,
}

_KIND_SCHEMA: dict[str, str | None] = {
    "remediation": REMEDIATION_SCHEMA_ID,
    "closure": CLOSURE_SCHEMA_ID,
    "summary": None,
    "probe": None,
}


@dataclass(frozen=True)
class ReportLlmIdentity:
    """The concrete provider/model the facade is expected to use for report tasks."""

    provider_id: str
    model: str
    route: str  # "wrb_first" | "alias:report_writer" | "cloud_fallback"


def resolve_report_llm_identity() -> ReportLlmIdentity | None:
    """Resolve the real provider/model for report tasks, or ``None`` if none is usable.

    Mirrors the facade routing: with the unified gateway on, the first configured
    model of the ``report_writer`` alias chain; otherwise WhiteRabbitNeo first when
    configured, then the first configured cloud model of the chain — only when the
    cloud report carve-out allows it. ``None`` means the LLM phase cannot be invoked.
    """
    registry = get_unified_registry()
    cloud_ok = _cloud_fallback_allowed(LLMTask.REMEDIATION_PLAN)
    chain = registry.aliases.resolve_models(REPORT_LLM_ALIAS)

    def _usable(record) -> bool:  # noqa: ANN001 - ModelRecord
        return record.is_configured and (cloud_ok or not record.cloud)

    if getattr(settings, "argus_unified_llm_gateway", False):
        for record in chain:
            if _usable(record):
                return ReportLlmIdentity(
                    record.provider_id, record.model, f"alias:{REPORT_LLM_ALIAS}"
                )
        return None

    wrb = registry.providers.get("local_wrb")
    if wrb is not None and wrb.is_configured:
        return ReportLlmIdentity(wrb.provider_id, wrb.model, "wrb_first")
    for record in chain:
        if record.cloud and _usable(record):
            return ReportLlmIdentity(record.provider_id, record.model, "cloud_fallback")
    return None


def build_facade_llm_callable(
    *,
    scan_id: str | None = None,
    tenant_id: str | None = None,
    use_schema: bool = False,
    fail_if_unconfigured: bool = False,
) -> LlmCallable:
    """Return an :data:`LlmCallable` backed by ``call_llm_sync``.

    ``use_schema`` opts into gateway JSON-schema enforcement where a schema id
    is registered; otherwise the model returns free-form JSON that the runner
    validates against the Pydantic contract. With ``fail_if_unconfigured`` the
    callable raises :class:`LlmNotInvokedError` up front when no report provider
    is usable, so the release records ``llm_not_invoked`` with the real reason.
    """
    identity = resolve_report_llm_identity() if fail_if_unconfigured else None

    def _call(system_prompt: str, user_prompt: str, kind: str) -> str:
        if fail_if_unconfigured and identity is None:
            raise LlmNotInvokedError(
                f"no usable provider for alias {REPORT_LLM_ALIAS}: WhiteRabbitNeo not "
                "configured and no cloud report provider is configured/allowed "
                "(check WHITERABBITNEO_URL, *_API_KEY, llm_cloud_enabled_for_reports)"
            )
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


__all__ = [
    "REPORT_LLM_ALIAS",
    "ReportLlmIdentity",
    "build_facade_llm_callable",
    "resolve_report_llm_identity",
]
