"""Role-specific agents for the ARGUS orchestrator (Backlog/dev1_md §17).

Five agents — :class:`PlannerAgent`, :class:`CriticAgent`,
:class:`VerifierAgent`, :class:`ReporterAgent`, :class:`FixerAgent` — each
own one prompt from the registry and one strict output contract:

* **Planner** → :class:`~src.orchestrator.schemas.loader.ValidationPlanV1`
* **Critic** → :class:`CriticVerdict`
* **Verifier** → ``list[FindingDTO]``
* **Reporter** → :class:`ReportNarrative`
* **Fixer** → ``dict[str, Any]`` (corrected JSON, re-validated by caller)

Why a base class?
-----------------
Every agent shares the same plumbing: render the prompt template, build an
:class:`~src.orchestrator.llm_provider.LLMRequest`, call the provider, and
parse the response into a typed Pydantic model. Subclasses override
:meth:`BaseAgent._parse_response` to plug their schema-specific validation.
The base class enforces the prompt-id ↔ role match at construction time so
a wiring mistake (passing a Critic prompt to a Planner agent) fails loudly.

Error semantics
---------------
* Schema-validation failures bubble up as :class:`AgentParseError`. The
  retry loop translates that into a Fixer invocation. ``AgentParseError``
  carries the malformed ``content`` and a sanitised error message so the
  Fixer prompt can be filled without leaking input values.
* Provider failures bubble up unchanged
  (:class:`~src.orchestrator.llm_provider.LLMProviderUnavailableError` etc.).
"""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from typing import Any, Final, cast
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictStr,
    ValidationError,
)

from src.oast.correlator import OASTInteraction
from src.orchestrator.llm_provider import (
    LLMProvider,
    LLMRequest,
    LLMResponse,
    ResponseFormat,
)
from src.orchestrator.prompt_registry import (
    AgentRole,
    PromptDefinition,
    PromptRegistry,
)
from src.orchestrator.schemas.loader import (
    ValidationPlanError,
    ValidationPlanV1,
    validate_validation_plan,
)
from src.pipeline.contracts.finding_dto import FindingDTO
from src.pipeline.contracts.phase_io import ScanPhase

_logger = logging.getLogger(__name__)


_MAX_FINDINGS_PER_VERIFIER_CALL: Final[int] = 32
_MAX_REASONS: Final[int] = 16
_MAX_RECOMMENDATIONS: Final[int] = 16


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class AgentError(Exception):
    """Base class for every error raised by the agent layer."""


class AgentParseError(AgentError):
    """Raised when an agent cannot validate the LLM response into its DTO.

    Attributes
    ----------
    field_path : str
        Best-effort JSON-pointer-like path to the offending field.
    reason : str
        Sanitised, payload-free error description.
    raw_content : str
        The original (possibly malformed) LLM response content. The Fixer
        agent consumes this verbatim so it can attempt repair.
    """

    def __init__(self, *, field_path: str, reason: str, raw_content: str) -> None:
        self.field_path = field_path
        self.reason = reason
        self.raw_content = raw_content
        super().__init__(f"agent parse failed at {field_path!r}: {reason}")


class AgentConfigError(AgentError):
    """Raised at construction time when an agent is wired incorrectly."""


# ---------------------------------------------------------------------------
# DTOs returned by specific agents
# ---------------------------------------------------------------------------


class CriticVerdict(BaseModel):
    """Output of :class:`CriticAgent` — review of a draft validation plan."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    approved: StrictBool
    reasons: list[StrictStr] = Field(default_factory=list, max_length=_MAX_REASONS)
    suggested_modifications: dict[str, Any] | None = None


class ReportNarrative(BaseModel):
    """Output of :class:`ReporterAgent` — human-readable summary block."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    executive_summary: StrictStr = Field(min_length=1, max_length=4000)
    technical_summary: StrictStr = Field(min_length=1, max_length=8000)
    recommendations: list[StrictStr] = Field(
        default_factory=list, max_length=_MAX_RECOMMENDATIONS
    )


class AgentContext(BaseModel):
    """Per-call execution envelope passed to every :meth:`BaseAgent.run`.

    Carries tenant / scan / phase identity (for the cost tracker and
    audit log) plus a snapshot of the previous findings the planner /
    verifier needs to reason about. Frozen so callers cannot mutate the
    snapshot mid-call.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: UUID
    scan_id: UUID
    phase: ScanPhase
    correlation_id: UUID
    previous_findings: list[FindingDTO] = Field(default_factory=list)
    target_summary: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Base agent
# ---------------------------------------------------------------------------


class BaseAgent(ABC):
    """Abstract base for every role-specific agent.

    Subclasses override :attr:`role` (class attribute) and
    :meth:`_parse_response`. The base class owns prompt rendering, LLM
    invocation, and metric / log emission.
    """

    role: AgentRole

    def __init__(
        self,
        provider: LLMProvider,
        registry: PromptRegistry,
        *,
        prompt_id: str,
    ) -> None:
        prompt = registry.get(prompt_id)
        if prompt.agent_role is not self.role:
            raise AgentConfigError(
                f"prompt_id={prompt_id!r} has role={prompt.agent_role.value} "
                f"but {type(self).__name__}.role={self.role.value}"
            )
        self._provider = provider
        self._registry = registry
        self._prompt_id = prompt_id
        self._prompt = prompt

    # -- public --------------------------------------------------------------

    @property
    def provider(self) -> LLMProvider:
        return self._provider

    @property
    def prompt_id(self) -> str:
        return self._prompt_id

    @property
    def prompt(self) -> PromptDefinition:
        return self._prompt

    async def call_raw(
        self,
        context: AgentContext,
        *,
        response_format: ResponseFormat | None = None,
        **kwargs: Any,
    ) -> LLMResponse:
        """Render the prompt with ``kwargs`` and dispatch to the provider.

        Subclasses' :meth:`_prepare_kwargs` hook is invoked first so the
        same context-derived defaults (phase, target_summary, …) apply
        whether the call originates from :meth:`run` or from the retry
        loop's direct :meth:`call_raw` path. Returned :class:`LLMResponse`
        is passed verbatim to subclasses; the orchestration layer (retry
        loop) inspects it for cost bookkeeping and ``parsed_json``
        presence before returning to :meth:`run`.
        """
        prepared = self._prepare_kwargs(context, dict(kwargs))
        request = self._build_request(
            context, response_format=response_format, **prepared
        )
        return await self._provider.call(request)

    async def run(
        self,
        context: AgentContext,
        **kwargs: Any,
    ) -> Any:
        """Render the prompt, call the LLM, and parse into the agent's DTO.

        Raises :class:`AgentParseError` when the response cannot be
        validated; the retry loop handles that path. Provider failures
        propagate unchanged.
        """
        response = await self.call_raw(context, **kwargs)
        return self._parse_response(response)

    # -- subclass hooks ------------------------------------------------------

    @abstractmethod
    def _parse_response(self, response: LLMResponse) -> Any:
        """Validate ``response`` into the agent's typed DTO.

        Subclasses raise :class:`AgentParseError` on any structural or
        semantic mismatch. The retry loop catches ``AgentParseError`` and
        invokes the Fixer agent.
        """

    def _prepare_kwargs(
        self,
        context: AgentContext,
        kwargs: dict[str, object],
    ) -> dict[str, object]:
        """Inject context-derived defaults into ``kwargs`` before rendering.

        Subclasses override to add agent-specific defaults (e.g. the
        Planner injects ``target_summary`` / ``phase`` from ``context``).
        Default implementation is a no-op so generic agents work without
        boilerplate. The base implementation MUST NOT mutate the caller's
        original mapping.
        """
        return kwargs

    def _expected_response_format(self) -> ResponseFormat:
        """Default JSON object output. Override for ``TEXT`` agents (none today)."""
        return ResponseFormat.JSON_OBJECT

    # -- helpers -------------------------------------------------------------

    def _build_request(
        self,
        context: AgentContext,
        *,
        response_format: ResponseFormat | None = None,
        **kwargs: Any,
    ) -> LLMRequest:
        format_hint = response_format or self._expected_response_format()
        rendered_user_prompt = _render_template(
            self._prompt.user_prompt_template, **kwargs
        )
        return LLMRequest(
            correlation_id=context.correlation_id,
            model_id=self._prompt.default_model_id,
            prompt_id=self._prompt_id,
            system_prompt=self._prompt.system_prompt,
            user_prompt=rendered_user_prompt,
            max_tokens=self._prompt.default_max_tokens,
            temperature=self._prompt.default_temperature,
            response_format=format_hint,
            expected_schema=None,
        )


def _render_template(template: str, **kwargs: Any) -> str:
    """Render ``template`` with ``str.format`` and friendly errors.

    The template uses Python's ``str.format`` syntax — ``{key}`` is
    substituted, ``{{`` / ``}}`` are literal braces. Missing keys raise
    :class:`AgentConfigError` (the prompt author asked for data the
    caller did not supply).
    """
    try:
        return template.format(**kwargs)
    except KeyError as exc:
        raise AgentConfigError(
            f"prompt template references missing placeholder {exc.args[0]!r}"
        ) from exc
    except (IndexError, ValueError) as exc:
        raise AgentConfigError(f"prompt template render failed: {exc}") from exc


def _require_parsed_json(response: LLMResponse) -> dict[str, Any]:
    """Return ``response.parsed_json`` or raise :class:`AgentParseError`.

    Used by every JSON-returning agent. The Fixer is the exception — it
    has its own narrower path because the parse error itself is the input.
    """
    if response.parsed_json is None:
        raise AgentParseError(
            field_path="<root>",
            reason="response is not valid JSON",
            raw_content=response.content,
        )
    return response.parsed_json


def _sanitize_pydantic_errors(exc: ValidationError) -> tuple[str, str]:
    """Project :class:`pydantic.ValidationError` to ``(field_path, reason)``.

    Strips ``input``/``ctx.input_value`` fields so the rejected payload
    never leaks back to the LLM (the Fixer prompt is fed the message
    only). Mirrors the helper in
    :mod:`src.orchestrator.schemas.loader` but is duplicated here to keep
    this module dependency-light.
    """
    items = exc.errors()
    if not items:
        return "<root>", type(exc).__name__
    first = items[0]
    loc = ".".join(str(p) for p in first.get("loc", ()) or ()) or "<root>"
    parts: list[str] = []
    for err in items:
        sub_loc = ".".join(str(p) for p in err.get("loc", ()) or ()) or "<root>"
        msg = str(err.get("msg", "")).strip() or "validation failed"
        err_type = str(err.get("type", "")).strip() or "unknown"
        parts.append(f"{sub_loc}: {msg} (type={err_type})")
    return loc, "; ".join(parts)


# ---------------------------------------------------------------------------
# Planner
# ---------------------------------------------------------------------------


class PlannerAgent(BaseAgent):
    """Generates a :class:`ValidationPlanV1` for the next pentest step."""

    role = AgentRole.PLANNER

    def _prepare_kwargs(
        self,
        context: AgentContext,
        kwargs: dict[str, object],
    ) -> dict[str, object]:
        """Inject phase, target_summary, and serialised previous findings."""
        kwargs.setdefault("phase", context.phase.value)
        kwargs.setdefault(
            "target_summary",
            json.dumps(context.target_summary, sort_keys=True, ensure_ascii=False),
        )
        kwargs.setdefault(
            "previous_findings",
            json.dumps(
                [
                    f.model_dump(mode="json", exclude_none=True)
                    for f in context.previous_findings
                ],
                sort_keys=True,
                ensure_ascii=False,
            ),
        )
        return kwargs

    async def run(
        self,
        context: AgentContext,
        **kwargs: Any,
    ) -> ValidationPlanV1:
        """Render planner prompt, call LLM, return the validated plan."""
        return cast(ValidationPlanV1, await super().run(context, **kwargs))

    def _parse_response(self, response: LLMResponse) -> ValidationPlanV1:
        parsed = _require_parsed_json(response)
        try:
            return validate_validation_plan(parsed)
        except ValidationPlanError as exc:
            raise AgentParseError(
                field_path=exc.field_path,
                reason=exc.reason,
                raw_content=response.content,
            ) from exc


# ---------------------------------------------------------------------------
# Critic
# ---------------------------------------------------------------------------


class CriticAgent(BaseAgent):
    """Reviews a draft :class:`ValidationPlanV1` for safety / cost / scope."""

    role = AgentRole.CRITIC

    def _prepare_kwargs(
        self,
        context: AgentContext,
        kwargs: dict[str, object],
    ) -> dict[str, object]:
        """Serialise ``plan_json`` + ``policy`` into the rendered template fields."""
        plan_json: object = kwargs.pop("plan_json", None)
        if plan_json is None:
            raise AgentConfigError(
                "CriticAgent.run requires a 'plan_json' keyword argument "
                "(serialised draft plan)"
            )
        if isinstance(plan_json, BaseModel):
            plan_repr = plan_json.model_dump_json()
        elif isinstance(plan_json, dict):
            plan_repr = json.dumps(plan_json, sort_keys=True, ensure_ascii=False)
        elif isinstance(plan_json, str):
            plan_repr = plan_json
        else:
            raise AgentConfigError(
                f"plan_json must be a Pydantic model, dict, or str; "
                f"got {type(plan_json).__name__}"
            )
        kwargs.setdefault("plan", plan_repr)
        kwargs.setdefault(
            "tenant_policy",
            json.dumps(kwargs.pop("policy", {}), sort_keys=True, ensure_ascii=False),
        )
        return kwargs

    async def run(
        self,
        context: AgentContext,
        **kwargs: Any,
    ) -> CriticVerdict:
        """Render critic prompt, call LLM, return the structured verdict."""
        return cast(CriticVerdict, await super().run(context, **kwargs))

    def _parse_response(self, response: LLMResponse) -> CriticVerdict:
        parsed = _require_parsed_json(response)
        try:
            return CriticVerdict.model_validate(parsed)
        except ValidationError as exc:
            field_path, reason = _sanitize_pydantic_errors(exc)
            raise AgentParseError(
                field_path=field_path,
                reason=reason,
                raw_content=response.content,
            ) from exc


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------


class VerifierAgent(BaseAgent):
    """Classifies tool output + OAST evidence into ``list[FindingDTO]``."""

    role = AgentRole.VERIFIER

    def _prepare_kwargs(
        self,
        context: AgentContext,
        kwargs: dict[str, object],
    ) -> dict[str, object]:
        """Serialise ``tool_output`` and ``oast_evidence`` into the template."""
        tool_output: object = kwargs.pop("tool_output", None)
        if tool_output is None:
            raise AgentConfigError(
                "VerifierAgent.run requires a 'tool_output' keyword argument"
            )
        oast_evidence = kwargs.pop("oast_evidence", None) or []
        if not isinstance(oast_evidence, list):
            raise AgentConfigError(
                "oast_evidence must be a list of OASTInteraction objects"
            )
        oast_repr = [
            (
                e.model_dump(mode="json", exclude_none=True)
                if isinstance(e, OASTInteraction)
                else dict(e)
                if isinstance(e, dict)
                else None
            )
            for e in oast_evidence
        ]
        kwargs.setdefault("phase", context.phase.value)
        kwargs.setdefault(
            "tool_output",
            json.dumps(tool_output, sort_keys=True, ensure_ascii=False, default=str),
        )
        kwargs.setdefault(
            "oast_evidence",
            json.dumps(oast_repr, sort_keys=True, ensure_ascii=False, default=str),
        )
        return kwargs

    async def run(
        self,
        context: AgentContext,
        **kwargs: Any,
    ) -> list[FindingDTO]:
        """Render verifier prompt, call LLM, return the parsed findings."""
        return cast(list[FindingDTO], await super().run(context, **kwargs))

    def _parse_response(self, response: LLMResponse) -> list[FindingDTO]:
        parsed = _require_parsed_json(response)
        findings_payload = parsed.get("findings")
        if not isinstance(findings_payload, list):
            raise AgentParseError(
                field_path="findings",
                reason="response.findings must be an array",
                raw_content=response.content,
            )
        if len(findings_payload) > _MAX_FINDINGS_PER_VERIFIER_CALL:
            raise AgentParseError(
                field_path="findings",
                reason=(
                    f"verifier returned {len(findings_payload)} findings; "
                    f"max is {_MAX_FINDINGS_PER_VERIFIER_CALL}"
                ),
                raw_content=response.content,
            )
        out: list[FindingDTO] = []
        for index, item in enumerate(findings_payload):
            if not isinstance(item, dict):
                raise AgentParseError(
                    field_path=f"findings[{index}]",
                    reason="each finding must be an object",
                    raw_content=response.content,
                )
            try:
                out.append(FindingDTO.model_validate(item))
            except ValidationError as exc:
                field_path, reason = _sanitize_pydantic_errors(exc)
                raise AgentParseError(
                    field_path=f"findings[{index}].{field_path}",
                    reason=reason,
                    raw_content=response.content,
                ) from exc
        return out


# ---------------------------------------------------------------------------
# Reporter
# ---------------------------------------------------------------------------


class ReporterAgent(BaseAgent):
    """Generates a :class:`ReportNarrative` from a list of findings."""

    role = AgentRole.REPORTER

    def _prepare_kwargs(
        self,
        context: AgentContext,
        kwargs: dict[str, object],
    ) -> dict[str, object]:
        """Serialise findings into the rendered ``{findings}`` placeholder."""
        findings: object = kwargs.pop("findings", None) or context.previous_findings
        if not isinstance(findings, list):
            raise AgentConfigError("findings must be a list of FindingDTO")
        findings_payload: list[dict[str, Any]] = []
        for f in findings:
            if isinstance(f, FindingDTO):
                findings_payload.append(f.model_dump(mode="json", exclude_none=True))
            elif isinstance(f, dict):
                findings_payload.append(f)
            else:
                raise AgentConfigError(
                    "every finding must be a FindingDTO or dict; got "
                    f"{type(f).__name__}"
                )
        kwargs.setdefault(
            "findings",
            json.dumps(
                findings_payload, sort_keys=True, ensure_ascii=False, default=str
            ),
        )
        return kwargs

    async def run(
        self,
        context: AgentContext,
        **kwargs: Any,
    ) -> ReportNarrative:
        """Render reporter prompt, call LLM, return the parsed narrative."""
        return cast(ReportNarrative, await super().run(context, **kwargs))

    def _parse_response(self, response: LLMResponse) -> ReportNarrative:
        parsed = _require_parsed_json(response)
        try:
            return ReportNarrative.model_validate(parsed)
        except ValidationError as exc:
            field_path, reason = _sanitize_pydantic_errors(exc)
            raise AgentParseError(
                field_path=field_path,
                reason=reason,
                raw_content=response.content,
            ) from exc


# ---------------------------------------------------------------------------
# Fixer
# ---------------------------------------------------------------------------


class FixerAgent(BaseAgent):
    """Repairs malformed JSON output from another agent.

    Inputs (via ``run`` kwargs):
    * ``original_content`` — the raw, malformed LLM response.
    * ``schema_errors`` — the sanitised error description (no input values).
    * ``schema_ref`` — string id of the target schema, e.g. ``validation_plan_v1``.

    Output: a ``dict[str, Any]`` parsed from the response. The retry loop
    re-runs the original agent's :meth:`_parse_response` against this dict.
    """

    role = AgentRole.FIXER

    def _prepare_kwargs(
        self,
        context: AgentContext,
        kwargs: dict[str, object],
    ) -> dict[str, object]:
        """Validate that the three Fixer-specific placeholders were supplied."""
        for required in ("original_content", "schema_errors", "schema_ref"):
            if required not in kwargs:
                raise AgentConfigError(
                    f"FixerAgent.run requires a {required!r} keyword argument"
                )
        return kwargs

    async def run(
        self,
        context: AgentContext,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Render fixer prompt, call LLM, return parsed corrected JSON."""
        return cast(dict[str, Any], await super().run(context, **kwargs))

    def _parse_response(self, response: LLMResponse) -> dict[str, Any]:
        parsed = _require_parsed_json(response)
        return parsed


__all__ = [
    "AgentConfigError",
    "AgentContext",
    "AgentError",
    "AgentParseError",
    "BaseAgent",
    "CriticAgent",
    "CriticVerdict",
    "FixerAgent",
    "PlannerAgent",
    "ReportNarrative",
    "ReporterAgent",
    "VerifierAgent",
]
