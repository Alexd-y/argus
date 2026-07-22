"""Applicability planner for playbooks (P2-PLAYBOOKS-002 skeleton).

The full ``ScenarioPlanner`` (prioritisation, dedup, budget, approval routing)
arrives in P4. This module provides the stable interface plus a **working**
minimal implementation: given an :class:`ApplicabilityContext` describing one
endpoint, it filters the registered playbooks by their declarative
``applies_when`` / ``required_principals`` / ``required_capabilities`` and
emits a :class:`PlannedScenario` for each — ``PLANNED`` when applicable,
``SKIPPED_NOT_APPLICABLE`` (with a concrete reason) otherwise.

There are no ``TODO``/``pass`` placeholders: the applicability logic is real
and unit-tested. P4 layers scheduling on top of these decisions.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Final

from pydantic import BaseModel, ConfigDict, StrictStr

from src.playbooks.lifecycle import ScenarioState, ScenarioStatus
from src.playbooks.schema import (
    ActionType,
    AppliesWhen,
    HttpMethod,
    InputKind,
    OracleType,
    Playbook,
)

# Action types with a real interpreter wired in :mod:`src.playbooks.actions`.
# ``browser_action`` has no execution backend yet, so a playbook that needs it
# is not applicable until a browser transport is available.
_EXECUTABLE_ACTIONS_DEFAULT: Final[frozenset[ActionType]] = frozenset(
    {
        ActionType.HTTP_REQUEST,
        ActionType.EXTRACT,
        ActionType.COMPARE,
        ActionType.WAIT,
        ActionType.REGISTER_CLEANUP,
    }
)

# Oracle types with a real, wired evaluation backend (all six as of P4).
_IMPLEMENTED_ORACLES: Final[frozenset[OracleType]] = frozenset(OracleType)


@dataclass(frozen=True)
class ApplicabilityContext:
    """Describes one endpoint / asset the planner evaluates playbooks against."""

    method: HttpMethod
    path: str
    has_openapi: bool = False
    input_kinds: frozenset[InputKind] = field(default_factory=frozenset)
    available_principals: frozenset[str] = field(default_factory=frozenset)
    available_capabilities: frozenset[str] = field(default_factory=frozenset)


class PlannedScenario(BaseModel):
    """A playbook decision for one context: PLANNED or SKIPPED_NOT_APPLICABLE."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    playbook_id: StrictStr
    title: StrictStr
    state: ScenarioState

    @property
    def status(self) -> ScenarioStatus:
        return self.state.status

    @property
    def is_planned(self) -> bool:
        return self.state.status is ScenarioStatus.PLANNED


def _applicability_reason(applies: AppliesWhen, ctx: ApplicabilityContext) -> str | None:
    """Return ``None`` if applicable, else a concrete not-applicable reason."""
    if applies.methods and ctx.method not in applies.methods:
        allowed = ", ".join(sorted(m.value for m in applies.methods))
        return f"method {ctx.method.value} not in applies_when.methods ({allowed})"
    if applies.path_globs and not any(fnmatchcase(ctx.path, glob) for glob in applies.path_globs):
        return f"path {ctx.path!r} matched none of applies_when.path_globs"
    if applies.requires_openapi and not ctx.has_openapi:
        return "playbook requires an OpenAPI spec but none is available"
    if applies.input_kinds and not (set(applies.input_kinds) & ctx.input_kinds):
        wanted = ", ".join(sorted(k.value for k in applies.input_kinds))
        return f"none of the required input_kinds present ({wanted})"
    return None


def _capability_reason(playbook: Playbook, ctx: ApplicabilityContext) -> str | None:
    missing_caps = sorted(set(playbook.required_capabilities) - ctx.available_capabilities)
    if missing_caps:
        return f"missing required capabilities: {', '.join(missing_caps)}"
    missing_principals = sorted(set(playbook.required_principals) - ctx.available_principals)
    if missing_principals:
        return f"missing required principals: {', '.join(missing_principals)}"
    return None


class PlaybookPlanner:
    """Selects applicable playbooks for a given context (P2 skeleton)."""

    def __init__(self, playbooks: Iterable[Playbook]) -> None:
        # Deterministic order: by playbook_id so plans are reproducible.
        self._playbooks: tuple[Playbook, ...] = tuple(
            sorted(playbooks, key=lambda p: p.playbook_id)
        )

    @property
    def playbooks(self) -> tuple[Playbook, ...]:
        return self._playbooks

    def select(self, context: ApplicabilityContext) -> list[PlannedScenario]:
        """Return one :class:`PlannedScenario` per playbook for ``context``.

        Each scenario starts at ``DISCOVERED`` and transitions to either
        ``PLANNED`` (applicable) or ``SKIPPED_NOT_APPLICABLE`` (with reason).
        """
        scenarios: list[PlannedScenario] = []
        for playbook in self._playbooks:
            scenarios.append(self._plan_one(playbook, context))
        return scenarios

    def planned_only(self, context: ApplicabilityContext) -> list[PlannedScenario]:
        """Convenience filter: only the scenarios that reached ``PLANNED``."""
        return [s for s in self.select(context) if s.is_planned]

    def _plan_one(self, playbook: Playbook, context: ApplicabilityContext) -> PlannedScenario:
        discovered = ScenarioState.initial()
        reason = _applicability_reason(playbook.applies_when, context)
        if reason is None:
            reason = _capability_reason(playbook, context)

        if reason is None:
            state = discovered.transition(ScenarioStatus.PLANNED)
        else:
            state = discovered.transition(ScenarioStatus.SKIPPED_NOT_APPLICABLE, reason=reason)
        return PlannedScenario(
            playbook_id=playbook.playbook_id,
            title=playbook.title,
            state=state,
        )


def select_for_contexts(
    playbooks: Iterable[Playbook], contexts: Sequence[ApplicabilityContext]
) -> dict[str, list[PlannedScenario]]:
    """Plan every context against ``playbooks``; keyed by ``"{method} {path}"``."""
    planner = PlaybookPlanner(playbooks)
    return {f"{ctx.method.value} {ctx.path}": planner.select(ctx) for ctx in contexts}


# ---------------------------------------------------------------------------
# ScenarioPlanner (P4) — full applicability + approval routing
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EndpointContext:
    """One discovered endpoint the scenario planner evaluates playbooks against."""

    method: HttpMethod
    path: str
    has_openapi: bool = False
    input_kinds: frozenset[InputKind] = field(default_factory=frozenset)


@dataclass(frozen=True)
class ScenarioPlanningContext:
    """Scan-wide inputs the :class:`ScenarioPlanner` needs to build a plan.

    The planner selects only *applicable* playbooks: the endpoint matches
    ``applies_when``; the required principals + capabilities are available; a
    real executor exists for every step action; every assertion oracle is
    implemented. Approval-gated playbooks are routed — ``WAITING_APPROVAL``
    (never a silent skip) unless pre-authorized by the EAP or a manual approval
    is already on file.

    The ``is_preauthorized`` / ``has_manual_approval`` predicates keep crypto /
    persistence out of the pure planner.
    """

    endpoints: Sequence[EndpointContext]
    available_principals: frozenset[str] = field(default_factory=frozenset)
    available_capabilities: frozenset[str] = field(default_factory=frozenset)
    available_action_types: frozenset[ActionType] = _EXECUTABLE_ACTIONS_DEFAULT
    is_preauthorized: Callable[[Playbook], bool] | None = None
    has_manual_approval: Callable[[Playbook], bool] | None = None
    # Descriptive metadata (roles / tenants / scope / scan profile) — carried
    # for downstream consumers and audit; not part of the selection algorithm.
    roles: frozenset[str] = field(default_factory=frozenset)
    tenants: frozenset[str] = field(default_factory=frozenset)
    scope_targets: tuple[str, ...] = ()
    scan_profile: str | None = None


def _executor_reason(
    playbook: Playbook, available_action_types: frozenset[ActionType]
) -> str | None:
    missing = sorted(
        {step.action.value for step in playbook.steps if step.action not in available_action_types}
    )
    if missing:
        return f"no executor available for action type(s): {', '.join(missing)}"
    return None


def _oracle_reason(playbook: Playbook) -> str | None:
    missing = sorted(
        {a.type.value for a in playbook.assertions if a.type not in _IMPLEMENTED_ORACLES}
    )
    if missing:
        return f"assertion oracle(s) not implemented: {', '.join(missing)}"
    return None


class ScenarioPlanner:
    """Select and route playbooks into scenarios for a whole scan (P4).

    Unlike the stateless :class:`PlaybookPlanner` (single-endpoint
    applicability), :class:`ScenarioPlanner` evaluates every discovered
    endpoint against every playbook and adds executor-availability and
    approval-routing gates on top of pure applicability.
    """

    def __init__(self, playbooks: Iterable[Playbook]) -> None:
        self._playbooks: tuple[Playbook, ...] = tuple(
            sorted(playbooks, key=lambda p: p.playbook_id)
        )

    @property
    def playbooks(self) -> tuple[Playbook, ...]:
        return self._playbooks

    def plan(self, context: ScenarioPlanningContext) -> list[PlannedScenario]:
        """Return one :class:`PlannedScenario` per (endpoint, playbook) pair."""
        scenarios: list[PlannedScenario] = []
        for endpoint in context.endpoints:
            app_ctx = ApplicabilityContext(
                method=endpoint.method,
                path=endpoint.path,
                has_openapi=endpoint.has_openapi,
                input_kinds=endpoint.input_kinds,
                available_principals=context.available_principals,
                available_capabilities=context.available_capabilities,
            )
            for playbook in self._playbooks:
                scenarios.append(self._plan_one(playbook, app_ctx, context))
        return scenarios

    def planned_only(self, context: ScenarioPlanningContext) -> list[PlannedScenario]:
        return [s for s in self.plan(context) if s.is_planned]

    def _plan_one(
        self,
        playbook: Playbook,
        app_ctx: ApplicabilityContext,
        context: ScenarioPlanningContext,
    ) -> PlannedScenario:
        discovered = ScenarioState.initial()

        reason = _applicability_reason(playbook.applies_when, app_ctx)
        if reason is None:
            reason = _capability_reason(playbook, app_ctx)
        if reason is None:
            reason = _executor_reason(playbook, context.available_action_types)
        if reason is None:
            reason = _oracle_reason(playbook)

        if reason is not None:
            state = discovered.transition(ScenarioStatus.SKIPPED_NOT_APPLICABLE, reason=reason)
            return PlannedScenario(
                playbook_id=playbook.playbook_id, title=playbook.title, state=state
            )

        planned = discovered.transition(ScenarioStatus.PLANNED)
        if playbook.requires_approval:
            preauthorized = context.is_preauthorized is not None and context.is_preauthorized(
                playbook
            )
            has_manual = context.has_manual_approval is not None and context.has_manual_approval(
                playbook
            )
            if not (preauthorized or has_manual):
                waiting = planned.transition(
                    ScenarioStatus.WAITING_APPROVAL,
                    reason=(
                        "playbook requires approval; not pre-authorized by an "
                        "Engagement Authorization Profile and no manual approval on file"
                    ),
                )
                return PlannedScenario(
                    playbook_id=playbook.playbook_id, title=playbook.title, state=waiting
                )
        return PlannedScenario(
            playbook_id=playbook.playbook_id, title=playbook.title, state=planned
        )


__all__ = [
    "ApplicabilityContext",
    "EndpointContext",
    "PlannedScenario",
    "PlaybookPlanner",
    "ScenarioPlanner",
    "ScenarioPlanningContext",
    "select_for_contexts",
]
