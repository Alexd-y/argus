"""Adaptive planner→critic→executor→verifier orchestration loop (overhaul §6).

Replaces the rigid "run all 8 phases in a fixed line" model with a feedback
loop driven by the runtime :class:`~src.orchestration.graph.AssetGraph`:

    plan → critic → execute → verify → update-graph → repeat

Each iteration the **planner** proposes next actions from the current graph
(untested surfaces), the **critic** prunes duplicates / budget violations, the
**executor** runs the action, the **verifier** classifies the evidence, and the
graph is updated (the acted node is marked tested) so coverage advances and the
loop terminates deterministically.

Design (KISS + SOLID + testability):
* Roles are :class:`typing.Protocol`s so the loop is agnostic to *how* actions
  are planned / executed / verified — plug the signed :func:`run_signed_tool`
  executor + the ``llm_orchestrator`` agents in production, or trivial mocks in
  tests.
* A dependency-free :class:`DeterministicPlanner` + :class:`DedupCritic` make the
  loop fully functional WITHOUT an LLM (safe default; also the test harness).
* Termination is guaranteed: every executed node is recorded, so the loop stops
  on budget (max actions), coverage target, or when no new actions remain.

Opt-in via ``settings.argus_adaptive_loop`` (default off): the linear
:mod:`state_machine` FSM is unchanged unless the flag routes a scan here.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

from src.orchestration.graph import AssetGraph, AssetNode, AssetNodeType
from src.orchestration.graph_builders import coverage_metrics

logger = logging.getLogger(__name__)

# Max characters of executor output retained per action record (bounds memory and
# keeps timeline/finding evidence snippets reasonable).
_EVIDENCE_SNIPPET_LIMIT = 2000


def _evidence_snippet(result: ExecResult) -> str:
    """Bounded evidence snippet from an execution result (stdout preferred)."""
    raw = result.stdout.strip() or result.stderr.strip()
    return raw[:_EVIDENCE_SNIPPET_LIMIT]


class VerifyOutcome(StrEnum):
    """Verifier classification of an executed action's evidence."""

    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True, slots=True)
class ActionProposal:
    """A single next action the planner wants to run against a graph node."""

    node_id: str
    tool: str
    target: str
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ExecResult:
    """Raw execution result handed to the verifier."""

    proposal: ActionProposal
    exit_code: int
    stdout: str = ""
    stderr: str = ""


@dataclass(frozen=True, slots=True)
class ActionRecord:
    """One completed plan→execute→verify step in the loop trace.

    ``evidence`` is a truncated snippet of the executor's output, retained so the
    artifact layer (:mod:`src.orchestration.adaptive_artifacts`) can turn confirmed
    records into findings with real evidence. It defaults to "" so existing
    constructions stay valid.
    """

    proposal: ActionProposal
    outcome: VerifyOutcome
    exit_code: int
    evidence: str = ""


@dataclass(slots=True)
class LoopBudget:
    """Termination bounds for the loop.

    ``max_actions`` caps total executed actions; ``target_parameter_coverage``
    (0.0–1.0) stops the loop once that fraction of PARAMETER nodes is tested.
    """

    max_actions: int = 50
    target_parameter_coverage: float = 1.0

    def __post_init__(self) -> None:
        self.max_actions = max(1, int(self.max_actions))
        self.target_parameter_coverage = min(1.0, max(0.0, float(self.target_parameter_coverage)))


@dataclass(slots=True)
class LoopReport:
    """Outcome of an adaptive-loop run."""

    actions_run: int
    confirmed: int
    rejected: int
    inconclusive: int
    stopped_reason: str
    coverage: dict[str, float | int]
    trace: list[ActionRecord]


@runtime_checkable
class Planner(Protocol):
    """Proposes next actions from the current asset graph."""

    def propose(self, graph: AssetGraph) -> list[ActionProposal]: ...


@runtime_checkable
class Critic(Protocol):
    """Prunes / reorders proposals (dedup, budget, RoE)."""

    def review(
        self, proposals: list[ActionProposal], graph: AssetGraph
    ) -> list[ActionProposal]: ...


@runtime_checkable
class Executor(Protocol):
    """Runs a proposed action and returns the raw result."""

    async def execute(self, proposal: ActionProposal) -> ExecResult: ...


@runtime_checkable
class Verifier(Protocol):
    """Classifies an execution result into a :class:`VerifyOutcome`."""

    def verify(self, result: ExecResult) -> VerifyOutcome: ...


class DeterministicPlanner:
    """LLM-free planner: propose one action per untested PARAMETER node.

    ``tool_resolver`` maps a node to the tool to run (return ``None`` to skip the
    node); ``target_resolver`` maps a node to the target string. Both default to
    reading the node's own properties, so the loop works out-of-the-box on a
    graph populated by :func:`~src.orchestration.graph_builders.build_asset_graph_from_surfaces`.
    """

    def __init__(
        self,
        tool_resolver: Callable[[AssetNode], str | None],
        target_resolver: Callable[[AssetNode], str] | None = None,
        *,
        node_type: AssetNodeType = AssetNodeType.PARAMETER,
    ) -> None:
        self._tool_resolver = tool_resolver
        self._target_resolver = target_resolver or (lambda n: str(n.properties.get("url", "")))
        self._node_type = node_type

    def propose(self, graph: AssetGraph) -> list[ActionProposal]:
        proposals: list[ActionProposal] = []
        for node in graph.untested(self._node_type):
            tool = self._tool_resolver(node)
            target = self._target_resolver(node)
            if not tool or not target:
                continue
            proposals.append(
                ActionProposal(
                    node_id=node.node_id,
                    tool=tool,
                    target=target,
                    reason=f"untested {self._node_type.value}",
                    metadata=dict(node.properties),
                )
            )
        return proposals


class DedupCritic:
    """Drops proposals for nodes already acted on this run + duplicate node_ids."""

    def __init__(self) -> None:
        self._acted: set[str] = set()

    def mark_acted(self, node_id: str) -> None:
        self._acted.add(node_id)

    def review(self, proposals: list[ActionProposal], _graph: AssetGraph) -> list[ActionProposal]:
        # ``_graph`` is part of the Critic protocol (RoE-aware critics use it); this
        # dedup-only critic intentionally ignores it.
        seen: set[str] = set()
        out: list[ActionProposal] = []
        for p in proposals:
            if p.node_id in self._acted or p.node_id in seen:
                continue
            seen.add(p.node_id)
            out.append(p)
        return out


async def run_adaptive_loop(
    *,
    graph: AssetGraph,
    planner: Planner,
    executor: Executor,
    verifier: Verifier,
    critic: Critic | None = None,
    budget: LoopBudget | None = None,
) -> LoopReport:
    """Drive the plan→critic→execute→verify→update-graph loop to termination.

    Terminates on: coverage target reached, budget (max actions) exhausted, or no
    new actions proposed. Every executed node is marked tested on the graph, so
    progress is monotonic and the loop cannot spin forever.
    """
    budget = budget or LoopBudget()
    critic = critic or DedupCritic()
    trace: list[ActionRecord] = []
    tally: dict[VerifyOutcome, int] = {
        VerifyOutcome.CONFIRMED: 0,
        VerifyOutcome.REJECTED: 0,
        VerifyOutcome.INCONCLUSIVE: 0,
    }
    acted: set[str] = set()
    stopped_reason = "no_more_actions"

    while len(trace) < budget.max_actions:
        params = graph.nodes_by_type(AssetNodeType.PARAMETER)
        if params and coverage_metrics(graph)["parameter_coverage"] >= (
            budget.target_parameter_coverage
        ):
            stopped_reason = "coverage_target_reached"
            break

        proposals = critic.review(planner.propose(graph), graph)
        proposals = [p for p in proposals if p.node_id not in acted]
        if not proposals:
            stopped_reason = "no_more_actions"
            break

        proposal = proposals[0]
        result = await executor.execute(proposal)
        outcome = verifier.verify(result)
        trace.append(
            ActionRecord(
                proposal=proposal,
                outcome=outcome,
                exit_code=result.exit_code,
                evidence=_evidence_snippet(result),
            )
        )
        tally[outcome] += 1
        acted.add(proposal.node_id)
        if isinstance(critic, DedupCritic):
            critic.mark_acted(proposal.node_id)
        if graph.has_node(proposal.node_id):
            graph.mark_tested(proposal.node_id)
    else:
        stopped_reason = "budget_exhausted"

    logger.info(
        "adaptive_loop_complete",
        extra={
            "event": "adaptive_loop_complete",
            "actions_run": len(trace),
            "stopped_reason": stopped_reason,
        },
    )
    return LoopReport(
        actions_run=len(trace),
        confirmed=tally[VerifyOutcome.CONFIRMED],
        rejected=tally[VerifyOutcome.REJECTED],
        inconclusive=tally[VerifyOutcome.INCONCLUSIVE],
        stopped_reason=stopped_reason,
        coverage=coverage_metrics(graph),
        trace=trace,
    )


__all__ = [
    "ActionProposal",
    "ActionRecord",
    "Critic",
    "DedupCritic",
    "DeterministicPlanner",
    "ExecResult",
    "Executor",
    "LoopBudget",
    "LoopReport",
    "Planner",
    "Verifier",
    "VerifyOutcome",
    "run_adaptive_loop",
]
