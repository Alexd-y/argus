"""Unit tests for the adaptive planner→critic→executor→verifier loop."""

from __future__ import annotations

from src.orchestration.adaptive_loop import (
    ActionProposal,
    DedupCritic,
    DeterministicPlanner,
    ExecResult,
    LoopBudget,
    VerifyOutcome,
    run_adaptive_loop,
)
from src.orchestration.graph import AssetGraph, AssetNodeType
from src.orchestration.graph_builders import build_asset_graph_from_surfaces
from src.recon.vulnerability_analysis.active_scan.input_surface_inventory import (
    InputSurfaceInventory,
    InputSurfaceItem,
)


def _graph(n: int) -> AssetGraph:
    items = [
        InputSurfaceItem(
            surface_id=f"s{i}",
            url=f"http://app.test/p{i}?q={i}",
            method="GET",
            param_name=f"q{i}",
            location="query",
        )
        for i in range(n)
    ]
    return build_asset_graph_from_surfaces(InputSurfaceInventory(items=items))


class _Executor:
    def __init__(self, exit_code: int = 0) -> None:
        self._exit_code = exit_code
        self.calls: list[ActionProposal] = []

    async def execute(self, proposal: ActionProposal) -> ExecResult:
        self.calls.append(proposal)
        return ExecResult(proposal=proposal, exit_code=self._exit_code)


class _Verifier:
    def verify(self, result: ExecResult) -> VerifyOutcome:
        return VerifyOutcome.CONFIRMED if result.exit_code == 0 else VerifyOutcome.REJECTED


class TestDeterministicPlanner:
    def test_proposes_for_untested_params(self) -> None:
        g = _graph(3)
        planner = DeterministicPlanner(tool_resolver=lambda _n: "nuclei")
        proposals = planner.propose(g)
        assert len(proposals) == 3
        assert all(p.tool == "nuclei" for p in proposals)
        assert all(p.target.startswith("http://app.test/") for p in proposals)

    def test_skips_when_tool_none(self) -> None:
        g = _graph(2)
        planner = DeterministicPlanner(tool_resolver=lambda _n: None)
        assert planner.propose(g) == []


class TestDedupCritic:
    def test_drops_acted_and_duplicates(self) -> None:
        g = _graph(1)
        critic = DedupCritic()
        p = ActionProposal(node_id="n1", tool="nuclei", target="http://x")
        assert critic.review([p, p], g) == [p]  # duplicate collapsed
        critic.mark_acted("n1")
        assert critic.review([p], g) == []  # acted → dropped


class TestRunAdaptiveLoop:
    async def test_full_coverage_then_stops(self) -> None:
        g = _graph(3)
        ex = _Executor(exit_code=0)
        report = await run_adaptive_loop(
            graph=g,
            planner=DeterministicPlanner(tool_resolver=lambda _n: "nuclei"),
            executor=ex,
            verifier=_Verifier(),
        )
        assert report.actions_run == 3
        assert report.confirmed == 3
        assert report.stopped_reason == "coverage_target_reached"
        assert report.coverage["parameter_coverage"] == 1.0
        # graph updated: all params tested.
        assert all(n.tested for n in g.nodes_by_type(AssetNodeType.PARAMETER))

    async def test_budget_caps_actions(self) -> None:
        g = _graph(10)
        ex = _Executor(exit_code=0)
        report = await run_adaptive_loop(
            graph=g,
            planner=DeterministicPlanner(tool_resolver=lambda _n: "nuclei"),
            executor=ex,
            verifier=_Verifier(),
            budget=LoopBudget(max_actions=4),
        )
        assert report.actions_run == 4
        assert report.stopped_reason == "budget_exhausted"
        assert len(ex.calls) == 4

    async def test_no_actions_when_no_tool(self) -> None:
        g = _graph(3)
        report = await run_adaptive_loop(
            graph=g,
            planner=DeterministicPlanner(tool_resolver=lambda _n: None),
            executor=_Executor(),
            verifier=_Verifier(),
        )
        assert report.actions_run == 0
        assert report.stopped_reason == "no_more_actions"

    async def test_rejected_outcome_tallied(self) -> None:
        g = _graph(2)
        report = await run_adaptive_loop(
            graph=g,
            planner=DeterministicPlanner(tool_resolver=lambda _n: "nuclei"),
            executor=_Executor(exit_code=1),
            verifier=_Verifier(),
            budget=LoopBudget(target_parameter_coverage=1.0),
        )
        assert report.rejected == 2
        assert report.confirmed == 0
        # still marks tested (coverage advances regardless of verdict).
        assert report.coverage["parameter_coverage"] == 1.0

    async def test_partial_coverage_target(self) -> None:
        g = _graph(4)
        report = await run_adaptive_loop(
            graph=g,
            planner=DeterministicPlanner(tool_resolver=lambda _n: "nuclei"),
            executor=_Executor(),
            verifier=_Verifier(),
            budget=LoopBudget(target_parameter_coverage=0.5),
        )
        # Stops once ≥50% params tested (2 of 4).
        assert report.actions_run == 2
        assert report.stopped_reason == "coverage_target_reached"

    def test_budget_clamps(self) -> None:
        b = LoopBudget(max_actions=0, target_parameter_coverage=5.0)
        assert b.max_actions == 1
        assert b.target_parameter_coverage == 1.0
