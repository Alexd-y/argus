"""Adaptive scan driver (overhaul §6, Step 3): the loop that *drives execution*.

Composes the pieces built in the previous steps into a single callable that runs
the adaptive plan→execute→verify loop against a discovered input-surface set and
returns the scan artifact contract:

    inventory ─▶ AssetGraph ─▶ run_adaptive_loop(planner, executor, verifier)
              ─▶ LoopReport ─▶ VulnAnalysisOutput (findings + coverage) + timeline

By returning a typed :class:`~src.orchestration.phases.VulnAnalysisOutput`, the
driver produces *all downstream scan artifacts* for free: the state machine's
existing ``_persist_report_and_findings`` turns those findings into ``Finding``
rows, ``ScanState`` and the report tiers — no persistence code is reimplemented.

The loop is dependency-injected: pass the signed
:class:`~src.orchestration.adaptive_integration.SignedToolExecutor` +
:class:`~src.orchestration.adaptive_integration.HeuristicVerifier` in production
(``run_adaptive_vuln_analysis_signed``), or trivial mocks in tests. Nothing here
runs unless ``settings.argus_adaptive_loop`` routes a scan to it.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from src.orchestration.adaptive_artifacts import (
    loop_report_timeline_entries,
    loop_report_to_vuln_output,
)
from src.orchestration.adaptive_integration import HeuristicVerifier, SignedToolExecutor
from src.orchestration.adaptive_loop import (
    Critic,
    DeterministicPlanner,
    Executor,
    LoopBudget,
    LoopReport,
    Verifier,
    run_adaptive_loop,
)
from src.orchestration.graph import AssetGraph, AssetNode
from src.orchestration.graph_builders import build_asset_graph_from_surfaces
from src.orchestration.phases import VulnAnalysisOutput
from src.recon.vulnerability_analysis.active_scan.input_surface_inventory import (
    InputSurfaceInventory,
)


@dataclass(slots=True)
class AdaptiveScanResult:
    """Artifacts produced by one adaptive-driver run.

    ``vuln_output`` is the phase-output contract (findings + coverage) the FSM
    persists; ``report`` and ``graph`` are retained for observability; and
    ``timeline_entries`` are append-only rows the caller records verbatim.
    """

    vuln_output: VulnAnalysisOutput
    report: LoopReport
    graph: AssetGraph
    timeline_entries: list[dict]


def make_constant_tool_resolver(tool_id: str) -> Callable[[AssetNode], str | None]:
    """Resolver that runs a single tool against every candidate node.

    A deliberately simple default; production may inject a family-aware resolver
    (e.g. derived from the exploitation vuln→tool map). Returns ``None`` for an
    empty ``tool_id`` so the planner skips the node.
    """
    tool = (tool_id or "").strip()

    def _resolver(_node: AssetNode) -> str | None:
        return tool or None

    return _resolver


async def run_adaptive_vuln_analysis(
    *,
    inventory: InputSurfaceInventory,
    tool_resolver: Callable[[AssetNode], str | None],
    executor: Executor,
    verifier: Verifier,
    target_resolver: Callable[[AssetNode], str] | None = None,
    budget: LoopBudget | None = None,
    critic: Critic | None = None,
) -> AdaptiveScanResult:
    """Drive the adaptive loop over ``inventory`` and return the artifact contract.

    Pure composition — no flag check, no DB, no globals — so it is fully unit
    testable with mock executor/verifier. Callers gate it behind
    ``settings.argus_adaptive_loop``.
    """
    graph = build_asset_graph_from_surfaces(inventory)
    planner = DeterministicPlanner(tool_resolver, target_resolver)
    report = await run_adaptive_loop(
        graph=graph,
        planner=planner,
        executor=executor,
        verifier=verifier,
        critic=critic,
        budget=budget,
    )
    return AdaptiveScanResult(
        vuln_output=loop_report_to_vuln_output(report),
        report=report,
        graph=graph,
        timeline_entries=loop_report_timeline_entries(report),
    )


async def run_adaptive_vuln_analysis_signed(
    *,
    inventory: InputSurfaceInventory,
    tool_resolver: Callable[[AssetNode], str | None],
    scan_id: str,
    tenant_id: str,
    timeout: int = 120,
    target_resolver: Callable[[AssetNode], str] | None = None,
    budget: LoopBudget | None = None,
    critic: Critic | None = None,
) -> AdaptiveScanResult:
    """Production entry: drive the loop via the signed single control plane.

    Wires the :class:`SignedToolExecutor` (signed-descriptor argv, ephemeral
    hardened container) + conservative :class:`HeuristicVerifier`, then delegates
    to :func:`run_adaptive_vuln_analysis`.
    """
    executor = SignedToolExecutor(scan_id=scan_id, tenant_id=tenant_id, timeout=timeout)
    return await run_adaptive_vuln_analysis(
        inventory=inventory,
        tool_resolver=tool_resolver,
        executor=executor,
        verifier=HeuristicVerifier(),
        target_resolver=target_resolver,
        budget=budget,
        critic=critic,
    )


__all__ = [
    "AdaptiveScanResult",
    "make_constant_tool_resolver",
    "run_adaptive_vuln_analysis",
    "run_adaptive_vuln_analysis_signed",
]
