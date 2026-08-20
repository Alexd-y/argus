"""Production adapters wiring the adaptive loop to the signed control plane.

Kept separate from :mod:`src.orchestration.adaptive_loop` so the loop engine
stays dependency-light (graph-only) and unit-testable, while these adapters
bind it to the single-control-plane runner (:func:`run_signed_tool`) and a
conservative evidence heuristic. Compose them as::

    graph = build_asset_graph_from_surfaces(inventory)
    report = await run_adaptive_loop(
        graph=graph,
        planner=DeterministicPlanner(tool_resolver=...),
        executor=SignedToolExecutor(scan_id=..., tenant_id=...),
        verifier=HeuristicVerifier(),
    )
"""

from __future__ import annotations

from src.orchestration.adaptive_loop import ActionProposal, ExecResult, VerifyOutcome
from src.orchestration.signed_tool_runner import run_signed_tool
from src.pipeline.contracts.tool_job import TargetKind

_SIGNED_UNAVAILABLE = "signed_path_unavailable"


def _target_kind_for(target: str) -> TargetKind:
    return (
        TargetKind.URL
        if (target or "").strip().startswith(("http://", "https://"))
        else TargetKind.HOST
    )


class SignedToolExecutor:
    """Adaptive-loop executor that runs actions via the signed single control plane.

    Each proposal is executed through :func:`run_signed_tool` (signed descriptor
    argv, ephemeral hardened container). When the signed path is not feasible
    (uncatalogued / unmappable tool) it yields a non-zero :class:`ExecResult`
    with ``stderr = "signed_path_unavailable"`` so the verifier treats it as
    inconclusive rather than a confirmed finding.
    """

    def __init__(self, *, timeout: int = 120, scan_id: str = "", tenant_id: str = "") -> None:
        self._timeout = max(1, int(timeout))
        self._scan_id = scan_id
        self._tenant_id = tenant_id

    async def execute(self, proposal: ActionProposal) -> ExecResult:
        result = await run_signed_tool(
            proposal.tool,
            proposal.target,
            timeout=self._timeout,
            scan_id=self._scan_id,
            tenant_id=self._tenant_id,
            target_kind=_target_kind_for(proposal.target),
            correlation_id="argus-adaptive-loop",
        )
        if result is None:
            return ExecResult(proposal=proposal, exit_code=-1, stderr=_SIGNED_UNAVAILABLE)
        return ExecResult(
            proposal=proposal,
            exit_code=int(result.get("exit_code", -1)),
            stdout=str(result.get("stdout", "")),
            stderr=str(result.get("stderr", "")),
        )


class HeuristicVerifier:
    """Conservative, LLM-free verdict for an executed action.

    * non-zero exit (including a missing signed path) → ``REJECTED`` /
      ``INCONCLUSIVE``;
    * exit 0 with output → ``CONFIRMED`` (tool produced signal);
    * exit 0 without output → ``INCONCLUSIVE`` (ran clean, nothing observed).

    Deliberately never over-claims: this is a heuristic gate, not evidence
    adjudication. Swap in an LLM verifier for richer analysis.
    """

    def verify(self, result: ExecResult) -> VerifyOutcome:
        if result.exit_code != 0:
            return (
                VerifyOutcome.INCONCLUSIVE
                if result.stderr == _SIGNED_UNAVAILABLE
                else (VerifyOutcome.REJECTED)
            )
        return VerifyOutcome.CONFIRMED if result.stdout.strip() else VerifyOutcome.INCONCLUSIVE


__all__ = ["HeuristicVerifier", "SignedToolExecutor"]
