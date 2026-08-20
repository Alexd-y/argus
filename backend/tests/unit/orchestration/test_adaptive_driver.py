"""Unit tests for the adaptive scan driver (Step 3): loop drives execution -> artifacts.

Exercises the full composition (inventory -> graph -> loop -> VulnAnalysisOutput)
with a mock executor + the real conservative HeuristicVerifier, plus the signed
production entry with ``run_signed_tool`` monkeypatched (no live container).
"""

from __future__ import annotations

from typing import Any

from src.orchestration import adaptive_integration
from src.orchestration.adaptive_driver import (
    AdaptiveScanResult,
    make_constant_tool_resolver,
    run_adaptive_vuln_analysis,
    run_adaptive_vuln_analysis_signed,
)
from src.orchestration.adaptive_integration import HeuristicVerifier
from src.orchestration.adaptive_loop import ActionProposal, ExecResult, LoopBudget
from src.orchestration.graph import AssetNodeType
from src.recon.vulnerability_analysis.active_scan.input_surface_inventory import (
    InputSurfaceInventory,
    InputSurfaceItem,
)


def _inventory(n: int = 3) -> InputSurfaceInventory:
    return InputSurfaceInventory(
        items=[
            InputSurfaceItem(
                surface_id=f"s{i}",
                url=f"https://app.test/p{i}?q={i}",
                method="GET",
                param_name=f"q{i}",
                location="query",
            )
            for i in range(n)
        ]
    )


class _MockExecutor:
    """Returns a scripted (exit_code, stdout) per tool; records calls."""

    def __init__(self, exit_code: int = 0, stdout: str = "signal") -> None:
        self._exit_code = exit_code
        self._stdout = stdout
        self.calls: list[ActionProposal] = []

    async def execute(self, proposal: ActionProposal) -> ExecResult:
        self.calls.append(proposal)
        return ExecResult(proposal=proposal, exit_code=self._exit_code, stdout=self._stdout)


class TestConstantToolResolver:
    def test_returns_tool_and_none_for_empty(self) -> None:
        node = object()  # resolver ignores the node
        assert make_constant_tool_resolver("sqlmap")(node) == "sqlmap"  # type: ignore[arg-type]
        assert make_constant_tool_resolver("")(node) is None  # type: ignore[arg-type]
        assert make_constant_tool_resolver("  ")(node) is None  # type: ignore[arg-type]


class TestRunAdaptiveVulnAnalysis:
    async def test_confirmed_actions_become_findings(self) -> None:
        executor = _MockExecutor(exit_code=0, stdout="found")
        result = await run_adaptive_vuln_analysis(
            inventory=_inventory(3),
            tool_resolver=make_constant_tool_resolver("sqlmap"),
            executor=executor,
            verifier=HeuristicVerifier(),
        )
        assert isinstance(result, AdaptiveScanResult)
        # 3 surfaces all probed and confirmed (exit 0 + output) -> 3 findings.
        assert result.report.actions_run == 3
        assert result.report.confirmed == 3
        assert len(result.vuln_output.findings) == 3
        assert all(f["cwe"] == "CWE-89" for f in result.vuln_output.findings)
        assert len(result.timeline_entries) == 3
        # Graph coverage advanced to full.
        assert all(n.tested for n in result.graph.nodes_by_type(AssetNodeType.PARAMETER))
        assert result.vuln_output.coverage_results[0]["parameter_coverage"] == 1.0

    async def test_no_output_yields_inconclusive_no_findings(self) -> None:
        # exit 0 but empty stdout -> HeuristicVerifier = INCONCLUSIVE -> no findings.
        executor = _MockExecutor(exit_code=0, stdout="")
        result = await run_adaptive_vuln_analysis(
            inventory=_inventory(2),
            tool_resolver=make_constant_tool_resolver("nuclei"),
            executor=executor,
            verifier=HeuristicVerifier(),
        )
        assert result.report.actions_run == 2
        assert result.report.confirmed == 0
        assert result.report.inconclusive == 2
        assert result.vuln_output.findings == []

    async def test_nonzero_exit_is_rejected_no_findings(self) -> None:
        executor = _MockExecutor(exit_code=1, stdout="boom")
        result = await run_adaptive_vuln_analysis(
            inventory=_inventory(2),
            tool_resolver=make_constant_tool_resolver("sqlmap"),
            executor=executor,
            verifier=HeuristicVerifier(),
        )
        assert result.report.rejected == 2
        assert result.vuln_output.findings == []

    async def test_budget_caps_actions(self) -> None:
        executor = _MockExecutor(exit_code=0, stdout="x")
        result = await run_adaptive_vuln_analysis(
            inventory=_inventory(10),
            tool_resolver=make_constant_tool_resolver("nuclei"),
            executor=executor,
            verifier=HeuristicVerifier(),
            budget=LoopBudget(max_actions=4, target_parameter_coverage=1.0),
        )
        assert result.report.actions_run == 4
        assert len(executor.calls) == 4

    async def test_target_resolver_default_uses_node_url(self) -> None:
        executor = _MockExecutor(exit_code=0, stdout="x")
        await run_adaptive_vuln_analysis(
            inventory=_inventory(1),
            tool_resolver=make_constant_tool_resolver("sqlmap"),
            executor=executor,
            verifier=HeuristicVerifier(),
        )
        assert executor.calls[0].target == "https://app.test/p0?q=0"


class TestSignedDriver:
    async def test_signed_entry_composes_via_run_signed_tool(self, monkeypatch: Any) -> None:
        async def _fake_run_signed_tool(tool_id: str, target: str, **_kwargs: Any) -> dict[str, Any]:
            return {"exit_code": 0, "stdout": f"{tool_id} hit {target}", "stderr": ""}

        monkeypatch.setattr(adaptive_integration, "run_signed_tool", _fake_run_signed_tool)

        result = await run_adaptive_vuln_analysis_signed(
            inventory=_inventory(2),
            tool_resolver=make_constant_tool_resolver("sqlmap"),
            scan_id="scan-1",
            tenant_id="tenant-1",
        )
        assert result.report.actions_run == 2
        assert result.report.confirmed == 2
        assert len(result.vuln_output.findings) == 2

    async def test_signed_unavailable_is_inconclusive(self, monkeypatch: Any) -> None:
        async def _none_run_signed_tool(_tool_id: str, _target: str, **_kwargs: Any) -> None:
            return None

        monkeypatch.setattr(adaptive_integration, "run_signed_tool", _none_run_signed_tool)

        result = await run_adaptive_vuln_analysis_signed(
            inventory=_inventory(2),
            tool_resolver=make_constant_tool_resolver("uncatalogued"),
            scan_id="scan-1",
            tenant_id="tenant-1",
        )
        # Signed path unavailable -> inconclusive -> no over-claimed findings.
        assert result.report.inconclusive == 2
        assert result.vuln_output.findings == []
