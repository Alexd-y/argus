"""Unit tests for the flag-gated adaptive VA routing in ``run_vuln_analysis``.

Covers the guarded helper ``_maybe_adaptive_vuln_analysis`` — the final adaptive
integration seam — which either drives VULN_ANALYSIS via the signed adaptive loop
(returning a typed VulnAnalysisOutput) or returns ``None`` so the caller falls back
to the linear active-scan + LLM path. The guard must be a strict no-op when the
flag is off and must never propagate an exception.
"""

from __future__ import annotations

from typing import Any

from src.orchestration import handlers
from src.orchestration.adaptive_driver import AdaptiveScanResult
from src.orchestration.adaptive_loop import LoopReport
from src.orchestration.graph import AssetGraph
from src.orchestration.phases import VulnAnalysisOutput
from src.recon.vulnerability_analysis.active_scan.input_surface_inventory import (
    InputSurfaceInventory,
    InputSurfaceItem,
)
from src.schemas.vulnerability_analysis.schemas import VulnerabilityAnalysisInputBundle


def _bundle() -> VulnerabilityAnalysisInputBundle:
    return VulnerabilityAnalysisInputBundle(engagement_id="scan-1")


def _inventory(n: int = 2) -> InputSurfaceInventory:
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


def _adaptive_result(findings: list[dict[str, Any]]) -> AdaptiveScanResult:
    return AdaptiveScanResult(
        vuln_output=VulnAnalysisOutput(findings=findings),
        report=LoopReport(
            actions_run=len(findings),
            confirmed=len(findings),
            rejected=0,
            inconclusive=0,
            stopped_reason="coverage_target_reached",
            coverage={"parameter_coverage": 1.0},
            trace=[],
        ),
        graph=AssetGraph(),
        timeline_entries=[],
    )


class TestMaybeAdaptiveVulnAnalysis:
    async def test_flag_off_is_noop(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(handlers.settings, "argus_adaptive_loop", False)
        called = False

        async def _spy(**_kwargs: Any) -> AdaptiveScanResult:
            nonlocal called
            called = True
            return _adaptive_result([])

        monkeypatch.setattr(handlers, "run_adaptive_vuln_analysis_signed", _spy)

        out = await handlers._maybe_adaptive_vuln_analysis(
            _bundle(), scan_id="scan-1", tenant_id="t1"
        )
        assert out is None
        assert called is False  # short-circuits before touching the driver

    async def test_flag_on_with_surfaces_drives_and_returns_output(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(handlers.settings, "argus_adaptive_loop", True)
        monkeypatch.setattr(
            handlers, "build_input_surface_inventory", lambda _bundle: _inventory(2)
        )
        findings = [{"title": "SQLi via sqlmap", "severity": "high"}]

        async def _driver(**kwargs: Any) -> AdaptiveScanResult:
            assert kwargs["scan_id"] == "scan-1"
            assert kwargs["tenant_id"] == "t1"
            assert len(kwargs["inventory"].items) == 2
            return _adaptive_result(findings)

        monkeypatch.setattr(handlers, "run_adaptive_vuln_analysis_signed", _driver)

        out = await handlers._maybe_adaptive_vuln_analysis(
            _bundle(), scan_id="scan-1", tenant_id="t1"
        )
        assert isinstance(out, VulnAnalysisOutput)
        assert out.findings == findings

    async def test_flag_on_no_surfaces_returns_none(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(handlers.settings, "argus_adaptive_loop", True)
        monkeypatch.setattr(
            handlers,
            "build_input_surface_inventory",
            lambda _bundle: InputSurfaceInventory(items=[]),
        )
        called = False

        async def _spy(**_kwargs: Any) -> AdaptiveScanResult:
            nonlocal called
            called = True
            return _adaptive_result([])

        monkeypatch.setattr(handlers, "run_adaptive_vuln_analysis_signed", _spy)

        out = await handlers._maybe_adaptive_vuln_analysis(
            _bundle(), scan_id="scan-1", tenant_id="t1"
        )
        assert out is None
        assert called is False  # no surfaces -> driver never invoked

    async def test_flag_on_driver_raises_falls_back_to_none(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(handlers.settings, "argus_adaptive_loop", True)
        monkeypatch.setattr(
            handlers, "build_input_surface_inventory", lambda _bundle: _inventory(1)
        )

        async def _boom(**_kwargs: Any) -> AdaptiveScanResult:
            raise RuntimeError("signed control plane exploded")

        monkeypatch.setattr(handlers, "run_adaptive_vuln_analysis_signed", _boom)

        out = await handlers._maybe_adaptive_vuln_analysis(
            _bundle(), scan_id="scan-1", tenant_id="t1"
        )
        assert out is None  # exception guarded -> linear fallback

    async def test_build_inventory_raises_falls_back_to_none(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(handlers.settings, "argus_adaptive_loop", True)

        def _boom(_bundle: Any) -> InputSurfaceInventory:
            raise ValueError("bad bundle")

        monkeypatch.setattr(handlers, "build_input_surface_inventory", _boom)

        out = await handlers._maybe_adaptive_vuln_analysis(
            _bundle(), scan_id="scan-1", tenant_id="t1"
        )
        assert out is None
