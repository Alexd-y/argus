"""Tests for adaptive-loop production adapters (signed executor + heuristic verifier)."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

from src.orchestration.adaptive_integration import HeuristicVerifier, SignedToolExecutor
from src.orchestration.adaptive_loop import ActionProposal, ExecResult, VerifyOutcome


class TestSignedToolExecutor:
    async def test_maps_signed_result(self) -> None:
        proposal = ActionProposal(node_id="n", tool="nuclei", target="http://t/")
        with patch(
            "src.orchestration.adaptive_integration.run_signed_tool",
            new_callable=AsyncMock,
            return_value={"stdout": "hit", "stderr": "", "exit_code": 0, "duration_ms": 3},
        ):
            res = await SignedToolExecutor(scan_id="s").execute(proposal)
        assert res.exit_code == 0
        assert res.stdout == "hit"
        assert res.proposal is proposal

    async def test_signed_none_is_unavailable(self) -> None:
        proposal = ActionProposal(node_id="n", tool="unknown", target="http://t/")
        with patch(
            "src.orchestration.adaptive_integration.run_signed_tool",
            new_callable=AsyncMock,
            return_value=None,
        ):
            res = await SignedToolExecutor().execute(proposal)
        assert res.exit_code == -1
        assert res.stderr == "signed_path_unavailable"

    async def test_target_kind_host_for_bare_target(self) -> None:
        proposal = ActionProposal(node_id="n", tool="subfinder", target="example.com")
        with patch(
            "src.orchestration.adaptive_integration.run_signed_tool",
            new_callable=AsyncMock,
            return_value={"stdout": "", "stderr": "", "exit_code": 0, "duration_ms": 1},
        ) as spawn:
            await SignedToolExecutor().execute(proposal)
        # target_kind passed as HOST for a non-http target
        _args, kwargs = spawn.call_args
        assert kwargs["target_kind"].value == "host"


class TestHeuristicVerifier:
    def _res(self, exit_code: int, stdout: str = "", stderr: str = "") -> ExecResult:
        return ExecResult(
            proposal=ActionProposal(node_id="n", tool="t", target="x"),
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
        )

    def test_confirmed_on_output(self) -> None:
        assert HeuristicVerifier().verify(self._res(0, stdout="found")) == VerifyOutcome.CONFIRMED

    def test_inconclusive_on_clean_no_output(self) -> None:
        assert HeuristicVerifier().verify(self._res(0, stdout="")) == VerifyOutcome.INCONCLUSIVE

    def test_rejected_on_nonzero(self) -> None:
        assert HeuristicVerifier().verify(self._res(1, stderr="boom")) == VerifyOutcome.REJECTED

    def test_unavailable_is_inconclusive_not_rejected(self) -> None:
        res = self._res(-1, stderr="signed_path_unavailable")
        assert HeuristicVerifier().verify(res) == VerifyOutcome.INCONCLUSIVE
