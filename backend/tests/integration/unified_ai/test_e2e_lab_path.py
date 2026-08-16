"""CONT-007 — depersonalized LAB unrestricted E2E path (mocked, no Docker/LLM)."""

from __future__ import annotations

from tests.integration.unified_ai.conftest import run_lab_path


def test_lab_path_manifest_boundary_lease_allow_all(
    rag_pipeline,
    rag_retriever,
    mock_sandbox,
    mock_llm,
) -> None:
    trace = run_lab_path(
        rag_pipeline=rag_pipeline,
        rag_retriever=rag_retriever,
        mock_sandbox=mock_sandbox,
        mock_llm=mock_llm,
    )

    assert trace.mode == "lab_unrestricted"
    assert trace.phase_input.get("lab_lease")
    assert trace.phase_input.get("lab_scope")
    assert trace.rag_hits >= 1
    assert trace.approval_required is False
    assert trace.policy.get("requires_approval") is False  # type: ignore[union-attr]
    assert trace.policy.get("lab_lease_active") is True  # type: ignore[union-attr]
    assert trace.sandbox_calls


def test_lab_path_nuclei_compiler_has_no_conservative_caps(
    rag_pipeline,
    rag_retriever,
    mock_sandbox,
    mock_llm,
) -> None:
    trace = run_lab_path(
        rag_pipeline=rag_pipeline,
        rag_retriever=rag_retriever,
        mock_sandbox=mock_sandbox,
        mock_llm=mock_llm,
    )

    argv = trace.nuclei_argv
    assert argv
    assert "-ni" not in argv
    assert "-rate-limit" not in argv
    joined = " ".join(argv)
    assert "rate-limit" not in joined

    nuclei_calls = [c for c in trace.sandbox_calls if c.get("tool") == "nuclei"]
    assert nuclei_calls
    sandbox_argv = nuclei_calls[0]["argv"]
    assert "-ni" not in sandbox_argv
    assert "-rate-limit" not in sandbox_argv


def test_lab_path_plan_steps_have_no_approval_flags(
    rag_pipeline,
    rag_retriever,
    mock_sandbox,
    mock_llm,
) -> None:
    trace = run_lab_path(
        rag_pipeline=rag_pipeline,
        rag_retriever=rag_retriever,
        mock_sandbox=mock_sandbox,
        mock_llm=mock_llm,
    )

    for step in trace.llm_response.get("steps", []):
        assert step.get("requires_approval") is False
