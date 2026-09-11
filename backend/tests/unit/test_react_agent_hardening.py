"""Regression tests for the ReAct loop (3.3 / section 9).

Behaviour tests with fake llm_caller / tool_executor — no real LLM or tools.
"""

from __future__ import annotations

import pytest
from src.orchestration.react_agent import ReActAgent, ReActStopReason


def _llm_returning(*responses: str):
    """A fake async llm_caller yielding the given responses in order."""
    seq = list(responses)

    async def _caller(_system_prompt, _prompt, scan_id=None, phase=None):  # noqa: ARG001
        return seq.pop(0) if seq else ""

    return _caller


async def test_missing_executor_in_tool_mode_is_config_error():
    agent = ReActAgent(task_description="exploit", max_iterations=3)
    result = await agent.run(
        llm_caller=_llm_returning("Thought: go\nAction: sqlmap({})"),
        tool_executor=None,
        require_tools=True,
    )
    assert result.stop_reason == ReActStopReason.NO_EXECUTOR
    assert result.evidence_backed is False
    assert result.error


async def test_no_llm_stops_immediately():
    agent = ReActAgent(task_description="x", max_iterations=3)
    result = await agent.run(llm_caller=None)
    assert result.stop_reason == ReActStopReason.NO_LLM


async def test_allowed_tool_runs_through_executor_and_marks_evidence():
    calls = []

    async def _exec(tool_name, tool_args):
        calls.append((tool_name, tool_args))
        return {"stdout": "sqlmap: parameter is injectable"}

    agent = ReActAgent(task_description="find sqli", max_iterations=3)
    result = await agent.run(
        llm_caller=_llm_returning(
            'Thought: test\nAction: sqlmap({"url": "u"})',
            "Final Answer: injectable confidence 0.9",
        ),
        tool_executor=_exec,
        require_tools=True,
    )
    assert calls == [("sqlmap", {"url": "u"})]
    assert result.stop_reason == ReActStopReason.FINAL_ANSWER
    assert result.evidence_backed is True


async def test_malformed_output_has_finite_retries():
    agent = ReActAgent(task_description="x", max_iterations=10)
    # Always garbage -> repaired at most max_malformed_repairs, then stop.
    result = await agent.run(
        llm_caller=_llm_returning(*(["garbage with no structure"] * 20)),
        tool_executor=None,
        max_malformed_repairs=2,
    )
    assert result.stop_reason == ReActStopReason.MALFORMED_OUTPUT
    # 2 repairs allowed + 1 that trips the limit = 3 iterations, well under 10.
    assert result.iterations <= 4


async def test_repeated_action_stops_loop():
    async def _exec(_tool_name, _tool_args):
        return {"stdout": "no change"}

    same = 'Thought: retry\nAction: nuclei({"t": "x"})'
    agent = ReActAgent(task_description="x", max_iterations=10)
    result = await agent.run(
        llm_caller=_llm_returning(same, same, same, same),
        tool_executor=_exec,
        require_tools=True,
    )
    assert result.stop_reason == ReActStopReason.REPEATED_ACTION


async def test_confidence_without_evidence_not_marked_backed():
    agent = ReActAgent(task_description="x", max_iterations=3)
    result = await agent.run(
        llm_caller=_llm_returning("Final Answer: totally vulnerable confidence 0.99"),
        tool_executor=None,
    )
    assert result.confidence == pytest.approx(0.99)
    # High confidence but no tool observation -> not evidence-backed.
    assert result.evidence_backed is False
    assert result.stop_reason == ReActStopReason.FINAL_ANSWER


def test_constructor_uses_task_description_kwarg():
    # The handlers bug called ReActAgent(task=...); the real kwarg is
    # task_description. Passing the wrong kwarg must raise.
    with pytest.raises(TypeError):
        ReActAgent(task="wrong kwarg")  # type: ignore[call-arg]
    agent = ReActAgent(task_description="right")
    assert agent.task_description == "right"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
