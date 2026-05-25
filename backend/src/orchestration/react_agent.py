"""ReAct-loop agent — iterative thought→action→observation cycle.

Replaces single-shot LLM calls with multi-step reasoning loops
(5-10 iterations) where the agent thinks, acts via tools, and
observes results before producing a final answer.

Inspired by the ReAct paper (Yao et al. 2022) and Shannon's
iterative exploitation approach (Ось D п.1 из Развитие2.md).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_MAX_ITERATIONS = 10
DEFAULT_TOOL_TIMEOUT_SECONDS = 120


class ReActStepType(StrEnum):
    THOUGHT = "thought"
    ACTION = "action"
    OBSERVATION = "observation"


@dataclass
class ReActStep:
    """A single step in a ReAct reasoning loop."""

    step_type: ReActStepType
    content: str
    tool_name: str | None = None
    tool_args: dict[str, Any] | None = None
    tool_result: Any = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class ReActResult:
    """Final result from a ReAct loop."""

    answer: str
    iterations: int
    steps: list[ReActStep] = field(default_factory=list)
    tools_used: list[str] = field(default_factory=list)
    confidence: float = 0.0
    total_duration_seconds: float = 0.0


class ReActAgent:
    """Iterative reasoning agent using thought→action→observation cycles.

    Instead of a single LLM call, the agent:
    1. THINKS about what to do next
    2. ACTS by invoking a tool
    3. OBSERVES the tool output
    4. Repeats until confident or max iterations reached

    This mirrors Shannon's iterative exploitation where the agent
    adapts its strategy based on real tool feedback.
    """

    def __init__(
        self,
        task_description: str,
        available_tools: dict[str, Any] | None = None,
        max_iterations: int = DEFAULT_MAX_ITERATIONS,
        confidence_threshold: float = 0.85,
    ) -> None:
        self.task_description = task_description
        self.available_tools = available_tools or {}
        self.max_iterations = max_iterations
        self.confidence_threshold = confidence_threshold
        self._steps: list[ReActStep] = []
        self._tools_used: list[str] = []

    @property
    def steps(self) -> list[ReActStep]:
        return list(self._steps)

    @property
    def tools_used(self) -> list[str]:
        return list(self._tools_used)

    def add_thought(self, content: str) -> ReActStep:
        step = ReActStep(step_type=ReActStepType.THOUGHT, content=content)
        self._steps.append(step)
        logger.debug("ReAct THOUGHT: %s", content[:100])
        return step

    def add_action(
        self,
        tool_name: str,
        tool_args: dict[str, Any] | None = None,
        content: str = "",
    ) -> ReActStep:
        step = ReActStep(
            step_type=ReActStepType.ACTION,
            content=content or f"Calling {tool_name}",
            tool_name=tool_name,
            tool_args=tool_args,
        )
        self._steps.append(step)
        if tool_name not in self._tools_used:
            self._tools_used.append(tool_name)
        logger.debug("ReAct ACTION: %s(%s)", tool_name, json.dumps(tool_args or {})[:100])
        return step

    def add_observation(self, content: str, tool_result: Any = None) -> ReActStep:
        step = ReActStep(
            step_type=ReActStepType.OBSERVATION,
            content=content,
            tool_result=tool_result,
        )
        self._steps.append(step)
        logger.debug("ReAct OBSERVATION: %s", content[:100])
        return step

    def should_continue(self, current_confidence: float) -> bool:
        if len(self._steps) >= self.max_iterations * 3:
            return False
        if current_confidence >= self.confidence_threshold:
            return False
        return True

    def build_context_for_prompt(self) -> str:
        """Build conversation context from ReAct steps for inclusion in LLM prompt."""
        lines: list[str] = []
        for step in self._steps:
            if step.step_type == ReActStepType.THOUGHT:
                lines.append(f"Thought: {step.content}")
            elif step.step_type == ReActStepType.ACTION:
                args_str = json.dumps(step.tool_args, default=str) if step.tool_args else ""
                lines.append(f"Action: {step.tool_name}({args_str})")
            elif step.step_type == ReActStepType.OBSERVATION:
                lines.append(f"Observation: {step.content}")
        return "\n".join(lines)

    def finalize(self, answer: str, confidence: float, duration: float = 0.0) -> ReActResult:
        return ReActResult(
            answer=answer,
            iterations=(len(self._steps) + 2) // 3,
            steps=self._steps,
            tools_used=self._tools_used,
            confidence=confidence,
            total_duration_seconds=duration,
        )


def format_react_prompt(
    system_prompt: str,
    task: str,
    agent: ReActAgent | None = None,
    max_iterations: int = DEFAULT_MAX_ITERATIONS,
) -> str:
    """Build a ReAct-formatted prompt for the LLM.

    Inserts ReAct structure into the prompt so the LLM follows
    thought→action→observation format.
    """
    context = ""
    if agent and agent.steps:
        context = "\n\nPrevious steps:\n" + agent.build_context_for_prompt()

    return (
        f"{system_prompt}\n\n"
        f"Task: {task}\n\n"
        f"You must reason step-by-step using the ReAct pattern:\n"
        f"1. Thought: Analyze the current state and decide what to do\n"
        f"2. Action: Choose a tool and provide arguments\n"
        f"3. Observation: Process the tool result\n"
        f"4. Repeat until confident (max {max_iterations} iterations)\n\n"
        f"Format each step as:\n"
        f'Thought: [your reasoning]\n'
        f'Action: [tool_name(args)]\n'
        f'Observation: [tool output summary]\n\n'
        f"When you have enough evidence, output:\n"
        f'Final Answer: [your conclusion with confidence 0.0-1.0]\n'
        f"{context}"
    )


__all__ = [
    "DEFAULT_MAX_ITERATIONS",
    "ReActAgent",
    "ReActResult",
    "ReActStep",
    "ReActStepType",
    "format_react_prompt",
]