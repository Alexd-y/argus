"""FIX-007: All LLM callers use call_llm_unified, ai_prompts passes task=."""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

BACKEND_SRC = Path(__file__).resolve().parent.parent / "src"


class TestAiPromptsPassesTask:
    """ai_prompts._call_llm_with_json_retry must pass task= to call_llm_unified."""

    def test_source_contains_task_kwarg(self) -> None:
        from src.orchestration import ai_prompts

        source = inspect.getsource(ai_prompts._call_llm_with_json_retry)
        assert "task=" in source, (
            "_call_llm_with_json_retry must pass task= to call_llm_unified"
        )

    def test_call_llm_unified_imported(self) -> None:
        from src.orchestration import ai_prompts

        source = inspect.getsource(ai_prompts)
        assert "call_llm_unified" in source, (
            "ai_prompts must import and use call_llm_unified"
        )


class TestVaOrchestratorUsesCallLlmUnified:
    """va_orchestrator must use call_llm_unified, not call_llm_for_task directly."""

    def test_uses_call_llm_unified(self) -> None:
        from src.agents import va_orchestrator

        source = inspect.getsource(va_orchestrator)
        assert "call_llm_unified" in source

    def test_no_direct_call_llm_for_task(self) -> None:
        """va_orchestrator should not import or call call_llm_for_task directly."""
        from src.agents import va_orchestrator

        source = inspect.getsource(va_orchestrator)
        assert "call_llm_for_task(" not in source, (
            "va_orchestrator must use call_llm_unified, not call_llm_for_task directly"
        )


class TestAiPromptsPhaseToTaskMapping:
    """_PHASE_TO_TASK must map all standard phases to LLMTask values."""

    def test_mapping_exists(self) -> None:
        from src.orchestration.ai_prompts import _PHASE_TO_TASK

        assert isinstance(_PHASE_TO_TASK, dict)
        assert len(_PHASE_TO_TASK) >= 5

    def test_all_values_are_llm_task(self) -> None:
        from src.llm.task_router import LLMTask
        from src.orchestration.ai_prompts import _PHASE_TO_TASK

        for phase, task in _PHASE_TO_TASK.items():
            assert isinstance(task, LLMTask), (
                f"_PHASE_TO_TASK[{phase!r}] should be LLMTask, got {type(task)}"
            )
