"""BKL-006: LLM facade — call_llm_unified routing + call_llm_sync.

Tests:
- call_llm_unified routes to task_router when task is specified
- call_llm_unified routes to generic router when task is None
- call_llm_sync works (mock the async call)
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestCallLlmUnifiedRouting:
    """BKL-006: call_llm_unified must route based on task parameter."""

    @pytest.mark.asyncio
    async def test_routes_to_task_router_when_task_specified(self) -> None:
        mock_response = MagicMock()
        mock_response.text = "task-routed response"
        mock_task_call = AsyncMock(return_value=mock_response)

        with patch(
            "src.llm.facade._task_router_call",
            mock_task_call,
        ):
            from src.llm.facade import call_llm_unified

            result = await call_llm_unified(
                "system prompt",
                "user prompt",
                task=MagicMock(),
            )

        assert result == "task-routed response"
        mock_task_call.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_routes_to_generic_router_when_task_none(self) -> None:
        mock_router = AsyncMock(return_value="generic response")

        with patch(
            "src.llm.facade._router_call_llm",
            mock_router,
        ):
            from src.llm.facade import call_llm_unified

            result = await call_llm_unified(
                "system prompt",
                "user prompt",
                task=None,
            )

        assert result == "generic response"
        mock_router.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_task_router_receives_system_prompt(self) -> None:
        mock_response = MagicMock()
        mock_response.text = "ok"
        mock_task_call = AsyncMock(return_value=mock_response)

        with patch(
            "src.llm.facade._task_router_call",
            mock_task_call,
        ):
            from src.llm.facade import call_llm_unified

            await call_llm_unified(
                "my system prompt",
                "my user prompt",
                task=MagicMock(),
            )

        _, kwargs = mock_task_call.call_args
        assert kwargs.get("system_prompt") == "my system prompt"

    @pytest.mark.asyncio
    async def test_generic_router_receives_model(self) -> None:
        mock_router = AsyncMock(return_value="ok")

        with patch(
            "src.llm.facade._router_call_llm",
            mock_router,
        ):
            from src.llm.facade import call_llm_unified

            await call_llm_unified(
                "sys",
                "usr",
                task=None,
                model="gpt-4o",
            )

        _, kwargs = mock_router.call_args
        assert kwargs.get("model") == "gpt-4o"


class TestCallLlmSync:
    """BKL-006: call_llm_sync must wrap the async call correctly."""

    def test_sync_wrapper_returns_result(self) -> None:
        mock_response = MagicMock()
        mock_response.text = "sync result"
        mock_task_call = AsyncMock(return_value=mock_response)

        with patch(
            "src.llm.facade._task_router_call",
            mock_task_call,
        ):
            from src.llm.facade import call_llm_sync

            result = call_llm_sync(
                "system",
                "user",
                task=MagicMock(),
            )

        assert result == "sync result"

    def test_sync_wrapper_with_no_task(self) -> None:
        mock_router = AsyncMock(return_value="sync generic")

        with patch(
            "src.llm.facade._router_call_llm",
            mock_router,
        ):
            from src.llm.facade import call_llm_sync

            result = call_llm_sync("system", "user", task=None)

        assert result == "sync generic"

    def test_sync_wrapper_propagates_errors(self) -> None:
        mock_router = AsyncMock(side_effect=ValueError("LLM error"))

        with patch(
            "src.llm.facade._router_call_llm",
            mock_router,
        ):
            from src.llm.facade import call_llm_sync

            with pytest.raises(ValueError, match="LLM error"):
                call_llm_sync("system", "user", task=None)
