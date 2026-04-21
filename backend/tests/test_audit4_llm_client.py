"""H-7: get_llm_client accepts task and scan_id."""

from __future__ import annotations

import os

import pytest
from unittest.mock import patch


class TestGetLlmClientSignature:
    """get_llm_client must accept task and scan_id kwargs."""

    def test_get_llm_client_accepts_task_and_scan_id(self) -> None:
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            from src.core.llm_config import get_llm_client
            from src.llm.task_router import LLMTask

            client = get_llm_client(task=LLMTask.REPORT_SECTION, scan_id="test-scan-123")
            assert callable(client)

    def test_get_llm_client_default_task(self) -> None:
        """get_llm_client works with no explicit task (backward compat)."""
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            from src.core.llm_config import get_llm_client

            client = get_llm_client()
            assert callable(client)

    def test_get_llm_client_raises_without_keys(self) -> None:
        env_clear = {k: "" for k in [
            "OPENAI_API_KEY", "DEEPSEEK_API_KEY", "OPENROUTER_API_KEY",
            "GOOGLE_API_KEY", "KIMI_API_KEY", "PERPLEXITY_API_KEY",
        ]}
        with patch.dict(os.environ, env_clear, clear=False):
            from src.core.llm_config import get_llm_client

            with pytest.raises(RuntimeError, match="No LLM provider"):
                get_llm_client()
