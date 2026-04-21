"""Tests for LLM facade unification (M-1, M-3, M-4)."""

from __future__ import annotations

from pathlib import Path

import pytest


class TestLlmFacadeUsageTokens:
    """M-3: Token counting should use tiktoken, not char estimate."""

    def test_no_chars_per_token_estimate_in_facade(self) -> None:
        facade = (
            Path(__file__).resolve().parent.parent / "src" / "llm" / "facade.py"
        )
        text = facade.read_text(encoding="utf-8")
        assert (
            "_CHARS_PER_TOKEN_ESTIMATE" not in text
        ), "Char-based estimation still present in facade"

    def test_tiktoken_in_facade(self) -> None:
        facade = (
            Path(__file__).resolve().parent.parent / "src" / "llm" / "facade.py"
        )
        text = facade.read_text(encoding="utf-8")
        assert "tiktoken" in text

    def test_tiktoken_in_requirements(self) -> None:
        req = Path(__file__).resolve().parent.parent / "requirements.txt"
        text = req.read_text(encoding="utf-8").lower()
        assert "tiktoken" in text

    def test_count_tokens_tiktoken_function_exists(self) -> None:
        """_count_tokens_tiktoken must use cl100k_base encoding."""
        facade = (
            Path(__file__).resolve().parent.parent / "src" / "llm" / "facade.py"
        )
        text = facade.read_text(encoding="utf-8")
        assert "_count_tokens_tiktoken" in text
        assert "cl100k_base" in text


class TestIntelligenceUsesFacade:
    """M-1: intelligence.py must use call_llm_unified."""

    def test_intelligence_uses_unified_facade(self) -> None:
        intel = (
            Path(__file__).resolve().parent.parent
            / "src"
            / "api"
            / "routers"
            / "intelligence.py"
        )
        text = intel.read_text(encoding="utf-8")
        assert "call_llm_unified" in text
        assert "from src.llm.router import call_llm" not in text

    def test_intelligence_imports_from_facade(self) -> None:
        """Import must come from src.llm.facade, not src.llm.router."""
        intel = (
            Path(__file__).resolve().parent.parent
            / "src"
            / "api"
            / "routers"
            / "intelligence.py"
        )
        text = intel.read_text(encoding="utf-8")
        assert "from src.llm.facade import call_llm_unified" in text


class TestJsonRetries:
    """M-4: MAX_JSON_RETRIES should be 3 with backoff."""

    def test_max_retries_is_3(self) -> None:
        prompts = (
            Path(__file__).resolve().parent.parent
            / "src"
            / "orchestration"
            / "ai_prompts.py"
        )
        text = prompts.read_text(encoding="utf-8")
        assert "MAX_JSON_RETRIES = 3" in text or "MAX_JSON_RETRIES=3" in text

    def test_backoff_in_retry_loop(self) -> None:
        """Retry logic should implement exponential backoff."""
        prompts = (
            Path(__file__).resolve().parent.parent
            / "src"
            / "orchestration"
            / "ai_prompts.py"
        )
        text = prompts.read_text(encoding="utf-8")
        assert "asyncio.sleep" in text
        assert "delay" in text or "backoff" in text.lower()
