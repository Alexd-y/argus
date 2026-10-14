"""Tests for LLM facade unification (M-1, M-3, M-4)."""

from __future__ import annotations

from pathlib import Path


class TestLlmFacadeUsageTokens:
    """M-3: Token counting should use tiktoken, not char estimate."""

    def test_no_chars_per_token_estimate_in_facade(self) -> None:
        facade = Path(__file__).resolve().parent.parent / "src" / "llm" / "facade.py"
        text = facade.read_text(encoding="utf-8")
        assert "_CHARS_PER_TOKEN_ESTIMATE" not in text, (
            "Char-based estimation still present in facade"
        )

    def test_tiktoken_in_facade(self) -> None:
        facade = Path(__file__).resolve().parent.parent / "src" / "llm" / "facade.py"
        text = facade.read_text(encoding="utf-8")
        assert "tiktoken" in text

    def test_tiktoken_in_requirements(self) -> None:
        req = Path(__file__).resolve().parent.parent / "requirements.txt"
        text = req.read_text(encoding="utf-8").lower()
        assert "tiktoken" in text

    def test_count_tokens_tiktoken_function_exists(self) -> None:
        """_count_tokens_tiktoken must use cl100k_base encoding."""
        facade = Path(__file__).resolve().parent.parent / "src" / "llm" / "facade.py"
        text = facade.read_text(encoding="utf-8")
        assert "_count_tokens_tiktoken" in text
        assert "cl100k_base" in text


class TestIntelligenceUsesFacade:
    """M-1: intelligence.py must use call_llm_unified."""

    def test_intelligence_uses_unified_facade(self) -> None:
        intel = (
            Path(__file__).resolve().parent.parent / "src" / "api" / "routers" / "intelligence.py"
        )
        text = intel.read_text(encoding="utf-8")
        assert "call_llm_unified" in text
        assert "from src.llm.router import call_llm" not in text

    def test_intelligence_imports_from_facade(self) -> None:
        """Import must come from src.llm.facade, not src.llm.router."""
        intel = (
            Path(__file__).resolve().parent.parent / "src" / "api" / "routers" / "intelligence.py"
        )
        text = intel.read_text(encoding="utf-8")
        assert "from src.llm.facade import call_llm_unified" in text


class TestJsonRetries:
    """M-4: the JSON-fixer retry count is configurable and defaults to >1.

    (Supersedes the original "MAX_JSON_RETRIES = 3 with exponential backoff"
    aspiration: the fixer re-prompts a LOCAL model, so a sleep/backoff between
    attempts only adds latency with no benefit — resilience comes from a
    configurable retry count plus a tolerant parser, not from backoff.)
    """

    def test_retry_count_is_configurable_and_defaults_above_one(self) -> None:
        from src.core.config import settings

        assert settings.argus_json_fixer_retries >= 2

    def test_fixer_loop_reads_the_setting(self) -> None:
        prompts = Path(__file__).resolve().parent.parent / "src" / "orchestration" / "ai_prompts.py"
        text = prompts.read_text(encoding="utf-8")
        assert "settings.argus_json_fixer_retries" in text
