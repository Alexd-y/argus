"""Tests for memory compressor secret redaction (M-8)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest


class TestMemoryCompressorRedaction:
    """M-8: Memory compressor should redact secrets."""

    def test_redact_function_exists(self) -> None:
        mc = (
            Path(__file__).resolve().parent.parent
            / "src"
            / "agents"
            / "memory_compressor.py"
        )
        text = mc.read_text(encoding="utf-8")
        assert "_redact_secrets" in text or "REDACTED" in text

    def test_prompt_forbids_secrets(self) -> None:
        mc = (
            Path(__file__).resolve().parent.parent
            / "src"
            / "agents"
            / "memory_compressor.py"
        )
        text = mc.read_text(encoding="utf-8")
        assert "REDACTED" in text
        assert "never store" in text.lower()

    def test_redaction_regex(self) -> None:
        """Secret patterns regex must match common credential formats."""
        _SECRET_PATTERNS = re.compile(
            r"(?i)(bearer\s+\S+|"
            r"api[_-]?key[=:]\s*\S+|"
            r"password[=:]\s*\S+|"
            r"token[=:]\s*\S+|"
            r"secret[=:]\s*\S+)"
        )
        test_cases = [
            ("Got bearer abc123xyz from server", True),
            ("api_key=sk-abc123", True),
            ("password: hunter2", True),
            ("token=eyJhbGciOiJIUzI1NiJ9", True),
            ("secret: mysecretvalue", True),
            ("Normal text without secrets", False),
        ]
        for text, should_match in test_cases:
            found = _SECRET_PATTERNS.search(text) is not None
            assert found == should_match, f"Failed for: {text!r}"

    def test_redact_secrets_function(self) -> None:
        """_redact_secrets must replace credential patterns with <REDACTED>."""
        from src.agents.memory_compressor import _redact_secrets

        assert "<REDACTED>" in _redact_secrets("bearer abc123xyz")
        assert "<REDACTED>" in _redact_secrets("api_key=sk-abc123")
        assert "<REDACTED>" in _redact_secrets("password: hunter2")
        assert "hunter2" not in _redact_secrets("password: hunter2")

    def test_redact_secrets_preserves_clean_text(self) -> None:
        """Clean text should pass through unchanged."""
        from src.agents.memory_compressor import _redact_secrets

        clean = "Found XSS in /search?q= parameter"
        assert _redact_secrets(clean) == clean

    def test_compression_system_prompt_mentions_redaction(self) -> None:
        """System prompt must instruct LLM to redact secrets."""
        from src.agents.memory_compressor import COMPRESSION_SYSTEM_PROMPT

        assert "REDACTED" in COMPRESSION_SYSTEM_PROMPT
        assert "secret" in COMPRESSION_SYSTEM_PROMPT.lower()
        assert "password" in COMPRESSION_SYSTEM_PROMPT.lower()
