"""Tests for LLM Gateway redaction and logging."""

import pytest
from src.llm_gateway.redaction import (
    hash_prompt, redact_api_keys, redact_response,
    summary_response, log_prompt, log_response,
)


class TestHashPrompt:
    def test_consistent_hashing(self):
        h1 = hash_prompt("hello world")
        h2 = hash_prompt("hello world")
        assert h1 == h2
        assert len(h1) == 32

    def test_different_inputs(self):
        h1 = hash_prompt("hello")
        h2 = hash_prompt("world")
        assert h1 != h2


class TestRedactApiKeys:
    def test_redacts_openai_key(self):
        text = "api key is sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx"
        result = redact_api_keys(text)
        assert "REDACTED:openai_key" in result
        assert "sk-proj-" not in result

    def test_redacts_bearer_token(self):
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        result = redact_api_keys(text)
        assert "REDACTED:bearer_token" in result
        assert "eyJ" not in result

    def test_redacts_perplexity_key(self):
        text = "key: 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"
        result = redact_api_keys(text)
        assert "REDACTED:perplexity_key" in result

    def test_redacts_private_key(self):
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
        result = redact_api_keys(text)
        assert "REDACTED:private_key" in result

    def test_redacts_password_in_url(self):
        text = "password=supersecret123"
        result = redact_api_keys(text)
        assert "REDACTED:password_param" in result

    def test_preserves_clean_text(self):
        text = "This is a normal vulnerability description"
        result = redact_api_keys(text)
        assert result == text


class TestSummaryResponse:
    def test_short_response_unchanged(self):
        text = "Short response"
        assert summary_response(text, max_length=500) == text

    def test_long_response_truncated(self):
        text = "a" * 1000
        result = summary_response(text, max_length=500)
        assert len(result) <= 503  # 500 + "..."
        assert result.endswith("...")


class TestLogModes:
    def test_full_logs_redacted_content(self):
        text = "Using key sk-abc123def456"
        result = log_prompt(text, mode="full")
        assert "REDACTED" in result
        assert "sk-" not in result

    def test_hashed_returns_hash(self):
        result = log_prompt("test prompt", mode="hashed")
        assert len(result) == 32
        assert "test prompt" not in result

    def test_off_returns_label(self):
        assert log_prompt("test", mode="off") == "<prompt_logging_off>"
        assert log_response("test", mode="off") == "<response_logging_off>"
