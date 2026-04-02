"""Tests for the Memory Compression module (ENH-V3)."""

import os
from unittest.mock import AsyncMock, patch

import pytest

from src.agents.memory_compressor import ScanMemoryCompressor


class TestShouldCompress:
    def test_short_history_no_compress(self):
        c = ScanMemoryCompressor("scan-1")
        history = [{"content": "short message"}]
        assert c.should_compress(history) is False

    def test_long_history_needs_compress(self):
        c = ScanMemoryCompressor("scan-1")
        history = [{"content": "x" * 1000} for _ in range(30)]
        assert c.should_compress(history) is True

    def test_custom_threshold(self):
        c = ScanMemoryCompressor("scan-1", compression_threshold_chars=100)
        history = [{"content": "x" * 60} for _ in range(3)]
        assert c.should_compress(history) is True

    def test_disabled_via_env(self):
        c = ScanMemoryCompressor("scan-1")
        with patch.dict(os.environ, {"MEMORY_COMPRESSION_ENABLED": "false"}):
            history = [{"content": "x" * 1000} for _ in range(30)]
            assert c.should_compress(history) is False


class TestBuildCompressedHistory:
    def test_no_summary_returns_original(self):
        c = ScanMemoryCompressor("scan-1")
        history = [{"role": "user", "content": "test"}]
        result = c.build_compressed_history(history)
        assert result == history

    def test_with_summary_replaces_history(self):
        c = ScanMemoryCompressor("scan-1")
        c.compressed_summary = "Compressed context here"
        c._compression_count = 1
        history = [{"role": "user", "content": f"msg {i}"} for i in range(20)]
        result = c.build_compressed_history(history)
        assert len(result) == 6
        assert "COMPRESSED CONTEXT" in result[0]["content"]
        assert result[0]["role"] == "system"


class TestGetStats:
    def test_initial_stats(self):
        c = ScanMemoryCompressor("scan-1")
        stats = c.get_stats()
        assert stats["scan_id"] == "scan-1"
        assert stats["call_count"] == 0
        assert stats["compression_count"] == 0
        assert stats["has_compressed_summary"] is False


@pytest.mark.asyncio
class TestMaybeCompress:
    async def test_no_compression_needed(self):
        c = ScanMemoryCompressor("scan-1")
        history = [{"content": "short"}]
        result = await c.maybe_compress(history)
        assert result is None
        assert c.call_count == 1

    async def test_compression_triggered(self):
        c = ScanMemoryCompressor("scan-1", compression_threshold_chars=50)
        history = [{"role": "user", "content": "x" * 100}]

        mock_response = AsyncMock()
        mock_response.text = "Compressed summary of scan progress"

        with patch("src.agents.memory_compressor.call_llm_for_task", return_value=mock_response):
            result = await c.maybe_compress(history)
            assert result is not None
            assert "Compressed summary" in result
            assert c.compressed_summary == result
            assert c._compression_count == 1

    async def test_compression_failure_returns_none(self):
        c = ScanMemoryCompressor("scan-1", compression_threshold_chars=50)
        history = [{"role": "user", "content": "x" * 100}]

        with patch("src.agents.memory_compressor.call_llm_for_task", side_effect=RuntimeError("LLM down")):
            result = await c.maybe_compress(history)
            assert result is None
            assert c.compressed_summary is None
