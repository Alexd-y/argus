"""BKL-007: executor use_cache wiring — cache hit/bypass tests.

Tests:
- execute_command with use_cache=True returns cached result on second call
- execute_command with use_cache=False bypasses cache
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


def _make_tool_cache_mock() -> MagicMock:
    """Create a mock ToolResultCache with get/set."""
    cache = MagicMock()
    cache._store: dict[str, dict] = {}

    def mock_get(key: str):
        return cache._store.get(key)

    def mock_set(key: str, value: dict, ttl: int = 300):
        cache._store[key] = dict(value)

    cache.get = MagicMock(side_effect=mock_get)
    cache.set = MagicMock(side_effect=mock_set)
    return cache


@pytest.fixture()
def _executor_patches(monkeypatch: pytest.MonkeyPatch) -> tuple[MagicMock, MagicMock]:
    """Patch external deps for executor tests."""
    cache_mock = _make_tool_cache_mock()
    run_mock = MagicMock(return_value={
        "success": True,
        "stdout": "PORT   STATE SERVICE\n80/tcp open  http",
        "stderr": "",
        "return_code": 0,
    })

    monkeypatch.setattr(
        "src.tools.executor.get_tool_cache",
        lambda: cache_mock,
    )
    monkeypatch.setattr(
        "src.tools.executor.cache_key_for_execute",
        lambda cmd, sb, to: f"cache:{cmd}:{sb}:{to}",
    )
    monkeypatch.setattr(
        "src.tools.executor.ttl_for_tool",
        lambda tool: 300,
    )
    monkeypatch.setattr(
        "src.tools.executor.extract_tool_name",
        lambda cmd: "nmap",
    )
    monkeypatch.setattr(
        "src.tools.executor.check_tool_available",
        lambda tool, use_sandbox=False: True,
    )
    monkeypatch.setattr(
        "src.tools.executor.build_sandbox_exec_argv",
        lambda parts, use_sandbox=False: parts,
    )
    monkeypatch.setattr(
        "src.tools.executor.run_argv_simple_sync",
        run_mock,
    )
    monkeypatch.setattr(
        "src.tools.executor.settings",
        MagicMock(recon_tools_timeout=300),
    )
    monkeypatch.setattr(
        "src.tools.executor.ALLOWED_TOOLS",
        {"nmap", "nuclei", "gobuster", "nikto"},
    )

    return cache_mock, run_mock


class TestExecutorCacheHit:
    """BKL-007: use_cache=True must return cached result on repeated call."""

    def test_first_call_runs_command(
        self, _executor_patches: tuple[MagicMock, MagicMock],
    ) -> None:
        _, run_mock = _executor_patches
        from src.tools.executor import execute_command

        result = execute_command("nmap -sV 10.0.0.1", use_cache=True)
        assert result["success"] is True
        run_mock.assert_called_once()

    def test_second_call_returns_cached(
        self, _executor_patches: tuple[MagicMock, MagicMock],
    ) -> None:
        cache_mock, run_mock = _executor_patches
        from src.tools.executor import execute_command

        execute_command("nmap -sV 10.0.0.1", use_cache=True)
        run_mock.reset_mock()

        result = execute_command("nmap -sV 10.0.0.1", use_cache=True)
        assert result["success"] is True
        assert result["execution_time"] == 0.0
        run_mock.assert_not_called()

    def test_cache_stores_successful_result(
        self, _executor_patches: tuple[MagicMock, MagicMock],
    ) -> None:
        cache_mock, _ = _executor_patches
        from src.tools.executor import execute_command

        execute_command("nmap -sV 10.0.0.1", use_cache=True)
        cache_mock.set.assert_called_once()


class TestExecutorCacheBypass:
    """BKL-007: use_cache=False must bypass cache entirely."""

    def test_bypass_cache_runs_command_every_time(
        self, _executor_patches: tuple[MagicMock, MagicMock],
    ) -> None:
        _, run_mock = _executor_patches
        from src.tools.executor import execute_command

        execute_command("nmap -sV 10.0.0.1", use_cache=False)
        execute_command("nmap -sV 10.0.0.1", use_cache=False)

        assert run_mock.call_count == 2

    def test_bypass_does_not_read_cache(
        self, _executor_patches: tuple[MagicMock, MagicMock],
    ) -> None:
        cache_mock, _ = _executor_patches
        from src.tools.executor import execute_command

        execute_command("nmap -sV 10.0.0.1", use_cache=False)
        cache_mock.get.assert_not_called()

    def test_bypass_does_not_write_cache(
        self, _executor_patches: tuple[MagicMock, MagicMock],
    ) -> None:
        cache_mock, _ = _executor_patches
        from src.tools.executor import execute_command

        execute_command("nmap -sV 10.0.0.1", use_cache=False)
        cache_mock.set.assert_not_called()


class TestExecutorNotAllowedTool:
    """BKL-007: disallowed tools are rejected regardless of cache."""

    def test_disallowed_tool_returns_failure(
        self, _executor_patches: tuple[MagicMock, MagicMock], monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            "src.tools.executor.extract_tool_name",
            lambda cmd: "rm",
        )
        from src.tools.executor import execute_command

        result = execute_command("rm -rf /", use_cache=True)
        assert result["success"] is False
        assert "not allowed" in result["stderr"].lower() or "allowed" in result["stderr"].lower()
