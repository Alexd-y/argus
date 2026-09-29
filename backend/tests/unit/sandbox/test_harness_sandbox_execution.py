"""F-H01 follow-up: CLI/Library validation harnesses must not execute an
attacker-influenceable reproducer payload on the host.

Previously ``CliHarness`` ran ``payload`` via ``asyncio.create_subprocess_shell``
and ``LibraryHarness`` ran it via host ``python3`` — arbitrary code execution on
the host. Both now route into the argus-sandbox through the single gateway and
fail closed when the sandbox is unavailable.
"""

from __future__ import annotations

import ast
import asyncio
from pathlib import Path

import pytest
from src.sandbox.docker_gateway import DockerGatewayError, ExecResult
from src.sandbox.validation.harness import profiles as harness


class TestCliHarnessContainment:
    def test_fails_closed_when_sandbox_disabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(harness.settings, "sandbox_enabled", False, raising=False)
        # Guard: exec_in must never be called when the sandbox is disabled.
        monkeypatch.setattr(
            harness, "exec_in", lambda *a, **k: pytest.fail("exec_in called while disabled")
        )
        res = asyncio.run(
            harness.CliHarness().execute({"payload": "id; cat /etc/shadow"}, {}, timeout=30)
        )
        assert res["exit_code"] == -1
        assert "sandbox" in res["stderr"].lower()

    def test_runs_in_sandbox_via_gateway(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict = {}

        async def _fake_exec(container, argv, *, timeout, workdir=None, env=None):  # noqa: ANN001
            captured["container"] = container
            captured["argv"] = argv
            return ExecResult(0, "reproducer-output", "", 0.01)

        monkeypatch.setattr(harness.settings, "sandbox_enabled", True, raising=False)
        monkeypatch.setattr(harness.settings, "sandbox_container_name", "argus-sandbox", raising=False)
        monkeypatch.setattr(harness, "exec_in", _fake_exec)

        payload = "'; id; echo pwned '| grep x"
        res = asyncio.run(harness.CliHarness().execute({"payload": payload}, {}, timeout=30))

        assert res["exit_code"] == 0
        assert res["stdout"] == "reproducer-output"
        # Payload carried as ONE argv element under sh -c (pipes preserved, no
        # argv injection into docker exec).
        assert captured["container"] == "argus-sandbox"
        assert captured["argv"] == ["sh", "-c", payload]

    def test_gateway_rejection_is_contained(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def _reject(*a, **k):  # noqa: ANN002, ANN003
            raise DockerGatewayError("bad container")

        monkeypatch.setattr(harness.settings, "sandbox_enabled", True, raising=False)
        monkeypatch.setattr(harness, "exec_in", _reject)
        res = asyncio.run(harness.CliHarness().execute({"payload": "id"}, {}, timeout=30))
        assert res["exit_code"] == 1
        assert "rejected" in res["stderr"]


class TestLibraryHarnessContainment:
    def test_fails_closed_when_sandbox_disabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(harness.settings, "sandbox_enabled", False, raising=False)
        monkeypatch.setattr(
            harness, "exec_in", lambda *a, **k: pytest.fail("exec_in called while disabled")
        )
        res = asyncio.run(
            harness.LibraryHarness().execute(
                {"payload": "import os; os.system('id')"}, {}, timeout=30
            )
        )
        assert res["exit_code"] == -1
        assert "sandbox" in res["stderr"].lower()

    def test_runs_python_in_sandbox(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict = {}

        async def _fake_exec(container, argv, *, timeout, workdir=None, env=None):  # noqa: ANN001
            captured["argv"] = argv
            return ExecResult(0, "py-out", "", 0.01)

        monkeypatch.setattr(harness.settings, "sandbox_enabled", True, raising=False)
        monkeypatch.setattr(harness.settings, "sandbox_container_name", "argus-sandbox", raising=False)
        monkeypatch.setattr(harness, "exec_in", _fake_exec)

        code = "print('hello')"
        res = asyncio.run(harness.LibraryHarness().execute({"payload": code}, {}, timeout=30))
        assert res["exit_code"] == 0
        assert captured["argv"] == ["python3", "-c", code]


def test_no_host_shell_execution_in_module() -> None:
    """Static guard: profiles.py must not use create_subprocess_shell."""
    src = Path(harness.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == "create_subprocess_shell":
            raise AssertionError("profiles.py still uses create_subprocess_shell (host shell)")
