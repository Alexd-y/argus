"""Phase 6 — worker drivers: WRB cycle, CLI argv parity (no dangerous flags), gating."""

from __future__ import annotations

import json

import pytest
from src.cairn.workers import wrb as wrb_module
from src.cairn.workers.adapters import ClaudeCodeDriver, CodexDriver, PiDriver
from src.cairn.workers.base import CairnTaskContext, CairnWorkerConfig
from src.cairn.workers.registry import get_driver
from src.cairn.workers.wrb import WrbAgentDriver


class _FakeResult:
    def __init__(self) -> None:
        self.answer = '{"description": "found it"}'
        self.steps = []
        self.evidence_backed = True


class _FakeAgent:
    def __init__(self, *args, **kwargs) -> None:  # noqa: D401
        pass

    async def run(self, *args, **kwargs) -> _FakeResult:
        return _FakeResult()


async def _dummy_llm(*args, **kwargs) -> str:
    return '{"description": "found it"}'


async def test_wrb_execute_returns_answer_text(monkeypatch) -> None:
    monkeypatch.setattr(wrb_module, "ReActAgent", _FakeAgent)
    driver = WrbAgentDriver()
    ctx = CairnTaskContext(
        tenant_id="t", project_id="p", task_type="explore", llm_caller=_dummy_llm
    )
    result = await driver.execute(ctx, "prompt", None)
    assert result.text == '{"description": "found it"}'
    assert result.session  # a session id is always assigned
    assert result.evidence_backed is True


async def test_wrb_fails_closed_without_llm_caller() -> None:
    driver = WrbAgentDriver()
    ctx = CairnTaskContext(tenant_id="t", project_id="p", task_type="explore", llm_caller=None)
    with pytest.raises(RuntimeError, match="requires an llm_caller"):
        await driver.execute(ctx, "prompt", None)


async def test_claudecode_argv_has_no_dangerous_flag() -> None:
    driver = ClaudeCodeDriver()
    ctx = CairnTaskContext(
        tenant_id="t",
        project_id="p",
        task_type="explore",
        worker=CairnWorkerConfig(name="w", type_name="claudecode"),
    )
    result = await driver.execute(ctx, "PROMPT", "sess-1")
    assert result.argv == ["claude", "--session-id", "sess-1", "-p", "--", "PROMPT"]
    assert "--dangerously-skip-permissions" not in result.argv


async def test_codex_argv_has_no_bypass_flag() -> None:
    driver = CodexDriver()
    ctx = CairnTaskContext(
        tenant_id="t",
        project_id="p",
        task_type="explore",
        worker=CairnWorkerConfig(
            name="w",
            type_name="codex",
            env={"CODEX_MODEL": "m", "CODEX_BASE_URL": "http://x"},
        ),
    )
    result = await driver.execute(ctx, "P", None)
    assert "--dangerously-bypass-approvals-and-sandbox" not in result.argv
    assert result.argv[:3] == ["codex", "exec", "--model"]
    assert result.argv[-1] == "P"


async def test_pi_jsonl_session_and_response() -> None:
    driver = PiDriver()
    stdout = "\n".join(
        [
            json.dumps({"type": "session", "id": "s1"}),
            json.dumps(
                {
                    "type": "turn_end",
                    "message": {
                        "role": "assistant",
                        "content": [{"type": "text", "text": "hello world"}],
                    },
                }
            ),
        ]
    )
    assert driver.extract_session(None, stdout, "") == "s1"
    assert driver.extract_response_text(stdout, "") == "hello world"


def test_registry_wrb_always_available() -> None:
    assert get_driver("wrb").type_name == "wrb"


def test_registry_blocks_cli_in_production() -> None:
    with pytest.raises(RuntimeError, match="lab_unrestricted"):
        get_driver("codex", execution_mode="production")


def test_registry_allows_cli_in_lab_with_flag(monkeypatch) -> None:
    from src.core.config import settings

    monkeypatch.setattr(settings, "cairn_cli_drivers_enabled", True, raising=False)
    assert get_driver("codex", execution_mode="lab_unrestricted").type_name == "codex"


def test_registry_unknown_driver_raises() -> None:
    with pytest.raises(RuntimeError, match="unknown"):
        get_driver("bogus")


def test_cairn_llm_tasks_never_cloud() -> None:
    from src.llm.facade import _CLOUD_FALLBACK_TASKS, _TASK_TO_PREFERRED_ALIAS
    from src.llm.task_router import LLMTask

    cairn_tasks = [
        LLMTask.CAIRN_BOOTSTRAP,
        LLMTask.CAIRN_REASON,
        LLMTask.CAIRN_EXPLORE,
        LLMTask.CAIRN_CONCLUDE,
    ]
    for task in cairn_tasks:
        assert task not in _CLOUD_FALLBACK_TASKS
        assert _TASK_TO_PREFERRED_ALIAS[task] == "security_reasoner"
