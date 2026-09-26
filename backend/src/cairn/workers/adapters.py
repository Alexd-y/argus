"""CLI parity drivers (claude / codex / pi) — opt-in, hardened.

Ported from ``_external/Cairn/cairn/src/cairn/dispatcher/workers/adapters/*`` with
the upstream ``--dangerously-skip-permissions`` /
``--dangerously-bypass-approvals-and-sandbox`` flags REMOVED (hard rule #1). These
drivers are only handed out by the registry under ``lab_unrestricted`` with
``cairn_cli_drivers_enabled``; in ``production`` requesting one fails closed.

Secrets (``*_API_KEY`` / ``*_AUTH_TOKEN``) live only in ``worker.env`` and are used
for the health ping; they are never placed on the argv or logged.
"""

from __future__ import annotations

import json
from pathlib import PurePosixPath
from typing import Any

from src.cairn.workers.base import (
    CairnTaskContext,
    CairnWorkerConfig,
    DriverResult,
    RegexSessionDriver,
    SeedSessionDriver,
)
from src.cairn.workers.health import HealthResult, http_ping, proxy_from_env

ANTHROPIC_VERSION = "2023-06-01"

# Session dir root INSIDE the sandbox container (never the host filesystem).
_PI_CONTAINER_ROOT = "/tmp/cairn-pi"  # nosec B108 - sandbox container path, not host


class ClaudeCodeDriver(SeedSessionDriver):
    type_name = "claudecode"

    def local_binary(self) -> str | None:
        return "claude"

    async def check_health(self, worker: CairnWorkerConfig, *, timeout: float) -> HealthResult:
        env = worker.env
        return await http_ping(
            f"{env['ANTHROPIC_BASE_URL']}/v1/messages",
            headers={
                "Authorization": f"Bearer {env['ANTHROPIC_AUTH_TOKEN']}",
                "anthropic-version": ANTHROPIC_VERSION,
                "content-type": "application/json",
            },
            json_body={
                "model": env["ANTHROPIC_MODEL"],
                "max_tokens": 10,
                "messages": [{"role": "user", "content": "ping"}],
            },
            timeout=timeout,
            proxy=proxy_from_env(env),
        )

    async def execute(
        self, _ctx: CairnTaskContext, prompt: str, session: str | None
    ) -> DriverResult:
        if session is None:
            raise RuntimeError("claudecode driver requires a seeded session id")
        return DriverResult(
            argv=["claude", "--session-id", session, "-p", "--", prompt],
            session=session,
        )

    async def conclude(self, _ctx: CairnTaskContext, prompt: str, session: str) -> DriverResult:
        return DriverResult(argv=["claude", "-r", session, "-p", "--", prompt], session=session)


class CodexDriver(RegexSessionDriver):
    type_name = "codex"

    def __init__(self, local: bool = False) -> None:
        self.local = local

    def local_binary(self) -> str | None:
        return "codex"

    async def check_health(self, worker: CairnWorkerConfig, *, timeout: float) -> HealthResult:
        env = worker.env
        return await http_ping(
            f"{env['CODEX_BASE_URL']}/responses",
            headers={
                "Authorization": f"Bearer {env['OPENAI_API_KEY']}",
                "content-type": "application/json",
            },
            json_body={
                "model": env["CODEX_MODEL"],
                "input": [{"role": "user", "content": "ping"}],
                "stream": False,
            },
            timeout=timeout,
            proxy=proxy_from_env(env),
        )

    def _provider_config(self, env: dict[str, str]) -> list[str]:
        return [
            "--model",
            env["CODEX_MODEL"],
            "-c",
            'model_provider="cairn"',
            "-c",
            'model_providers.cairn.name="cairn"',
            "-c",
            'model_providers.cairn.wire_api="responses"',
            "-c",
            'model_reasoning_effort="high"',
            "-c",
            f'model_providers.cairn.base_url="{env["CODEX_BASE_URL"]}"',
            "-c",
            'model_providers.cairn.env_key="OPENAI_API_KEY"',
        ]

    async def execute(
        self, ctx: CairnTaskContext, prompt: str, _session: str | None
    ) -> DriverResult:
        if self.local:
            return DriverResult(argv=["codex", "exec", "--", prompt])
        argv = [
            "codex",
            "exec",
            *self._provider_config(ctx.worker.env if ctx.worker else {}),
            "--",
            prompt,
        ]
        return DriverResult(argv=argv)

    async def conclude(self, ctx: CairnTaskContext, prompt: str, session: str) -> DriverResult:
        if self.local:
            return DriverResult(argv=["codex", "exec", "resume", session, "--", prompt])
        argv = [
            "codex",
            "exec",
            "resume",
            session,
            *self._provider_config(ctx.worker.env if ctx.worker else {}),
            "--",
            prompt,
        ]
        return DriverResult(argv=argv)


class PiDriver(RegexSessionDriver):
    type_name = "pi"

    def __init__(self, local: bool = False) -> None:
        self.local = local

    def local_binary(self) -> str | None:
        return "pi"

    async def check_health(self, worker: CairnWorkerConfig, *, timeout: float) -> HealthResult:
        env = worker.env
        base = env["PI_BASE_URL"].rstrip("/")
        model = env["PI_MODEL"]
        api = env["PI_PROVIDER_API"]
        proxy = proxy_from_env(env)
        headers = {
            "Authorization": f"Bearer {env['PI_API_KEY']}",
            "content-type": "application/json",
        }
        if "anthropic" in api:
            return await http_ping(
                f"{base}/v1/messages",
                headers={**headers, "anthropic-version": ANTHROPIC_VERSION},
                json_body={
                    "model": model,
                    "max_tokens": 10,
                    "messages": [{"role": "user", "content": "ping"}],
                },
                timeout=timeout,
                proxy=proxy,
            )
        if "responses" in api:
            return await http_ping(
                f"{base}/responses",
                headers=headers,
                json_body={
                    "model": model,
                    "input": [{"role": "user", "content": "ping"}],
                    "stream": False,
                },
                timeout=timeout,
                proxy=proxy,
            )
        return await http_ping(
            f"{base}/chat/completions",
            headers=headers,
            json_body={
                "model": model,
                "max_tokens": 10,
                "messages": [{"role": "user", "content": "ping"}],
            },
            timeout=timeout,
            proxy=proxy,
        )

    async def execute(
        self, ctx: CairnTaskContext, prompt: str, session: str | None
    ) -> DriverResult:
        worker = ctx.worker
        argv = [
            "--provider",
            "cairn",
            "--model",
            worker.env["PI_MODEL"] if worker else "",
            "--mode",
            "json",
        ]
        if session:
            argv.extend(["--session", session])
        argv.extend(["-p", prompt])
        return DriverResult(argv=argv, session=session)

    async def conclude(self, ctx: CairnTaskContext, prompt: str, session: str) -> DriverResult:
        worker = ctx.worker
        argv = [
            "--provider",
            "cairn",
            "--model",
            worker.env["PI_MODEL"] if worker else "",
            "--mode",
            "json",
            "--session",
            session,
            "-p",
            prompt,
        ]
        return DriverResult(argv=argv, session=session)

    def extract_session(self, session: str | None, stdout: str, _stderr: str) -> str | None:
        if session:
            return session
        for event in self._iter_events(stdout):
            if event.get("type") == "session":
                sid = event.get("id")
                if isinstance(sid, str) and sid:
                    return sid
        return None

    def extract_response_text(self, stdout: str, _stderr: str) -> str:
        assistant: dict[str, Any] | None = None
        for event in self._iter_events(stdout):
            if event.get("type") == "turn_end":
                msg = event.get("message")
                if isinstance(msg, dict) and msg.get("role") == "assistant":
                    assistant = msg
            elif event.get("type") == "agent_end":
                messages = event.get("messages")
                if isinstance(messages, list):
                    for msg in reversed(messages):
                        if isinstance(msg, dict) and msg.get("role") == "assistant":
                            assistant = msg
                            break
        if assistant is None:
            return stdout
        content = assistant.get("content")
        if not isinstance(content, list):
            return stdout
        parts = [
            item["text"]
            for item in content
            if isinstance(item, dict)
            and item.get("type") == "text"
            and isinstance(item.get("text"), str)
        ]
        return "\n".join(parts).strip() or stdout

    @staticmethod
    def _session_dir(worker: CairnWorkerConfig) -> str:
        return str(PurePosixPath(_PI_CONTAINER_ROOT) / worker.name / "sessions")

    @staticmethod
    def _iter_events(stdout: str) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                events.append(payload)
        return events


__all__ = ["ClaudeCodeDriver", "CodexDriver", "PiDriver"]
