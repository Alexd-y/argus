"""CairnToolExecutor — the security bridge between ReActAgent and the sandbox.

Every tool the agent asks for passes a fail-closed gate chain (§9.4). Any failed
check denies execution, is logged as a structured event, and is returned to the
agent as an observation (so the loop can adapt) rather than silently dropped.

Gate order (each fail-closed):
  1. tool in the task allowlist;
  2. free-form ``bash`` only under ``lab_unrestricted``;
  3. target in scope (``ScopeEngine``);
  4. ``assert_execution_allowed`` (LAB lease / boundary gate);
  5. approval policy for aggressive tools (``evaluate_tool_approval_policy``);
  6. budget / rate limit (injected);
  7. run via the injected sandbox runner;
  8. truncate + redact output, persist full output as an artifact, return a short
     summary + reference to the agent.

Dependencies are injected so the gate chain is unit-testable without Docker.
"""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from src.pipeline.contracts.tool_job import TargetKind, TargetSpec
from src.policy.scope import ScopeEngine
from src.sandbox.execution_lease_gate import assert_execution_allowed

logger = logging.getLogger(__name__)

# Output returned inline to the agent is capped; the full output is an artifact.
_MAX_INLINE_OUTPUT = 4000

#: Runner runs a tool in the sandbox and returns stdout/stderr/exit_code and,
#: optionally, an ``artifact_object_key`` for the full persisted output.
ToolRunner = Callable[..., Awaitable[dict[str, Any]]]
#: Approval policy: returns an object/dict with an ``approved``/``allowed`` bool.
ApprovalPolicy = Callable[[str], Any]
#: Budget check: raises or returns False when exhausted.
BudgetCheck = Callable[[str], Awaitable[bool]] | Callable[[str], bool]


class CairnToolDenied(Exception):
    """Raised internally when a gate denies a tool; surfaced as an observation."""

    def __init__(self, reason: str, code: str = "denied") -> None:
        super().__init__(reason)
        self.reason = reason
        self.code = code


@dataclass(slots=True)
class ToolExecutionResult:
    ok: bool
    tool_name: str
    summary: str
    exit_code: int | None = None
    artifact_object_key: str | None = None
    denied: bool = False
    reason: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)

    def as_observation(self) -> dict[str, Any]:
        """Compact dict the ReActAgent observes."""
        return {
            "ok": self.ok,
            "tool": self.tool_name,
            "summary": self.summary,
            "exit_code": self.exit_code,
            "artifact": self.artifact_object_key,
            "denied": self.denied,
            "reason": self.reason,
        }


def _target_spec_from_str(target: str) -> TargetSpec:
    """Best-effort TargetSpec for scope evaluation."""
    value = target.strip()
    if value.startswith(("http://", "https://")):
        return TargetSpec(kind=TargetKind.URL, url=value)
    host = value
    try:
        ipaddress.ip_address(host)
        return TargetSpec(kind=TargetKind.IP, ip=host)
    except ValueError:
        pass
    return TargetSpec(kind=TargetKind.DOMAIN, domain=host)


def _redact(text: str) -> str:
    """Redact secret PATTERNS in free-form tool output (keys/tokens/passwords).

    Uses the pattern-based ``rag.ingestion.redact_secrets`` — NOT the single-value
    middle-masker ``parsers._base.redact_secret``, which would mangle all output.
    """
    try:
        from src.rag.ingestion import redact_secrets

        return redact_secrets(text)
    except Exception:  # pragma: no cover - redaction must never crash the gate
        return text


class CairnToolExecutor:
    """Fail-closed tool executor injected into ``ReActAgent.tool_executor``."""

    def __init__(
        self,
        *,
        tenant_id: str,
        execution_mode: str,
        scope_engine: ScopeEngine,
        allowed_tools: set[str],
        scan_options: dict[str, Any] | None = None,
        runner: ToolRunner,
        approval_policy: ApprovalPolicy | None = None,
        budget_check: BudgetCheck | None = None,
        aggressive_tools: set[str] | None = None,
        default_timeout: int = 120,
    ) -> None:
        self._tenant_id = tenant_id
        self._execution_mode = execution_mode
        self._scope = scope_engine
        self._allowed = allowed_tools
        self._opts = scan_options or {}
        self._runner = runner
        self._approval = approval_policy
        self._budget = budget_check
        self._aggressive = aggressive_tools or set()
        self._timeout = default_timeout

    async def __call__(self, tool_name: str, tool_args: dict[str, Any]) -> dict[str, Any]:
        try:
            result = await self._run(tool_name, dict(tool_args or {}))
        except CairnToolDenied as denied:
            logger.warning(
                "cairn_tool_denied",
                extra={"event": "cairn_tool_denied", "tool": tool_name, "reason": denied.reason},
            )
            return ToolExecutionResult(
                ok=False,
                tool_name=tool_name,
                summary=f"denied: {denied.reason}",
                denied=True,
                reason=denied.reason,
            ).as_observation()
        return result.as_observation()

    async def _run(self, tool_name: str, args: dict[str, Any]) -> ToolExecutionResult:
        # 1. allowlist
        if tool_name not in self._allowed:
            raise CairnToolDenied(f"tool {tool_name!r} not in allowlist", "not_allowed")

        # 2. free-form bash only under lab_unrestricted
        if tool_name == "bash" and self._execution_mode != "lab_unrestricted":
            raise CairnToolDenied("bash is only permitted in lab_unrestricted", "bash_forbidden")

        target = str(args.get("target") or args.get("url") or "").strip()

        # 3. scope check (skip only for non-targeted utility tools)
        if target:
            decision = self._scope.check(_target_spec_from_str(target))
            if not decision.allowed:
                raise CairnToolDenied(
                    f"target {target!r} out of scope: {decision.failure_summary}",
                    "out_of_scope",
                )

        # 4. LAB lease / boundary gate (fail-closed)
        try:
            assert_execution_allowed(
                tool_name, target, self._opts, tenant_id=self._tenant_id or None
            )
        except PermissionError as exc:
            raise CairnToolDenied(f"execution gate: {exc}", "gate_denied") from exc

        # 5. approval policy for aggressive tools
        if tool_name in self._aggressive and self._approval is not None:
            verdict = self._approval(tool_name)
            approved = getattr(verdict, "approved", None)
            if approved is None:
                approved = getattr(verdict, "allowed", None)
            if approved is None and isinstance(verdict, dict):
                approved = verdict.get("approved", verdict.get("allowed"))
            if not approved:
                raise CairnToolDenied(f"tool {tool_name!r} requires approval", "approval_required")

        # 6. budget / rate limit
        if self._budget is not None:
            allowed = self._budget(tool_name)
            if hasattr(allowed, "__await__"):
                allowed = await allowed  # type: ignore[assignment]
            if not allowed:
                raise CairnToolDenied("budget exhausted", "budget_exhausted")

        # 7. run
        raw = await self._runner(tool_name, args, timeout=self._timeout)
        stdout = _redact(str(raw.get("stdout", "")))
        stderr = _redact(str(raw.get("stderr", "")))
        exit_code = raw.get("exit_code")
        artifact = raw.get("artifact_object_key")

        # 8. truncate for the agent; full output lives in the artifact
        inline = stdout if len(stdout) <= _MAX_INLINE_OUTPUT else stdout[:_MAX_INLINE_OUTPUT] + "…"
        summary = inline or (stderr[:_MAX_INLINE_OUTPUT] if stderr else "(no output)")
        return ToolExecutionResult(
            ok=(exit_code == 0),
            tool_name=tool_name,
            summary=summary,
            exit_code=exit_code,
            artifact_object_key=artifact,
            evidence={"artifact_object_key": artifact} if artifact else {},
        )


__all__ = ["CairnToolDenied", "CairnToolExecutor", "ToolExecutionResult"]
