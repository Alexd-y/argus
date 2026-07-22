"""Repeater: scope-gated, byte-exact request replay (WB-P3b).

The workbench analogue of Burp's Repeater. The security-critical invariant is
that **every** replay passes the mandatory forward gate *before* a single byte
leaves the process (SI-WB-1): scope first, then the optional full preflight hook
(ownership / policy / approval, wired by the live surface). A blocked replay
never touches the injected :class:`HttpSender`.

Network egress itself is delegated to an injected ``HttpSender`` so this engine
is pure and offline-testable; the concrete httpx/sandbox sender (which performs
real, infra-gated network I/O) is provided by the live surface (WB-P3b-2).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from src.web_workbench.message_editor.engine import RawHttpMessage
from src.web_workbench.proxy.forward_gate import (
    ForwardGate,
    ForwardOutcome,
    PreflightHook,
)
from src.web_workbench.proxy.transport import HttpMessageError, NormalizedRequest
from src.web_workbench.projects.service import ProjectScopeService


@dataclass(frozen=True)
class RawResponse:
    """A replay response captured verbatim (raw bytes + parsed status).

    ``raw`` is the reconstructed status line + headers + (bounded) body. When the
    body exceeded the sender's cap it is truncated and ``truncated`` is ``True``.
    """

    status_code: int
    raw: bytes
    duration_ms: int
    truncated: bool = False


class HttpSender(Protocol):
    """Performs the actual (infra-gated) upstream send for an allowed replay."""

    def send(self, request: NormalizedRequest, body: bytes) -> RawResponse: ...


@dataclass(frozen=True)
class ReplayResult:
    """Outcome of a replay attempt.

    ``response`` is present only when ``outcome`` is ``FORWARD``. On a block the
    sender was never invoked and ``reason`` carries the closed-taxonomy cause.
    """

    outcome: ForwardOutcome
    reason: str | None
    scope_summary: str | None
    response: RawResponse | None

    @property
    def forwarded(self) -> bool:
        return self.outcome is ForwardOutcome.FORWARD


class RepeaterService:
    """Replays a raw request through the mandatory forward gate.

    Construct once per project (scope rule set closed over via
    :class:`ProjectScopeService`); pass a ``preflight_hook`` to enforce the full
    ownership/policy/approval guardrail on the live surface.
    """

    def __init__(
        self,
        scope_service: ProjectScopeService,
        *,
        preflight_hook: PreflightHook | None = None,
    ) -> None:
        self._gate = ForwardGate(scope_service, preflight_hook=preflight_hook)

    def replay(self, raw_request: bytes, sender: HttpSender) -> ReplayResult:
        """Gate then (only if allowed) send ``raw_request`` byte-exactly.

        Raises :class:`HttpMessageError` if the request head is malformed (the
        operator must fix it before it can be gated or sent).
        """
        request = NormalizedRequest.parse(raw_request)
        decision = self._gate.evaluate(request)
        if not decision.allowed:
            return ReplayResult(
                outcome=decision.outcome,
                reason=decision.reason,
                scope_summary=decision.scope_summary,
                response=None,
            )
        body = RawHttpMessage.from_bytes(raw_request).body
        response = sender.send(request, body)
        return ReplayResult(
            outcome=ForwardOutcome.FORWARD,
            reason=None,
            scope_summary=None,
            response=response,
        )


__all__ = [
    "HttpMessageError",
    "HttpSender",
    "RawResponse",
    "ReplayResult",
    "RepeaterService",
]
