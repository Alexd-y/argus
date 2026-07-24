"""Owner/attacker replay runner → authorization analysis (WB-P6b).

Fires the **same** owner-owned resource request as each principal (owner,
other authenticated attacker, anonymous), captures the request/response pairs,
and feeds them to the pure :func:`~src.web_workbench.checks.authorization_analyzer.
analyze_authorization` adapter (which reuses the battle-tested ``AuthzOracle``)
to classify proven cross-user reads as IDOR / BFLA / unauth-access findings.

Invariants:

* **Gate first (SI-WB-1).** Every principal's request is evaluated by
  :class:`~src.web_workbench.proxy.forward_gate.ForwardGate` before a byte
  leaves the process; a blocked principal is skipped (recorded), never sent.
* **Byte-fidelity.** The owner target request bytes are reused verbatim; only a
  per-principal ``Cookie`` header is injected (session established by the macro
  runner). This keeps the diff meaningful — same request, different identity.
* **No raw secrets / bodies leak.** The analyzer emits only field *paths*,
  the URL object-id token and coarse metadata; this runner adds no body bytes.

Network egress is delegated to an injected :class:`~src.web_workbench.repeater.
engine.HttpSender`, so the runner is offline-testable with a stub sender.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from src.web_workbench.checks.authorization_analyzer import (
    AuthorizationFinding,
    CapturedExchange,
    analyze_authorization,
)
from src.web_workbench.message_editor.engine import RawHttpMessage
from src.web_workbench.proxy.forward_gate import ForwardGate
from src.web_workbench.proxy.transport import (
    HttpMessageError,
    NormalizedRequest,
    NormalizedResponse,
)
from src.web_workbench.repeater.engine import HttpSender
from src.web_workbench.sessions.cookies import inject_cookie_header
from src.web_workbench.sessions.repository import ROLE_ANONYMOUS


class ReplayRunnerError(Exception):
    """Raised on malformed replay input (fail-closed)."""


@dataclass(frozen=True)
class PrincipalRequest:
    """A principal to replay the target request as.

    ``cookie_header`` is the session cookie value established for this principal
    (``None`` / empty for the anonymous principal). ``role`` is
    ``owner`` | ``attacker`` | ``anonymous``.
    """

    principal: str
    role: str
    cookie_header: str | None = None


@dataclass(frozen=True)
class ReplayOutcome:
    """Result of an owner/attacker replay round."""

    owner_forwarded: bool
    owner_status: int | None
    findings: tuple[AuthorizationFinding, ...]
    blocked_principals: tuple[str, ...] = field(default_factory=tuple)


class AuthorizationReplayRunner:
    """Replays a target request across principals and diffs the responses."""

    def __init__(self, gate: ForwardGate, sender: HttpSender) -> None:
        self._gate = gate
        self._sender = sender

    def _capture(self, target_raw: bytes, principal: PrincipalRequest) -> CapturedExchange | None:
        """Gate + send the target as ``principal``; ``None`` if gate-blocked."""
        raw = inject_cookie_header(target_raw, principal.cookie_header or "")
        try:
            request = NormalizedRequest.parse(raw)
        except HttpMessageError as exc:
            raise ReplayRunnerError("target request is malformed") from exc

        decision = self._gate.evaluate(request)
        if not decision.allowed:
            return None

        request_body = RawHttpMessage.from_bytes(raw).body
        raw_response = self._sender.send(request, request_body).raw
        response = NormalizedResponse.parse(raw_response)
        response_body = RawHttpMessage.from_bytes(raw_response).body
        return CapturedExchange(
            principal=principal.principal,
            request=request,
            response=response,
            request_body=request_body,
            response_body=response_body,
            is_anonymous=(principal.role == ROLE_ANONYMOUS),
        )

    def run(
        self,
        target_raw: bytes,
        owner: PrincipalRequest,
        attackers: Sequence[PrincipalRequest],
        *,
        sensitive_fields: Sequence[str] = (),
        volatile_fields: Sequence[str] = (),
        denied_statuses: Sequence[int] = (),
    ) -> ReplayOutcome:
        """Replay ``target_raw`` as ``owner`` then each attacker; classify diffs."""
        if not attackers:
            raise ReplayRunnerError("at least one attacker principal is required")

        blocked: list[str] = []
        owner_exchange = self._capture(target_raw, owner)
        if owner_exchange is None:
            # The owner baseline itself is out of scope — nothing to compare.
            return ReplayOutcome(
                owner_forwarded=False,
                owner_status=None,
                findings=(),
                blocked_principals=(owner.principal,),
            )

        attacker_exchanges: list[CapturedExchange] = []
        for attacker in attackers:
            exchange = self._capture(target_raw, attacker)
            if exchange is None:
                blocked.append(attacker.principal)
                continue
            attacker_exchanges.append(exchange)

        findings: tuple[AuthorizationFinding, ...] = ()
        if attacker_exchanges:
            findings = tuple(
                analyze_authorization(
                    owner=owner_exchange,
                    attackers=attacker_exchanges,
                    sensitive_fields=sensitive_fields,
                    volatile_fields=volatile_fields,
                    denied_statuses=denied_statuses,
                )
            )

        return ReplayOutcome(
            owner_forwarded=True,
            owner_status=owner_exchange.response.status_code,
            findings=findings,
            blocked_principals=tuple(blocked),
        )


__all__ = [
    "AuthorizationReplayRunner",
    "PrincipalRequest",
    "ReplayOutcome",
    "ReplayRunnerError",
]
