"""Intruder execution service — gated, budgeted, resumable attack runner (WB-P4b).

Ties the pure request generator (:func:`~src.web_workbench.intruder.engine.
generate_requests`) to the mandatory forward gate, an authorized request budget,
persistence, and pause/resume/cancel control. The security-critical invariants:

* **Every request passes the gate first (SI-WB-1).** Each generated request is
  evaluated by :class:`~src.web_workbench.proxy.forward_gate.ForwardGate` (scope,
  then the optional preflight hook) BEFORE a byte leaves the process; a blocked
  request is recorded ``blocked`` and the sender is never invoked.
* **Bounded blast radius.** The attack's total request count is checked against
  an authorized ``max_requests`` budget (typically derived from the project's
  EAP) before any request is sent — an over-budget attack fails closed without
  sending anything.
* **Payloads come from the signed registry.** ``payload_sets`` are materialised
  by the caller through the signed ``PayloadRegistry`` / ``PayloadBuilder``
  (SI-5); this service never sources payloads itself and never persists raw
  payload material (only a reference label + index).
* **Every attempt is recorded** (audit) and the run is **resumable** — progress
  is checkpointed so a paused/interrupted attack resumes at the next index
  without re-sending completed requests.

Network egress is delegated to an injected :class:`~src.web_workbench.repeater.
engine.HttpSender` (the same Protocol the Repeater uses) so this service is
offline-testable with a stub sender / ``httpx.MockTransport``.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum

from src.web_workbench.intruder.analysis import grep_match
from src.web_workbench.intruder.engine import generate_requests, planned_total
from src.web_workbench.intruder.positions import parse_template
from src.web_workbench.intruder.repository import (
    STATUS_CANCELLED,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_PAUSED,
    STATUS_RUNNING,
    IntruderRepository,
)
from src.web_workbench.intruder.strategies import PayloadSet, Strategy
from src.web_workbench.message_editor.engine import RawHttpMessage
from src.web_workbench.proxy.forward_gate import ForwardGate, ForwardOutcome, PreflightHook
from src.web_workbench.proxy.transport import HttpMessageError, NormalizedRequest
from src.web_workbench.projects.service import ProjectScopeService
from src.web_workbench.repeater.engine import HttpSender

_OUTCOME_FORWARD = str(ForwardOutcome.FORWARD.value)
_OUTCOME_BLOCKED = str(ForwardOutcome.BLOCKED.value)

#: Closed-taxonomy reasons for a request that never reached the gate/sender.
_REASON_MALFORMED = "malformed_request"
_REASON_SEND_FAILED = "send_failed"
_REASON_BUDGET_EXCEEDED = "budget_exceeded"


class AttackControl(StrEnum):
    """Control signal polled during a run to honour pause/cancel."""

    CONTINUE = "continue"
    PAUSE = "pause"
    CANCEL = "cancel"


#: Polled every ``control_poll_interval`` requests. The live surface backs this
#: with a fresh status read / Redis flag; tests inject a stub.
ControlHook = Callable[[], AttackControl]


class IntruderRunError(Exception):
    """Raised when an attack cannot start (bad template / config)."""


@dataclass(frozen=True)
class AttackRunSummary:
    """Terminal summary of an attack run (secret-free)."""

    attack_id: str
    status: str
    requests_planned: int
    forwarded: int
    blocked: int
    errored: int
    flagged: int
    completed: int


@dataclass(frozen=True)
class _GrepConfig:
    patterns: tuple[str, ...]
    regex: bool
    flag_statuses: frozenset[int]

    @property
    def active(self) -> bool:
        return bool(self.patterns) or bool(self.flag_statuses)


def _grep_config_from(config: dict[str, object] | None) -> _GrepConfig:
    """Read grep/flag options from the persisted attack ``config`` (fail-safe)."""
    if not config:
        return _GrepConfig(patterns=(), regex=False, flag_statuses=frozenset())
    grep = config.get("grep")
    patterns: tuple[str, ...] = ()
    regex = False
    if isinstance(grep, dict):
        raw_patterns = grep.get("patterns")
        if isinstance(raw_patterns, (list, tuple)):
            patterns = tuple(str(p) for p in raw_patterns)
        regex = bool(grep.get("regex", False))
    flag_statuses: set[int] = set()
    raw_statuses = config.get("flag_statuses")
    if isinstance(raw_statuses, (list, tuple)):
        for value in raw_statuses:
            try:
                flag_statuses.add(int(value))
            except (TypeError, ValueError):
                continue
    return _GrepConfig(patterns=patterns, regex=regex, flag_statuses=frozenset(flag_statuses))


def _max_requests_from(config: dict[str, object] | None) -> int | None:
    if not config:
        return None
    value = config.get("max_requests")
    if not isinstance(value, (int, str)):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


class IntruderService:
    """Runs an Intruder attack end-to-end: gate → send → record → checkpoint.

    Construct once (stateless apart from injected collaborators); call
    :meth:`run_attack` per attack. The ``control_hook`` (optional) is polled
    every ``control_poll_interval`` requests to honour pause/cancel promptly.
    """

    def __init__(
        self,
        repository: IntruderRepository,
        *,
        sender: HttpSender,
        control_hook: ControlHook | None = None,
        control_poll_interval: int = 25,
    ) -> None:
        if control_poll_interval < 1:
            raise ValueError("control_poll_interval must be >= 1")
        self._repo = repository
        self._sender = sender
        self._control_hook = control_hook
        self._control_poll = control_poll_interval

    async def run_attack(
        self,
        session,  # AsyncSession — kept untyped to avoid a hard import cycle
        tenant_id: str,
        attack_id: str,
        *,
        scope_service: ProjectScopeService,
        payload_sets: Sequence[PayloadSet],
        payload_labels: Sequence[str] = (),
        preflight_hook: PreflightHook | None = None,
    ) -> AttackRunSummary:
        """Execute (or resume) an attack, persisting every gated outcome.

        ``payload_sets`` MUST already be materialised from the signed payload
        registry by the caller. ``payload_labels`` (optional, indexed by request
        ordinal) records which registry payload was used — a reference, never the
        raw payload value.
        """
        attack = await self._repo.get_attack(session, tenant_id, attack_id)
        if attack is None:
            raise IntruderRunError(f"attack {attack_id!r} not found")

        try:
            template = parse_template(attack.raw_request_template)
            strategy = Strategy(attack.attack_type)
            planned = planned_total(template, strategy, payload_sets)
        except (HttpMessageError, ValueError) as exc:
            await self._repo.save_progress(
                session, tenant_id, attack_id, status=STATUS_FAILED, error_reason=str(exc)[:256]
            )
            raise IntruderRunError(str(exc)) from exc

        max_requests = _max_requests_from(attack.config)
        if max_requests is not None and planned > max_requests:
            await self._repo.save_progress(
                session,
                tenant_id,
                attack_id,
                status=STATUS_FAILED,
                requests_total=planned,
                error_reason=_REASON_BUDGET_EXCEEDED,
            )
            return AttackRunSummary(
                attack_id=attack_id,
                status=STATUS_FAILED,
                requests_planned=planned,
                forwarded=0,
                blocked=0,
                errored=0,
                flagged=0,
                completed=0,
            )

        # Resume: skip indices already recorded (idempotent re-send guard).
        start_index = int((attack.checkpoint or {}).get("next_index", 0))
        gate = ForwardGate(scope_service, preflight_hook=preflight_hook)
        grep = _grep_config_from(attack.config)

        await self._repo.save_progress(
            session, tenant_id, attack_id, status=STATUS_RUNNING, requests_total=planned
        )

        forwarded = blocked = errored = flagged = completed = 0
        terminal = STATUS_COMPLETED
        next_index = start_index

        for generated in generate_requests(template, strategy, payload_sets):
            index = generated.index
            if index < start_index:
                continue

            if completed and completed % self._control_poll == 0:
                signal = self._poll_control()
                if signal is AttackControl.CANCEL:
                    terminal = STATUS_CANCELLED
                    break
                if signal is AttackControl.PAUSE:
                    terminal = STATUS_PAUSED
                    break

            label = payload_labels[index] if index < len(payload_labels) else None
            outcome = await self._run_one(
                session,
                tenant_id,
                attack.project_id,
                attack_id,
                index,
                generated.raw,
                gate=gate,
                grep=grep,
                payload_label=label,
            )
            forwarded += outcome.forwarded
            blocked += outcome.blocked
            errored += outcome.errored
            flagged += outcome.flagged
            completed += 1
            next_index = index + 1

            # Periodic checkpoint so a crash resumes cleanly.
            if completed % self._control_poll == 0:
                await self._repo.save_progress(
                    session,
                    tenant_id,
                    attack_id,
                    requests_completed=completed,
                    findings_total=flagged,
                    checkpoint={"next_index": next_index},
                )

        await self._repo.save_progress(
            session,
            tenant_id,
            attack_id,
            status=terminal,
            requests_completed=completed,
            findings_total=flagged,
            checkpoint={"next_index": next_index},
        )
        return AttackRunSummary(
            attack_id=attack_id,
            status=terminal,
            requests_planned=planned,
            forwarded=forwarded,
            blocked=blocked,
            errored=errored,
            flagged=flagged,
            completed=completed,
        )

    # -- internals -----------------------------------------------------------

    def _poll_control(self) -> AttackControl:
        if self._control_hook is None:
            return AttackControl.CONTINUE
        return self._control_hook()

    async def _run_one(
        self,
        session,
        tenant_id: str,
        project_id: str,
        attack_id: str,
        index: int,
        raw: bytes,
        *,
        gate: ForwardGate,
        grep: _GrepConfig,
        payload_label: str | None,
    ) -> _OneOutcome:
        try:
            request = NormalizedRequest.parse(raw)
        except HttpMessageError:
            await self._repo.record_request(
                session,
                tenant_id,
                project_id=project_id,
                attack_id=attack_id,
                request_index=index,
                forward_outcome=_OUTCOME_BLOCKED,
                payload_label=payload_label,
                payload_index=index,
                error_reason=_REASON_MALFORMED,
            )
            return _OneOutcome(errored=1)

        decision = gate.evaluate(request)
        if not decision.allowed:
            await self._repo.record_request(
                session,
                tenant_id,
                project_id=project_id,
                attack_id=attack_id,
                request_index=index,
                forward_outcome=_OUTCOME_BLOCKED,
                payload_label=payload_label,
                payload_index=index,
                block_reason=decision.reason,
            )
            return _OneOutcome(blocked=1)

        body = RawHttpMessage.from_bytes(raw).body
        try:
            response = self._sender.send(request, body)
        except Exception:  # noqa: BLE001 - transport failures must not abort the run
            await self._repo.record_request(
                session,
                tenant_id,
                project_id=project_id,
                attack_id=attack_id,
                request_index=index,
                forward_outcome=_OUTCOME_FORWARD,
                payload_label=payload_label,
                payload_index=index,
                error_reason=_REASON_SEND_FAILED,
            )
            return _OneOutcome(errored=1)

        is_flagged = self._flag(response.raw, response.status_code, grep)
        await self._repo.record_request(
            session,
            tenant_id,
            project_id=project_id,
            attack_id=attack_id,
            request_index=index,
            forward_outcome=_OUTCOME_FORWARD,
            payload_label=payload_label,
            payload_index=index,
            status_code=response.status_code,
            response_length=len(response.raw),
            response_time_ms=response.duration_ms,
            response_sha256=hashlib.sha256(response.raw).hexdigest(),
            flagged=is_flagged,
        )
        return _OneOutcome(forwarded=1, flagged=1 if is_flagged else 0)

    @staticmethod
    def _flag(raw_response: bytes, status_code: int, grep: _GrepConfig) -> bool:
        if not grep.active:
            return False
        if status_code in grep.flag_statuses:
            return True
        if grep.patterns:
            return any(grep_match(raw_response, grep.patterns, regex=grep.regex))
        return False


@dataclass(frozen=True)
class _OneOutcome:
    forwarded: int = 0
    blocked: int = 0
    errored: int = 0
    flagged: int = 0


__all__ = [
    "AttackControl",
    "AttackRunSummary",
    "ControlHook",
    "IntruderRunError",
    "IntruderService",
]
